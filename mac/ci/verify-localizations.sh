#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_CATALOG="$ROOT/Sources/SallyportApp/Resources/Localizable.xcstrings"
INFO_CATALOG="$ROOT/Resources/InfoPlist.xcstrings"
EXPECTED_LOCALES='["de","en","es","fr","pt-BR","ru","zh-Hans"]'
EXPECTED_DNT='["-y @modelcontextprotocol/server-github","203.0.113.10","22","AWS Signature Version 4","Bearer {secret}","Claude Code","Cursor","GITHUB_TOKEN","LOG_LEVEL=info","Sallyport","Touch ID","VS Code","X-Api-Key","api.example.com, 10.0.0.5","deploy","github","https://mcp.linear.app/mcp","linear","npx","web-prod"]'

die() {
  echo "localization verification failed: $*" >&2
  exit 1
}

command -v jq >/dev/null || die "jq is required"
command -v xcrun >/dev/null || die "xcrun is required"
[[ -f "$APP_CATALOG" ]] || die "missing app string catalog"
[[ -f "$INFO_CATALOG" ]] || die "missing Info.plist string catalog"

jq -e --argjson locales "$EXPECTED_LOCALES" --argjson dnt "$EXPECTED_DNT" '
  def units:
    if .stringUnit then [.stringUnit]
    elif .variations.plural then [.variations.plural[] | .stringUnit]
    else []
    end;
  def placeholders: [scan("%(?:[0-9]+\\$)?(?:lld|@)")] | sort;
  def protected_tokens:
    [scan("`[^`]+`|\\{secret\\}|Secure Enclave|Apple Silicon|Claude Code|VS Code|Touch ID|Sallyport|HTTPS|HTTP|OAuth|MCP|SSH|API|AWS|Cursor")]
    | sort;

  .sourceLanguage == "en"
  and .version == "1.1"
  and (.strings | length > 0)
  and ([.strings | to_entries[] | select(.value.shouldTranslate == false) | .key] | sort) == ($dnt | sort)
  and all(.strings | to_entries[];
    .key as $source
    | (.value.localizations | keys | sort) == $locales
      and (.value.shouldTranslate == null or .value.shouldTranslate == false)
      and all(.value.localizations[];
        (units | length) > 0
        and all(units[];
          .state == "translated"
          and (.value | type == "string" and length > 0)
          and ((.value | placeholders) == ($source | placeholders))
          and ((.value | protected_tokens) == ($source | protected_tokens))
        )
      )
      and (if .value.shouldTranslate == false then
        all(.value.localizations[] | units[]; .value == $source)
      else true end)
  )
' "$APP_CATALOG" >/dev/null || die "app catalog has missing locales, invalid states, changed placeholders, or invalid do-not-translate entries"

jq -e --argjson locales "$EXPECTED_LOCALES" '
  .sourceLanguage == "en"
  and .version == "1.1"
  and (.strings | keys | sort) == ["NSAppleEventsUsageDescription", "NSFaceIDUsageDescription"]
  and all(.strings[];
    (.localizations | keys | sort) == $locales
    and all(.localizations[].stringUnit;
      .state == "translated" and (.value | type == "string" and length > 0)
    )
  )
' "$INFO_CATALOG" >/dev/null || die "Info.plist catalog is incomplete"

plural_keys=(
  '%lld calls'
  '%lld events'
  '%lld more requests'
  '%lld pending requests'
  '%lld requests waiting'
  '%lld requests waiting for your decision.'
)

for key in "${plural_keys[@]}"; do
  for locale in en de es fr pt-BR ru zh-Hans; do
    case "$locale" in
      ru) categories='["few","many","one","other"]' ;;
      zh-Hans) categories='["other"]' ;;
      *) categories='["one","other"]' ;;
    esac
    jq -e --arg key "$key" --arg locale "$locale" --argjson categories "$categories" '
      (.strings[$key].localizations[$locale].variations.plural | keys | sort) == $categories
    ' "$APP_CATALOG" >/dev/null || die "missing plural categories for $locale: $key"
  done
done

work="$(mktemp -d "${TMPDIR:-/tmp}/sallyport-localizations.XXXXXX")"
trap 'rm -rf "$work"' EXIT
xcrun xcstringstool compile "$APP_CATALOG" --output-directory "$work"
xcrun xcstringstool compile "$INFO_CATALOG" --output-directory "$work"
for locale in en de es fr pt-BR ru zh-Hans; do
  [[ -s "$work/$locale.lproj/Localizable.strings" ]] || die "compiler omitted Localizable.strings for $locale"
  [[ -s "$work/$locale.lproj/Localizable.stringsdict" ]] || die "compiler omitted Localizable.stringsdict for $locale"
  [[ -s "$work/$locale.lproj/InfoPlist.strings" ]] || die "compiler omitted InfoPlist.strings for $locale"
  plutil -lint "$work/$locale.lproj/Localizable.strings" >/dev/null || die "invalid compiled app strings for $locale"
  plutil -lint "$work/$locale.lproj/Localizable.stringsdict" >/dev/null || die "invalid compiled app plurals for $locale"
  plutil -lint "$work/$locale.lproj/InfoPlist.strings" >/dev/null || die "invalid compiled Info.plist strings for $locale"
done

if [[ $# -gt 0 ]]; then
  [[ $# -eq 2 && $1 == --stringsdata ]] || die "usage: $0 [--stringsdata DIRECTORY]"
  stringsdata=$2
  [[ -d "$stringsdata" ]] || die "stringsdata directory does not exist: $stringsdata"
  files=()
  while IFS= read -r path; do files+=("$path"); done < <(find "$stringsdata" -type f -name '*.stringsdata' -print | sort)
  [[ ${#files[@]} -gt 0 ]] || die "no compiler stringsdata found in $stringsdata"
  extracted="$(jq -cs '[.[].tables.Localizable[]?.key | select(. != "")] | unique | sort' "${files[@]}")"
  catalog="$(jq -c '.strings | keys | sort' "$APP_CATALOG")"
  [[ $extracted == "$catalog" ]] || die "catalog keys do not match compiler extraction"
fi

echo "localization catalogs verified"
