#!/usr/bin/env bash
set -euo pipefail

die() {
  echo "release verification failed: $*" >&2
  exit 1
}

is_stable_semver() {
  [[ ${1:-} =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
}

check_version() {
  local version=${1:-}
  is_stable_semver "$version" || die "version must be a stable SemVer (x.y.z): ${version:-<empty>}"
}

self_test() {
  local value
  local script_dir sparkle_bin sign_update generate_keys work attrs signature

  for value in 0.0.0 1.2.3 10.20.300; do
    is_stable_semver "$value" || die "self-test rejected valid version: $value"
  done

  for value in '' v1.2.3 01.2.3 1.02.3 1.2.03 1.2 1.2.3.4 \
    1.2.3-alpha 1.2.3+build '1.2.3;touch pwned' '1.2.3$(id)' '1.2.3/../../x'; do
    if is_stable_semver "$value"; then
      die "self-test accepted invalid version: ${value:-<empty>}"
    fi
  done

  # When SwiftPM artifacts are present, exercise the pinned Sparkle CLI contract
  # with a deterministic test seed. The lightweight MR job may not have fetched
  # dependencies yet; the real release job runs this after `swift test`, where
  # absence or incompatible behavior is fatal.
  script_dir="$(cd "$(dirname "$0")" && pwd)"
  sparkle_bin="$script_dir/../.build/artifacts/sparkle/Sparkle/bin"
  sign_update="$sparkle_bin/sign_update"
  generate_keys="$sparkle_bin/generate_keys"
  if [[ -e "$sign_update" || -e "$generate_keys" ]]; then
    [[ -x "$sign_update" && -x "$generate_keys" ]] || die "Sparkle tool pair is incomplete"
    [[ $(shasum -a 256 "$sign_update" | awk '{print $1}') == bfb52400c3da18bb4c251ac4818c2c2e1e31c2e649a45b31c11109b6e57b34ad ]] || \
      die "self-test refused unpinned sign_update binary"
    [[ $(shasum -a 256 "$generate_keys" | awk '{print $1}') == 2d18ed3a9c744e58150513d9b2e3c2eb76fd0b9621e3e4678d46dd972547e8fe ]] || \
      die "self-test refused unpinned generate_keys binary"
    "$generate_keys" --help 2>&1 | grep -Fq 'Generate public & private keys' || die "unexpected generate_keys CLI"
    work="$(mktemp -d "${TMPDIR:-/tmp}/sp-release-selftest.XXXXXX")"
    trap 'rm -rf "$work"' EXIT
    printf '%s' 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=' > "$work/key"
    printf '%s\n' 'deterministic update payload' > "$work/update.bin"
    attrs="$("$sign_update" --ed-key-file "$work/key" "$work/update.bin")"
    [[ "$attrs" =~ ^sparkle:edSignature=\"[A-Za-z0-9+/]{86}==\"\ length=\"[1-9][0-9]*\"$ ]] || \
      die "unexpected sign_update enclosure output"
    signature="${attrs#*sparkle:edSignature=\"}"
    signature="${signature%%\"*}"
    "$sign_update" --verify --ed-key-file "$work/key" "$work/update.bin" "$signature" >/dev/null || \
      die "Sparkle archive signature round-trip failed"
    printf '%s\n' '<?xml version="1.0"?><rss><channel><title>fixture</title></channel></rss>' > "$work/appcast.xml"
    "$sign_update" --ed-key-file "$work/key" "$work/appcast.xml" >/dev/null
    "$sign_update" --verify --ed-key-file "$work/key" "$work/appcast.xml" >/dev/null || \
      die "Sparkle feed signature round-trip failed"
    grep -Fq '<!-- sparkle-signatures:' "$work/appcast.xml" || die "Sparkle feed signature marker missing"
    rm -rf "$work"
    trap - EXIT
  fi

  echo "release verifier self-test passed"
}

publication_self_test() {
  local script_dir repo ci_file work
  local fixture_sha fixture_appcast_sha fixture_manifest_sha root downloads old_sha old_appcast_sha name

  script_dir="$(cd "$(dirname "$0")" && pwd)"
  repo="$(cd "$script_dir/../.." && pwd)"
  ci_file="$repo/.gitlab-ci.yml"
  [[ -f "$ci_file" ]] || die "cannot locate .gitlab-ci.yml"
  command -v ruby >/dev/null || die "ruby is required to extract the exact remote publication script"
  command -v sha256sum >/dev/null || die "sha256sum is required for the publication fixture"

  extract_origin_script() {
    ruby -ryaml -e '
      path = ARGV.fetch(0)
      config = YAML.safe_load(File.read(path), aliases: true, filename: path)
      script = config.fetch("publish-mac-release").fetch("script").fetch(0)
      abort("REMOTE_PUBLISH block missing") unless script.include?("<<'"'"'REMOTE_PUBLISH'"'"'\n")
      puts script.split("<<'"'"'REMOTE_PUBLISH'"'"'\n", 2).fetch(1).split("\nREMOTE_PUBLISH", 2).fetch(0)
    ' "$ci_file"
  }

  run_origin_script() {
    extract_origin_script | sh -s -- "$@"
  }

  write_fixture_manifest() {
    local output=$1 version=$2 build=$3 sha=$4 appcast_sha=$5
    printf '{"version":"%s","build":%s,"sha256":"%s","appcast_sha256":"%s"}\n' \
      "$version" "$build" "$sha" "$appcast_sha" > "$output"
  }

  make_fixture_stage() {
    local fixture_root=$1 version=$2 build=$3 token=$4 stage
    stage="$fixture_root/downloads/.incoming-$token"
    mkdir -p "$fixture_root/downloads/releases" "$stage"
    printf 'dmg-%s-%s' "$version" "$build" > "$stage/Sallyport-$version.dmg"
    printf 'appcast-%s-%s' "$version" "$build" > "$stage/appcast.xml"
    fixture_sha="$(sha256sum "$stage/Sallyport-$version.dmg" | awk '{print $1}')"
    fixture_appcast_sha="$(sha256sum "$stage/appcast.xml" | awk '{print $1}')"
    write_fixture_manifest "$stage/manifest.json" "$version" "$build" "$fixture_sha" "$fixture_appcast_sha"
    fixture_manifest_sha="$(sha256sum "$stage/manifest.json" | awk '{print $1}')"
    printf '%s  Sallyport-%s.dmg\n' "$fixture_sha" "$version" > "$stage/SHA256SUMS"
  }

  work="$(mktemp -d "${TMPDIR:-/tmp}/sp-publish-selftest.XXXXXX")"
  trap 'rm -rf "$work"' EXIT

  # Pristine: install the four stable links, then expose them with one current flip.
  root="$work/pristine"
  make_fixture_stage "$root" 1.0.0 1 pristine
  run_origin_script "$root" 1.0.0 1 "$fixture_sha" "$fixture_appcast_sha" "$fixture_manifest_sha" pristine
  [[ $(readlink "$root/downloads/current") == releases/1.0.0-1 ]] || die "pristine current link mismatch"
  for name in Sallyport.dmg SHA256SUMS manifest.json appcast.xml; do
    [[ $(readlink "$root/downloads/$name") == "current/$name" ]] || die "pristine stable link mismatch: $name"
  done

  # Complete legacy layout: snapshot the old generation, then flip to the new one.
  root="$work/legacy"; downloads="$root/downloads"
  mkdir -p "$downloads/releases"
  printf old-dmg > "$downloads/Sallyport.dmg"
  printf old-sums > "$downloads/SHA256SUMS"
  printf old-appcast > "$downloads/appcast.xml"
  old_sha="$(sha256sum "$downloads/Sallyport.dmg" | awk '{print $1}')"
  old_appcast_sha="$(sha256sum "$downloads/appcast.xml" | awk '{print $1}')"
  write_fixture_manifest "$downloads/manifest.json" 1.0.0 1 "$old_sha" "$old_appcast_sha"
  make_fixture_stage "$root" 1.1.0 2 legacy
  run_origin_script "$root" 1.1.0 2 "$fixture_sha" "$fixture_appcast_sha" "$fixture_manifest_sha" legacy
  [[ $(readlink "$downloads/current") == releases/1.1.0-2 ]] || die "legacy current link mismatch"
  [[ -f "$downloads/releases/legacy-legacy/manifest.json" ]] || die "legacy snapshot missing"

  # A partial legacy layout is ambiguous and must fail without installing current.
  root="$work/partial"; downloads="$root/downloads"
  mkdir -p "$downloads/releases"
  printf old-appcast > "$downloads/appcast.xml"
  old_sha="$(printf old-dmg | sha256sum | awk '{print $1}')"
  old_appcast_sha="$(sha256sum "$downloads/appcast.xml" | awk '{print $1}')"
  write_fixture_manifest "$downloads/manifest.json" 1.0.0 1 "$old_sha" "$old_appcast_sha"
  make_fixture_stage "$root" 1.1.0 2 partial
  if run_origin_script "$root" 1.1.0 2 "$fixture_sha" "$fixture_appcast_sha" "$fixture_manifest_sha" partial \
      >"$work/partial.out" 2>&1; then
    die "partial origin layout unexpectedly published"
  fi
  grep -Fq 'partial release layout' "$work/partial.out" || die "partial layout failed for the wrong reason"
  [[ ! -e "$downloads/current" && ! -L "$downloads/current" ]] || die "partial layout changed current"

  # The origin gate, not CDN state, must reject a semantic rollback.
  root="$work/rollback"; downloads="$root/downloads"
  mkdir -p "$downloads/releases/2.0.0-10"
  printf old-dmg > "$downloads/releases/2.0.0-10/Sallyport.dmg"
  printf old-sums > "$downloads/releases/2.0.0-10/SHA256SUMS"
  printf old-appcast > "$downloads/releases/2.0.0-10/appcast.xml"
  old_sha="$(sha256sum "$downloads/releases/2.0.0-10/Sallyport.dmg" | awk '{print $1}')"
  old_appcast_sha="$(sha256sum "$downloads/releases/2.0.0-10/appcast.xml" | awk '{print $1}')"
  write_fixture_manifest "$downloads/releases/2.0.0-10/manifest.json" 2.0.0 10 "$old_sha" "$old_appcast_sha"
  ln -s releases/2.0.0-10 "$downloads/current"
  for name in Sallyport.dmg SHA256SUMS manifest.json appcast.xml; do ln -s "current/$name" "$downloads/$name"; done
  make_fixture_stage "$root" 1.9.0 11 rollback
  if run_origin_script "$root" 1.9.0 11 "$fixture_sha" "$fixture_appcast_sha" "$fixture_manifest_sha" rollback \
      >"$work/rollback.out" 2>&1; then
    die "origin semantic rollback unexpectedly published"
  fi
  grep -Fq 'origin anti-rollback: version' "$work/rollback.out" || die "rollback failed for the wrong reason"
  [[ $(readlink "$downloads/current") == releases/2.0.0-10 ]] || die "rollback changed current"

  rm -rf "$work"
  trap - EXIT
  echo "origin publication self-test passed"
}

plist_value() {
  /usr/libexec/PlistBuddy -c "Print :$2" "$1" 2>/dev/null || true
}

assert_team_identifier() {
  local path=$1
  local expected_team=$2
  local details team

  details="$(codesign -dvv "$path" 2>&1)" || die "cannot inspect code signature: $path"
  team="$(printf '%s\n' "$details" | sed -n 's/^TeamIdentifier=//p' | tail -1)"
  [[ $team == "$expected_team" ]] || die "unexpected TeamIdentifier for $path: ${team:-<missing>}"
}

verify_artifacts() {
  [[ $# -eq 11 ]] || die "--artifacts requires APP DIST VERSION BUILD TEAM BUNDLE FEED PUBLIC_KEY KEY_FILE SIGN_UPDATE ARCH"

  local app=$1
  local dist=$2
  local version=$3
  local build=$4
  local team=$5
  local bundle=$6
  local feed=$7
  local public_key=$8
  local key_file=$9
  local sign_update=${10}
  local arch=${11}
  local info="$app/Contents/Info.plist"
  local dmg="$dist/Sallyport-$version.dmg"
  local appcast="$dist/appcast.xml"
  local manifest="$dist/manifest.json"
  local sums="$dist/SHA256SUMS"
  local dmg_signature
  local path

  check_version "$version"
  [[ $build =~ ^[1-9][0-9]*$ ]] || die "build must be a positive integer"
  [[ $team =~ ^[A-Z0-9]{10}$ ]] || die "invalid expected team identifier"
  [[ $bundle =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || die "invalid expected bundle identifier"
  [[ $feed == https://* ]] || die "feed URL must use HTTPS"
  [[ $arch == arm64 || $arch == x86_64 ]] || die "unexpected release architecture: $arch"
  [[ -x $sign_update ]] || die "missing exact Sparkle sign_update binary: $sign_update"
  [[ -s $key_file ]] || die "missing Sparkle private key file"
  [[ -d $app ]] || die "missing app bundle: $app"
  [[ -f $info && -f $dmg && -f $appcast && -f $manifest && -f $sums ]] || die "release artifact set is incomplete"

  plutil -lint "$info" >/dev/null || die "invalid app Info.plist"
  [[ $(plist_value "$info" CFBundleIdentifier) == "$bundle" ]] || die "unexpected app bundle identifier"
  [[ $(plist_value "$info" CFBundleShortVersionString) == "$version" ]] || die "unexpected app short version"
  [[ $(plist_value "$info" CFBundleVersion) == "$build" ]] || die "unexpected app build version"
  [[ $(plist_value "$info" CFBundleDevelopmentRegion) == en ]] || die "unexpected app development language"
  [[ $(plist_value "$info" SUFeedURL) == "$feed" ]] || die "unexpected app feed URL"
  [[ $(plist_value "$info" SUPublicEDKey) == "$public_key" ]] || die "unexpected embedded Sparkle public key"
  [[ $(plist_value "$info" SURequireSignedFeed) == true ]] || die "signed Sparkle feeds are not required"
  [[ $(plist_value "$info" SUVerifyUpdateBeforeExtraction) == true ]] || die "pre-extraction Sparkle verification is not required"

  local locale
  for locale in en de es fr pt-BR ru zh-Hans; do
    [[ -f "$app/Contents/Resources/$locale.lproj/Localizable.strings" ]] || \
      die "missing Localizable.strings for $locale"
    [[ -f "$app/Contents/Resources/$locale.lproj/Localizable.stringsdict" ]] || \
      die "missing Localizable.stringsdict for $locale"
    [[ -f "$app/Contents/Resources/$locale.lproj/InfoPlist.strings" ]] || \
      die "missing InfoPlist.strings for $locale"
    plutil -lint "$app/Contents/Resources/$locale.lproj/Localizable.strings" >/dev/null || \
      die "invalid Localizable.strings for $locale"
    plutil -lint "$app/Contents/Resources/$locale.lproj/Localizable.stringsdict" >/dev/null || \
      die "invalid Localizable.stringsdict for $locale"
    plutil -lint "$app/Contents/Resources/$locale.lproj/InfoPlist.strings" >/dev/null || \
      die "invalid InfoPlist.strings for $locale"
  done

  codesign --verify --deep --strict --verbose=2 "$app" || die "app code signature verification failed"
  [[ $(codesign -d --verbose=2 "$app" 2>&1 | sed -n 's/^Identifier=//p' | tail -1) == "$bundle" ]] || \
    die "signed app identifier does not match"
  # Read the signing identity from the embedded leaf certificate. The codesign
  # Authority field can be unavailable with CI's temporary keychain even when
  # signature verification passes. Check the team separately below.
  local cert_dir cert_cn
  cert_dir="$(mktemp -d)"
  codesign -d --extract-certificates="$cert_dir/cert" "$app" 2>/dev/null || {
    rm -rf "$cert_dir"; die "cannot extract app signing certificate"; }
  cert_cn="$(/usr/bin/openssl x509 -inform DER -in "$cert_dir/cert0" -noout -subject -nameopt RFC2253 2>/dev/null \
    | grep -oE 'CN=[^,]*' | sed 's/^CN=//')"
  rm -rf "$cert_dir"
  [[ $cert_cn == "Developer ID Application: "* ]] || \
    die "app is not signed with a Developer ID Application identity (leaf CN: ${cert_cn:-<none>})"

  for path in \
    "$app" \
    "$app/Contents/MacOS/Sallyport" \
    "$app/Contents/MacOS/sp" \
    "$app/Contents/MacOS/sp-ssh" \
    "$app/Contents/Frameworks/Sparkle.framework" \
    "$app/Contents/Frameworks/Sparkle.framework/Versions/B/Autoupdate" \
    "$app/Contents/Frameworks/Sparkle.framework/Versions/B/Updater.app" \
    "$app/Contents/Frameworks/Sparkle.framework/Versions/B/XPCServices/Downloader.xpc" \
    "$app/Contents/Frameworks/Sparkle.framework/Versions/B/XPCServices/Installer.xpc"; do
    [[ -e $path ]] || die "missing signed nested component: $path"
    assert_team_identifier "$path" "$team"
  done

  [[ $(lipo -archs "$app/Contents/MacOS/Sallyport") == "$arch" ]] || die "unexpected app architecture"
  [[ $(lipo -archs "$app/Contents/MacOS/sp") == "$arch" ]] || die "unexpected sp architecture"
  [[ $(lipo -archs "$app/Contents/MacOS/sp-ssh") == "$arch" ]] || die "unexpected sp-ssh architecture"
  for path in \
    "$app/Contents/Frameworks/Sparkle.framework/Versions/B/Sparkle" \
    "$app/Contents/Frameworks/Sparkle.framework/Versions/B/Autoupdate" \
    "$app/Contents/Frameworks/Sparkle.framework/Versions/B/Updater.app/Contents/MacOS/Updater" \
    "$app/Contents/Frameworks/Sparkle.framework/Versions/B/XPCServices/Downloader.xpc/Contents/MacOS/Downloader" \
    "$app/Contents/Frameworks/Sparkle.framework/Versions/B/XPCServices/Installer.xpc/Contents/MacOS/Installer"; do
    [[ $(lipo -archs "$path") == "$arch" ]] || die "unexpected Sparkle component architecture: $path"
  done

  python3 - "$manifest" "$version" "$build" "$dmg" "$feed" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

manifest_path, version, build, dmg_path, feed = sys.argv[1:]
with open(manifest_path, "rb") as stream:
    manifest = json.load(stream)

dmg = pathlib.Path(dmg_path)
expected = {
    "version": version,
    "build": int(build),
    "dmg": dmg.name,
    "sha256": hashlib.sha256(dmg.read_bytes()).hexdigest(),
    "size": dmg.stat().st_size,
    "url": f"{feed.rsplit('/', 1)[0]}/{dmg.name}",
    "appcast": feed,
}
for key, value in expected.items():
    if manifest.get(key) != value:
        raise SystemExit(f"manifest {key!r} mismatch: {manifest.get(key)!r} != {value!r}")
if set(manifest) != {*expected, "appcast_sha256", "published_at"}:
    raise SystemExit("manifest contains missing or unexpected fields")
appcast = pathlib.Path(manifest_path).with_name("appcast.xml")
if manifest.get("appcast_sha256") != hashlib.sha256(appcast.read_bytes()).hexdigest():
    raise SystemExit("manifest appcast_sha256 mismatch")
if not isinstance(manifest.get("published_at"), str) or not re.fullmatch(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", manifest["published_at"]
):
    raise SystemExit("manifest published_at is not canonical UTC")
PY

  (cd "$dist" && shasum -a 256 -c SHA256SUMS) || die "SHA256SUMS verification failed"

  dmg_signature="$(python3 - "$appcast" "$version" "$build" "$dmg" "$feed" <<'PY'
import sys
import xml.etree.ElementTree as ET

path, version, build, dmg, feed = sys.argv[1:]
sparkle = "http://www.andymatuschak.org/xml-namespaces/sparkle"
root = ET.parse(path).getroot()
channel = root.find("channel")
if channel is None:
    raise SystemExit("appcast channel missing")
if channel.findtext("title") != "Sallyport" or channel.findtext("link") != feed:
    raise SystemExit("appcast channel metadata mismatch")
items = channel.findall("item")
if len(items) != 1:
    raise SystemExit("appcast must contain exactly one item")
item = items[0]
if item.findtext("title") != version:
    raise SystemExit("appcast item title mismatch")
if item.findtext(f"{{{sparkle}}}version") != build:
    raise SystemExit("appcast item build mismatch")
if item.findtext(f"{{{sparkle}}}shortVersionString") != version:
    raise SystemExit("appcast item short version mismatch")
if item.findtext(f"{{{sparkle}}}minimumSystemVersion") != "14.0":
    raise SystemExit("appcast minimum system version mismatch")
enclosure = item.find("enclosure")
if enclosure is None:
    raise SystemExit("appcast enclosure missing")
expected = {
    f"{{{sparkle}}}shortVersionString": version,
    f"{{{sparkle}}}version": build,
    "url": f"{feed.rsplit('/', 1)[0]}/{dmg.rsplit('/', 1)[-1]}",
    "type": "application/octet-stream",
}
for key, value in expected.items():
    if enclosure.get(key) != value:
        raise SystemExit(f"appcast enclosure {key!r} mismatch")
description = item.find("description")
if description is None or not (description.text or "").strip():
    raise SystemExit("appcast release notes are missing")
signature = enclosure.get(f"{{{sparkle}}}edSignature", "")
if not signature:
    raise SystemExit("appcast enclosure signature missing")
if enclosure.get("length") != str(__import__("pathlib").Path(dmg).stat().st_size):
    raise SystemExit("appcast enclosure length mismatch")
print(signature)
PY
)" || die "appcast validation failed"

  grep -Fq '<!-- sparkle-signatures:' "$appcast" || die "appcast feed is not signed"
  "$sign_update" --verify --ed-key-file "$key_file" "$dmg" "$dmg_signature" >/dev/null || \
    die "Sparkle DMG signature verification failed"
  "$sign_update" --verify --ed-key-file "$key_file" "$appcast" >/dev/null || \
    die "Sparkle appcast signature verification failed"
}

case ${1:-} in
  --check-version)
    [[ $# -eq 2 ]] || die "usage: $0 --check-version VERSION"
    check_version "$2"
    ;;
  --self-test)
    [[ $# -eq 1 ]] || die "usage: $0 --self-test"
    self_test
    ;;
  --self-test-publication)
    [[ $# -eq 1 ]] || die "usage: $0 --self-test-publication"
    publication_self_test
    ;;
  --artifacts)
    shift
    verify_artifacts "$@"
    ;;
  *)
    die "usage: $0 --check-version VERSION | --self-test | --self-test-publication | --artifacts ..."
    ;;
esac
