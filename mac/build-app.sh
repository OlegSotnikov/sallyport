#!/usr/bin/env bash
#
# Assemble and sign Sallyport.app.
#
# The app runs in the menu bar, uses the hardened runtime, and stores its Secure
# Enclave trust roots in the Data Protection Keychain.
#
# `keychain-access-groups` requires a matching embedded provisioning profile.
# Without one, AMFI kills the app at launch even if codesign and spctl pass.
# SP_KEYCHAIN_GROUP=0 omits the entitlement and profile for development builds;
# release builds reject that setting. See mac/README.md.
#
# Usage:
#   ./build-app.sh                       # release build and sign
#   CONFIG=debug ./build-app.sh          # debug build
#   SP_KEYCHAIN_GROUP=0 ./build-app.sh   # development only, without a profile
#   IDENTITY="Apple Development: Name (TEAMID)" ./build-app.sh
#
# Verify:
#   codesign -dv --entitlements - build/Sallyport.app
#   open build/Sallyport.app
#   build/Sallyport.app/Contents/MacOS/Sallyport --selftest
set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(pwd)"

# Configuration. Override with environment variables.
CONFIG="${CONFIG:-release}"                       # release | debug
BUNDLE_ID="${BUNDLE_ID:-dev.sallyport.mac}"
APP_NAME="${APP_NAME:-Sallyport}"
# This paid team provides one-year profiles for the keychain access group.
# The access-group prefix must match the team ID.
TEAM_ID="${TEAM_ID:-9MZ2ZL5CA3}"
# All builds — local ones included — sign under the AppMaster team, matching
# the release lane (mac/ci/release.sh) and the shim's peer-trust check, which
# requires the app and sp to share one Team ID.
IDENTITY="${IDENTITY:-Developer ID Application: AppMaster Inc (9MZ2ZL5CA3)}"

[[ "$CONFIG" == "release" || "$CONFIG" == "debug" ]] || {
	echo "error: CONFIG must be release or debug" >&2; exit 1;
}
[[ "$BUNDLE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || {
	echo "error: invalid BUNDLE_ID: $BUNDLE_ID" >&2; exit 1;
}
[[ "$APP_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._\ -]*$ ]] || {
	echo "error: invalid APP_NAME: $APP_NAME" >&2; exit 1;
}
[[ "$TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || {
	echo "error: TEAM_ID must be a ten-character Apple Team ID" >&2; exit 1;
}
[[ -n "$IDENTITY" && "$IDENTITY" != *$'\n'* && "$IDENTITY" != *$'\r'* ]] || {
	echo "error: invalid signing identity" >&2; exit 1;
}
# Distribution and development builds use different profiles and timestamp
# policies. Developer ID uses the committed direct-distribution profile and a
# secure timestamp. Development uses the local wildcard profile without a
# timestamp so offline builds do not wait for Apple's service.
if [[ "$IDENTITY" == Developer\ ID\ Application* ]]; then
	TIMESTAMP="--timestamp"
	PROFILE="${PROFILE:-$ROOT/dev.sallyport.mac.developerid.provisionprofile}"
	DISTRIBUTION_BUILD=1
else
	TIMESTAMP="--timestamp=none"
	PROFILE="${PROFILE:-$ROOT/dev.sallyport.provisionprofile}"
	DISTRIBUTION_BUILD=0
fi
# SP_KEYCHAIN_GROUP=0 uses the development-only file store. Release builds must
# keep the Data Protection Keychain-backed trust roots.
[[ "${SP_KEYCHAIN_GROUP:-1}" == "0" || "${SP_KEYCHAIN_GROUP:-1}" == "1" ]] || {
	echo "error: SP_KEYCHAIN_GROUP must be 0 or 1" >&2; exit 1;
}
if [[ "$CONFIG" == "release" && "${SP_KEYCHAIN_GROUP:-1}" != "1" ]]; then
	echo "error: SP_KEYCHAIN_GROUP=0 is not allowed for release builds; trust roots require the Data Protection Keychain (see mac/README.md)" >&2
	exit 1
fi
if [[ "${SP_KEYCHAIN_GROUP:-1}" == "1" ]]; then
	ENTITLEMENTS="${ENTITLEMENTS:-$ROOT/Sallyport.keychain-group.entitlements}"
	EMBED_PROFILE=1
else
	ENTITLEMENTS="${ENTITLEMENTS:-$ROOT/Sallyport.entitlements}"
	EMBED_PROFILE=0
fi

[[ -f "$ENTITLEMENTS" ]] || { echo "error: entitlements not found at $ENTITLEMENTS" >&2; exit 1; }
plutil -lint "$ENTITLEMENTS" >/dev/null || { echo "error: invalid entitlements plist: $ENTITLEMENTS" >&2; exit 1; }
python3 - "$ENTITLEMENTS" "$TEAM_ID" "$BUNDLE_ID" "$EMBED_PROFILE" <<'PY'
import plistlib
import sys

path, team, bundle, embeds_profile = sys.argv[1:]
with open(path, "rb") as stream:
    entitlements = plistlib.load(stream)
if entitlements.get("com.apple.security.automation.apple-events") is not True:
    raise SystemExit("error: Automation Apple Events entitlement is required")
expected_group = f"{team}.{bundle}"
groups = entitlements.get("keychain-access-groups", [])
if embeds_profile == "1" and groups != [expected_group]:
    raise SystemExit(f"error: keychain access group must be exactly {expected_group!r}")
if embeds_profile == "0" and groups:
    raise SystemExit("error: profile-less build may not carry a keychain access group")
PY

# Validate the profile before building. Its entitlement, App ID, team,
# distribution class, expiry, and certificate must match this build.
if [[ "$EMBED_PROFILE" == "1" ]]; then
	[[ -f "$PROFILE" ]] || { echo "error: provisioning profile not found at $PROFILE (see mac/README.md)" >&2; exit 1; }
	PROFILE_PLIST="$(mktemp "${TMPDIR:-/tmp}/sallyport-profile.XXXXXX")"
	trap 'rm -f "$PROFILE_PLIST"' EXIT
	security cms -D -i "$PROFILE" > "$PROFILE_PLIST" || {
		echo "error: provisioning profile CMS signature/contents are invalid" >&2; exit 1;
	}
	PROFILE_CERT_HASHES="$(python3 - "$PROFILE_PLIST" "$TEAM_ID" "$BUNDLE_ID" "$DISTRIBUTION_BUILD" <<'PY'
import datetime
import hashlib
import plistlib
import sys

path, team, bundle, distribution = sys.argv[1:]
with open(path, "rb") as stream:
    profile = plistlib.load(stream)

expected_app = f"{team}.{bundle}"
if profile.get("TeamIdentifier") != [team]:
    raise SystemExit("error: provisioning profile TeamIdentifier mismatch")
if profile.get("ApplicationIdentifierPrefix") != [team]:
    raise SystemExit("error: provisioning profile application prefix mismatch")
if "OSX" not in profile.get("Platform", []):
    raise SystemExit("error: provisioning profile is not a macOS profile")
expiry = profile.get("ExpirationDate")
if not isinstance(expiry, datetime.datetime) or expiry <= datetime.datetime.now(expiry.tzinfo):
    raise SystemExit("error: provisioning profile is expired or has no valid expiry")
entitlements = profile.get("Entitlements", {})
profile_app = entitlements.get("com.apple.application-identifier")
if distribution == "1" and profile_app != expected_app:
    raise SystemExit("error: direct-distribution profile App ID mismatch")
if distribution == "0" and profile_app not in (expected_app, f"{team}.*"):
    raise SystemExit("error: development profile does not authorize the App ID")
if entitlements.get("com.apple.developer.team-identifier") != team:
    raise SystemExit("error: provisioning profile entitlement team mismatch")
allowed_groups = entitlements.get("keychain-access-groups", [])
if expected_app not in allowed_groups and f"{team}.*" not in allowed_groups:
    raise SystemExit("error: provisioning profile does not authorize the keychain group")
if distribution == "1" and profile.get("ProvisionsAllDevices") is not True:
    raise SystemExit("error: Developer ID build requires an all-devices direct-distribution profile")
if distribution == "1" and entitlements.get("com.apple.security.get-task-allow") is True:
    raise SystemExit("error: Developer ID profile must not enable get-task-allow")
certificates = profile.get("DeveloperCertificates", [])
if not certificates:
    raise SystemExit("error: provisioning profile has no authorized signing certificates")
print("\n".join(hashlib.sha1(cert).hexdigest().upper() for cert in certificates))
PY
)" || exit 1
	IDENTITY_LINES="$(security find-identity -v -p codesigning | grep -F "\"$IDENTITY\"" || true)"
	[[ -n "$IDENTITY_LINES" ]] || { echo "error: exact signing identity is not valid: $IDENTITY" >&2; exit 1; }
	SIGN_IDENTITY=""
	while IFS= read -r identity_line; do
		identity_sha1="$(printf '%s\n' "$identity_line" | awk '{print $2}')"
		if printf '%s\n' "$PROFILE_CERT_HASHES" | grep -Fxq "$identity_sha1"; then
			[[ -z "$SIGN_IDENTITY" ]] || { echo "error: multiple installed certificates match the identity and profile" >&2; exit 1; }
			SIGN_IDENTITY="$identity_sha1"
		fi
	done <<< "$IDENTITY_LINES"
	[[ -n "$SIGN_IDENTITY" ]] || {
		echo "error: no valid '$IDENTITY' certificate is authorized by $PROFILE" >&2; exit 1;
	}
	rm -f "$PROFILE_PLIST"
	trap - EXIT
else
	SIGN_IDENTITY="$IDENTITY"
fi
OUT_DIR="${OUT_DIR:-$ROOT/build}"
APP="$OUT_DIR/$APP_NAME.app"

# The release lane supplies the short version. Local builds use the latest tag.
# The build number comes from the Git revision count when not set explicitly.
SHORT_VERSION="${SHORT_VERSION:-$(git -C "$ROOT" describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')}"
SHORT_VERSION="${SHORT_VERSION:-0.1.0}"
"$ROOT/ci/verify-release.sh" --check-version "$SHORT_VERSION"
if [[ -z "${BUILD_VERSION:-}" ]]; then
	if BUILD_VERSION="$(git -C "$ROOT" rev-list --count HEAD 2>/dev/null)"; then :; else BUILD_VERSION="1"; fi
fi
[[ "$BUILD_VERSION" =~ ^[1-9][0-9]*$ ]] || {
	echo "error: BUILD_VERSION must be a positive integer" >&2; exit 1;
}

# Sparkle feed URL and public key. CI keeps the private signing key.
SP_APPCAST_URL="${SP_APPCAST_URL:-https://sallyport.dev/downloads/appcast.xml}"
SP_SPARKLE_PUBLIC_KEY="${SP_SPARKLE_PUBLIC_KEY:-xvIEDp3Pc8viCoZskmecU+xEmS2y5BHuYvKo5UGHk4E=}"
[[ "$SP_APPCAST_URL" =~ ^https://[^[:space:][:cntrl:]]+$ ]] || {
	echo "error: SP_APPCAST_URL must be a non-empty HTTPS URL" >&2; exit 1;
}
[[ "$SP_SPARKLE_PUBLIC_KEY" =~ ^[A-Za-z0-9+/]{43}=$ ]] || {
	echo "error: SP_SPARKLE_PUBLIC_KEY must be a 32-byte base64 Ed25519 public key" >&2; exit 1;
}
python3 - "$SP_SPARKLE_PUBLIC_KEY" <<'PY'
import base64
import binascii
import sys

encoded = sys.argv[1]
try:
    decoded = base64.b64decode(encoded, validate=True)
except binascii.Error as error:
    raise SystemExit(f"error: invalid Sparkle public key: {error}")
if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != encoded:
    raise SystemExit("error: Sparkle public key must be canonical base64 for exactly 32 bytes")
PY

# SP_ARCH pins the target architecture. Releases use arm64; local builds default
# to the host architecture. The array form is compatible with macOS Bash 3.2.
[[ -z "${SP_ARCH:-}" || "$SP_ARCH" == "arm64" || "$SP_ARCH" == "x86_64" ]] || {
	echo "error: SP_ARCH must be arm64 or x86_64" >&2; exit 1;
}
[[ "${SP_NO_PREVIEWS:-0}" == "0" || "${SP_NO_PREVIEWS:-0}" == "1" ]] || {
	echo "error: SP_NO_PREVIEWS must be 0 or 1" >&2; exit 1;
}
SWIFT_ARGS=(-c "$CONFIG")
if [[ -n "${SP_ARCH:-}" ]]; then
	SWIFT_ARGS+=(--arch "$SP_ARCH")
fi
# SP_NO_PREVIEWS=1 omits SwiftUI previews when only Command Line Tools are installed.
if [[ "${SP_NO_PREVIEWS:-0}" == "1" ]]; then
	SWIFT_ARGS+=(-Xswiftc -DSP_NO_PREVIEWS)
fi

echo "==> verify localizations"
"$ROOT/ci/verify-localizations.sh"
echo "==> swift build ${SWIFT_ARGS[*]}"
swift build "${SWIFT_ARGS[@]}"
BIN_PATH="$(swift build "${SWIFT_ARGS[@]}" --show-bin-path)"
EXE="$BIN_PATH/sallyport-app"
[[ -x "$EXE" ]] || { echo "error: built executable not found at $EXE" >&2; exit 1; }

# Bundle the Swift MCP shim and Go SSH helper. Production SSH signing uses the
# inherited agentFD and signatures. Stdin key material is limited to
# normalize_key, import, and legacy tests.
SP_SWIFT="$BIN_PATH/sp"
[[ -x "$SP_SWIFT" ]] || { echo "error: Swift 'sp' not built at $SP_SWIFT" >&2; exit 1; }

CORE_DIR="${CORE_DIR:-$ROOT/../core}"
command -v go >/dev/null || { echo "error: go not found (needed to build sp-ssh)" >&2; exit 1; }
echo "==> go build sp-ssh"
if [[ -n "${SP_ARCH:-}" ]]; then
	GO_ARCH="$SP_ARCH"; [[ "$GO_ARCH" == "x86_64" ]] && GO_ARCH="amd64"
	( cd "$CORE_DIR" && CGO_ENABLED=0 GOOS=darwin GOARCH="$GO_ARCH" go build -o bin/sp-ssh ./cmd/sp-ssh )
else
	( cd "$CORE_DIR" && go build -o bin/sp-ssh ./cmd/sp-ssh )
fi
[[ -x "$CORE_DIR/bin/sp-ssh" ]] || { echo "error: sp-ssh not built: $CORE_DIR/bin/sp-ssh" >&2; exit 1; }

echo "==> assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# Name the executable after CFBundleExecutable.
cp "$EXE" "$APP/Contents/MacOS/$APP_NAME"
chmod +x "$APP/Contents/MacOS/$APP_NAME"

# Copy the generated app icon.
cp "$ROOT/Resources/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"

# Compile the app and privacy-purpose string catalogs into the main bundle.
# SwiftUI resolves these strings through Bundle.main in the signed app.
LOCALIZABLE_CATALOG="$ROOT/Sources/SallyportApp/Resources/Localizable.xcstrings"
INFO_PLIST_CATALOG="$ROOT/Resources/InfoPlist.xcstrings"
for catalog in "$LOCALIZABLE_CATALOG" "$INFO_PLIST_CATALOG"; do
	[[ -f "$catalog" ]] || { echo "error: localization catalog not found: $catalog" >&2; exit 1; }
	xcrun xcstringstool compile "$catalog" --output-directory "$APP/Contents/Resources"
done

# Copy both helpers next to the app executable.
cp "$SP_SWIFT"              "$APP/Contents/MacOS/sp"
cp "$CORE_DIR/bin/sp-ssh"   "$APP/Contents/MacOS/sp-ssh"
chmod +x "$APP/Contents/MacOS/sp" "$APP/Contents/MacOS/sp-ssh"

# Embed the Sparkle framework from the Swift build output.
SPARKLE_FW="$BIN_PATH/Sparkle.framework"
[[ -d "$SPARKLE_FW" ]] || { echo "error: Sparkle.framework not at $SPARKLE_FW (swift build first)" >&2; exit 1; }
mkdir -p "$APP/Contents/Frameworks"
cp -R "$SPARKLE_FW" "$APP/Contents/Frameworks/Sparkle.framework"
FW="$APP/Contents/Frameworks/Sparkle.framework"
# Thin universal Sparkle binaries when a target architecture is set.
if [[ -n "${SP_ARCH:-}" ]]; then
	while IFS= read -r macho; do
		lipo -info "$macho" 2>/dev/null | grep -q 'fat file' && lipo "$macho" -thin "$SP_ARCH" -output "$macho"
	done < <(find "$FW" -type f -perm +111)
fi

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key>            <string></string>
	<key>CFBundleDisplayName</key>     <string></string>
	<key>CFBundleExecutable</key>      <string></string>
	<key>CFBundleIdentifier</key>      <string></string>
	<key>CFBundlePackageType</key>     <string>APPL</string>
	<key>CFBundleShortVersionString</key> <string></string>
	<key>CFBundleVersion</key>         <string></string>
	<key>CFBundleInfoDictionaryVersion</key> <string>6.0</string>
	<key>CFBundleDevelopmentRegion</key> <string>en</string>
	<key>LSMinimumSystemVersion</key>  <string>14.0</string>
	<!-- Menu-bar accessory only: no Dock icon, no default window. -->
	<key>LSUIElement</key>             <true/>
	<key>CFBundleIconFile</key>        <string>AppIcon</string>
	<key>NSHumanReadableCopyright</key><string>© 2025-2026 Oleg Sotnikov · AppMaster</string>
	<!-- Face ID copy for Macs that use it; Touch ID reuses the reason string. -->
	<key>NSFaceIDUsageDescription</key><string>Approve a Sallyport action with biometrics.</string>
	<!-- Apple Events reveal the terminal window for a selected session. -->
	<key>NSAppleEventsUsageDescription</key><string>Sallyport reveals the terminal window for a selected agent session.</string>
	<key>NSHighResolutionCapable</key> <true/>
	<!-- Sparkle checks the signed feed automatically but waits for approval
	     before installing an update. -->
	<key>SUFeedURL</key>              <string></string>
	<key>SUPublicEDKey</key>          <string></string>
	<!-- Reject unsigned feeds and verify archives before extraction. -->
	<key>SURequireSignedFeed</key>    <true/>
	<key>SUVerifyUpdateBeforeExtraction</key><true/>
	<key>SUEnableAutomaticChecks</key><true/>
	<key>SUAutomaticallyUpdate</key>  <false/>
</dict>
</plist>
PLIST

# Use plutil so dynamic values are encoded safely.
plutil -replace CFBundleName -string "$APP_NAME" "$APP/Contents/Info.plist"
plutil -replace CFBundleDisplayName -string "$APP_NAME" "$APP/Contents/Info.plist"
plutil -replace CFBundleExecutable -string "$APP_NAME" "$APP/Contents/Info.plist"
plutil -replace CFBundleIdentifier -string "$BUNDLE_ID" "$APP/Contents/Info.plist"
plutil -replace CFBundleShortVersionString -string "$SHORT_VERSION" "$APP/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$BUILD_VERSION" "$APP/Contents/Info.plist"
plutil -replace SUFeedURL -string "$SP_APPCAST_URL" "$APP/Contents/Info.plist"
plutil -replace SUPublicEDKey -string "$SP_SPARKLE_PUBLIC_KEY" "$APP/Contents/Info.plist"
plutil -lint "$APP/Contents/Info.plist" >/dev/null

# Add PkgInfo for tools that expect it.
printf 'APPL????' > "$APP/Contents/PkgInfo"

# Embed the profile before signing so AMFI authorizes the access group.
if [[ "$EMBED_PROFILE" == "1" ]]; then
	[[ -f "$PROFILE" ]] || { echo "error: provisioning profile not found at $PROFILE (see mac/README.md)" >&2; exit 1; }
	cp "$PROFILE" "$APP/Contents/embedded.provisionprofile"
	echo "==> embedded provisioning profile"
fi

# Sign helpers before their enclosing bundle. They use the app's identity and
# hardened runtime but need no app entitlements.
echo "==> codesign nested helpers (sp, sp-ssh)"
for b in sp sp-ssh; do
	codesign --force "$TIMESTAMP" --options runtime \
		--sign "$SIGN_IDENTITY" \
		"$APP/Contents/MacOS/$b"
done

# Re-sign Sparkle inside out with the app's identity for notarization.
echo "==> codesign Sparkle.framework (inside-out)"
FWV="$FW/Versions/B"
for nested in \
	"$FWV/XPCServices/Installer.xpc" \
	"$FWV/XPCServices/Downloader.xpc" \
	"$FWV/Autoupdate" \
	"$FWV/Updater.app"; do
	[[ -e "$nested" ]] && codesign --force "$TIMESTAMP" --options runtime --sign "$SIGN_IDENTITY" "$nested"
done
codesign --force "$TIMESTAMP" --options runtime --sign "$SIGN_IDENTITY" "$FW"

echo "==> codesign app bundle ($IDENTITY)"
codesign --force "$TIMESTAMP" --options runtime \
	--entitlements "$ENTITLEMENTS" \
	--sign "$SIGN_IDENTITY" \
	"$APP"

echo
echo "==> verify: codesign --verify --deep --strict"
codesign --verify --deep --strict --verbose=2 "$APP"

echo "==> verify: exact signer, team, bundle identifier, and entitlements"
APP_SIGNATURE="$(codesign -dvvv "$APP" 2>&1)"
SIGNED_IDENTIFIER="$(printf '%s\n' "$APP_SIGNATURE" | sed -n 's/^Identifier=//p' | tail -1)"
SIGNED_TEAM="$(printf '%s\n' "$APP_SIGNATURE" | sed -n 's/^TeamIdentifier=//p' | tail -1)"
SIGNED_AUTHORITY="$(printf '%s\n' "$APP_SIGNATURE" | sed -n 's/^Authority=//p' | head -1)"
[[ "$SIGNED_IDENTIFIER" == "$BUNDLE_ID" ]] || { echo "error: signed bundle identifier mismatch: $SIGNED_IDENTIFIER" >&2; exit 1; }
[[ "$SIGNED_TEAM" == "$TEAM_ID" ]] || { echo "error: signed TeamIdentifier mismatch: $SIGNED_TEAM" >&2; exit 1; }
[[ "$SIGNED_AUTHORITY" == "$IDENTITY" ]] || { echo "error: signed authority mismatch: $SIGNED_AUTHORITY" >&2; exit 1; }

for signed_path in \
	"$APP/Contents/MacOS/sp" \
	"$APP/Contents/MacOS/sp-ssh" \
	"$FW" \
	"$FWV/XPCServices/Installer.xpc" \
	"$FWV/XPCServices/Downloader.xpc" \
	"$FWV/Autoupdate" \
	"$FWV/Updater.app"; do
	[[ -e "$signed_path" ]] || { echo "error: signed component missing: $signed_path" >&2; exit 1; }
	component_team="$(codesign -dvv "$signed_path" 2>&1 | sed -n 's/^TeamIdentifier=//p' | tail -1)"
	[[ "$component_team" == "$TEAM_ID" ]] || { echo "error: component TeamIdentifier mismatch for $signed_path: $component_team" >&2; exit 1; }
done

SIGNED_ENTITLEMENTS="$(mktemp "${TMPDIR:-/tmp}/sallyport-entitlements.XXXXXX")"
trap 'rm -f "$SIGNED_ENTITLEMENTS"' EXIT
codesign -d --entitlements :- "$APP" > "$SIGNED_ENTITLEMENTS" 2>/dev/null
python3 - "$SIGNED_ENTITLEMENTS" "$TEAM_ID" "$BUNDLE_ID" "$EMBED_PROFILE" <<'PY'
import plistlib
import sys

path, team, bundle, embeds_profile = sys.argv[1:]
with open(path, "rb") as stream:
    entitlements = plistlib.load(stream)
if entitlements.get("com.apple.security.automation.apple-events") is not True:
    raise SystemExit("error: signed app is missing the Automation Apple Events entitlement")
expected = f"{team}.{bundle}"
groups = entitlements.get("keychain-access-groups", [])
if embeds_profile == "1" and groups != [expected]:
    raise SystemExit("error: signed app keychain access group mismatch")
if embeds_profile == "0" and groups:
    raise SystemExit("error: profile-less app unexpectedly carries a keychain group")
PY
rm -f "$SIGNED_ENTITLEMENTS"
trap - EXIT

echo
echo "==> nested helper signatures (codesign -dv)"
for b in sp sp-ssh; do
	echo "$b:"
	codesign -dv "$APP/Contents/MacOS/$b" 2>&1
done

echo
echo "==> codesign -dv --entitlements -"
codesign -dv --entitlements - "$APP" 2>&1

# Register the bundle so notifications resolve its current icon.
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
if [[ -x "$LSREGISTER" ]]; then
	echo "==> register with LaunchServices (so notifications find the icon)"
	"$LSREGISTER" -f "$APP" || true
fi

echo
echo "Built and signed: $APP"
echo "  short=$SHORT_VERSION build=$BUILD_VERSION config=$CONFIG bundle=$BUNDLE_ID team=$TEAM_ID"
echo "  run   : open \"$APP\"   (or \"$APP/Contents/MacOS/$APP_NAME\")"
echo "  proof : \"$APP/Contents/MacOS/$APP_NAME\" --selftest"
