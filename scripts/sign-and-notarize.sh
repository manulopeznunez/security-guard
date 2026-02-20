#!/bin/bash
set -euo pipefail

# MacSecurityGuard — Build, Sign, and Notarize
#
# Usage:
#   ./scripts/sign-and-notarize.sh                  # Build + sign with Hardened Runtime
#   ./scripts/sign-and-notarize.sh --notarize        # Build + sign + notarize with Apple
#
# Required environment variables:
#   DEVELOPER_ID     — "Developer ID Application: Your Name (TEAMID)"
#
# For notarization (--notarize):
#   TEAM_ID          — Your Apple Developer Team ID
#   APPLE_ID         — Your Apple ID email
#   NOTARY_PASSWORD  — App-specific password or @keychain:notarytool

APP_NAME="MacSecurityGuard"
BUILD_DIR=".build/release"
BINARY="${BUILD_DIR}/${APP_NAME}"
ENTITLEMENTS="MacSecurityGuard.entitlements"

echo "=== Building ${APP_NAME} (release) ==="
swift build -c release

if [ ! -f "${BINARY}" ]; then
    echo "ERROR: Binary not found at ${BINARY}"
    exit 1
fi

echo "=== Signing with Hardened Runtime ==="
codesign --force --options runtime \
    --entitlements "${ENTITLEMENTS}" \
    --sign "${DEVELOPER_ID:--}" \
    "${BINARY}"

echo "=== Verifying signature ==="
codesign -dvvv "${BINARY}" 2>&1
codesign --verify --strict "${BINARY}"
echo "Signature valid."

if [ "${1:-}" = "--notarize" ]; then
    if [ -z "${APPLE_ID:-}" ] || [ -z "${TEAM_ID:-}" ] || [ -z "${NOTARY_PASSWORD:-}" ]; then
        echo "ERROR: APPLE_ID, TEAM_ID, and NOTARY_PASSWORD must be set for notarization"
        exit 1
    fi

    echo "=== Creating ZIP for notarization ==="
    ZIP_PATH="${BUILD_DIR}/${APP_NAME}.zip"
    ditto -c -k --keepParent "${BINARY}" "${ZIP_PATH}"

    echo "=== Submitting to Apple for notarization ==="
    xcrun notarytool submit "${ZIP_PATH}" \
        --apple-id "${APPLE_ID}" \
        --team-id "${TEAM_ID}" \
        --password "${NOTARY_PASSWORD}" \
        --wait

    echo "=== Stapling notarization ticket ==="
    xcrun stapler staple "${BINARY}" 2>/dev/null || echo "Note: stapling may not apply to CLI tools"

    echo "=== Notarization complete ==="
fi

echo "=== Done. Binary at: ${BINARY} ==="
