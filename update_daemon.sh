#!/bin/bash
# WayChain Daemon Auto-Updater
# Watches GitHub releases and auto-deploys new versions
# Run via systemd: systemctl enable waychain-updater.timer
# Or run manually: ./update_daemon.sh

set -e

REPO="ThinkIbrokeIt/waychain-consensus"
BINARY_PATH="/usr/local/bin/waychain"
SERVICE_NAME="waychain"
GITHUB_API="https://api.github.com/repos/$REPO/releases/latest"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $1"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)] WARNING:${NC} $1"; }
err() { echo -e "${RED}[$(date +%H:%M:%S)] ERROR:${NC} $1"; }

# Get currently running version
get_current_version() {
    if [ -f "$BINARY_PATH" ]; then
        "$BINARY_PATH" version 2>/dev/null || echo "unknown"
    else
        echo "not_installed"
    fi
}

# Get latest release from GitHub
get_latest_release() {
    curl -s "$GITHUB_API" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d['tag_name'])
except:
    print('none')
"
}

get_latest_tarball() {
    curl -s "$GITHUB_API" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for asset in d.get('assets', []):
        if 'linux-amd64' in asset['name']:
            print(asset['browser_download_url'])
            break
except:
    print('')
"
}

# Main update logic
CURRENT=$(get_current_version)
LATEST_TAG=$(get_latest_release)

log "Current version: $CURRENT"
log "Latest release:  $LATEST_TAG"

if [ "$LATEST_TAG" = "none" ]; then
    err "No releases found on GitHub"
    exit 1
fi

if [ "$CURRENT" = "$LATEST_TAG" ]; then
    log "Already up to date ($CURRENT)"
    exit 0
fi

log "New version available: $LATEST_TAG"

# Download new binary
TARBALL_URL=$(get_latest_tarball)
if [ -z "$TARBALL_URL" ]; then
    err "No linux-amd64 binary found in release $LATEST_TAG"
    exit 1
fi

log "Downloading $LATEST_TAG..."
TEMP_BINARY=$(mktemp /tmp/waychain.XXXXXX)
curl -sL -o "$TEMP_BINARY" "$TARBALL_URL"

# Verify checksums
log "Verifying checksums..."
CHECKSUM_URL=$(curl -s "$GITHUB_API" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for a in d.get('assets', []):
    if a['name'] == 'checksums.txt':
        print(a['browser_download_url'])
        break
")

if [ -n "$CHECKSUM_URL" ]; then
    TEMP_CHECKSUMS=$(mktemp /tmp/checksums.XXXXXX)
    curl -sL -o "$TEMP_CHECKSUMS" "$CHECKSUM_URL"
    
    EXPECTED=$(grep "linux-amd64" "$TEMP_CHECKSUMS" | awk '{print $1}')
    ACTUAL=$(sha256sum "$TEMP_BINARY" | awk '{print $1}')
    
    if [ "$EXPECTED" != "$ACTUAL" ]; then
        err "Checksum mismatch!"
        err "  Expected: $EXPECTED"
        err "  Actual:   $ACTUAL"
        rm -f "$TEMP_BINARY" "$TEMP_CHECKSUMS"
        exit 1
    fi
    log "Checksum verified ✅"
    rm -f "$TEMP_CHECKSUMS"
fi

# Install new binary
log "Installing $LATEST_TAG..."
chmod +x "$TEMP_BINARY"

# Backup current binary
if [ -f "$BINARY_PATH" ]; then
    cp "$BINARY_PATH" "${BINARY_PATH}.bak"
    log "Backed up current binary to ${BINARY_PATH}.bak"
fi

# Install new binary
mv "$TEMP_BINARY" "$BINARY_PATH"
log "Binary installed: $BINARY_PATH"

# Restart daemon
log "Restarting $SERVICE_NAME..."
sudo systemctl restart "$SERVICE_NAME"

# Wait for daemon to be ready
sleep 3

# Verify
NEW_VERSION=$("$BINARY_PATH" version 2>/dev/null || echo "unknown")
if [ "$NEW_VERSION" = "$LATEST_TAG" ]; then
    log "✅ Successfully updated to $LATEST_TAG"
    # Clean up backup after successful update
    rm -f "${BINARY_PATH}.bak"
else
    err "Update may have failed — running version: $NEW_VERSION"
    err "Backup available at: ${BINARY_PATH}.bak"
    exit 1
fi
