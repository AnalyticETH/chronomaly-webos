#!/bin/bash
# WebOS Deployment Script for Chronomaly Exploit
# LG webOS 5.4.268-320 (ARM64)

set -e

EXPLOIT_BINARY="exploit-arm64"
WEBOS_TARGET_DIR="/tmp"
WEBOS_EXPLOIT_PATH="${WEBOS_TARGET_DIR}/${EXPLOIT_BINARY}"

# SSH Configuration (can be overridden with environment variables)
WEBOS_IP="${WEBOS_IP:-192.168.1.100}"
WEBOS_PORT="${WEBOS_PORT:-9922}"
WEBOS_USER="${WEBOS_USER:-prisoner}"
WEBOS_KEY="${WEBOS_KEY:-$HOME/.ssh/webos_rsa}"
SSH_OPTS="-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"

echo "[*] Chronomaly WebOS Deployment Script"
echo "[*] Target: LG webOS 5.4.268-320 (ARM64)"
echo ""

# Always rebuild to ensure latest code
echo "[*] Building exploit for ARM64..."
make clean
make webos

if [ ! -f "$EXPLOIT_BINARY" ]; then
    echo "[!] Build failed. Make sure aarch64-linux-gnu-gcc is installed:"
    echo "    sudo apt-get install gcc-aarch64-linux-gnu"
    exit 1
fi

echo "[*] Build successful: $EXPLOIT_BINARY"
echo "[*] Size: $(stat -f%z "$EXPLOIT_BINARY" 2>/dev/null || stat -c%s "$EXPLOIT_BINARY" 2>/dev/null) bytes"
echo ""

# Check for SSH key
if [ ! -f "$WEBOS_KEY" ]; then
    echo "[!] Error: SSH key not found at: $WEBOS_KEY"
    echo ""
    echo "Set the correct path with:"
    echo "    export WEBOS_KEY=/path/to/your/webos_rsa_key"
    echo ""
    echo "Or edit this script to set the default path."
    exit 1
fi

echo "[*] SSH Configuration:"
echo "    IP:   $WEBOS_IP"
echo "    Port: $WEBOS_PORT"
echo "    User: $WEBOS_USER"
echo "    Key:  $WEBOS_KEY"
echo ""

# Test SSH connection
echo "[*] Testing SSH connection..."
if ! ssh -i "$WEBOS_KEY" -p "$WEBOS_PORT" $SSH_OPTS "$WEBOS_USER@$WEBOS_IP" "echo 'Connection successful'" 2>/dev/null; then
    echo "[!] Error: Cannot connect to webOS device"
    echo ""
    echo "Make sure:"
    echo "  1. TV is powered on and connected to network"
    echo "  2. IP address is correct: $WEBOS_IP"
    echo "  3. SSH key is correct: $WEBOS_KEY"
    echo "  4. Developer mode is enabled on TV"
    echo ""
    echo "Override settings with environment variables:"
    echo "    export WEBOS_IP=<your_tv_ip>"
    echo "    export WEBOS_KEY=/path/to/your/key"
    exit 1
fi

echo "[+] WebOS device connected"
echo ""

# Push exploit to device (use SSH pipe since SCP to /tmp fails on webOS)
echo "[*] Copying exploit to webOS device..."
if ssh -i "$WEBOS_KEY" -p "$WEBOS_PORT" $SSH_OPTS "$WEBOS_USER@$WEBOS_IP" "cat > $WEBOS_EXPLOIT_PATH" < "$EXPLOIT_BINARY"; then
    echo "[+] Binary copied successfully"
else
    echo "[!] Error: Failed to copy binary"
    exit 1
fi

# Set executable permissions
echo "[*] Setting executable permissions..."
if ssh -i "$WEBOS_KEY" -p "$WEBOS_PORT" $SSH_OPTS "$WEBOS_USER@$WEBOS_IP" "chmod +x $WEBOS_EXPLOIT_PATH"; then
    echo "[+] Permissions set"
else
    echo "[!] Error: Failed to set permissions"
    exit 1
fi

# Copy HBC IPK if available (exploit will install it if HBC isn't already present)
IPK_FILE=$(ls org.webosbrew.hbchannel_*_all.ipk 2>/dev/null | head -1)
if [ -n "$IPK_FILE" ]; then
    echo "[*] Copying HBC IPK ($IPK_FILE) to device..."
    if ssh -i "$WEBOS_KEY" -p "$WEBOS_PORT" $SSH_OPTS "$WEBOS_USER@$WEBOS_IP" "cat > /tmp/hbchannel.ipk" < "$IPK_FILE"; then
        echo "[+] IPK copied"
    else
        echo "[!] Warning: Failed to copy IPK (HBC install will be skipped if not already present)"
    fi
else
    echo "[*] No HBC IPK found locally (org.webosbrew.hbchannel_*_all.ipk), skipping copy"
    echo "    Download from: https://github.com/webosbrew/webos-homebrew-channel/releases/"
    echo "    (OK to skip if already installed on TV)"
fi

echo ""
echo "[+] Deployment complete!"
echo ""
echo "=========================================="
echo "IMPORTANT: PRE-INSTALL HOMEBREW CHANNEL"
echo "=========================================="
echo ""
echo "For best results, install the Homebrew Channel app BEFORE running"
echo "the exploit. This way the rooting payload only needs to elevate it"
echo "(fast, reliable) rather than install + elevate (slower, can fail)."
echo ""
echo "  ares-install org.webosbrew.hbchannel_0.7.3_all.ipk"
echo ""
echo "=========================================="
echo "NOTES:"
echo "=========================================="
echo ""
echo "1. WebOS System Info:"
echo "   - Kernel: 5.4.268-320 (ARM64)"
echo "   - CPUs: 4 cores"
echo "   - User: prisoner (uid=5038)"
echo "   - CONFIG_POSIX_CPU_TIMERS_TASK_WORK: Not present (5.4 kernel)"
echo ""
echo "2. Tuning Parameters:"
echo "   The exploit uses ARM64-optimized defaults, but you may need to adjust:"
echo "   ./exploit-arm64 [DELAY] [DELTA] [THRESHOLD]"
echo "   Defaults: DELAY=31000 DELTA=50 THRESHOLD=3000"
echo "   See README.md for known-good values per TV model."
echo ""
echo "3. Connect and run:"
echo "   ssh -i $WEBOS_KEY -p $WEBOS_PORT $SSH_OPTS $WEBOS_USER@$WEBOS_IP"
echo "   $WEBOS_EXPLOIT_PATH"
echo ""
echo "   On 'Rooting payload executed!', devmode + elevate-service + HBC install are done."
echo "   Reboot the TV. After reboot, Homebrew Channel provides SSH on port 22."
echo ""
echo "4. Tuning guidance:"
echo "   - If you see 'Parent raced too late' often: DECREASE delay"
echo "   - If you see 'Parent raced too early' often: INCREASE delay"
echo "   - Ideally see both messages appearing for best results"
echo ""
echo "=========================================="
echo ""
echo "Connect:"
echo "ssh -i $WEBOS_KEY -p $WEBOS_PORT $SSH_OPTS $WEBOS_USER@$WEBOS_IP"
echo ""
echo "Run:  $WEBOS_EXPLOIT_PATH"
