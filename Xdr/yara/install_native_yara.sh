#!/bin/bash
set -e

# Ensure running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] ERROR: This script must be run as root or with sudo." >&2
    exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
LOG_FILE="${SCRIPT_DIR}/status_install.log"
# Redirect stdout and stderr to both terminal and log file
exec > >(tee -i "$LOG_FILE") 2>&1

# Function to display installation status phase
print_status() {
    echo -e "\n========================================================"
    echo " [*] PHASE: $1"
    echo "========================================================"
}

echo "========================================================"
echo "      Auto-Installer: Wazuh YARA Active Response        "
echo "      Logging to: $LOG_FILE                             "
echo "========================================================"

print_status "1. OS & Package Manager Detection"
PKG_MGR="unknown"
OS_NAME="unknown"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME="${NAME:-$ID}"
    OS_ID="${ID:-unknown}"
    OS_LIKE="${ID_LIKE:-}"
    echo "[*] Detected OS: $OS_NAME (ID: $OS_ID, ID_LIKE: $OS_LIKE)"
else
    echo "[!] /etc/os-release not found. Detecting via package manager..."
fi

# Detect Package Manager based on OS ID / ID_LIKE or binary availability
if command -v apt-get >/dev/null 2>&1; then
    PKG_MGR="apt"
elif command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
elif command -v zypper >/dev/null 2>&1; then
    PKG_MGR="zypper"
elif command -v apk >/dev/null 2>&1; then
    PKG_MGR="apk"
elif command -v pacman >/dev/null 2>&1; then
    PKG_MGR="pacman"
fi
echo "[*] Selected Package Manager: $PKG_MGR"

print_status "2. Install Dependencies"
case $PKG_MGR in
    apt)
        export DEBIAN_FRONTEND=noninteractive
        echo "[*] Removing old package-managed yara (if any)..."
        apt-get remove --purge -y yara >/dev/null 2>&1 || true
        apt-get autoremove -y >/dev/null 2>&1 || true

        echo "[*] Updating apt repository and installing build dependencies..."
        apt-get update
        if apt-get install -y make gcc autoconf automake libtool libssl-dev pkg-config jq curl libmagic-dev auditd; then
            echo "[*] Dependencies installed successfully via apt-get."
        else
            echo "[!] Failed to install dependencies via apt-get."
            exit 1
        fi
        ;;

    dnf|yum)
        echo "[*] Removing old package-managed yara (if any)..."
        $PKG_MGR remove -y yara >/dev/null 2>&1 || true

        echo "[*] Setting up EPEL / CodeReady repositories if applicable..."
        case "$OS_ID" in
            amzn)
                # Amazon Linux 2 vs Amazon Linux 2023
                if command -v amazon-linux-extras >/dev/null 2>&1; then
                    amazon-linux-extras install epel -y || true
                fi
                ;;
            rhel)
                # Enable CodeReady Linux Builder (CRB) on RHEL 8/9 if subscription-manager available
                if command -v subscription-manager >/dev/null 2>&1; then
                    subscription-manager repos --enable "codeready-builder-for-rhel-$(rpm -E %{rhel})-$(uname -m)-rpms" >/dev/null 2>&1 || true
                fi
                $PKG_MGR install -y epel-release || true
                ;;
            centos|rocky|almalinux|ol)
                # Enable CRB / PowerTools
                if command -v dnf >/dev/null 2>&1; then
                    dnf config-manager --set-enabled crb >/dev/null 2>&1 || dnf config-manager --set-enabled powertools >/dev/null 2>&1 || true
                fi
                $PKG_MGR install -y epel-release || true
                ;;
            *)
                $PKG_MGR install -y epel-release || true
                ;;
        esac

        echo "[*] Installing build tools and devel libraries via $PKG_MGR..."
        $PKG_MGR groupinstall -y "Development Tools" >/dev/null 2>&1 || true
        if $PKG_MGR install -y gcc make autoconf automake libtool openssl-devel file-devel jq curl pkgconfig audit; then
            echo "[*] Dependencies installed successfully via $PKG_MGR."
        else
            echo "[!] Failed to install dependencies via $PKG_MGR."
            exit 1
        fi
        ;;

    zypper)
        echo "[*] Removing old package-managed yara (if any)..."
        zypper --non-interactive remove yara >/dev/null 2>&1 || true

        echo "[*] Installing dependencies via zypper..."
        zypper --non-interactive refresh
        if zypper --non-interactive install -y autoconf automake libtool make gcc gcc-c++ libopenssl-devel file-devel pkg-config jq curl audit; then
            echo "[*] Dependencies installed successfully via zypper."
        else
            echo "[!] Failed to install dependencies via zypper."
            exit 1
        fi
        ;;

    apk)
        echo "[*] Installing dependencies via apk (Alpine Linux)..."
        apk update
        if apk add --no-cache build-base autoconf automake libtool openssl-dev file-dev pkgconf jq curl bash audit; then
            echo "[*] Dependencies installed successfully via apk."
        else
            echo "[!] Failed to install dependencies via apk."
            exit 1
        fi
        ;;

    pacman)
        echo "[*] Installing dependencies via pacman (Arch/Manjaro)..."
        pacman -Sy --noconfirm
        if pacman -S --noconfirm --needed base-devel autoconf automake libtool openssl file pkgconf jq curl audit; then
            echo "[*] Dependencies installed successfully via pacman."
        else
            echo "[!] Failed to install dependencies via pacman."
            exit 1
        fi
        ;;

    *)
        echo "[!] Unsupported or unknown package manager. Continuing assuming dependencies already exist..."
        ;;
esac

print_status "3. Build & Install Yara 4.5.5 from source"
SRC_BASE="/usr/local/src"
mkdir -p "$SRC_BASE"
cd "$SRC_BASE"

echo "[*] Downloading Yara 4.5.5 source tarball..."
rm -rf yara-4.5.5 v4.5.5.tar.gz
if command -v curl >/dev/null 2>&1; then
    curl -fsSLO https://github.com/VirusTotal/yara/archive/refs/tags/v4.5.5.tar.gz
elif command -v wget >/dev/null 2>&1; then
    wget -q https://github.com/VirusTotal/yara/archive/refs/tags/v4.5.5.tar.gz
else
    echo "[!] Neither curl nor wget is available to download Yara source."
    exit 1
fi

tar -xzf v4.5.5.tar.gz
cd yara-4.5.5

echo "[*] Compiling Yara with Cuckoo, Magic, and Dotnet modules..."
./bootstrap.sh
./configure --enable-cuckoo --enable-magic --enable-dotnet
make -j"$(nproc 2>/dev/null || echo 2)"
make install

# Configure shared library path (fix common libyara.so missing error)
echo "[*] Configuring dynamic linker cache..."
if [ -d /etc/ld.so.conf.d ]; then
    echo "/usr/local/lib" > /etc/ld.so.conf.d/usr-local-lib.conf
elif [ -f /etc/ld.so.conf ] && ! grep -q "^/usr/local/lib" /etc/ld.so.conf; then
    echo "/usr/local/lib" >> /etc/ld.so.conf
fi
ldconfig 2>/dev/null || true

# Ensure binary is in /usr/bin for universal accessibility
if [ -f /usr/local/bin/yara ]; then
    ln -sf /usr/local/bin/yara /usr/bin/yara
fi

echo "[*] Yara compiled and installed successfully: $(yara --version 2>/dev/null || echo 'OK')"

print_status "4. Configure Wazuh Active Response Scripts"

WAZUH_GID=$(getent group wazuh | cut -d: -f3 2>/dev/null || true)
[ -z "$WAZUH_GID" ] && WAZUH_GID="wazuh"

mkdir -p /var/ossec/active-response/bin

for SRC in "${SCRIPT_DIR}"/*.sh "${SCRIPT_DIR}"/*.cmd "${SCRIPT_DIR}"/*.ps1; do
    [ -e "$SRC" ] || continue
    SCRIPT_NAME=$(basename "$SRC")
    if [ "$SCRIPT_NAME" = "install_native_yara.sh" ]; then
        continue
    fi
    
    DEST="/var/ossec/active-response/bin/${SCRIPT_NAME}"
    if [ "$SRC" != "$DEST" ]; then
        cp "$SRC" "$DEST"
    fi
    chown root:"$WAZUH_GID" "$DEST" 2>/dev/null || chown root:root "$DEST"
    chmod 750 "$DEST"
    echo "[*] Applied permissions (-rwxr-x---) to $DEST"
done

print_status "5. Configure Auditd Rules (C2/Exec Dropzone)"
RULE_SRC="${SCRIPT_DIR}/c2-exec.rules"
RULE_DEST="/etc/audit/rules.d/c2-exec.rules"

if [ -f "$RULE_SRC" ]; then
    mkdir -p /etc/audit/rules.d
    if [ "$RULE_SRC" != "$RULE_DEST" ]; then
        cp "$RULE_SRC" "$RULE_DEST"
    fi
    echo "[*] Rule deployed to $RULE_DEST"
    
    echo "[*] Reloading auditd rules..."
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load 2>/dev/null || true
    fi
    if command -v auditctl >/dev/null 2>&1; then
        auditctl -R "$RULE_DEST" 2>/dev/null || true
    fi
    
    echo "[*] Reloading auditd service..."
    service auditd restart >/dev/null 2>&1 || systemctl restart auditd >/dev/null 2>&1 || true
    echo "[*] Auditd configured successfully."
else
    echo "[!] Rule file $RULE_SRC not found, skipping auditd rule setup."
fi

print_status "6. Test Yara Installation & Rule Compilation"
YARA_BIN=$(command -v yara || echo "/usr/local/bin/yara")
if [ -x "$YARA_BIN" ]; then
    echo "[*] Yara binary verified: $("$YARA_BIN" --version 2>&1)"
    
    # Check potential rule file locations
    RULE_FOUND=0
    for RULE_PATH in "/var/ossec/etc/shared/default/yara_rules.yar" "/var/ossec/etc/shared/yara_rules.yar"; do
        if [ -f "$RULE_PATH" ]; then
            RULE_FOUND=1
            echo "[*] Testing compilation of: $RULE_PATH"
            if "$YARA_BIN" "$RULE_PATH" /dev/null >/dev/null 2>&1; then
                echo "[*] Yara rule test PASSED ($RULE_PATH)."
            else
                echo "[!] Yara rule compilation test produced warnings or errors in $RULE_PATH."
            fi
            break
        fi
    done

    if [ "$RULE_FOUND" -eq 0 ]; then
        echo "[*] No active yara_rules.yar file found yet (Wazuh Manager will synchronize it to the agent)."
    fi
else
    echo "[!] Yara binary not executable at $YARA_BIN."
    exit 1
fi

print_status "COMPLETE!"
echo "[*] Installation Successfully Completed."
echo "[*] Review log details at: $LOG_FILE"
