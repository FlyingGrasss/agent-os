#!/usr/bin/env bash
# AgentOS Daemon Installation Script
# Installs agentosd as a systemd user service
# 
# Usage: ./scripts/install.sh [--user|--system] [--prefix PATH]

set -euo pipefail

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
INSTALL_MODE="user"
PREFIX="/usr/local"
CARGO_PROFILE="release"
BINARY_NAME="agentosd"
SERVICE_NAME="agentosd"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --user)
            INSTALL_MODE="user"
            shift
            ;;
        --system)
            INSTALL_MODE="system"
            shift
            ;;
        --prefix)
            PREFIX="$2"
            shift 2
            ;;
        --profile)
            CARGO_PROFILE="$2"
            shift 2
            ;;
        -h|--help)
            cat <<EOF
Usage: $0 [OPTIONS]

Options:
    --user          Install as user service (default)
    --system        Install as system service (requires root)
    --prefix PATH   Installation prefix (default: /usr/local)
    --profile NAME  Cargo profile to build (default: release)
    -h, --help      Show this help

Examples:
    $0                    # Install as user service
    $0 --system           # Install as system service (requires sudo)
    $0 --prefix /opt/agentos  # Custom prefix
EOF
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}" >&2
            exit 1
            ;;
    esac
done

# Check if running as root for system install
if [[ "$INSTALL_MODE" == "system" && $EUID -ne 0 ]]; then
    echo -e "${RED}System installation requires root privileges. Run with sudo.${NC}" >&2
    exit 1
fi

# Determine paths based on install mode
if [[ "$INSTALL_MODE" == "system" ]]; then
    BIN_DIR="${PREFIX}/bin"
    SERVICE_DIR="/etc/systemd/system"
    STATE_DIR="/var/lib/agentosd"
    INBOX_DIR="/var/spool/agentosd/inbox"
    CONFIG_DIR="/etc/agentos"
    SERVICE_USER="agentosd"
    SERVICE_GROUP="agentosd"
else
    BIN_DIR="${HOME}/.local/bin"
    SERVICE_DIR="${HOME}/.config/systemd/user"
    STATE_DIR="${HOME}/.local/state/agentosd"
    INBOX_DIR="${HOME}/.local/share/agentos/inbox"
    CONFIG_DIR="${HOME}/.config/agentos"
    SERVICE_USER="${USER}"
    SERVICE_GROUP="${USER}"
fi

echo -e "${BLUE}=== AgentOS Daemon Installation ===${NC}"
echo -e "Mode:          ${INSTALL_MODE}"
echo -e "Prefix:        ${PREFIX}"
echo -e "Binary dir:    ${BIN_DIR}"
echo -e "Service dir:   ${SERVICE_DIR}"
echo -e "State dir:     ${STATE_DIR}"
echo -e "Inbox dir:     ${INBOX_DIR}"
echo -e "Config dir:    ${CONFIG_DIR}"
echo -e "Profile:       ${CARGO_PROFILE}"
echo ""

# Step 1: Build the release binary
echo -e "${BLUE}Step 1: Building release binary...${NC}"
cd "$(dirname "$0")/.."
if ! cargo build --profile "${CARGO_PROFILE}" -p agentos-cli --bin agentosd; then
    echo -e "${RED}Build failed!${NC}" >&2
    exit 1
fi
echo -e "${GREEN}Build successful!${NC}"

# Step 2: Install binary
echo -e "${BLUE}Step 2: Installing binary to ${BIN_DIR}...${NC}"
mkdir -p "${BIN_DIR}"
cp "target/${CARGO_PROFILE}/${BINARY_NAME}" "${BIN_DIR}/${BINARY_NAME}"
chmod 755 "${BIN_DIR}/${BINARY_NAME}"
echo -e "${GREEN}Binary installed!${NC}"

# Step 3: Create directories
echo -e "${BLUE}Step 3: Creating directory structure...${NC}"
mkdir -p "${STATE_DIR}"
mkdir -p "${INBOX_DIR}"
mkdir -p "${CONFIG_DIR}"
mkdir -p "${SERVICE_DIR}"

# Set permissions
chmod 700 "${STATE_DIR}"
chmod 755 "${INBOX_DIR}"
chmod 755 "${CONFIG_DIR}"

# For system install, set ownership
if [[ "$INSTALL_MODE" == "system" ]]; then
    # Create user/group if they don't exist
    if ! getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
        groupadd --system "${SERVICE_GROUP}"
    fi
    if ! getent passwd "${SERVICE_USER}" >/dev/null 2>&1; then
        useradd --system --home-dir "${STATE_DIR}" --shell /usr/sbin/nologin \
            --gid "${SERVICE_GROUP}" "${SERVICE_USER}"
    fi
    chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${STATE_DIR}"
    chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${INBOX_DIR}"
    chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${CONFIG_DIR}"
fi

echo -e "${GREEN}Directories created!${NC}"

# Step 4: Install systemd service file
echo -e "${BLUE}Step 4: Installing systemd service...${NC}"
SERVICE_FILE_SOURCE="$(dirname "$0")/../contrib/systemd/agentosd.service"
SERVICE_FILE_DEST="${SERVICE_DIR}/${SERVICE_NAME}.service"

# For system install, we need to adjust the service file paths
if [[ "$INSTALL_MODE" == "system" ]]; then
    sed -e "s|%h|${STATE_DIR}|g" \
        -e "s|%h/.local/share/agentos/inbox|${INBOX_DIR}|g" \
        -e "s|%h/.config/agentos|${CONFIG_DIR}|g" \
        -e "s|/usr/local/bin/agentosd|${BIN_DIR}/${BINARY_NAME}|g" \
        -e "s|User=%i|User=${SERVICE_USER}|g" \
        -e "s|Group=%i|Group=${SERVICE_GROUP}|g" \
        -e "s|WantedBy=default.target|WantedBy=multi-user.target|g" \
        "${SERVICE_FILE_SOURCE}" > "${SERVICE_FILE_DEST}"
else
    # User install - use the template as-is with %h expansion
    cp "${SERVICE_FILE_SOURCE}" "${SERVICE_FILE_DEST}"
fi

echo -e "${GREEN}Service file installed to ${SERVICE_FILE_DEST}!${NC}"

# Step 5: Reload systemd and enable service
echo -e "${BLUE}Step 5: Reloading systemd...${NC}"
if [[ "$INSTALL_MODE" == "system" ]]; then
    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}.service"
    echo -e "${GREEN}Service enabled! Start with: sudo systemctl start ${SERVICE_NAME}${NC}"
else
    systemctl --user daemon-reload
    systemctl --user enable "${SERVICE_NAME}.service"
    # Enable lingering so user service starts at boot
    loginctl enable-linger "${USER}" 2>/dev/null || true
    echo -e "${GREEN}Service enabled! Start with: systemctl --user start ${SERVICE_NAME}${NC}"
fi

# Step 6: Create default config if it doesn't exist
CONFIG_FILE="${CONFIG_DIR}/config.toml"
if [[ ! -f "${CONFIG_FILE}" ]]; then
    echo -e "${BLUE}Step 6: Creating default configuration...${NC}"
    cat > "${CONFIG_FILE}" <<EOF
# AgentOS Daemon Configuration
# See https://github.com/agent-os/agent-os for documentation

# Model to use for planning (Ollama model name)
model = "llama3.2:3b"

# Inbox directory to watch for dropped files
inbox_path = "${INBOX_DIR}"

# Allowed hosts for http.fetch (empty = none allowed)
allowed_hosts = []

# Write roots for fs.write (empty = none allowed)
write_roots = []

# Enable email sending (requires outbox configuration)
send_email_enabled = false

# Maximum concurrent tasks
max_concurrent_tasks = 1

# Inbox rate limiting (payloads per minute)
inbox_rate_per_minute = 12
inbox_burst = 8

# TCP listen address (empty = Unix socket only)
# tcp_addr = "127.0.0.1:54321"
EOF
    echo -e "${GREEN}Configuration created at ${CONFIG_FILE}!${NC}"
else
    echo -e "${YELLOW}Configuration already exists at ${CONFIG_FILE}, skipping.${NC}"
fi

# Step 7: Verify installation
echo -e "${BLUE}Step 7: Verifying installation...${NC}"
if [[ -x "${BIN_DIR}/${BINARY_NAME}" ]]; then
    echo -e "${GREEN}✓ Binary installed and executable${NC}"
else
    echo -e "${RED}✗ Binary not found or not executable${NC}" >&2
    exit 1
fi

if [[ -f "${SERVICE_FILE_DEST}" ]]; then
    echo -e "${GREEN}✓ Service file installed${NC}"
    
    # Validate service file
    if [[ "$INSTALL_MODE" == "system" ]]; then
        if systemctl analyze verify "${SERVICE_FILE_DEST}" 2>/dev/null; then
            echo -e "${GREEN}✓ Service file passes systemd-analyze verify${NC}"
        else
            echo -e "${YELLOW}⚠ Service file validation warnings (may be OK)${NC}"
        fi
    else
        if systemctl --user analyze verify "${SERVICE_FILE_DEST}" 2>/dev/null; then
            echo -e "${GREEN}✓ Service file passes systemd-analyze verify${NC}"
        else
            echo -e "${YELLOW}⚠ Service file validation warnings (may be OK)${NC}"
        fi
    fi
else
    echo -e "${RED}✗ Service file not found${NC}" >&2
    exit 1
fi

echo ""
echo -e "${GREEN}=== Installation Complete! ===${NC}"
echo ""
echo -e "Next steps:"
if [[ "$INSTALL_MODE" == "system" ]]; then
    echo -e "  Start service:    ${BLUE}sudo systemctl start ${SERVICE_NAME}${NC}"
    echo -e "  Check status:     ${BLUE}sudo systemctl status ${SERVICE_NAME}${NC}"
    echo -e "  View logs:        ${BLUE}sudo journalctl -u ${SERVICE_NAME} -f${NC}"
else
    echo -e "  Start service:    ${BLUE}systemctl --user start ${SERVICE_NAME}${NC}"
    echo -e "  Check status:     ${BLUE}systemctl --user status ${SERVICE_NAME}${NC}"
    echo -e "  View logs:        ${BLUE}journalctl --user -u ${SERVICE_NAME} -f${NC}"
fi
echo -e "  Config file:      ${BLUE}${CONFIG_DIR}/config.toml${NC}"
echo -e "  Inbox directory:  ${BLUE}${INBOX_DIR}${NC}"
echo -e "  State directory:  ${BLUE}${STATE_DIR}${NC}"
echo ""
echo -e "The daemon will create its auth token on first start in:"
echo -e "  ${STATE_DIR}/auth.token"
echo ""
echo -e "To drop a file for processing, copy it to the inbox:"
echo -e "  ${BLUE}cp your-file.txt ${INBOX_DIR}/${NC}"