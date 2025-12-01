#!/bin/bash

# Logstag Agent Installation Script for Linux
#
# This script installs the Logstag Agent on supported Linux distributions
#
# Usage:
#   curl -sSL https://techmindpartners.github.io/logstag-agent-dist/agent-install.sh | bash
#   curl -sSL https://techmindpartners.github.io/logstag-agent-dist/agent-install.sh | bash -s -- --channel dev
#   curl -sSL https://techmindpartners.github.io/logstag-agent-dist/agent-install.sh | bash -s -- --version 0.1.79
#   curl -sSL https://techmindpartners.github.io/logstag-agent-dist/agent-install.sh | bash -s -- --channel dev --version 0.1.79
#   curl -sSL https://techmindpartners.github.io/logstag-agent-dist/agent-install.sh | bash -s -- --no-start-service
#
# Parameters:
#   --channel <main|dev>    Release channel (default: main)
#   --version <x.y.z>       Specific version to install (default: latest)
#   --start-service         Start the service after successful configuration (default: true)
#   --no-start-service      Do not start the service after installation
#
# Environment Variables:
#   LOGSTAG_CHANNEL                 Release channel
#   LOGSTAG_VERSION                 Specific version to install
#   LOGSTAG_INSTALL_NONINTERACTIVE  Non-interactive installation
#   LOGSTAG_START_SERVICE           Start service after configuration (default: true)
#   LOGSTAG_API_KEY                 API key for configuration
#   LOGSTAG_API_BASE_URL            API base URL for configuration
#   LOGSTAG_ENCRYPT_API_KEY         Set to "false" to disable API key encryption

# Exit immediately if a command exits with a non-zero status.
set -e

# Path variables
INSTALL_PATH="/opt/logstag-agent"
CONFIG_PATH="/etc/logstag-agent.toml"
LOG_PATH="/var/log/logstag-agent"

# Add cleanup trap for temporary files
cleanup() {
  if [ -f "/tmp/logstag_key.asc" ]; then
    rm -f /tmp/logstag_key.asc
  fi
  if [ -f "/tmp/logstag_key.tmp" ]; then
    rm -f /tmp/logstag_key.tmp
  fi
}

trap cleanup EXIT

# Function to handle installation failures
# Displays error message and provides helpful guidance for manual installation
fail () {
  >&2 echo
  >&2 echo "❌ Install failed: $1"
  >&2 echo
  >&2 echo "Troubleshooting:"
  >&2 echo "  • Check internet connectivity"
  >&2 echo "  • Verify you have sudo permissions"
  >&2 echo "  • Check system logs: journalctl -xe"
  >&2 echo "  • Visit: https://docs.logstag.com/troubleshooting"
  >&2 echo "  • For security issues, verify GPG key fingerprint"
  exit 1
}

# Function to download files with retry logic and timeout
download_with_retry() {
  local url="$1"
  local output="$2"
  local max_attempts=3
  local attempt=1
  
  while [ $attempt -le $max_attempts ]; do
    echo "Download attempt $attempt of $max_attempts: $url"
    if curl -L --fail --connect-timeout 30 --max-time 120 --retry 2 --retry-delay 1 "$url" -o "$output"; then
      echo "Download successful"
      return 0
    fi

    # Get HTTP status code for better error reporting
    http_code=$(curl -L --connect-timeout 30 --max-time 120 --retry 2 --retry-delay 1 -w "%{http_code}" -o /dev/null -s "$url" || echo "000")
    if [ "$http_code" = "404" ]; then
      echo "Error: File not found (404). This may indicate the specified version does not exist."
      return 1
    fi

    echo "Download attempt $attempt failed (HTTP $http_code)"
    attempt=$((attempt + 1))
    if [ $attempt -le $max_attempts ]; then
      echo "Retrying in 2 seconds..."
      sleep 2
    fi
  done
  
  echo "Failed to download $url after $max_attempts attempts"
  return 1
}

# Function to validate version format
validate_version() {
  local version="$1"
  if [ -n "$version" ]; then
    if ! echo "$version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
      fail "Invalid version format: $version. Expected format: x.y.z (e.g., 0.1.79)"
    fi
  fi
}

# Function to construct download URL for specific version
get_version_download_url() {
  local base_url="$1"
  local channel="$2"
  local arch="$3"
  local version="$4"
  local package_type="$5"

  # For specific versions, use GitHub raw URL for actual downloads
  local github_base_url="https://github.com/techmindpartners/logstag-agent-dist/raw/main"

  # Convert version format from x.y.z to x.y.z (keep dots for new structure)
  local url_version="$version"

  # Construct filename based on package type and architecture
  local filename=""
  local path=""
  case "$package_type" in
    "rpm")
      # RPM path: /rpm/{channel}/{arch}/
      filename="logstag-agent-${url_version}-1.${arch}.rpm"
      path="rpm/${channel}/${arch}"
      ;;
    "deb")
      # DEB path: /pool/{channel}/l/logstag-agent/
      filename="logstag-agent_${url_version}-1_${arch}.deb"
      path="pool/${channel}/l/logstag-agent"
      ;;
    *)
      fail "Unsupported package type: $package_type"
      ;;
  esac

  echo "${github_base_url}/${path}/${filename}"
}

# Function to validate URL format
validate_url() {
  local url="$1"
  if [ -n "$url" ] && ! echo "$url" | grep -qE '^https?://[a-zA-Z0-9.-]+'; then
    fail "Invalid URL format: $url"
  fi
}

# Function to validate API key format
validate_api_key() {
  local api_key="$1"
  if [ -n "$api_key" ]; then
    if [ ${#api_key} -lt 32 ]; then
      fail "API key appears to be too short (minimum 32 characters expected)"
    fi
    # Check for basic format (alphanumeric and common special chars)
    if ! echo "$api_key" | grep -qE '^[a-zA-Z0-9._-]+$'; then
      fail "API key contains invalid characters"
    fi
  fi
}

# Function to verify configuration after changes
validate_config() {
  echo "Validating configuration..."
  if test -x "$INSTALL_PATH/bin/logstag-agent"; then
    if ! "$INSTALL_PATH/bin/logstag-agent" --check-config 2>/dev/null; then
      echo "Warning: Configuration validation failed, but continuing with installation"
    else
      echo "Configuration validation successful"
    fi
  fi
}

# Function to enable and start the systemd service
enable_and_start_service() {
  echo "Enabling and starting logstag-agent service..."
  
  # Enable the service to start on boot
  if $maybe_sudo systemctl enable logstag-agent 2>/dev/null; then
    echo "Service enabled successfully"
  else
    echo "Warning: Failed to enable service for automatic startup"
    return 1
  fi
  
  # Start the service
  if $maybe_sudo systemctl start logstag-agent 2>/dev/null; then
    echo "Service started successfully"
    return 0
  else
    echo "Warning: Failed to start service"
    return 1
  fi
}

# Function to verify service status and provide diagnostics
verify_service_status() {
  echo "Checking service status..."
  
  # Check if service is active
  if $maybe_sudo systemctl is-active --quiet logstag-agent; then
    echo "✅ Logstag Agent service is running"
    # Show brief status
    $maybe_sudo systemctl status logstag-agent --no-pager --lines=3
    return 0
  else
    echo "❌ Logstag Agent service is not running"
    show_service_diagnostics
    return 1
  fi
}

# Function to show service diagnostics for troubleshooting
show_service_diagnostics() {
  echo "Service diagnostics:"
  echo "  Service status:"
  $maybe_sudo systemctl status logstag-agent --no-pager --lines=5 || echo "    Could not get service status"
  
  echo "  Recent logs:"
  $maybe_sudo journalctl -u logstag-agent --no-pager --lines=5 || echo "    Could not get recent logs"
  
  echo "  Troubleshooting steps:"
  echo "    • Check configuration: $INSTALL_PATH/bin/logstag-agent --check-config"
  echo "    • View logs: journalctl -u logstag-agent -f"
  echo "    • Restart service: sudo systemctl restart logstag-agent"
  echo "    • Check service status: sudo systemctl status logstag-agent"
}

# Parse command line arguments for channel selection, version, and service options
channel=""  # Initialize empty, will be set based on args or defaults
version=""  # Initialize empty, will be set based on args or environment
start_service="true"  # Default to starting service, can be overridden
while [[ $# -gt 0 ]]; do
  case $1 in
    --channel=*)
      channel="${1#*=}"
      shift
      ;;
    --channel)
      channel="$2"
      shift 2
      ;;
    --version=*)
      version="${1#*=}"
      shift
      ;;
    --version)
      version="$2"
      shift 2
      ;;
    --start-service)
      start_service="true"
      shift
      ;;
    --no-start-service)
      start_service="false"
      shift
      ;;
    main)
      channel="main"
      shift
      ;;
    dev)
      channel="dev"
      shift
      ;;
    *)
      # Unknown option, ignore or handle as needed
      shift
      ;;
  esac
done

# Use environment variables if no command line argument provided
if [ -z "$channel" ] && [ -n "$LOGSTAG_CHANNEL" ]; then
  channel="$LOGSTAG_CHANNEL"
fi

if [ -z "$version" ] && [ -n "$LOGSTAG_VERSION" ]; then
  version="$LOGSTAG_VERSION"
fi

# Use environment variable for start_service if not set via command line
if [ -n "$LOGSTAG_START_SERVICE" ]; then
  start_service="$LOGSTAG_START_SERVICE"
fi

# Default to main channel if still not set
if [ -z "$channel" ]; then
  channel="main"
fi

# Validate channel parameter
if [ "$channel" != "main" ] && [ "$channel" != "dev" ]; then
  fail "Invalid channel: $channel. Must be 'main' or 'dev'"
fi

# Validate version parameter if provided
validate_version "$version"

echo "Installing Logstag Agent from '$channel' channel"
if [ -n "$version" ]; then
  echo "Target version: $version"
else
  echo "Target version: latest"
fi

# Initialize variables for installation options
# These will be set differently based on whether we're in interactive or non-interactive mode
logstag_opts=''
user_input=''
yum_opts=''
apt_opts=''
if [ -n "$LOGSTAG_INSTALL_NONINTERACTIVE" ];
then
  # Non-interactive mode: don't prompt for user input, assume yes for all prompts
  user_input=/dev/null
  apt_opts='--yes'
  yum_opts='--assumeyes'
  logstag_opts="--recommended --db-name=${DB_NAME:-postgres}"
else
  # Interactive mode: read user input from terminal
  user_input=/dev/tty
fi

# Function to prompt user for confirmation
# Returns true (0) if user confirms or doesn't provide input (default is yes)
# Returns false (1) if user explicitly declines
confirm () {
  if [ -n "$LOGSTAG_INSTALL_NONINTERACTIVE" ];
  then
    # In non-interactive mode, always return true (proceed)
    return 0
  fi

  local confirmation
  # N.B.: default is always yes
  read -r -n1 -p "$1 [Y/n]" confirmation <$user_input
  # Return true if input is empty or starts with Y or y
  [ -z "$confirmation" ] || [[ "$confirmation" =~ [Yy] ]]
}

# Initialize variables for package manager, distribution, and OS version
# These will be set based on OS detection
pkg=''
distribution=''
os_version=''

# Check if we can read OS information
if ! test -r /etc/os-release;
then
  fail "cannot read /etc/os-release to determine distribution"
fi

# Detect system architecture
arch=$(uname -m)
if [ "$arch" != 'x86_64' ] && [ "$arch" != 'arm64' ] && [ "$arch" != 'aarch64' ];
then
  # Only x86_64 and ARM64 architectures are supported
  fail "unsupported architecture: $arch"
fi

# Detect operating system and version
# This section uses /etc/os-release to identify the distribution and determine:
# 1. Which package manager to use (yum or apt)
# 2. The distribution name for repository URLs
# 3. The version identifier for repository URLs

if grep -q '^ID="amzn"$' /etc/os-release && grep -q '^VERSION_ID="2"$' /etc/os-release;
then
  # Amazon Linux 2, based on RHEL7
  pkg=yum
  distribution=el
  os_version=7
elif grep -q '^ID="amzn"$' /etc/os-release && grep -q '^VERSION_ID="2023"$' /etc/os-release;
then
  # Amazon Linux 2023, utilizing same glibc version (2.34) as CentOS Streams 9
  pkg=yum
  distribution=el
  os_version=9
elif grep -q '^ID="\(rhel\|almalinux\|rocky\|centos\|ol\)"$' /etc/os-release;
then
  # RHEL, AlmaLinux, Rocky Linux, CentOS and Oracle Linux
  pkg=yum
  distribution=el
  os_version=$(grep VERSION_ID /etc/os-release | cut -d= -f2 | tr -d '"' | cut -d. -f1)
  if [ "$os_version" != 7 ] && [ "$os_version" != 8 ] && [ "$os_version" != 9 ];
  then
    # If version is not supported, ask user if they want to try RHEL9 package
    if confirm "Unsupported RHEL, AlmaLinux, Rocky Linux, CentOS or Oracle Linux version; try RHEL9 package?";
    then
      os_version=9
    else
      fail "unrecognized RHEL, AlmaLinux, Rocky Linux, CentOS or Oracle Linux version: ${os_version}"
    fi
  fi
elif grep -q '^ID=fedora$' /etc/os-release;
then
  # Fedora
  pkg=yum
  distribution=fedora
  os_version=$(grep VERSION_ID /etc/os-release | cut -d= -f2)

  if [ "$os_version" != 40 ] && [ "$os_version" != 39 ] && [ "$os_version" != 38 ] && [ "$os_version" != 37 ];
  then
    # If version is not supported, ask user if they want to try Fedora 40 package
    if confirm "Unsupported Fedora version; try Fedora 40 package?";
    then
      os_version=40
    else
      fail "unrecognized Fedora version: ${os_version}"
    fi
  fi
elif grep -q '^ID=ubuntu$' /etc/os-release;
then
  # Ubuntu
  pkg=deb
  distribution=ubuntu
  # Extract the codename (e.g., focal, jammy, noble) from os-release
  os_version=$(grep VERSION_CODENAME /etc/os-release | cut -d= -f2)
  if [ "$os_version" != noble ] && [ "$os_version" != jammy ] && [ "$os_version" != focal ];
  then
    # If version is not supported, ask user if they want to try Ubuntu Noble package
    if confirm "Unsupported Ubuntu version; try Ubuntu Noble (24.04) package?";
    then
      os_version=noble
    else
      fail "unrecognized Ubuntu version: ${os_version}"
    fi
  fi
elif grep -q '^ID=debian$' /etc/os-release;
then
  # Debian
  pkg=deb
  distribution=debian
  # Extract the codename (e.g., bookworm) from os-release
  os_version=$(grep VERSION_CODENAME /etc/os-release | cut -d= -f2)
  if [ "$os_version" != bookworm ];
  then
    # If version is not supported, ask user if they want to try Debian Bookworm package
    if confirm "Unsupported Debian version; try Debian Bookworm (12) package?";
    then
      os_version=bookworm
    else
      fail "unrecognized Debian version: ${os_version}"
    fi
  fi
else
  # If we reach here, the distribution was not recognized
  # Output the content of os-release to stderr for troubleshooting
  >&2 cat /etc/os-release
  fail "unrecognized distribution"
fi

# If we're already running as sudo or root, no need to do anything;
# if we're not, set up sudo for relevant commands
maybe_sudo=''
if [ "$(id -u)" != "0" ]; then
  # We're not running as root, try to find sudo command
  maybe_sudo=$(command -v sudo)
  echo "This script requires superuser access to install packages"

  if [ -z "$maybe_sudo" ];
  then
    fail "not running as root and could not find sudo command"
  fi

  echo "You may be prompted for your password by sudo"

  # clear any previous sudo permission to avoid inadvertent confirmation
  $maybe_sudo -k
fi

# Install the package based on the detected package manager
if [ "$pkg" = yum ];
then
  # For RPM-based distributions (RHEL, CentOS, Fedora, etc.)
  # Map architecture to RPM architecture naming
  if [ "$arch" = 'x86_64' ];
  then
    rpm_arch=x86_64
  elif [ "$arch" = 'arm64' ] || [ "$arch" = 'aarch64' ];
  then
    rpm_arch=aarch64
  else
    # This should never happen due to the check above, but just in case
    fail "unsupported architecture for RPM: $arch"
  fi

  if [ -n "$version" ]; then
    # Install specific version by downloading RPM directly
    echo "Installing specific version: $version"
    rpm_url=$(get_version_download_url "https://techmindpartners.github.io/logstag-agent-dist" "$channel" "$rpm_arch" "$version" "rpm")
    echo "Downloading: $rpm_url"

    # Download the RPM package
    rpm_file="/tmp/logstag-agent-${version}.rpm"
    if ! download_with_retry "$rpm_url" "$rpm_file"; then
      fail "Failed to download version $version for architecture $rpm_arch. The specified version may not exist or may not be available for your platform."
    fi

    # Install the downloaded RPM
    $maybe_sudo yum $yum_opts localinstall "$rpm_file" <$user_input

    # Clean up
    rm -f "$rpm_file"
  else
    # Install latest version from repository
    echo "Installing latest version from repository"

    # Create repository configuration file for Logstag Agent
    echo "[logstag_agent]
name=logstag_agent
baseurl=https://techmindpartners.github.io/logstag-agent-dist/rpm/$channel/$rpm_arch
repo_gpgcheck=0
gpgcheck=0
enabled=1
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
metadata_expire=300" | $maybe_sudo tee -a /etc/yum.repos.d/logstag_agent.repo
    # Update package metadata cache
    $maybe_sudo yum $yum_opts makecache <$user_input
    # Install the Logstag Agent package
    $maybe_sudo yum $yum_opts install logstag-agent <$user_input
  fi
elif [ "$pkg" = deb ];
then
  # For Debian-based distributions (Ubuntu, Debian)
  # Map architecture for DEB packages
  if [ "$arch" = 'x86_64' ];
  then
    deb_arch=amd64
  elif [ "$arch" = 'arm64' ] || [ "$arch" = 'aarch64' ];
  then
    deb_arch=arm64
  else
    fail "unsupported architecture for DEB: $arch"
  fi

  if [ -n "$version" ]; then
    # Install specific version by downloading DEB directly
    echo "Installing specific version: $version"
    deb_url=$(get_version_download_url "https://techmindpartners.github.io/logstag-agent-dist" "$channel" "$deb_arch" "$version" "deb")
    echo "Downloading: $deb_url"

    # Download the DEB package
    deb_file="/tmp/logstag-agent-${version}.deb"
    if ! download_with_retry "$deb_url" "$deb_file"; then
      fail "Failed to download version $version for architecture $deb_arch. The specified version may not exist or may not be available for your platform."
    fi

    # Install the downloaded DEB
    $maybe_sudo dpkg -i "$deb_file" || {
      # If dpkg fails due to missing dependencies, try to fix them
      echo "Attempting to fix dependencies..."
      $maybe_sudo apt-get $apt_opts install -f <$user_input
    }

    # Clean up
    rm -f "$deb_file"
  else
    # Install latest version from repository
    echo "Installing latest version from repository"

    # Configure the apt source based on architecture and channel
    apt_source="deb [arch=$deb_arch signed-by=/etc/apt/keyrings/logstag_signing_key.asc] https://techmindpartners.github.io/logstag-agent-dist/ stable $channel"

    # Create keyrings directory and download signing key with retry logic
    $maybe_sudo mkdir -p /etc/apt/keyrings
    download_with_retry "https://techmindpartners.github.io/logstag-agent-dist/logstag_signing_key.asc" "/tmp/logstag_key.asc"
    $maybe_sudo mv /tmp/logstag_key.asc /etc/apt/keyrings/logstag_signing_key.asc
    # Add logstag repository to sources list
    echo "$apt_source" | $maybe_sudo tee /etc/apt/sources.list.d/logstag_agent.list
    # Update package lists
    $maybe_sudo apt-get $apt_opts update <$user_input
    # Install the Logstag Agent package
    $maybe_sudo apt-get $apt_opts install logstag-agent <$user_input
  fi
else
  fail "unrecognized package kind: $pkg"
fi

# Configure the agent if environment variables are provided
if [ -n "$LOGSTAG_API_BASE_URL" ];
then
  # Validate URL format before using it
  validate_url "$LOGSTAG_API_BASE_URL"
  # Set custom API base URL if provided (create backup first)
  $maybe_sudo sed -i.bak "s|^api_base_url = \"api_base_url\"$|api_base_url = \"${LOGSTAG_API_BASE_URL}\"|" "$CONFIG_PATH"
fi

if [ -n "$LOGSTAG_API_KEY" ];
then
  # Validate API key format before using it
  validate_api_key "$LOGSTAG_API_KEY"
  
  # Check if API key encryption is disabled (default is enabled)
  if [ -n "$LOGSTAG_ENCRYPT_API_KEY" ] && [ "$LOGSTAG_ENCRYPT_API_KEY" = "false" ];
  then
    echo "API key encryption disabled by configuration"
    # Set API key as plain text when explicitly disabled
    $maybe_sudo sed -i.bak "s|^api_key = \"your_api_key\"$|api_key = \"${LOGSTAG_API_KEY}\"|" "$CONFIG_PATH"
  else
    echo "Encrypting API key for secure storage..."
    # Use the agent's encrypt command to encrypt the API key (default behavior)
    encrypted_api_key=$("$INSTALL_PATH/bin/logstag-agent" encrypt "$LOGSTAG_API_KEY" 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$encrypted_api_key" ];
    then
      echo "API key encrypted successfully"
      # Set encrypted API key in configuration (reuse existing backup)
      $maybe_sudo sed -i "s|^api_key = \"your_api_key\"$|api_key = \"${encrypted_api_key}\"|" "$CONFIG_PATH"
    else
      echo "Warning: Failed to encrypt API key, storing as plain text"
      # Fallback to plain text if encryption fails (reuse existing backup)
      $maybe_sudo sed -i "s|^api_key = \"your_api_key\"$|api_key = \"${LOGSTAG_API_KEY}\"|" "$CONFIG_PATH"
    fi
  fi
fi

# Validate configuration after modifications
if [ -n "$LOGSTAG_API_KEY" ] || [ -n "$LOGSTAG_API_BASE_URL" ]; then
  validate_config
fi

# Verify the installation was successful
echo "Checking install by running 'logstag-agent --version'"
"$INSTALL_PATH/bin/logstag-agent" --version
echo

# Offer to configure the agent if in interactive mode and not already configured
configuration_completed=false
if [ -z "$LOGSTAG_INSTALL_NONINTERACTIVE" ];
then
  if confirm "Would you like to configure the agent now?";
  then
    echo "Starting interactive configuration..."
    if "$INSTALL_PATH/bin/logstag-agent" configure --channel "$channel"; then
      configuration_completed=true
    fi
  else
    echo "You can configure the agent later by running: $INSTALL_PATH/bin/logstag-agent configure --channel \"$channel\""
  fi
else
  echo "Non-interactive installation complete"
  if [ -z "$LOGSTAG_API_KEY" ];
  then
    echo "Configure the agent by running: $INSTALL_PATH/bin/logstag-agent configure --channel \"$channel\""
  else
    # If API key was provided via environment, consider configuration completed
    configuration_completed=true
  fi
fi

# Start the service if requested and configuration was completed successfully
if [ "$start_service" = "true" ]; then
  # Determine if we should start the service
  should_start_service=false
  
  if [ "$configuration_completed" = "true" ]; then
    # Configuration was completed successfully
    should_start_service=true
  elif [ -n "$LOGSTAG_API_KEY" ] || [ -n "$LOGSTAG_API_BASE_URL" ]; then
    # Environment-based configuration was applied
    should_start_service=true
  elif [ -n "$LOGSTAG_INSTALL_NONINTERACTIVE" ]; then
    # In non-interactive mode, try to start even without full configuration
    # The service will fail gracefully if not properly configured
    should_start_service=true
  fi
  
  if [ "$should_start_service" = "true" ]; then
    echo
    echo "Starting Logstag Agent service..."
    if enable_and_start_service; then
      # Give the service a moment to start up
      sleep 2
      verify_service_status
    else
      echo "⚠️  Service startup failed, but installation was successful"
      echo "You can start the service manually with: sudo systemctl start logstag-agent"
    fi
  else
    echo
    echo "⚠️  Service not started automatically (configuration not completed)"
    echo "After configuring the agent, start the service with: sudo systemctl start logstag-agent"
  fi
else
  echo
  echo "ℹ️  Service startup was disabled (--no-start-service)"
  echo "To start the service manually: sudo systemctl start logstag-agent"
fi

echo
echo "The Logstag Agent was installed successfully"
echo "Installation path: $INSTALL_PATH"
echo "Configuration file: $CONFIG_PATH"
echo "Log file path: $LOG_PATH"
echo "Service name: logstag-agent"
echo
echo "Useful commands:"
echo "  • Check service status: sudo systemctl status logstag-agent"
echo "  • View service logs: sudo journalctl -u logstag-agent -f"
echo "  • Restart service: sudo systemctl restart logstag-agent"
echo "  • Configure agent: $INSTALL_PATH/bin/logstag-agent configure --channel \"$channel\""
echo
