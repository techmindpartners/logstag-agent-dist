#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Add cleanup trap for temporary files
cleanup() {
  if [ -f "/tmp/dbpigeon_key.asc" ]; then
    rm -f /tmp/dbpigeon_key.asc
  fi
  if [ -f "/tmp/dbpigeon_key.tmp" ]; then
    rm -f /tmp/dbpigeon_key.tmp
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
  >&2 echo "  • Visit: https://docs.dbpigeon.com/troubleshooting"
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
    echo "Download attempt $attempt failed"
    attempt=$((attempt + 1))
    if [ $attempt -le $max_attempts ]; then
      echo "Retrying in 2 seconds..."
      sleep 2
    fi
  done
  
  fail "Failed to download $url after $max_attempts attempts"
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
  if test -x /opt/dbpigeon-agent/bin/dbpigeon-agent; then
    if ! /opt/dbpigeon-agent/bin/dbpigeon-agent --check-config 2>/dev/null; then
      echo "Warning: Configuration validation failed, but continuing with installation"
    else
      echo "Configuration validation successful"
    fi
  fi
}

# Parse command line arguments for channel selection
channel=""  # Initialize empty, will be set based on args or defaults
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

# Use environment variable if no command line argument provided
if [ -z "$channel" ] && [ -n "$DBPIGEON_CHANNEL" ]; then
  channel="$DBPIGEON_CHANNEL"
fi

# Default to main channel if still not set
if [ -z "$channel" ]; then
  channel="main"
fi

# Validate channel parameter
if [ "$channel" != "main" ] && [ "$channel" != "dev" ]; then
  fail "Invalid channel: $channel. Must be 'main' or 'dev'"
fi

echo "Installing dbPigeon Agent from '$channel' channel"

# Initialize variables for installation options
# These will be set differently based on whether we're in interactive or non-interactive mode
dbpigeon_opts=''
user_input=''
yum_opts=''
apt_opts=''
if [ -n "$DBPIGEON_INSTALL_NONINTERACTIVE" ];
then
  # Non-interactive mode: don't prompt for user input, assume yes for all prompts
  user_input=/dev/null
  apt_opts='--yes'
  yum_opts='--assumeyes'
  dbpigeon_opts="--recommended --db-name=${DB_NAME:-postgres}"
else
  # Interactive mode: read user input from terminal
  user_input=/dev/tty
fi

# Function to prompt user for confirmation
# Returns true (0) if user confirms or doesn't provide input (default is yes)
# Returns false (1) if user explicitly declines
confirm () {
  if [ -n "$DBPIGEON_INSTALL_NONINTERACTIVE" ];
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

# Initialize variables for package manager, distribution, and version
# These will be set based on OS detection
pkg=''
distribution=''
version=''

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
  version=7
elif grep -q '^ID="amzn"$' /etc/os-release && grep -q '^VERSION_ID="2023"$' /etc/os-release;
then
  # Amazon Linux 2023, utilizing same glibc version (2.34) as CentOS Streams 9
  pkg=yum
  distribution=el
  version=9
elif grep -q '^ID="\(rhel\|almalinux\|rocky\|centos\)"$' /etc/os-release;
then
  # RHEL, AlmaLinux, Rocky Linux and CentOS
  pkg=yum
  distribution=el
  version=$(grep VERSION_ID /etc/os-release | cut -d= -f2 | tr -d '"' | cut -d. -f1)
  if [ "$version" != 7 ] && [ "$version" != 8 ] && [ "$version" != 9 ];
  then
    # If version is not supported, ask user if they want to try RHEL9 package
    if confirm "Unsupported RHEL, AlmaLinux, Rocky Linux or CentOS version; try RHEL9 package?";
    then
      version=9
    else
      fail "unrecognized RHEL, AlmaLinux, Rocky Linux or CentOS version: ${version}"
    fi
  fi
elif grep -q '^ID=fedora$' /etc/os-release;
then
  # Fedora
  pkg=yum
  distribution=fedora
  version=$(grep VERSION_ID /etc/os-release | cut -d= -f2)

  if [ "$version" != 40 ] && [ "$version" != 39 ] && [ "$version" != 38 ] && [ "$version" != 37 ];
  then
    # If version is not supported, ask user if they want to try Fedora 40 package
    if confirm "Unsupported Fedora version; try Fedora 40 package?";
    then
      version=40
    else
      fail "unrecognized Fedora version: ${version}"
    fi
  fi
elif grep -q '^ID=ubuntu$' /etc/os-release;
then
  # Ubuntu
  pkg=deb
  distribution=ubuntu
  # Extract the codename (e.g., jammy, noble) from os-release
  version=$(grep VERSION_CODENAME /etc/os-release | cut -d= -f2)
  if [ "$version" != noble ] && [ "$version" != jammy ];
  then
    # If version is not supported, ask user if they want to try Ubuntu Noble package
    if confirm "Unsupported Ubuntu version; try Ubuntu Noble (24.04) package?";
    then
      version=noble
    else
      fail "unrecognized Ubuntu version: ${version}"
    fi
  fi
elif grep -q '^ID=debian$' /etc/os-release;
then
  # Debian
  pkg=deb
  distribution=debian
  # Extract the codename (e.g., bookworm) from os-release
  version=$(grep VERSION_CODENAME /etc/os-release | cut -d= -f2)
  if [ "$version" != bookworm ];
  then
    # If version is not supported, ask user if they want to try Debian Bookworm package
    if confirm "Unsupported Debian version; try Debian Bookworm (12) package?";
    then
      version=bookworm
    else
      fail "unrecognized Debian version: ${version}"
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
  # Create repository configuration file for dbPigeon Agent
  echo "[dbpigeon_agent]
name=dbpigeon_agent
baseurl=https://techmindpartners.github.io/dbpigeon-agent-dist/rpm/$channel/$rpm_arch
repo_gpgcheck=0
gpgcheck=0
enabled=1
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
metadata_expire=300" | $maybe_sudo tee -a /etc/yum.repos.d/dbpigeon_agent.repo
  # Update package metadata cache
  $maybe_sudo yum $yum_opts makecache <$user_input
  # Install the dbPigeon Agent package
  $maybe_sudo yum $yum_opts install dbpigeon-agent <$user_input
elif [ "$pkg" = deb ];
then
  # For Debian-based distributions (Ubuntu, Debian)
  # Configure the apt source based on architecture and channel
  if [ "$arch" = 'x86_64' ];
  then
    apt_source="deb [arch=amd64 signed-by=/etc/apt/keyrings/dbpigeon_signing_key.asc] https://techmindpartners.github.io/dbpigeon-agent-dist/ stable $channel"
  elif [ "$arch" = 'arm64' ] || [ "$arch" = 'aarch64' ];
  then
    apt_source="deb [arch=arm64 signed-by=/etc/apt/keyrings/dbpigeon_signing_key.asc] https://techmindpartners.github.io/dbpigeon-agent-dist/ stable $channel"
  fi
  # Create keyrings directory and download signing key with retry logic
  $maybe_sudo mkdir -p /etc/apt/keyrings
  download_with_retry "https://techmindpartners.github.io/dbpigeon-agent-dist/dbpigeon_signing_key.asc" "/tmp/dbpigeon_key.asc"
  $maybe_sudo mv /tmp/dbpigeon_key.asc /etc/apt/keyrings/dbpigeon_signing_key.asc
  # Add dbpigeon repository to sources list
  echo "$apt_source" | $maybe_sudo tee /etc/apt/sources.list.d/dbpigeon_agent.list
  # Update package lists
  $maybe_sudo apt-get $apt_opts update <$user_input
  # Install the dbPigeon Agent package
  $maybe_sudo apt-get $apt_opts install dbpigeon-agent <$user_input
else
  fail "unrecognized package kind: $pkg"
fi

# Configure the collector if environment variables are provided
if [ -n "$DBPIGEON_API_BASE_URL" ];
then
  # Validate URL format before using it
  validate_url "$DBPIGEON_API_BASE_URL"
  # Set custom API base URL if provided (create backup first)
  $maybe_sudo sed -i.bak "s|^api_base_url = \"api_base_url\"$|api_base_url = \"${DBPIGEON_API_BASE_URL}\"|" /etc/dbpigeon-agent.toml
fi

if [ -n "$DBPIGEON_API_KEY" ];
then
  # Validate API key format before using it
  validate_api_key "$DBPIGEON_API_KEY"
  # Set API key if provided (create backup first)
  $maybe_sudo sed -i.bak "s|^api_key = \"your_api_key\"$|api_key = \"${DBPIGEON_API_KEY}\"|" /etc/dbpigeon-agent.toml
fi

# Validate configuration after modifications
if [ -n "$DBPIGEON_API_KEY" ] || [ -n "$DBPIGEON_API_BASE_URL" ]; then
  validate_config
fi

# Verify the installation was successful
echo "Checking install by running 'dbpigeon-agent --version'"
/opt/dbpigeon-agent/bin/dbpigeon-agent --version
echo

echo "The dbPigeon Agent was installed successfully"
echo

# Offer to configure the agent if in interactive mode and not already configured
if [ -z "$DBPIGEON_INSTALL_NONINTERACTIVE" ];
then
  if confirm "Would you like to configure the agent now?";
  then
    echo "Starting interactive configuration..."
    /opt/dbpigeon-agent/bin/dbpigeon-agent configure
  else
    echo "You can configure the agent later by running: /opt/dbpigeon-agent/bin/dbpigeon-agent configure"
  fi
else
  echo "Non-interactive installation complete"
  if [ -z "$DBPIGEON_API_KEY" ];
  then
    echo "Configure the agent by running: /opt/dbpigeon-agent/bin/dbpigeon-agent configure"
  fi
fi
echo
