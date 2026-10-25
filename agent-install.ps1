# Logstag Agent Windows Installation Script
# This script downloads and installs MSI packages for proper Windows service integration
# Supports Windows Server 2019+ and Windows 10/11
# Architectures: x64, arm64
#
# IMPORTANT: This installer only supports MSI packages. For binary updates of existing
# installations, use the agent's built-in update mechanism.
#
# Quick Installation (handles execution policy automatically):
#   iwr -UseBasicParsing https://techmindpartners.github.io/logstag-agent-dist/agent-install.ps1 | iex
#
# Install specific version:
#   iex "& { $(iwr -UseBasicParsing https://techmindpartners.github.io/logstag-agent-dist/agent-install.ps1) } -Version '0.1.79'"
#
# Alternative if execution policy is restricted:
#   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
#   iwr -UseBasicParsing https://techmindpartners.github.io/logstag-agent-dist/agent-install.ps1 -OutFile agent-install.ps1
#   .\agent-install.ps1 -Version "0.1.79"
#
# Parameters:
#   -Channel: Release channel (main, dev). Default: main
#   -Version: Specific version to install (e.g., "0.1.79"). Default: latest
#   -NonInteractive: Skip interactive prompts. Default: false
#   -StartService: Start service after installation. Default: true
#   -ApiKey: API key for configuration
#   -ApiBaseUrl: Base URL for API configuration
#   -InstallPath: Installation directory path
#
# Environment Variables:
#   LOGSTAG_INSTALL_DEBUG: Set to "true" to enable debug logging
#   LOGSTAG_INSTALL_NONINTERACTIVE: Set to "true" for non-interactive mode
#   LOGSTAG_VERSION: Specific version to install (e.g., "0.1.79")

[CmdletBinding()]
param(
    [string]$Channel = "main",
    [string]$Version,
    [switch]$NonInteractive,
    [switch]$StartService = $true,
    [string]$ApiKey,
    [string]$ApiBaseUrl,
    [string]$InstallPath = "$env:ProgramFiles\Logstag Agent"
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Global variables
$DownloadBaseUrl = "https://techmindpartners.github.io/logstag-agent-dist/windows"
$TempDir = "$env:TEMP\logstag-install"
$ServiceName = "Logstag Agent"
$ConfigPath = "$env:ProgramData\Logstag Agent\logstag-agent.toml"
$LogPath = "$env:ProgramData\Logstag Agent\logs"

# Logging function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Only show DEBUG messages if debug mode is enabled
    if ($Level -eq "DEBUG" -and $env:LOGSTAG_INSTALL_DEBUG -ne "true") {
        return
    }
    
    Write-Host "[$timestamp] [$Level] $Message"
}

# Function to check and handle PowerShell execution policy
function Test-ExecutionPolicyAndSuggestFix {
    $currentPolicy = Get-ExecutionPolicy -Scope CurrentUser
    $systemPolicy = Get-ExecutionPolicy -Scope LocalMachine
    
    Write-Log "Current execution policy (CurrentUser): $currentPolicy"
    Write-Log "Current execution policy (LocalMachine): $systemPolicy"
    
    # Check if the current policy allows script execution
    $restrictivePolicies = @("Restricted", "AllSigned")
    
    if ($currentPolicy -in $restrictivePolicies -and $systemPolicy -in $restrictivePolicies) {
        Write-Log "PowerShell execution policy is restrictive" "WARN"
        Write-Host ""
        Write-Host "PowerShell Execution Policy Notice:" -ForegroundColor Yellow
        Write-Host "Your system has restrictive PowerShell execution policies that prevent running scripts." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "To resolve this, you can:" -ForegroundColor Yellow
        Write-Host "1. Set execution policy for current user (recommended):" -ForegroundColor Yellow
        Write-Host "   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "2. Use the direct download method instead:" -ForegroundColor Yellow
        Write-Host "   iwr -UseBasicParsing https://techmindpartners.github.io/logstag-agent-dist/agent-install.ps1 | iex" -ForegroundColor Cyan
        Write-Host ""
        
        if (-not $NonInteractive) {
            if (Get-UserConfirmation "Would you like to set the execution policy for the current user now?") {
                try {
                    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
                    Write-Log "Execution policy updated successfully"
                    return $true
                }
                catch {
                    Write-Log "Failed to update execution policy: $($_.Exception.Message)" "ERROR"
                    Write-Host "Please run the command manually with Administrator privileges if needed." -ForegroundColor Yellow
                    return $false
                }
            }
            else {
                Write-Host "Continuing with current execution policy. Script may fail if downloaded to file." -ForegroundColor Yellow
                return $false
            }
        }
        else {
            Write-Log "Non-interactive mode: Execution policy check failed but continuing" "WARN"
            return $false
        }
    }
    
    return $true
}

# Function to display troubleshooting information
function Show-TroubleshootingInfo {
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  - Verify you have Administrator permissions" -ForegroundColor Yellow
    Write-Host "  - Check Windows Event Logs (Event Viewer > Windows Logs > Application)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "If you encountered PowerShell execution policy issues:" -ForegroundColor Yellow
    Write-Host "  - Try the direct installation method:" -ForegroundColor Yellow
    Write-Host "    iwr -UseBasicParsing https://techmindpartners.github.io/logstag-agent-dist/agent-install.ps1 | iex" -ForegroundColor Cyan
    Write-Host "  - Or set execution policy:" -ForegroundColor Yellow
    Write-Host "    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force" -ForegroundColor Cyan
    Write-Host ""
}

# Function to handle interactive pause
function Wait-ForUserInput {
    # Check if running interactively (not from ISE or direct execution)
    $IsInteractive = [Environment]::UserInteractive -and 
                     (-not [Environment]::GetCommandLineArgs().Contains('-NonInteractive')) -and
                     (-not $env:LOGSTAG_INSTALL_NONINTERACTIVE)
    
    if ($IsInteractive) {
        Write-Host "Press any key to continue..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

# Error handling function
function Write-Error-And-Exit {
    param([string]$Message)
    Write-Log $Message "ERROR"
    Show-TroubleshootingInfo
    Wait-ForUserInput
    exit 1
}

# Function to check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to detect system architecture
function Get-SystemArchitecture {
    $arch = $env:PROCESSOR_ARCHITECTURE
    $wow64Arch = $env:PROCESSOR_ARCHITEW6432
    
    if ($wow64Arch) {
        $arch = $wow64Arch
    }
    
    switch ($arch) {
        "AMD64" { return "x64" }
        "ARM64" { return "arm64" }
        default { 
            Write-Error-And-Exit "Unsupported architecture: $arch. Supported: x64, arm64"
        }
    }
}

# Function to validate version format
function Test-Version {
    param([string]$VersionString)
    if ($VersionString) {
        if ($VersionString -notmatch '^\d+\.\d+\.\d+$') {
            Write-Error-And-Exit "Invalid version format: $VersionString. Expected format: x.y.z (e.g., 0.1.79)"
        }
    }
}

# Function to construct download URL for specific version
function Get-VersionDownloadUrl {
    param(
        [string]$BaseUrl,
        [string]$Channel,
        [string]$Architecture,
        [string]$Version,
        [string]$PackageType = "msi"
    )
    
    # Convert version format from x.y.z to x_y_z for URL
    $urlVersion = $Version -replace '\.', '_'
    
    # Map architecture to URL path
    $archPath = switch ($Architecture) {
        "x64" { "x64" }
        "arm64" { "arm64" }
        default { $Architecture }
    }
    
    # Construct filename based on package type
    $filename = switch ($PackageType) {
        "msi" { "logstag-agent-$urlVersion-$archPath.msi" }
        "binary" { "logstag-agent-$urlVersion-$archPath.exe" }
        "updater" { "logstag-agent-updater-$urlVersion-$archPath.exe" }
        default { "logstag-agent-$urlVersion-$archPath.$PackageType" }
    }
    
    return "$BaseUrl/$Channel/$archPath/$filename"
}

# Function to validate channel
function Test-Channel {
    param([string]$ChannelName)
    if ($ChannelName -notin @("main", "dev")) {
        Write-Error-And-Exit "Invalid channel: $ChannelName. Must be 'main' or 'dev'"
    }
}

# Function to validate API key format
function Test-ApiKey {
    param([string]$Key)
    if ($Key) {
        if ($Key.Length -lt 32) {
            Write-Error-And-Exit "API key appears to be too short (minimum 32 characters expected)"
        }
        if ($Key -notmatch '^[a-zA-Z0-9._-]+$') {
            Write-Error-And-Exit "API key contains invalid characters"
        }
    }
}

# Function to validate URL format
function Test-Url {
    param([string]$Url)
    if ($Url) {
        try {
            $uri = [System.Uri]$Url
            if ($uri.Scheme -notin @("http", "https")) {
                Write-Error-And-Exit "Invalid URL scheme: $($uri.Scheme). Must be http or https"
            }
        }
        catch {
            Write-Error-And-Exit "Invalid URL format: $Url"
        }
    }
}

# Function to download file with retry
function Get-FileWithRetry {
    param(
        [string]$Url,
        [string]$OutputPath,
        [int]$MaxAttempts = 3
    )
    
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        Write-Log ("Download attempt $attempt of $MaxAttempts" + ": " + $Url)
        try {
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($Url, $OutputPath)
            Write-Log "Download successful"
            $webClient.Dispose()
            return
        }
        catch [System.Net.WebException] {
            $webClient.Dispose()
            $statusCode = $_.Exception.Response.StatusCode
            if ($statusCode -eq 404) {
                Write-Error-And-Exit "File not found (404): $Url. This may indicate the specified version does not exist."
            }
            Write-Log "Download attempt $attempt failed: HTTP $statusCode - $($_.Exception.Message)" "WARN"
            if ($attempt -lt $MaxAttempts) {
                Write-Log "Retrying in 2 seconds..."
                Start-Sleep -Seconds 2
            }
        }
        catch {
            Write-Log "Download attempt $attempt failed: $($_.Exception.Message)" "WARN"
            if ($attempt -lt $MaxAttempts) {
                Write-Log "Retrying in 2 seconds..."
                Start-Sleep -Seconds 2
            }
        }
        finally {
            if ($webClient) { $webClient.Dispose() }
        }
    }
    
    Write-Error-And-Exit "Failed to download $Url after $MaxAttempts attempts"
}

# Function to prompt for confirmation
function Get-UserConfirmation {
    param([string]$Message)
    
    if ($NonInteractive) {
        return $true
    }
    
    do {
        $response = Read-Host "$Message [Y/n]"
        if ([string]::IsNullOrWhiteSpace($response) -or $response -match '^[Yy]') {
            return $true
        }
        elseif ($response -match '^[Nn]') {
            return $false
        }
        else {
            Write-Host "Please enter Y or N"
        }
    } while ($true)
}

# Function to stop and remove existing service
function Remove-ExistingService {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        Write-Log "Stopping existing $ServiceName service..."
        if ($service.Status -eq "Running") {
            Stop-Service -Name $ServiceName -Force
        }
        
        Write-Log "Removing existing $ServiceName service..."
        sc.exe delete $ServiceName | Out-Null
        
        # Wait for service to be fully removed
        do {
            Start-Sleep -Seconds 1
            $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        } while ($service)
    }
}

# Function to check for existing installations
function Test-ExistingInstallation {
    Write-Log "Checking for existing installations..."
    
    # Check for existing MSI installation
    $existingProduct = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "Logstag Agent" }
    if ($existingProduct) {
        Write-Log "Found existing installation: $($existingProduct.Name) version $($existingProduct.Version)" "WARN"
        
        if ($NonInteractive -or (Get-UserConfirmation "Uninstall existing version before proceeding?")) {
            Write-Log "Uninstalling existing version..."
            $uninstallResult = $existingProduct.Uninstall()
            if ($uninstallResult.ReturnValue -eq 0) {
                Write-Log "Existing installation removed successfully"
                # Wait for uninstall to complete
                Start-Sleep -Seconds 5
            } else {
                Write-Error-And-Exit "Failed to uninstall existing version. Return code: $($uninstallResult.ReturnValue)"
            }
        } else {
            Write-Error-And-Exit "Cannot proceed with existing installation present"
        }
    }
    
    # Check if installation directory exists and is not empty
    if (Test-Path $InstallPath) {
        $files = Get-ChildItem $InstallPath -Recurse -ErrorAction SilentlyContinue
        if ($files) {
            Write-Log "Installation directory exists and contains files: $InstallPath" "WARN"
            if ($NonInteractive -or (Get-UserConfirmation "Remove existing installation directory?")) {
                Write-Log "Removing existing installation directory..."
                Remove-Item $InstallPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

# Function to configure the WiX-installed service
function Configure-LogstagService {
    Write-Log "Configuring $ServiceName Windows service..."
    
    # Verify the service was created by WiX
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Error-And-Exit "Service '$ServiceName' was not created by MSI installer"
    }
    
    Write-Log "Service found: $($service.Name) - Status: $($service.Status)"
    
    # Configure service description (if not already set by WiX)
    try {
        $descResult = sc.exe description $ServiceName "Logstag database monitoring agent" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Warning: Failed to set service description: $descResult" "WARN"
        } else {
            Write-Log "Service description configured successfully"
        }
    }
    catch {
        Write-Log "Warning: Could not set service description: $($_.Exception.Message)" "WARN"
    }
    
    # Configure service recovery options (restart on failure)
    try {
        $recoveryResult = sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Warning: Failed to set service recovery options: $recoveryResult" "WARN"
        } else {
            Write-Log "Service recovery options configured successfully"
        }
    }
    catch {
        Write-Log "Warning: Could not set service recovery options: $($_.Exception.Message)" "WARN"
    }
    
    # Create Windows Event Log source for better diagnostics
    try {
        Write-Log "Creating Windows Event Log source..."
        $eventLogSource = "Logstag Agent"
        if (-not [System.Diagnostics.EventLog]::SourceExists($eventLogSource)) {
            New-EventLog -LogName Application -Source $eventLogSource
            Write-Log "Windows Event Log source created successfully"
        } else {
            Write-Log "Windows Event Log source already exists"
        }
    }
    catch {
        Write-Log "Warning: Could not create Windows Event Log source: $($_.Exception.Message)" "WARN"
        Write-Log "Service will still function but may have limited Windows Event Log integration" "WARN"
    }
    
    Write-Log "$ServiceName service configuration completed"
}

# Function to start the service
function Start-LogstagService {
    Write-Log "Starting $ServiceName service..."
    
    # Check current start mode and set to Auto if needed
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.StartType -ne "Automatic") {
            Write-Log "Setting service start mode to Automatic..."
            try {
                $scResult = sc.exe config $ServiceName start= auto 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "Service start mode set to Automatic"
                } else {
                    Write-Log "Warning: Failed to set service start mode to Automatic: $scResult" "WARN"
                }
            }
            catch {
                Write-Log "Warning: Could not set service start mode: $($_.Exception.Message)" "WARN"
            }
        }
    }
    
    try {
        Start-Service -Name $ServiceName -ErrorAction Stop
        
        # Wait for service to start and verify
        Start-Sleep -Seconds 5
        $service = Get-Service -Name $ServiceName
        if ($service.Status -eq "Running") {
            Write-Log "$ServiceName service started successfully"
            return $true
        }
        else {
            Write-Log "Service did not start properly - running diagnostics..." "WARN"
            Test-ServiceDiagnostics $ServiceName
            Write-Log "Service startup failed. Check the diagnostics above for details." "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Failed to start service: $($_.Exception.Message)" "ERROR"
        Write-Log "Running service diagnostics..."
        Test-ServiceDiagnostics $ServiceName
        # Return instead of throwing so the installation summary (with recovery
        # commands) is still printed; the package itself is installed.
        return $false
    }
}

# Function to update configuration
function Update-Configuration {
    if (-not (Test-Path $ConfigPath)) {
        Write-Log "Configuration file not found at $ConfigPath. Cannot update configuration." "ERROR"
        return $false
    }
    
    $configBackup = "$ConfigPath.bak"
    Copy-Item $ConfigPath $configBackup -Force
    Write-Log "Configuration backup created: $configBackup"
    
    $configContent = [System.IO.File]::ReadAllText($ConfigPath, [System.Text.Encoding]::UTF8)
    $originalContent = $configContent
    
    if ($ApiBaseUrl) {
        Test-Url $ApiBaseUrl
        $configContent = [regex]::Replace($configContent, '(?m)^api_base_url\s*=\s*"[^"]*"', { "api_base_url = `"$ApiBaseUrl`"" })
    }
    
    if ($ApiKey) {
        Test-ApiKey $ApiKey
        Write-Log "Adding API key to configuration"
        $configContent = [regex]::Replace($configContent, '(?m)^api_key\s*=\s*"[^"]*"', { "api_key = `"$ApiKey`"" })
    }
    
    if ($configContent -ne $originalContent) {
        [System.IO.File]::WriteAllText($ConfigPath, $configContent, [System.Text.UTF8Encoding]::new($false))
        Write-Log "Updated API settings in configuration"
        return $true
    }
    return $false
}

# Function to validate configuration
# Returns the `check-config` exit code: 0 = valid with targets, 3 = valid but no
# targets, 1 = invalid, 2 = subcommand unsupported (older agent binary), -1 = exe missing.
function Test-Configuration {
    $exePath = Join-Path $InstallPath "bin\logstag-agent.exe"
    if (-not (Test-Path $exePath)) {
        return -1
    }
    Write-Log "Validating configuration..."
    # Send the exe's stdout to the host. Without this it would become part of
    # this function's return value (e.g. @("...valid...", 0)) and break `-eq 0`.
    # stderr is deliberately NOT redirected: with $ErrorActionPreference = "Stop",
    # Windows PowerShell 5.1 turns redirected native stderr into a terminating error.
    & $exePath check-config | ForEach-Object { Write-Host "  $_" }
    $exitCode = [int]$LASTEXITCODE
    switch ($exitCode) {
        0 { Write-Log "Configuration validation: valid with database targets" "INFO" }
        3 { Write-Log "Configuration validation: valid but no database targets configured" "WARN" }
        1 { Write-Log "Configuration validation: invalid configuration" "WARN" }
        2 { Write-Log "Configuration validation: 'check-config' not supported by this agent version" "WARN" }
        default { Write-Log "Configuration validation returned exit code $exitCode" "WARN" }
    }
    return $exitCode
}

# Function to check system requirements
function Test-SystemRequirements {
    Write-Log "Checking system requirements..."
    
    # Check Windows Installer service
    $msiService = Get-Service -Name "msiserver" -ErrorAction SilentlyContinue
    if (-not $msiService -or $msiService.Status -ne "Running") {
        Write-Log "Starting Windows Installer service..."
        try {
            Start-Service -Name "msiserver" -ErrorAction Stop
        }
        catch {
            Write-Error-And-Exit "Failed to start Windows Installer service: $($_.Exception.Message)"
        }
    }
    
    # Check disk space (require at least 100MB)
    $installDrive = [System.IO.Path]::GetPathRoot($InstallPath)
    $drive = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $installDrive.TrimEnd('\') }
    if ($drive) {
        $freeSpaceMB = [math]::Round($drive.FreeSpace / 1MB, 2)
        Write-Log ("Available disk space on " + $installDrive + ": " + $freeSpaceMB + " MB")
        if ($freeSpaceMB -lt 100) {
            Write-Error-And-Exit ("Insufficient disk space. At least 100 MB required, but only " + $freeSpaceMB + " MB available")
        }
    }
    
    # Check if we can write to installation directory
    $testPath = [System.IO.Path]::GetDirectoryName($InstallPath)
    if (-not (Test-Path $testPath)) {
        try {
            New-Item -ItemType Directory -Path $testPath -Force | Out-Null
        }
        catch {
            Write-Error-And-Exit "Cannot create installation directory: $($_.Exception.Message)"
        }
    }
    
    # Test write permissions
    $testFile = Join-Path $testPath "test-write-$(Get-Random).tmp"
    try {
        "test" | Out-File $testFile -ErrorAction Stop
        Remove-Item $testFile -ErrorAction SilentlyContinue
    }
    catch {
        Write-Error-And-Exit "No write permission to installation directory: $testPath"
    }
    
    Write-Log "System requirements check passed"
}

# Main installation function
function Install-LogstagAgent {
    Write-Log "Starting Logstag Agent installation"
    Write-Log "Channel: $Channel"
    if ($Version) {
        Write-Log "Target Version: $Version"
    } else {
        Write-Log "Target Version: latest"
    }
    
    # Check PowerShell execution policy early
    Test-ExecutionPolicyAndSuggestFix
    
    # Validate inputs
    Test-Channel $Channel
    Test-Version $Version
    Test-ApiKey $ApiKey
    Test-Url $ApiBaseUrl
    
    # Check administrator privileges
    if (-not (Test-Administrator)) {
        Write-Error-And-Exit "This script must be run as Administrator"
    }
    
    # Check system requirements
    Test-SystemRequirements
    
    # Detect architecture
    $arch = Get-SystemArchitecture
    Write-Log "Detected architecture: $arch"
    
    # Check Windows version
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -lt 10) {
        Write-Error-And-Exit "Windows Server 2019 or later is required"
    }
    
    # Create temp directory
    if (Test-Path $TempDir) {
        Remove-Item $TempDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
    
    try {
        # Determine if we're installing a specific version or the latest
        if ($Version) {
            # For specific version, construct download URL directly
            Write-Log "Installing specific version: $Version"
            
            # Map architecture to platform key for URL construction
            $archPath = switch ($arch) {
                "x64" { "x64" }
                "arm64" { "arm64" }
                default { $arch }
            }
            
            # Construct download URL for the specific version
            $downloadUrl = Get-VersionDownloadUrl -BaseUrl $DownloadBaseUrl -Channel $Channel -Architecture $archPath -Version $Version -PackageType "msi"
            
            Write-Log "Constructed download URL: $downloadUrl"
            
            # For specific versions, we don't have checksum/size info from manifest
            # so we'll skip verification (or implement a separate verification method)
            $expectedChecksum = $null
            $expectedSize = $null
            
        } else {
            # For latest version, get version information from manifest
            Write-Log "Getting latest version information..."
            $manifestUrl = "$DownloadBaseUrl/$Channel/version.json"
            $manifestPath = Join-Path $TempDir "version.json"
            
            Get-FileWithRetry -Url $manifestUrl -OutputPath $manifestPath
            
            # Parse manifest to get download information
            $manifest = Get-Content $manifestPath | ConvertFrom-Json
            
            # Map architecture to platform key
            $platformKey = switch ($arch) {
                "x64" { "windows-x86_64" }
                "arm64" { "windows-aarch64" }
                default { "windows-$arch" }
            }
            
            # Get release information for our platform
            if (-not $manifest.releases.$platformKey) {
                Write-Error-And-Exit "No release available for platform: $platformKey"
            }
            
            $releaseInfo = $manifest.releases.$platformKey
            
            # For installations, MSI package is required
            if ($releaseInfo.msi -and $releaseInfo.msi.download_url) {
                # Use nested MSI info for installation
                $downloadUrl = $releaseInfo.msi.download_url
                $expectedChecksum = $releaseInfo.msi.checksum
                $expectedSize = $releaseInfo.msi.size
                Write-Log "Using MSI package for installation"
            } else {
                Write-Error-And-Exit "No MSI package available for platform: $platformKey. This installer requires MSI packages for proper Windows service installation."
            }
            
            # Log the version we're installing
            Write-Log "Installing latest version: $($manifest.latest_version)"
        }
        
        # Extract filename from download URL
        $msiFileName = [System.IO.Path]::GetFileName($downloadUrl)
        $msiPath = Join-Path $TempDir $msiFileName
        
        # Validate that we're downloading an MSI file
        if (-not $msiFileName.EndsWith(".msi", [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Error-And-Exit "Expected MSI package, but download URL points to: $msiFileName. This installer only supports MSI packages."
        }
        
        Write-Log "Downloading $msiFileName..."
        try {
            Get-FileWithRetry -Url $downloadUrl -OutputPath $msiPath
        }
        catch {
            if ($Version) {
                $platformInfo = if ($arch -eq "x64") { "windows-x86_64" } elseif ($arch -eq "arm64") { "windows-aarch64" } else { "windows-$arch" }
                Write-Error-And-Exit "Failed to download version $Version. The specified version may not exist or may not be available for your platform ($platformInfo). Please check available versions or try without specifying a version to get the latest."
            } else {
                throw
            }
        }
        
        # Verify downloaded file
        if ($expectedSize -and (Get-Item $msiPath).Length -ne $expectedSize) {
            Write-Error-And-Exit "Downloaded file size mismatch. Expected: $expectedSize, Actual: $((Get-Item $msiPath).Length)"
        } elseif (-not $expectedSize) {
            # For specific versions without manifest info, just check that file is reasonable size
            $fileSize = (Get-Item $msiPath).Length
            if ($fileSize -lt 1048576) { # Less than 1MB is suspicious for MSI
                Write-Error-And-Exit "Downloaded file is too small ($fileSize bytes). Expected MSI package should be several MB."
            }
            Write-Log "Downloaded file size: $fileSize bytes (checksum verification skipped for specific version)"
        }
        
        if ($expectedChecksum) {
            Write-Log "Verifying file integrity..."
            $actualChecksum = (Get-FileHash $msiPath -Algorithm SHA256).Hash.ToLower()
            if ($actualChecksum -ne $expectedChecksum) {
                Write-Error-And-Exit "Downloaded file checksum mismatch. Expected: $expectedChecksum, Actual: $actualChecksum"
            }
            Write-Log "File integrity verified"
        } else {
            Write-Log "Checksum verification skipped (not available for specific version downloads)"
        }
        
        # Verify the downloaded file is actually an MSI package
        try {
            $fileInfo = Get-Item $msiPath
            if ($fileInfo.Length -lt 1024) {
                Write-Error-And-Exit "Downloaded file is too small to be a valid MSI package"
            }
            
            # Check MSI file signature (first few bytes should indicate MSI format)
            $bytes = [System.IO.File]::ReadAllBytes($msiPath) | Select-Object -First 8
            $signature = [System.Text.Encoding]::ASCII.GetString($bytes)
            if (-not $signature.StartsWith("?MZ") -and -not $signature.Contains("MSI")) {
                Write-Log "Warning: Downloaded file may not be a valid MSI package" "WARN"
            }
        }
        catch {
            Write-Log "Warning: Could not verify MSI file format: $($_.Exception.Message)" "WARN"
        }
        
        # Stop existing service if running
        Remove-ExistingService
        
        # Check for and handle existing installations
        Test-ExistingInstallation
        
        # Install MSI package
        Write-Log "Installing Logstag Agent..."
        
        # Create log file for MSI installation
        $msiLogPath = Join-Path $TempDir "msi-install.log"
        
        $msiArgs = @(
            "/i", "`"$msiPath`""
            "/quiet"
            "/l*v", "`"$msiLogPath`""
            "INSTALLDIR=`"$InstallPath`""
        )
        
        Write-Log "MSI command: msiexec.exe $($msiArgs -join ' ')"
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
        
        if ($process.ExitCode -ne 0) {
            Write-Log "MSI installation failed with exit code: $($process.ExitCode)" "ERROR"
            
            # Show MSI error code meanings
            $errorMeaning = switch ($process.ExitCode) {
                1603 { "Fatal error during installation" }
                1618 { "Another installation is in progress" }
                1619 { "Installation package could not be opened" }
                1620 { "Installation package could not be opened (corrupt)" }
                1633 { "Platform not supported" }
                1638 { "Another version is already installed" }
                default { "Unknown MSI error" }
            }
            
            Write-Log "Error meaning: $errorMeaning" "ERROR"
            
            # Show log file location and last few lines
            if (Test-Path $msiLogPath) {
                Write-Log "MSI installation log saved to: $msiLogPath" "ERROR"
                Write-Log "Last 20 lines of MSI log:" "ERROR"
                $logContent = Get-Content $msiLogPath -Tail 20
                foreach ($line in $logContent) {
                    Write-Host "  $line" -ForegroundColor Red
                }
            }
            
            Write-Error-And-Exit "MSI installation failed with exit code: $($process.ExitCode) - $errorMeaning"
        }
        
        Write-Log "Logstag Agent installed successfully"
        
        # Configure the WiX-installed Windows service
        Configure-LogstagService
        
        # Verify installation
        $exePath = Join-Path $InstallPath "bin\logstag-agent.exe"
        if (Test-Path $exePath) {
            Write-Log "Verifying installation..."
            $version = & $exePath --version 2>$null
            Write-Log "Installed version: $version"
        }
        
        # Step 1: If API credentials were provided as arguments, apply them first
        if ($ApiKey -or $ApiBaseUrl) {
            Write-Log "Applying provided API settings..."
            Update-Configuration | Out-Null
        }

        # Step 2: Pre-configure validation
        $initialConfigStatus = Test-Configuration

        # Step 3: Run interactive configure only if NOT non-interactive
        if (-not $NonInteractive) {
            Write-Log "Starting agent configuration..."
            & $exePath configure --channel $Channel
            $configureOutcome = $LASTEXITCODE
            switch ($configureOutcome) {
                0 { Write-Log "Agent configuration completed with targets" "INFO" }
                3 { Write-Log "Agent configuration finished without a database target saved" "WARN" }
                default { Write-Log "Agent configuration failed (exit code $configureOutcome)" "WARN" }
            }
        }
        else {
            Write-Log "Non-interactive mode: skipping interactive configuration"
        }

        # Step 4: Final configuration validation (authoritative for the service decision)
        $finalConfigStatus = if (-not $NonInteractive) { Test-Configuration } else { $initialConfigStatus }
        # Older agent binaries do not know `check-config` (clap exits 2). Fall back to
        # the legacy behaviour (start the service) rather than blocking those installs.
        $legacyBinary = ($finalConfigStatus -eq 2)

        # Step 4: Service startup decision (D5)
        # Only start the service if configuration is valid and has at least 1 target (exit code 0),
        # unless user explicitly asked not to start via -StartService:$false
        $serviceStarted = $false
        if ($StartService) {
            if ($finalConfigStatus -eq 0 -or $legacyBinary) {
                if ($legacyBinary) {
                    Write-Log "Could not validate configuration with this agent version; starting service anyway" "WARN"
                }
                $serviceStarted = Start-LogstagService
            }
            elseif ($finalConfigStatus -eq 3) {
                Write-Log "Service not started: agent configuration has no database targets" "WARN"
            }
            else {
                Write-Log "Service not started: agent configuration is invalid or incomplete" "WARN"
            }
        }
        else {
            Write-Log "Skipping service startup (-StartService:`$false was specified)"
        }

        # Step 5: Summary and instructions
        $agentExe = Join-Path $InstallPath "bin\logstag-agent.exe"
        Write-Host ""
        Write-Host "--- Installation Summary ---" -ForegroundColor Cyan
        Write-Host "Package: Installed at $InstallPath" -ForegroundColor Green
        
        if ($finalConfigStatus -eq 0) {
            Write-Host "Configuration: Complete (database target configured)" -ForegroundColor Green
        }
        elseif ($finalConfigStatus -eq 3) {
            Write-Host "Configuration: API configured, but no database target saved" -ForegroundColor Yellow
        }
        elseif ($legacyBinary) {
            Write-Host "Configuration: Unknown (agent version cannot validate it)" -ForegroundColor Yellow
        }
        else {
            Write-Host "Configuration: Incomplete or invalid" -ForegroundColor Yellow
        }

        if ($serviceStarted) {
            Write-Host "Service: Running ($ServiceName)" -ForegroundColor Green
        }
        elseif (-not $StartService) {
            Write-Host "Service: Not started (-StartService:`$false)" -ForegroundColor Yellow
        }
        elseif ($finalConfigStatus -eq 0 -or $legacyBinary) {
            Write-Host "Service: Failed to start (see diagnostics above and logs in $LogPath)" -ForegroundColor Red
        }
        else {
            Write-Host "Service: Not started (configuration incomplete)" -ForegroundColor Yellow
        }

        if ($serviceStarted -and ($finalConfigStatus -eq 0 -or $legacyBinary)) {
            Write-Log "Installation completed successfully!" "INFO"
        }
        else {
            Write-Log "Installation finished with warnings" "WARN"
            Write-Host ""
            if ($finalConfigStatus -eq 0 -and -not $StartService) {
                Write-Host "To start monitoring:" -ForegroundColor Yellow
                Write-Host "  Start-Service `"$ServiceName`"" -ForegroundColor White
                Write-Host "  sc.exe config `"$ServiceName`" start= auto" -ForegroundColor White
            }
            elseif (($finalConfigStatus -eq 0 -or $legacyBinary) -and $StartService -and -not $serviceStarted) {
                Write-Host "The service failed to stay running. Inspect the logs and restart:" -ForegroundColor Yellow
                Write-Host "  Get-Content `"$LogPath\agent.log`" -Tail 50" -ForegroundColor White
                Write-Host "  Restart-Service `"$ServiceName`"" -ForegroundColor White
            }
            elseif ($finalConfigStatus -ne 0 -and -not $legacyBinary) {
                Write-Host "To complete database setup and start monitoring, run:" -ForegroundColor Yellow
                Write-Host "  & `"$agentExe`" configure" -ForegroundColor White
                Write-Host "  sc.exe config `"$ServiceName`" start= auto     # start at boot" -ForegroundColor White
                Write-Host "  Restart-Service `"$ServiceName`"     # also starts a stopped service" -ForegroundColor White
                Write-Host "Note: restarting briefly interrupts collection for every database monitored on this host." -ForegroundColor DarkGray
            }
        }

        Write-Host ""
        Write-Host "Service name: $ServiceName" -ForegroundColor Green
        Write-Host "Installation path: $InstallPath" -ForegroundColor Green
        Write-Host "Configuration file: $ConfigPath" -ForegroundColor Green
        Write-Host "Log file path: $LogPath" -ForegroundColor Green
        Write-Host ""

        if ($StartService -and ($finalConfigStatus -eq 0 -or $legacyBinary) -and -not $serviceStarted) {
            exit 1
        }
    }
    finally {
        # Clean up temp files
        if (Test-Path $TempDir) {
            Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# Function to diagnose service issues
function Test-ServiceDiagnostics {
    param([string]$ServiceName)
    
    Write-Log "Running service diagnostics..." "INFO"
    
    # Check if service exists
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Log "Service '$ServiceName' does not exist" "ERROR"
        return
    }
    
    Write-Log "Service Name: $($service.Name)"
    Write-Log "Service Status: $($service.Status)"
    Write-Log "Service Start Type: $($service.StartType)"
    
    # Check service binary path
    try {
        $serviceConfig = Get-WmiObject Win32_Service | Where-Object { $_.Name -eq $ServiceName }
        if ($serviceConfig) {
            Write-Log "Service Binary Path: $($serviceConfig.PathName)"
            
            # Extract executable path from service path (handle quoted paths)
            $execPath = $serviceConfig.PathName
            if ($execPath -match '^"([^"]+)"') {
                $execPath = $matches[1]
            } elseif ($execPath -match '^([^\s]+)') {
                $execPath = $matches[1]
            }
            
            # Check if executable exists
            if (Test-Path $execPath) {
                Write-Log "Service executable exists: $execPath"
                
                # Try to get version info
                try {
                    $version = & $execPath --version 2>&1
                    Write-Log "Service executable version: $version"
                } catch {
                    Write-Log "Warning: Could not get version from service executable" "WARN"
                }
            } else {
                Write-Log "ERROR: Service executable not found: $execPath" "ERROR"
            }
        }
    } catch {
        Write-Log "Warning: Could not get service configuration details: $($_.Exception.Message)" "WARN"
    }
    
    # Check recent Windows Event Log entries
    try {
        Write-Log "Checking recent service events..."
        $events = Get-EventLog -LogName System -Source "Service Control Manager" -Newest 10 -ErrorAction SilentlyContinue | 
                 Where-Object { $_.Message -like "*$ServiceName*" }
        
        if ($events) {
            Write-Log "Recent service events found:"
            foreach ($event in $events) {
                $eventTime = $event.TimeGenerated.ToString("yyyy-MM-dd HH:mm:ss")
                $eventType = $event.EntryType
                $eventMessage = $event.Message.Substring(0, [Math]::Min(100, $event.Message.Length))
                Write-Log "  [$eventTime] [$eventType] $eventMessage"
            }
        } else {
            Write-Log "No recent service events found in System log"
        }
    } catch {
        Write-Log "Warning: Could not check Windows Event Log: $($_.Exception.Message)" "WARN"
    }
    
    # Check Application Event Log for service-specific errors
    try {
        $appEvents = Get-EventLog -LogName Application -Source "Logstag Agent" -Newest 5 -ErrorAction SilentlyContinue
        if ($appEvents) {
            Write-Log "Recent application events:"
            foreach ($event in $appEvents) {
                $eventTime = $event.TimeGenerated.ToString("yyyy-MM-dd HH:mm:ss")
                $eventType = $event.EntryType
                $eventMessage = $event.Message.Substring(0, [Math]::Min(100, $event.Message.Length))
                Write-Log "  [$eventTime] [$eventType] $eventMessage"
            }
        }
    } catch {
        Write-Log "No recent application events found (this is normal for new installations)" "INFO"
    }
}

# Handle environment variables for non-interactive installation
if ($env:LOGSTAG_INSTALL_NONINTERACTIVE) {
    $NonInteractive = $true
}

if ($env:LOGSTAG_START_SERVICE) {
    $StartService = $true
}

if ($env:LOGSTAG_CHANNEL) {
    $Channel = $env:LOGSTAG_CHANNEL
}

if ($env:LOGSTAG_VERSION) {
    $Version = $env:LOGSTAG_VERSION
}

if ($env:LOGSTAG_API_KEY) {
    $ApiKey = $env:LOGSTAG_API_KEY
}

if ($env:LOGSTAG_API_BASE_URL) {
    $ApiBaseUrl = $env:LOGSTAG_API_BASE_URL
}

# Execute installation
try {
    Install-LogstagAgent
}
catch {
    Write-Log "Installation failed: $($_.Exception.Message)" "ERROR"
    Show-TroubleshootingInfo
    Wait-ForUserInput
    exit 1
}