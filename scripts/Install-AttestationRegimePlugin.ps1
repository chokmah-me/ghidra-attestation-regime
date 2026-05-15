# Install-AttestationRegimePlugin.ps1
# Installs the Attestation Regime Classifier plugin into Ghidra 12.x

param(
    [string]$GhidraInstallDir = "C:\Tools\ghidra_12.0.4_PUBLIC",
    [string]$PluginZip = "$PSScriptRoot\..\dist\AttestationRegimeClassifier-0.8.0.zip"
)

Write-Host "=== Attestation Regime Classifier Plugin Installer ===" -ForegroundColor Cyan

# Verify inputs
if (-not (Test-Path $GhidraInstallDir)) {
    Write-Host "ERROR: Ghidra not found at: $GhidraInstallDir" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $PluginZip)) {
    Write-Host "ERROR: Plugin ZIP not found at: $PluginZip" -ForegroundColor Red
    exit 1
}

$ExtensionsDir = "$GhidraInstallDir\Ghidra\Extensions"
$PluginDir = "$ExtensionsDir\AttestationRegimeClassifier"

Write-Host "Ghidra: $GhidraInstallDir" -ForegroundColor Green
Write-Host "Plugin ZIP: $PluginZip" -ForegroundColor Green

# Step 1: Kill Ghidra
Write-Host "`n[1/4] Stopping Ghidra..." -ForegroundColor Yellow
Get-Process ghidra -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

# Step 2: Remove old plugin directory
Write-Host "[2/4] Removing old plugin installation..." -ForegroundColor Yellow
if (Test-Path $PluginDir) {
    Remove-Item $PluginDir -Recurse -Force
    Write-Host "  ✓ Removed: $PluginDir"
}

# Step 3: Extract new plugin
Write-Host "[3/4] Extracting plugin ZIP..." -ForegroundColor Yellow
Expand-Archive -Path $PluginZip -DestinationPath $ExtensionsDir -Force
Write-Host "  ✓ Extracted to: $PluginDir"

# Step 4: Verify extension.properties (no plugin.properties needed in Ghidra 12.x)
Write-Host "[4/4] Verifying extension.properties..." -ForegroundColor Yellow
$extensionPropsPath = "$PluginDir\extension.properties"

if (-not (Test-Path $extensionPropsPath)) {
    Write-Host "  ✗ ERROR: extension.properties not found!" -ForegroundColor Red
    exit 1
}
Write-Host "  ✓ Found: $extensionPropsPath"

# Verify installation
Write-Host "`n=== Verification ===" -ForegroundColor Cyan
Write-Host "Plugin directory contents:" -ForegroundColor Green
ls $PluginDir | Select-Object Name

Write-Host "`nextension.properties:" -ForegroundColor Green
cat $extensionPropsPath

Write-Host "`n✓ Installation complete!" -ForegroundColor Green
Write-Host "Next: Launch Ghidra with:" -ForegroundColor Yellow
Write-Host "  & `"$GhidraInstallDir\ghidraRun.bat`""
Write-Host "`nThen check: Tools > Attestation Regime" -ForegroundColor Yellow
