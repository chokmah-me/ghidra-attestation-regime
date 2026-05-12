# Orchestrator: Build plugin and analyze all firmware ELF files headless
# Runs InputSourceTagger, ControlFlowAnalyzer, ComplexityAnalyzer, RegimeAssigner
# and WeightedRegimePropagator on each ELF and collects results

param(
    [string]$GhidraInstallDir = "C:\Tools\ghidra_12.0.4_PUBLIC",
    [string]$JavaHome = "C:\Program Files\Java\jdk-21.0.11",
    [string]$MemoryMapJson = "data/stm32f407_memory_map.json",
    [string]$DownloadDir = "data/firmware/download",
    [string]$BuildDir = "data/firmware/built",
    [string]$ResultsDir = "data/firmware/results"
)

$ErrorActionPreference = "Stop"

# Set environment
$env:JAVA_HOME = $JavaHome
$env:GHIDRA_INSTALL_DIR = $GhidraInstallDir

Write-Host "=== Attestation Regime Firmware Analysis Orchestrator ==="
Write-Host "Java: $JavaHome"
Write-Host "Ghidra: $GhidraInstallDir"
Write-Host "Memory map: $MemoryMapJson"
Write-Host ""

# Step 1: Build plugin extension
Write-Host "[1/3] Building plugin JAR..."
gradle buildExtension --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Error "gradle buildExtension failed"
}
Write-Host "  OK: dist/AttestationRegimeClassifier-*.zip"

# Step 2: Collect ELF files
$elfs = @()

if (Test-Path $DownloadDir) {
    $elfs += Get-ChildItem $DownloadDir -Filter "*.elf" -ErrorAction SilentlyContinue
}

if (Test-Path $BuildDir) {
    $elfs += Get-ChildItem $BuildDir -Filter "*.elf" -ErrorAction SilentlyContinue
}

if ($elfs.Count -eq 0) {
    Write-Error "No ELF files found in $DownloadDir or $BuildDir"
}

Write-Host "[2/3] Analyzing $($elfs.Count) firmware ELF files..."
Write-Host ""

# Ensure results directory
New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null

$analyzeHeadless = Join-Path $GhidraInstallDir "support\analyzeHeadless.bat"
if (-not (Test-Path $analyzeHeadless)) {
    Write-Error "analyzeHeadless not found at $analyzeHeadless"
}

# Step 3: Analyze each ELF
foreach ($elf in $elfs) {
    $baseName = $elf.BaseName
    $outputJson = Join-Path $ResultsDir "$baseName.json"
    $tempProj = Join-Path $env:TEMP "ghidra_$baseName"

    Write-Host "  [$($elfs.IndexOf($elf) + 1)/$($elfs.Count)] $baseName"

    # Clean temp project dir if it exists
    if (Test-Path $tempProj) {
        Remove-Item -Recurse -Force $tempProj | Out-Null
    }
    New-Item -ItemType Directory -Force -Path $tempProj | Out-Null

    # Run analyzeHeadless with GhidraScript
    $projectName = "regime_$baseName"

    $cmdLine = "`"$analyzeHeadless`" `"$tempProj`" `"$projectName`"" +
        " -import `"$($elf.FullName)`"" +
        " -scriptPath scripts" +
        " -postScript GhidraHeadlessAnalyze.java `"$MemoryMapJson`" `"$outputJson`"" +
        " -deleteProject -noAnalysis 2>&1 | findstr /V `"INFO`""

    Invoke-Expression "cmd.exe /c $cmdLine"

    if ($LASTEXITCODE -ne 0) {
        Write-Warning "  analyzeHeadless exited with code $LASTEXITCODE (may be OK)"
    }

    if (Test-Path $outputJson) {
        Write-Host "    -> $outputJson"
    } else {
        Write-Warning "    -> No output JSON generated"
    }
}

Write-Host ""
Write-Host "[3/3] Summary"
Write-Host ""

# Parse and display results
$resultCount = (Get-ChildItem $ResultsDir -Filter "*.json" -ErrorAction SilentlyContinue).Count
Write-Host "Results generated: $resultCount JSON files in $ResultsDir"
Write-Host ""

$totalRegimes = @{
    REGIME_1 = 0
    REGIME_2 = 0
    REGIME_3A = 0
    PROVENANCE = 0
    UNCLASSIFIED = 0
}

foreach ($jsonFile in Get-ChildItem $ResultsDir -Filter "*.json" -ErrorAction SilentlyContinue) {
    $content = Get-Content $jsonFile | ConvertFrom-Json
    $firmware = $content.firmware
    $counts = $content.regimeCounts

    Write-Host "  ${firmware}:"
    Write-Host "    Total functions: $($content.totalFunctions)"
    foreach ($regime in $counts.PSObject.Properties) {
        Write-Host "      $($regime.Name): $($regime.Value)"
        $totalRegimes[$regime.Name] += $regime.Value
    }
}

Write-Host ""
Write-Host "Totals across all firmware:"
foreach ($regime in $totalRegimes.Keys | Sort-Object) {
    Write-Host "  $regime : $($totalRegimes[$regime])"
}

Write-Host ""
Write-Host "Analysis complete. Results in: $ResultsDir"
