# Save this as C:\Temp\ghidra-headless-analyze.ps1
# Usage: .\ghidra-headless-analyze.ps1

$elfPath = "C:\Temp\stm32f4-test\.pio\build\disco_f407vg\firmware.elf"
$projectDir = "C:\Users\Elke Shayna\ghidra_projects\stm32f4-test"
$projectName = "stm32f4-test"
$ghidraHome = "C:\Tools\ghidra_12.0.4_PUBLIC"
$pluginSrc = "C:\Users\Elke Shayna\Documents\00Dev\ghidra-attestation-regime\src"

# Ensure project directory exists
New-Item -ItemType Directory -Path $projectDir -Force | Out-Null

# Set env vars for this session
$env:JAVA_HOME = "C:\Program Files\Java\jdk-21.0.11"
$env:GHIDRA_INSTALL_DIR = $ghidraHome

# Run headless analysis
& "$ghidraHome\support\analyzeHeadless.bat" `
    $projectDir `
    $projectName `
    -import $elfPath `
    -processor "ARM:LE:32:Cortex" `
    -cspec "default" `
    -analysisTimeoutPerFile 300 `
    -postScript "RegimeAnalyzerPlugin.java" `
    -scriptPath $pluginSrc `
    -log "$projectDir\headless.log"

# Check output
if (Test-Path "$projectDir\headless.log") {
    Get-Content "$projectDir\headless.log" -Tail 20
}