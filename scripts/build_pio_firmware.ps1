# Build PlatformIO firmware projects
# Compiles STM32CubeF4 examples using the arm-none-eabi-gcc toolchain

param(
    [string]$ProjectsDir = "data/pio_projects",
    [string]$OutputDir = "data/firmware/built"
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$projects = @("adc_dma", "gpio_exti", "tim_timebase")

foreach ($proj in $projects) {
    $projPath = Join-Path $ProjectsDir $proj
    if (-not (Test-Path "$projPath/platformio.ini")) {
        Write-Error "Missing: $projPath/platformio.ini"
    }

    Write-Host "Building: $proj"
    Push-Location $projPath

    pio run

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed: $proj"
    }

    # Copy ELF to output dir
    $elf = Get-ChildItem ".pio/build" -Recurse -Filter "*.elf" | Select-Object -First 1
    if ($elf) {
        Copy-Item $elf.FullName (Join-Path $OutputDir "$proj.elf")
        Write-Host "  Copied: $($elf.Name) -> $proj.elf"
    } else {
        Write-Warning "No ELF found in .pio/build for $proj"
    }

    Pop-Location
}

Write-Host "`nPlatformIO builds complete. ELFs in: $OutputDir"
Get-ChildItem $OutputDir -Filter "*.elf" | ForEach-Object { Write-Host "  $_" }
