# Download pre-built ELF firmware files from Antmicro CDN
# These are from the Renode test suite and serve as diverse test cases

param(
    [string]$OutputDir = "data/firmware/download"
)

$ErrorActionPreference = "Stop"

# Ensure output directory exists
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Firmware catalog: (local name, Antmicro CDN hash URL)
$firmware = @(
    @{
        name = "zephyr-hello_world_stm32f4.elf"
        url = "https://dl.antmicro.com/projects/renode/stm32f4_discovery--zephyr-hello_world.elf-s_515008-2180a4018e82fcbc8821ef4330c9b5f3caf2dcdb"
    },
    @{
        name = "riot-rtc_stm32f4.elf"
        url = "https://dl.antmicro.com/projects/renode/stm32f4_discovery--riot-tests_periph_rtc.elf-s_1249644-ca2effb6a0a8bcde39496b99bcb8b160a4ed292e"
    },
    @{
        name = "timer-upcount_stm32f4.elf"
        url = "https://dl.antmicro.com/projects/renode/stm32f4disco-timer-upcount.elf-g2d98d1b-s_1021132-961284be838516abea9db8302c9af2dcb67b482a"
    },
    @{
        name = "timer-downcount_stm32f4.elf"
        url = "https://dl.antmicro.com/projects/renode/stm32f4disco-timer-downcount.elf-g2d98d1b-s_1021136-4995992fa219c49c38d7163da1381104c26c823a"
    },
    @{
        name = "cubemx-hello_world_stm32f4.elf"
        url = "https://dl.antmicro.com/projects/renode/stm32f4--cube_mx-hello_world.elf-s_625976-606092c29de896f3bd83a4e981f2c7f3a6ed3142"
    },
    @{
        name = "faultmask_stm32f4.elf"
        url = "https://dl.antmicro.com/projects/renode/stm32f4disco-faultmask.elf-s_434744-080256edf201b1e2f7c67bf15000ba1ffa031990"
    },
    @{
        name = "zephyr-button_stm32f103.elf"
        url = "https://dl.antmicro.com/projects/renode/zephyr-stm32f103-button.elf-s_276760-1bf32c99bbb3c01d81e13ca68118eaf08b2a815f"
    },
    @{
        name = "crc-test_stm32f0.elf"
        url = "https://dl.antmicro.com/projects/renode/stm32f0-crc-test.elf-s_915148-a4b6b448dca6f24df573f23cd05224d11f9d83ff"
    },
    @{
        name = "tock_kernel_stm32f412.elf"
        url = "https://dl.antmicro.com/projects/renode/stm32f412gdiscovery--tock_kernel.elf-s_3392340-6da12cfcd5c4180b60ce7bf2ad32f019c9e8216e"
    }
)

foreach ($fw in $firmware) {
    $outpath = Join-Path $OutputDir $fw.name
    if (Test-Path $outpath) {
        Write-Host "Skipping (exists): $($fw.name)"
    } else {
        Write-Host "Downloading: $($fw.name)"
        curl.exe -L -o $outpath $fw.url
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to download $($fw.url)"
        }
    }
}

Write-Host "`nFirmware download complete. Files in: $OutputDir"
Get-ChildItem $OutputDir -Filter "*.elf" | ForEach-Object { Write-Host "  $_" }
