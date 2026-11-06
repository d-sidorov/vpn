# Кросс-сборка veil. Из корня репозитория: .\build.ps1
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Set-Location $PSScriptRoot

$savedGoos = $env:GOOS
$savedGoarch = $env:GOARCH
$savedCgo = $env:CGO_ENABLED

function Restore-GoEnv {
    if ($null -eq $savedGoos) {
        Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    } else {
        $env:GOOS = $savedGoos
    }
    if ($null -eq $savedGoarch) {
        Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    } else {
        $env:GOARCH = $savedGoarch
    }
    if ($null -eq $savedCgo) {
        Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
    } else {
        $env:CGO_ENABLED = $savedCgo
    }
}

try {
    $outDir = Join-Path $PSScriptRoot "dist"
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    $targets = @(
        @{ GOOS = "windows"; GOARCH = "amd64"; Name = "veil-windows-amd64.exe" },
        @{ GOOS = "linux"; GOARCH = "amd64"; Name = "veil-linux-amd64" },
        @{ GOOS = "linux"; GOARCH = "arm64"; Name = "veil-linux-arm64" },
        @{ GOOS = "darwin"; GOARCH = "amd64"; Name = "veil-darwin-amd64" },
        @{ GOOS = "darwin"; GOARCH = "arm64"; Name = "veil-darwin-arm64" }
    )

    foreach ($t in $targets) {
        $out = Join-Path $outDir $t.Name
        if (Test-Path -LiteralPath $out) {
            Remove-Item -LiteralPath $out -Force
        }
        Write-Host ("сборка {0}/{1} -> dist/{2}" -f $t.GOOS, $t.GOARCH, $t.Name)
        $env:CGO_ENABLED = "0"
        $env:GOOS = $t.GOOS
        $env:GOARCH = $t.GOARCH
        & go build -trimpath -ldflags "-s -w" -o $out ./cmd/veil
        if ($LASTEXITCODE -ne 0) {
            if (Test-Path -LiteralPath $out) {
                Remove-Item -LiteralPath $out -Force
            }
            throw ("сборка {0}/{1} завершилась с кодом {2}" -f $t.GOOS, $t.GOARCH, $LASTEXITCODE)
        }
        if (-not (Test-Path -LiteralPath $out)) {
            throw ("сборка {0}/{1} не создала файл" -f $t.GOOS, $t.GOARCH)
        }
    }
}
finally {
    Restore-GoEnv
}
