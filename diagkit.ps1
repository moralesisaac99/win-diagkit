#Requires -Version 5.1
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$DesktopPath = [Environment]::GetFolderPath('Desktop')
$KitDir      = Join-Path $DesktopPath "DiagKit"
$SpecifyDir  = Join-Path $KitDir "Specify"
$SIDir       = Join-Path $KitDir "SystemInformer"
$Headers     = @{ "User-Agent" = "Win-DiagKit-Auditor" }

function Test-IsAdmin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SpecifyExe {
    if (-not (Test-Path $SpecifyDir)) { return $null }
    return Get-ChildItem -Path $SpecifyDir -Filter "Specify*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
}

function Get-SIExe {
    if (-not (Test-Path $SIDir)) { return $null }
    return Get-ChildItem -Path $SIDir -Filter "SystemInformer.exe" -Recurse -ErrorAction SilentlyContinue |
           Where-Object { $_.DirectoryName -like "*amd64*" } | Select-Object -First 1
}

function Show-Banner {
    Clear-Host
    $specStatus = if (Get-SpecifyExe) { "INSTALADO" } else { "NO INSTALADO" }
    $siStatus   = if (Get-SIExe)      { "INSTALADO" } else { "NO INSTALADO" }
    $adminText  = if (Test-IsAdmin)   { "SI (Correcto)" } else { "NO (Faltan permisos para SMART/WHEA)" }

    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host "              WIN-DIAGKIT - AUDITORIA PC             " -ForegroundColor White
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host " Ruta destino    : $KitDir" -ForegroundColor Gray
    Write-Host " Administrador   : $adminText" -ForegroundColor $(if (Test-IsAdmin) { "Green" } else { "Yellow" })
    Write-Host " Specify         : $specStatus" -ForegroundColor $(if ($specStatus -eq "INSTALADO") { "Green" } else { "DarkGray" })
    Write-Host " System Informer : $siStatus" -ForegroundColor $(if ($siStatus -eq "INSTALADO") { "Green" } else { "DarkGray" })
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Instalar / Actualizar herramientas en Desktop" -ForegroundColor White
    Write-Host "  [2] Ejecutar diagnostico completo y abrir reporte" -ForegroundColor White
    Write-Host "  [3] Eliminar todo lo creado (Limpiar Desktop)" -ForegroundColor White
    Write-Host "  [0] Salir" -ForegroundColor DarkGray
    Write-Host ""
}

function Install-DiagKit {
    Write-Host "`n[+] Preparando carpetas en $KitDir..." -ForegroundColor Cyan
    New-Item -ItemType Directory -Force -Path $SpecifyDir, $SIDir -ErrorAction Stop | Out-Null

    try {
        Write-Host "[1/2] Descargando Specify (noring0)..." -ForegroundColor Cyan
        $specRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/Spec-ify/specify/releases/latest" -Headers $Headers -ErrorAction Stop
        $specAsset = $specRelease.assets | Where-Object { $_.name -like "*noring0*.exe" } | Select-Object -First 1
        if (-not $specAsset) {
            $specAsset = $specRelease.assets | Where-Object { $_.name -like "*.exe" } | Select-Object -First 1
        }
        if (-not $specAsset) { throw "No se encontro un ejecutable .exe en el release de Specify." }

        $specOut = Join-Path $SpecifyDir $specAsset.name
        Invoke-WebRequest -Uri $specAsset.browser_download_url -OutFile $specOut -Headers $Headers -ErrorAction Stop
        Write-Host "      OK -> $($specAsset.name)" -ForegroundColor Green

        Write-Host "[2/2] Descargando System Informer portable..." -ForegroundColor Cyan
        $siRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/winsiderss/si-builds/releases/latest" -Headers $Headers -ErrorAction Stop
        $siAsset = $siRelease.assets | Where-Object { $_.name -like "*-bin.zip" } | Select-Object -First 1
        if (-not $siAsset) { throw "No se encontro el paquete -bin.zip de System Informer." }

        $zipPath = Join-Path $SIDir "si_portable.zip"
        Invoke-WebRequest -Uri $siAsset.browser_download_url -OutFile $zipPath -Headers $Headers -ErrorAction Stop
        Expand-Archive -Path $zipPath -DestinationPath $SIDir -Force -ErrorAction Stop
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

        Get-ChildItem -Path $SIDir -Filter "SystemInformer.exe" -Recurse | ForEach-Object {
            $xmlFile = Join-Path $_.DirectoryName "SystemInformer.exe.settings.xml"
            if (-not (Test-Path $xmlFile)) {
                New-Item -ItemType File -Path $xmlFile -Force | Out-Null
            }
        }
        Write-Host "      OK -> System Informer portable listo" -ForegroundColor Green
        Write-Host "`nInstalacion completada." -ForegroundColor Green
    }
    catch {
        Write-Host "`n[ERROR] Fallo en la instalacion: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Show-QuickSummary {
    param([string]$JsonPath)
    try {
        $data = Get-Content -Path $JsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
        Write-Host "`n--- RESUMEN RAPIDO DEL REPORTE ---" -ForegroundColor Cyan
        if ($data.System) {
            Write-Host "SO      : $($data.System.OsName) (Build $($data.System.OsBuild))" -ForegroundColor White
        }
        if ($data.Hardware.Cpu) {
            Write-Host "CPU     : $($data.Hardware.Cpu.Name)" -ForegroundColor White
        }
        if ($data.Hardware.Gpu) {
            $gpus = ($data.Hardware.Gpu | ForEach-Object { "$($_.Name) [Driver: $($_.DriverVersion)]" }) -join " | "
            Write-Host "GPU     : $gpus" -ForegroundColor White
        }
        if ($data.Storage.Disks) {
            foreach ($disk in $data.Storage.Disks) {
                Write-Host "Disco   : $($disk.Model) - Salud: $($disk.HealthStatus) ($($disk.SmartStatus))" -ForegroundColor Yellow
            }
        }
        Write-Host "----------------------------------" -ForegroundColor Cyan
    }
    catch {
        # Si la estructura JSON cambia entre versiones de Specify, continuamos sin interrumpir
    }
}

function Invoke-Diagnostic {
    $specExe = Get-SpecifyExe
    if (-not $specExe) {
        Write-Host "`n[!] Specify no esta instalado." -ForegroundColor Yellow
        $resp = Read-Host "Deseas instalar el kit ahora? (S/N)"
        if ($resp -match "^[sS]$") {
            Install-DiagKit
            $specExe = Get-SpecifyExe
        } else {
            return
        }
    }

    if (-not $specExe) { return }

    Write-Host "`n[+] Ejecutando $($specExe.Name)..." -ForegroundColor Cyan
    Write-Host "    1. Marca la casilla 'Don't Upload'." -ForegroundColor Yellow
    Write-Host "    2. Haz clic en 'Start' y espera a que termine." -ForegroundColor Yellow
    Write-Host "    3. Cierra la ventana de Specify para continuar." -ForegroundColor Yellow

    $scanStart = Get-Date
    Start-Process -FilePath $specExe.FullName -WorkingDirectory $SpecifyDir -Wait

    $reportFile = Get-ChildItem -Path $SpecifyDir -Filter "*.json" -ErrorAction SilentlyContinue |
                  Where-Object { $_.LastWriteTime -ge $scanStart } |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if ($reportFile) {
        Write-Host "`n[+] Reporte generado: $($reportFile.FullName)" -ForegroundColor Green
        Show-QuickSummary -JsonPath $reportFile.FullName
        Write-Host "Abriendo reporte completo..." -ForegroundColor Cyan
        Start-Process -FilePath "notepad.exe" -ArgumentList "`"$($reportFile.FullName)`""
    } else {
        Write-Host "`n[!] No se genero un reporte nuevo (cerraste Specify antes de completar el analisis)." -ForegroundColor Yellow
    }
}

function Remove-DiagKit {
    if (-not (Test-Path $KitDir)) {
        Write-Host "`n[!] No existe la carpeta DiagKit en el Escritorio." -ForegroundColor Yellow
        return
    }

    Write-Host "`n[+] Cerrando procesos asociados..." -ForegroundColor Cyan
    Get-Process -Name "Specify*", "SystemInformer*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 600

    try {
        Remove-Item -Path $KitDir -Recurse -Force -ErrorAction Stop
        Write-Host "[OK] Todo eliminado limpiamente de $KitDir" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Cierra cualquier ventana o archivo abierto dentro de DiagKit e intentalo de nuevo." -ForegroundColor Red
    }
}

$running = $true
while ($running) {
    Show-Banner
    $choice = Read-Host "Selecciona una opcion [0-3]"

    switch ($choice) {
        "1" { Install-DiagKit;    Read-Host "`nPresiona Enter para continuar" }
        "2" { Invoke-Diagnostic; Read-Host "`nPresiona Enter para continuar" }
        "3" { Remove-DiagKit;    Read-Host "`nPresiona Enter para continuar" }
        "0" { $running = $false }
        default { Write-Host "`nOpcion invalida." -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }
}
