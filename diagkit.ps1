#Requires -Version 5.1
<#
.SYNOPSIS
    Win-DiagKit v2.0 - Auditoria, diagnostico heuristico e inspeccion portable para Windows.
.DESCRIPTION
    Arquitectura modular (Functional Core / Imperative Shell) compatible con PowerShell 5.1+
    y ejecucion directa remota via 'irm <url> | iex'.
#>

& {
$ErrorActionPreference = "Continue"
$ProgressPreference    = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# ==============================================================================
# CAPA 1: CONFIGURACION Y CONSTANTES (Single Source of Truth)
# ==============================================================================
$Config = @{
    Version        = "2.0.0"
    SelfUrl        = "https://raw.githubusercontent.com/moralesguasca99/win-diagkit/main/diagkit.ps1"
    WorkDir        = "C:\WinDiagKit"
    BinDir         = "C:\WinDiagKit\Bin"
    DesktopDir     = [Environment]::GetFolderPath('Desktop')
    Headers        = @{ "User-Agent" = "Win-DiagKit/2.0" }
    Urls           = @{
        SpecifyApi = "https://api.github.com/repos/Spec-ify/specify/releases/latest"
        ProcExp    = "https://live.sysinternals.com/procexp64.exe"
        Autoruns   = "https://live.sysinternals.com/autoruns64.exe"
    }
    Thresholds     = @{
        UptimeHoursWarning        = 48
        MemCompressionWarningMB   = 400
        RamFreePercentWarning     = 15
        StartupCountWarning       = 6
        DiskFreePercentWarning    = 20
        DiskTempWarningC          = 60
        DiskWearWarningPct        = 85
        MinExeSizeBytes           = 102400
    }
    Signatures     = @{
        HeavyAvAndBloat = @("AvastSvc", "aswEngSrv", "TuneupSvc", "DriverUpdSvc", "McShield", "NortonSecurity", "ApCent", "AVGSvc", "AvgUi", "AVGToolsSvc")
        RemoteTools     = @("AnyDesk", "rustdesk", "TeamViewer", "tv_w32", "ScreenConnect")
        NonEssentialRun = @("Steam", "EpicGamesLauncher", "AvastBrowser", "MicrosoftEdge", "OneDrive", "Spotify", "Discord")
    }
}

# ==============================================================================
# CAPA 2: UTILIDADES Y CAPA IMPERATIVA (Sistema, UAC, Red, WMI/CIM)
# ==============================================================================
function Test-IsAdmin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-ElevationIfNeeded {
    if (Test-IsAdmin) { return "ADMIN" }

    Write-Host "`n[!] El script se esta ejecutando SIN permisos de Administrador." -ForegroundColor Yellow
    Write-Host "    Sin elevacion, Windows bloquea S.M.A.R.T., Minidumps y eventos WHEA." -ForegroundColor Gray
    $ans = Read-Host "Deseas relanzar Win-DiagKit como Administrador ahora? (S/N)"

    if ($ans -match "^[sS]$") {
        try {
            if ($PSCommandPath -and (Test-Path $PSCommandPath)) {
                $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
            } else {
                $elevCmd = "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; irm '$($Config.SelfUrl)' | iex"
                $argList = "-NoProfile -ExecutionPolicy Bypass -Command `"$elevCmd`""
            }
            Start-Process -FilePath "powershell.exe" -ArgumentList $argList -Verb RunAs -ErrorAction Stop
            return "ELEVATED"
        }
        catch {
            Write-Host "[!] No se pudo elevar (UAC cancelado). Continuando en modo limitado..." -ForegroundColor Yellow
            Start-Sleep -Seconds 2
        }
    }
    return "LIMITED"
}

function Get-SafeProp {
    param($Object, [string]$PropertyName, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $prop = $Object.PSObject.Properties[$PropertyName]
    if ($null -eq $prop -or $null -eq $prop.Value) { return $Default }
    return $prop.Value
}

function ConvertTo-HtmlSafe {
    param($Value)
    if ($null -eq $Value) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-ToolPath {
    param([ValidateSet("Specify", "ProcExp", "Autoruns")][string]$Tool)
    if (-not (Test-Path $Config.BinDir)) { return $null }
    switch ($Tool) {
        "Specify"  { return (Get-ChildItem -Path $Config.BinDir -Filter "Specify*.exe" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1) }
        "ProcExp"  { return (Get-Item -Path (Join-Path $Config.BinDir "procexp64.exe") -ErrorAction SilentlyContinue) }
        "Autoruns" { return (Get-Item -Path (Join-Path $Config.BinDir "autoruns64.exe") -ErrorAction SilentlyContinue) }
    }
}

function Invoke-VerifiedDownload {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$OutFile,
        [string]$Label = "Archivo",
        [switch]$RequireMicrosoftSignature
    )
    Write-Host "    Descargando $Label..." -ForegroundColor Cyan
    $parentDir = Split-Path -Path $OutFile -Parent
    $leafName  = Split-Path -Path $OutFile -Leaf
    $tmpFile   = Join-Path $parentDir (".tmp_" + $leafName)
    try {
        Invoke-WebRequest -Uri $Uri -OutFile $tmpFile -Headers $Config.Headers -UseBasicParsing -ErrorAction Stop
        $size = (Get-Item $tmpFile -ErrorAction Stop).Length
        if ($size -lt $Config.Thresholds.MinExeSizeBytes) {
            Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
            throw "Tamano invalido ($size bytes). Posible bloqueo de red o enlace roto."
        }
        if ($RequireMicrosoftSignature) {
            $sig = Get-AuthenticodeSignature -FilePath $tmpFile -ErrorAction Stop
            if ($sig.Status -ne "Valid" -or ($sig.SignerCertificate.Subject -notlike "*Microsoft*")) {
                Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
                throw "Firma digital invalida o no emitida por Microsoft (Estado: $($sig.Status))."
            }
        }
        Move-Item -Path $tmpFile -Destination $OutFile -Force
        Unblock-File -Path $OutFile -ErrorAction SilentlyContinue
        Write-Host "    [OK] $Label ($([math]::Round($size / 1MB, 2)) MB)" -ForegroundColor Green
        return $true
    }
    catch {
        if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }
        Write-Host "    [ERROR] Fallo al descargar ${Label}: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Get-NativeStorageAndEvents {
    $result = [PSCustomObject]@{
        PhysicalDisks  = @()
        Volumes        = @()
        CriticalEvents = @()
        MinidumpFiles  = @()
        ExactUptimeHrs = $null
        RamFreePct     = $null
        RamTotalGB     = $null
        HiberbootOn    = $null
        DefenderPassv  = $null
        RebootPending  = $false
    }

    # Uptime exacto y RAM libre via CIM
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($os.LastBootUpTime) {
            $result.ExactUptimeHrs = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)
        }
        if ($os.TotalVisibleMemorySize -gt 0) {
            # TotalVisibleMemorySize viene en KB desde Win32_OperatingSystem
            $result.RamTotalGB = [math]::Round(($os.TotalVisibleMemorySize * 1KB) / 1GB, 1)
            $result.RamFreePct = [math]::Round(($os.FreePhysicalMemory / $os.TotalVisibleMemorySize) * 100, 1)
        }
    } catch {}

    # Claves de registro criticas
    try {
        $hiber = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -ErrorAction SilentlyContinue
        if ($null -ne $hiber) { $result.HiberbootOn = ($hiber.HiberbootEnabled -eq 1) }

        $def = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Name "PassiveMode" -ErrorAction SilentlyContinue
        if ($null -ne $def) { $result.DefenderPassv = ($def.PassiveMode -eq 1) }

        $cbsReboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
        $wuReboot  = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        $result.RebootPending = ($cbsReboot -or $wuReboot)
    } catch {}

    # Discos fisicos y S.M.A.R.T.
    try {
        $disks = @(Get-PhysicalDisk -ErrorAction Stop)
        foreach ($d in $disks) {
            $wear = $null; $temp = $null; $readErr = $null; $writeErr = $null
            try {
                $rel = $d | Get-StorageReliabilityCounter -ErrorAction Stop
                $wear     = $rel.Wear
                $temp     = $rel.Temperature
                $readErr  = $rel.ReadErrorsTotal
                $writeErr = $rel.WriteErrorsTotal
            } catch {}

            $result.PhysicalDisks += [PSCustomObject]@{
                Model        = $d.FriendlyName
                MediaType    = [string]$d.MediaType
                BusType      = [string]$d.BusType
                HealthStatus = [string]$d.HealthStatus
                SizeGB       = [math]::Round($d.Size / 1GB, 1)
                WearPct      = $wear
                TempC        = $temp
                ReadErrors   = $readErr
                WriteErrors  = $writeErr
            }
        }
    } catch {}

    # Volumenes y espacio libre
    try {
        $vols = @(Get-Volume -ErrorAction Stop | Where-Object { $_.DriveLetter -and $_.Size -gt 0 })
        foreach ($v in $vols) {
            $result.Volumes += [PSCustomObject]@{
                Drive      = "$($v.DriveLetter):"
                Label      = $v.FileSystemLabel
                SizeGB     = [math]::Round($v.Size / 1GB, 1)
                FreeGB     = [math]::Round($v.SizeRemaining / 1GB, 1)
                FreePct    = [math]::Round(($v.SizeRemaining / $v.Size) * 100, 1)
                Health     = [string]$v.HealthStatus
            }
        }
    } catch {}

    # Minidumps locales
    try {
        if (Test-Path "C:\Windows\Minidump") {
            $result.MinidumpFiles = @(Get-ChildItem -Path "C:\Windows\Minidump" -Filter "*.dmp" -ErrorAction SilentlyContinue |
                                      Sort-Object LastWriteTime -Descending | Select-Object -First 5)
        }
    } catch {}

    # Eventos criticos BSOD / Kernel-Power 41 / WHEA (incluyendo warnings corregidos 17/19) de los ultimos 14 dias
    try {
        $startTime = (Get-Date).AddDays(-14)
        $rawEvents = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 41, 1001, 17, 18, 19, 20
            StartTime = $startTime
        } -ErrorAction Stop)

        $events = @($rawEvents | Where-Object {
            ($_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' -and $_.Id -eq 41) -or
            ($_.ProviderName -eq 'BugCheck' -and $_.Id -eq 1001) -or
            ($_.ProviderName -like '*WHEA-Logger*' -and $_.Id -in @(17, 18, 19, 20))
        } | Select-Object -First 15)

        foreach ($ev in $events) {
            $msg = if ($ev.Message) { ($ev.Message -split "`r?`n")[0] } else { "Sin detalle" }
            $result.CriticalEvents += [PSCustomObject]@{
                Time     = $ev.TimeCreated.ToString("yyyy-MM-dd HH:mm")
                Id       = $ev.Id
                Provider = $ev.ProviderName
                Summary  = $msg
            }
        }
    } catch {}

    return $result
}

# ==============================================================================
# CAPA 3: ADAPTADORES DE DATOS (Esquema Canonico Unificado)
# ==============================================================================
function ConvertFrom-SpecifyToCanonical {
    param(
        [Parameter(Mandatory)]$SpecJson,
        [Parameter(Mandatory)]$NativeExtra,
        [string]$JsonPath = ""
    )

    $basic  = Get-SafeProp $SpecJson "BasicInfo"
    $sys    = Get-SafeProp $SpecJson "System"
    $hw     = Get-SafeProp $SpecJson "Hardware"

    # Extraer valores de registro desde ChoiceRegistryValues si NativeExtra no los obtuvo
    $regVals = @(Get-SafeProp $sys "ChoiceRegistryValues" @())
    $hiberVal = $NativeExtra.HiberbootOn
    if ($null -eq $hiberVal) {
        $hEntry = $regVals | Where-Object { $_.Name -eq "HiberbootEnabled" } | Select-Object -First 1
        if ($hEntry) { $hiberVal = ($hEntry.Value -eq 1) }
    }
    $defPassv = $NativeExtra.DefenderPassv
    if ($null -eq $defPassv) {
        $dEntry = $regVals | Where-Object { $_.Name -like "*Passive Mode*" } | Select-Object -First 1
        if ($dEntry) { $defPassv = ($dEntry.Value -eq 1) }
    }

    # RAM normalizada (solo modulos poblados)
    $ramModules = @()
    foreach ($r in @(Get-SafeProp $hw "Ram" @())) {
        $rawCap = [long](Get-SafeProp $r "Capacity" 0)
        if ($rawCap -gt 0) {
            $capMB = if ($rawCap -gt 10485760) { [long][math]::Round($rawCap / 1MB, 0) } else { $rawCap }
            $ramModules += [PSCustomObject]@{
                Slot            = "$($r.BankLocator) / $($r.DeviceLocation)"
                PartNumber      = ([string]$r.PartNumber).Trim()
                ConfiguredSpeed = [int]$r.ConfiguredSpeed
                CapacityMB      = $capMB
                IsSoldered      = $false
            }
        }
    }

    # Procesos normalizados
    $procs = @()
    foreach ($p in @(Get-SafeProp $sys "RunningProcesses" @())) {
        $procs += [PSCustomObject]@{
            Name         = [string]$p.ProcessName
            Path         = [string]$p.ExePath
            WorkingSetMB = [math]::Round(([double]$p.WorkingSet) / 1MB, 1)
        }
    }

    # Plan de energia activo
    $activePlan = "Desconocido"
    $planObj = @(Get-SafeProp $sys "PowerProfiles" @()) | Where-Object { $_.IsActive -eq $true } | Select-Object -First 1
    if ($planObj) { $activePlan = $planObj.ElementName }

    # GPU(s)
    $gpuList = @()
    foreach ($g in @(Get-SafeProp $hw "Gpu" @())) {
        $gpuName = if (Get-SafeProp $g "Description") { $g.Description } else { Get-SafeProp $g "Name" "GPU Desconocida" }
        $gpuList += "$gpuName (Driver: $($g.DriverVersion))"
    }

    $minidumpCount = [math]::Max([int](Get-SafeProp $sys "RecentMinidumps" 0), $NativeExtra.MinidumpFiles.Count)

    return [PSCustomObject]@{
        SourceMode       = "Specify + Enriquecimiento Nativo"
        SourceJsonPath   = $JsonPath
        GeneratedAt      = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        IsAdminCapture   = (Test-IsAdmin)
        Hostname         = Get-SafeProp $basic "Hostname" $env:COMPUTERNAME
        OsEdition        = "$(Get-SafeProp $basic 'Edition' 'Windows') $(Get-SafeProp $basic 'FriendlyVersion' '') (Build $(Get-SafeProp $basic 'Version' ''))".Trim()
        BootMode         = Get-SafeProp $basic "BootMode" "N/A"
        UptimeHours      = $NativeExtra.ExactUptimeHrs
        HiberbootEnabled = $hiberVal
        DefenderPassive  = $defPassv
        RebootPending    = $NativeExtra.RebootPending
        PowerPlan        = $activePlan
        CpuName          = ([string](Get-SafeProp (Get-SafeProp $hw "Cpu") "Name" "N/A")).Trim()
        CpuLoadPct       = Get-SafeProp (Get-SafeProp $hw "Cpu") "LoadPercentage" $null
        Motherboard      = "$(Get-SafeProp (Get-SafeProp $hw 'Motherboard') 'Manufacturer' '') $(Get-SafeProp (Get-SafeProp $hw 'Motherboard') 'Product' '')".Trim()
        Gpus             = $gpuList
        RamModules       = $ramModules
        RamTotalGB       = if ($NativeExtra.RamTotalGB) { $NativeExtra.RamTotalGB } else { [math]::Round((($ramModules | Measure-Object CapacityMB -Sum).Sum) / 1024, 1) }
        RamFreePct       = $NativeExtra.RamFreePct
        Processes        = $procs
        Services         = @(Get-SafeProp $sys "Services" @())
        StartupTasks     = @(Get-SafeProp $sys "StartupTasks" @() | Where-Object { $_.AppName -ne "desktop.ini" })
        BrowserExts      = @(Get-SafeProp $sys "BrowserExtensions" @())
        MinidumpCount    = $minidumpCount
        MinidumpFiles    = $NativeExtra.MinidumpFiles
        CriticalEvents   = $NativeExtra.CriticalEvents
        PhysicalDisks    = $NativeExtra.PhysicalDisks
        Volumes          = $NativeExtra.Volumes
    }
}

function New-NativeOnlyCanonical {
    param([Parameter(Mandatory)]$NativeExtra)

    $os   = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cpu  = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $mb   = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue | Select-Object -First 1
    $gpus = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue)
    $rams = @(Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue)

    $ramModules = @()
    foreach ($r in $rams) {
        $speed = if ($r.ConfiguredClockSpeed) { [int]$r.ConfiguredClockSpeed } else { [int]$r.Speed }
        $isSoldered = ($r.FormFactor -eq 24) -or ($r.SMBIOSMemoryType -in @(29, 30, 35))
        $ramModules += [PSCustomObject]@{
            Slot            = "$($r.BankLabel) / $($r.DeviceLocator)"
            PartNumber      = ([string]$r.PartNumber).Trim()
            ConfiguredSpeed = $speed
            CapacityMB      = [long][math]::Round($r.Capacity / 1MB, 0)
            IsSoldered      = $isSoldered
        }
    }

    $procs = @()
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        $procs += [PSCustomObject]@{
            Name         = $p.ProcessName
            Path         = ""
            WorkingSetMB = [math]::Round($p.WorkingSet64 / 1MB, 1)
        }
    }

    $startups = @()
    try {
        foreach ($st in @(Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "desktop.ini" })) {
            $startups += [PSCustomObject]@{
                AppName        = $st.Name
                AppDescription = $st.Location
                ImagePath      = $st.Command
            }
        }
    } catch {}

    $services = @()
    try {
        foreach ($sv in @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' })) {
            $services += [PSCustomObject]@{ Name = $sv.Name; Caption = $sv.DisplayName; State = "Running" }
        }
    } catch {}

    $activePlan = "N/A"
    try {
        $planLine = (powercfg /getactivescheme) 2>$null
        if ($planLine -match "\((.+)\)") { $activePlan = $Matches[1] }
    } catch {}

    return [PSCustomObject]@{
        SourceMode       = "Auditoria 100% Nativa (Sin descargas)"
        SourceJsonPath   = ""
        GeneratedAt      = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        IsAdminCapture   = (Test-IsAdmin)
        Hostname         = $env:COMPUTERNAME
        OsEdition        = if ($os) { "$($os.Caption) (Build $($os.BuildNumber))" } else { "Windows" }
        BootMode         = "N/A"
        UptimeHours      = $NativeExtra.ExactUptimeHrs
        HiberbootEnabled = $NativeExtra.HiberbootOn
        DefenderPassive  = $NativeExtra.DefenderPassv
        RebootPending    = $NativeExtra.RebootPending
        PowerPlan        = $activePlan
        CpuName          = if ($cpu) { $cpu.Name.Trim() } else { "N/A" }
        CpuLoadPct       = if ($cpu) { $cpu.LoadPercentage } else { $null }
        Motherboard      = if ($mb) { "$($mb.Manufacturer) $($mb.Product)".Trim() } else { "N/A" }
        Gpus             = @($gpus | ForEach-Object { "$($_.Name) (Driver: $($_.DriverVersion))" })
        RamModules       = $ramModules
        RamTotalGB       = if ($NativeExtra.RamTotalGB) { $NativeExtra.RamTotalGB } elseif ($ramModules.Count -gt 0) { [math]::Round((($ramModules | Measure-Object CapacityMB -Sum).Sum) / 1024, 1) } else { $null }
        RamFreePct       = $NativeExtra.RamFreePct
        Processes        = $procs
        Services         = $services
        StartupTasks     = $startups
        BrowserExts      = @()
        MinidumpCount    = $NativeExtra.MinidumpFiles.Count
        MinidumpFiles    = $NativeExtra.MinidumpFiles
        CriticalEvents   = $NativeExtra.CriticalEvents
        PhysicalDisks    = $NativeExtra.PhysicalDisks
        Volumes          = $NativeExtra.Volumes
    }
}

# ==============================================================================
# CAPA 4: MOTOR HEURISTICO (Functional Core - Reglas Puras Deterministas)
# ==============================================================================
function New-Finding {
    param(
        [ValidateSet("CRITICAL", "WARNING", "INFO", "OK")][string]$Severity,
        [string]$Category,
        [string]$Title,
        [string]$Evidence,
        [string]$Recommendation
    )
    return [PSCustomObject]@{
        Severity       = $Severity
        Category       = $Category
        Title          = $Title
        Evidence       = $Evidence
        Recommendation = $Recommendation
    }
}

function Get-AggregatedTopProcesses {
    param($Processes, [int]$Top = 10)
    return @($Processes | Group-Object -Property Name | ForEach-Object {
        $totalMB = [math]::Round((($_.Group | Measure-Object WorkingSetMB -Sum).Sum), 1)
        [PSCustomObject]@{
            Name      = $_.Name
            Instances = $_.Count
            TotalMB   = $totalMB
        }
    } | Sort-Object TotalMB -Descending | Select-Object -First $Top)
}

function Invoke-HeuristicAnalysis {
    param([Parameter(Mandatory)]$Model)

    $findings = New-Object System.Collections.Generic.List[object]
    $th       = $Config.Thresholds

    # REGLA 1: Frecuencia RAM (XMP/DOCP) y Single Channel
    if ($Model.RamModules.Count -gt 0) {
        if ($Model.RamModules.Count -eq 1 -and -not $Model.RamModules[0].IsSoldered) {
            $findings.Add((New-Finding -Severity "WARNING" -Category "Memoria RAM" `
                -Title "Memoria operando en Single Channel (1 solo modulo)" `
                -Evidence "Solo se detecto 1 modulo instalado ($($Model.RamModules[0].CapacityMB) MB en $($Model.RamModules[0].Slot))." `
                -Recommendation "Anadir un segundo modulo identico activa Dual Channel y mejora el rendimiento de CPU/graficos. Nota: en portatiles con RAM soldada (LPDDR4/LPDDR5), SMBIOS puede reportar 1 solo bloque aunque opere en Dual/Quad Channel."))
        }

        $validSpeedPattern = "(2133|2400|2666|2933|3000|3200|3466|3600|3733|3800|4000|4133|4266|4400|4600|4800|5200|5600|6000|6200|6400|6600|6800|7000|7200|7600|8000|8200|8400)"
        $xmpIssues = @()
        foreach ($mod in $Model.RamModules) {
            $nominal = 0
            if ($mod.PartNumber -match "KF[45](\d{2})[CS]") {
                $candidate = ([int]$Matches[1]) * 100
                if ($candidate -ge 2133 -and $candidate -le 9600) { $nominal = $candidate }
            } elseif ($mod.PartNumber -match "(?<!\d)$validSpeedPattern(?!\d)") {
                $nominal = [int]$Matches[1]
            }
            if ($nominal -gt 0 -and $mod.ConfiguredSpeed -gt 0 -and $mod.ConfiguredSpeed -lt $nominal) {
                $xmpIssues += "$($mod.PartNumber): corriendo a $($mod.ConfiguredSpeed) MHz (deberia ser $nominal MHz)"
            }
        }
        if ($xmpIssues.Count -gt 0) {
            $findings.Add((New-Finding -Severity "WARNING" -Category "Memoria RAM" `
                -Title "Perfil XMP/DOCP desactivado (RAM por debajo de su velocidad)" `
                -Evidence ($xmpIssues -join " | ") `
                -Recommendation "Entra a la BIOS de la placa ($($Model.Motherboard)) y activa el perfil X.M.P. / D.O.C.P. Profile 1."))
        } else {
            $speeds = ($Model.RamModules.ConfiguredSpeed | Select-Object -Unique) -join "/"
            $ramTotStr = if ($null -ne $Model.RamTotalGB) { "$($Model.RamTotalGB) GB" } else { "N/A" }
            $findings.Add((New-Finding -Severity "OK" -Category "Memoria RAM" `
                -Title "Configuracion de frecuencia RAM consistente" `
                -Evidence "$($Model.RamModules.Count) modulo(s) detectados a $speeds MHz (Total: $ramTotStr)." `
                -Recommendation "Sin acciones necesarias."))
        }
    }

    # REGLA 2: Pantallazos Azules (BSOD), Minidumps y Errores WHEA
    $wheaCount = @($Model.CriticalEvents | Where-Object { $_.Provider -like "*WHEA*" }).Count
    if ($Model.MinidumpCount -gt 0 -or $wheaCount -gt 0 -or $Model.CriticalEvents.Count -gt 0) {
        $evParts = @()
        if ($Model.MinidumpCount -gt 0) { $evParts += "Minidumps recientes: $($Model.MinidumpCount)" }
        if ($wheaCount -gt 0) { $evParts += "Errores fisicos WHEA: $wheaCount" }
        if ($Model.CriticalEvents.Count -gt 0) { $evParts += "Eventos criticos Kernel/BSOD (14 dias): $($Model.CriticalEvents.Count)" }

        $findings.Add((New-Finding -Severity "CRITICAL" -Category "Estabilidad / BSOD" `
            -Title "Se detectaron fallos criticos del sistema o pantallazos azules" `
            -Evidence ($evParts -join " | ") `
            -Recommendation "Revisa la tabla de Eventos Criticos abajo. Si hay WHEA, verifica estabilidad de RAM/CPU/temperaturas; si hay BugCheck, actualiza drivers de GPU/chipset."))
    } else {
        $evNote = if ($Model.IsAdminCapture) { "0 minidumps y 0 eventos Kernel-Power/WHEA en los ultimos 14 dias." } else { "Sin minidumps reportados (ejecuta como Admin para lectura completa del Visor de Eventos)." }
        $findings.Add((New-Finding -Severity "OK" -Category "Estabilidad / BSOD" `
            -Title "Sin cierres criticos recientes detectados" `
            -Evidence $evNote `
            -Recommendation "Sin acciones necesarias."))
    }

    # REGLA 3: Uptime prolongado + Inicio Rapido (Hiberboot)
    if ($null -ne $Model.UptimeHours -and $Model.UptimeHours -ge $th.UptimeHoursWarning) {
        $hiberTxt = if ($Model.HiberbootEnabled) { "con Inicio Rapido (Hiberboot) ACTIVADO" } else { "sin reinicio reciente" }
        $findings.Add((New-Finding -Severity "WARNING" -Category "Sistema Operativo" `
            -Title "Kernel sin reinicio real por mas de $($th.UptimeHoursWarning) horas" `
            -Evidence "Tiempo activo acumulado: $($Model.UptimeHours) horas ($hiberTxt)." `
            -Recommendation "Usa Inicio -> Reiniciar (no Apagar) para vaciar fugas de memoria y reiniciar controladores."))
    }

    # REGLA 4: Presion de memoria RAM y Compresion
    $memComp = ($Model.Processes | Where-Object { $_.Name -eq "Memory Compression" } | Measure-Object WorkingSetMB -Sum).Sum
    $memComp = [math]::Round($memComp, 1)
    if (($memComp -ge $th.MemCompressionWarningMB) -or ($null -ne $Model.RamFreePct -and $Model.RamFreePct -lt $th.RamFreePercentWarning)) {
        $ramFreeTxt = if ($null -ne $Model.RamFreePct) { "$($Model.RamFreePct)%" } else { "N/A" }
        $findings.Add((New-Finding -Severity "WARNING" -Category "Rendimiento RAM" `
            -Title "Alta presion de memoria RAM en el equipo" `
            -Evidence "Memory Compression: $memComp MB | RAM fisica libre actual: $ramFreeTxt." `
            -Recommendation "Revisa la tabla de Top 10 consumidores reales abajo y cierra apps multi-proceso o pestanas innecesarias."))
    }

    # REGLA 5: Antivirus de terceros / Bloatware / Defender Pasivo
    $detectedBloat = @()
    foreach ($sig in $Config.Signatures.HeavyAvAndBloat) {
        $hitProc = $Model.Processes | Where-Object { $_.Name -like "*$sig*" } | Select-Object -First 1
        $hitSvc  = $Model.Services  | Where-Object { $_.State -eq "Running" -and ($_.Name -like "*$sig*" -or $_.Caption -like "*$sig*") } | Select-Object -First 1
        if ($hitProc -or $hitSvc) { $detectedBloat += $sig }
    }
    $detectedBloat = @($detectedBloat | Select-Object -Unique)

    if ($Model.DefenderPassive -eq $true -or $detectedBloat.Count -gt 0) {
        $evBloat = @()
        if ($Model.DefenderPassive) { $evBloat += "Windows Defender en Modo Pasivo" }
        if ($detectedBloat.Count -gt 0) { $evBloat += "Procesos/servicios detectados: $($detectedBloat -join ', ')" }

        $findings.Add((New-Finding -Severity "WARNING" -Category "Bloatware / Antivirus" `
            -Title "Suite antivirus pesada o bloatware activo en segundo plano" `
            -Evidence ($evBloat -join " | ") `
            -Recommendation "Evalua desinstalar utilidades innecesarias (Driver Updaters, Cleanups, App Centers) o sustituir suites pesadas por Microsoft Defender nativo."))
    }

    # REGLA 5B (Extra): Multiples clientes de acceso remoto activos simultaneamente
    $activeRemotes = @()
    foreach ($rt in $Config.Signatures.RemoteTools) {
        if ($Model.Processes | Where-Object { $_.Name -like "*$rt*" } | Select-Object -First 1) {
            $activeRemotes += $rt
        }
    }
    if ($activeRemotes.Count -gt 1) {
        $findings.Add((New-Finding -Severity "INFO" -Category "Seguridad / Red" `
            -Title "Multiples herramientas de acceso remoto activas al mismo tiempo" `
            -Evidence "Activos simultaneamente: $($activeRemotes -join ', ')." `
            -Recommendation "Verifica que el usuario conozca y autorice ambos programas; desactiva el servicio permanente del que no se use."))
    }

    # REGLA 6: Arranque sobrecargado
    if ($Model.StartupTasks.Count -gt $th.StartupCountWarning) {
        $nonEss = @($Model.StartupTasks | Where-Object {
            $n = "$($_.AppName) $($_.ImagePath)"
            $matched = $false
            foreach ($k in $Config.Signatures.NonEssentialRun) { if ($n -like "*$k*") { $matched = $true; break } }
            $matched
        } | ForEach-Object { $_.AppName })

        $extra = if ($nonEss.Count -gt 0) { " | No esenciales sugeridos a desactivar: $($nonEss -join ', ')" } else { "" }
        $findings.Add((New-Finding -Severity "WARNING" -Category "Inicio de Windows" `
            -Title "Arranque sobrecargado ($($Model.StartupTasks.Count) programas al iniciar sesion)" `
            -Evidence "Se supero el umbral recomendado de $($th.StartupCountWarning) aplicaciones$extra." `
            -Recommendation "Deshabilita launchers y navegadores secundarios desde Administrador de tareas -> Aplicaciones de arranque o usando Autoruns (Opcion 3)."))
    }

    # REGLA 7: Salud S.M.A.R.T. (estado, errores R/W, desgaste, temperatura) y espacio en disco
    $unhealthyDisks = @($Model.PhysicalDisks | Where-Object { $_.HealthStatus -and $_.HealthStatus -ne "Healthy" })
    if ($unhealthyDisks.Count -gt 0) {
        $desc = ($unhealthyDisks | ForEach-Object { "$($_.Model) [$($_.HealthStatus)]" }) -join ", "
        $findings.Add((New-Finding -Severity "CRITICAL" -Category "Almacenamiento" `
            -Title "Disco fisico reporta estado de salud degradado (S.M.A.R.T.)" `
            -Evidence $desc `
            -Recommendation "Realiza copia de seguridad inmediata de los datos criticos y planifica reemplazo de la unidad."))
    }

    $rwErrorDisks = @($Model.PhysicalDisks | Where-Object {
        ($null -ne $_.ReadErrors -and $_.ReadErrors -gt 0) -or ($null -ne $_.WriteErrors -and $_.WriteErrors -gt 0)
    })
    if ($rwErrorDisks.Count -gt 0) {
        $rwDesc = ($rwErrorDisks | ForEach-Object { "$($_.Model) (Lectura: $($_.ReadErrors) / Escritura: $($_.WriteErrors))" }) -join " | "
        $findings.Add((New-Finding -Severity "WARNING" -Category "Almacenamiento" `
            -Title "Errores de lectura/escritura S.M.A.R.T. detectados en disco fisico" `
            -Evidence $rwDesc `
            -Recommendation "Respalda datos importantes, verifica el cable/puerto SATA o ranura M.2 y monitoriza si los contadores siguen aumentando."))
    }

    $wornDisks = @($Model.PhysicalDisks | Where-Object { $null -ne $_.WearPct -and $_.WearPct -ge $th.DiskWearWarningPct })
    if ($wornDisks.Count -gt 0) {
        $wearDesc = ($wornDisks | ForEach-Object { "$($_.Model) (Desgaste: $($_.WearPct)%)" }) -join " | "
        $findings.Add((New-Finding -Severity "WARNING" -Category "Almacenamiento" `
            -Title "Desgaste elevado en unidad de almacenamiento (S.M.A.R.T.)" `
            -Evidence $wearDesc `
            -Recommendation "El SSD se acerca al final de su vida util estimada (TBW). Manten copias de seguridad actualizadas y planifica su sustitucion."))
    }

    $hotDisks = @($Model.PhysicalDisks | Where-Object { $null -ne $_.TempC -and $_.TempC -gt 0 -and $_.TempC -ge $th.DiskTempWarningC })
    if ($hotDisks.Count -gt 0) {
        $hotDesc = ($hotDisks | ForEach-Object { "$($_.Model) ($($_.TempC) C)" }) -join " | "
        $findings.Add((New-Finding -Severity "WARNING" -Category "Almacenamiento" `
            -Title "Temperatura elevada en disco fisico (>= $($th.DiskTempWarningC) C)" `
            -Evidence $hotDesc `
            -Recommendation "Mejora el flujo de aire del chasis o instala un disipador termico (especialmente en unidades NVMe M.2) para evitar thermal throttling."))
    }

    $lowVols = @($Model.Volumes | Where-Object { $_.FreePct -lt $th.DiskFreePercentWarning })
    if ($lowVols.Count -gt 0) {
        $vDesc = ($lowVols | ForEach-Object { "$($_.Drive) libre $($_.FreeGB) GB ($($_.FreePct)%)" }) -join " | "
        $findings.Add((New-Finding -Severity "WARNING" -Category "Almacenamiento" `
            -Title "Volumen con menos del $($th.DiskFreePercentWarning)% de espacio libre" `
            -Evidence $vDesc `
            -Recommendation "Libera espacio. Los SSD (especialmente SATA sin cache DRAM) reducen drasticamente su velocidad al llenarse por encima del 80%."))
    }

    # REGLA 8: Extensiones de navegador sin nombre (Higiene)
    $suspiciousExts = @()
    foreach ($browser in $Model.BrowserExts) {
        foreach ($prof in @(Get-SafeProp $browser "Profiles" @())) {
            foreach ($ext in @(Get-SafeProp $prof "Extensions" @())) {
                $eName = ([string](Get-SafeProp $ext "name" "")).Trim()
                if ([string]::IsNullOrWhiteSpace($eName)) {
                    $suspiciousExts += "$($browser.Name) ($($prof.name)) - v$(Get-SafeProp $ext 'version' '?')"
                }
            }
        }
    }
    if ($suspiciousExts.Count -gt 0) {
        $findings.Add((New-Finding -Severity "WARNING" -Category "Navegadores" `
            -Title "Extensiones sin nombre detectadas en navegadores" `
            -Evidence ($suspiciousExts -join " | ") `
            -Recommendation "Abre la pagina de extensiones del navegador (ej. chrome://extensions) y elimina extensiones desconocidas o retiradas de la tienda."))
    }

    # REGLA 9: Reinicio pendiente de Windows Update
    if ($Model.RebootPending) {
        $findings.Add((New-Finding -Severity "INFO" -Category "Actualizaciones" `
            -Title "Reinicio pendiente para completar actualizaciones de Windows" `
            -Evidence "Bandera RebootPending / RebootRequired activa en el registro." `
            -Recommendation "Reinicia el PC para aplicar parches pendientes y liberar procesos de Windows Update."))
    }

    # Ordenar por severidad: CRITICAL -> WARNING -> INFO -> OK
    $rankMap = @{ "CRITICAL" = 1; "WARNING" = 2; "INFO" = 3; "OK" = 4 }
    return @($findings | Sort-Object { $rankMap[$_.Severity] })
}

# ==============================================================================
# CAPA 5: PRESENTACION (Resumen en Consola + Generador HTML Tema Oscuro)
# ==============================================================================
function Show-ConsoleSummary {
    param($Model, $Findings, $TopProcesses)

    $critCount = @($Findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    $warnCount = @($Findings | Where-Object { $_.Severity -eq "WARNING" }).Count

    $cpuLoadStr = if ($null -ne $Model.CpuLoadPct) { "$($Model.CpuLoadPct)%" } else { "N/A" }
    $ramTotStr  = if ($null -ne $Model.RamTotalGB) { "$($Model.RamTotalGB) GB" } else { "N/A" }
    $ramFreeStr = if ($null -ne $Model.RamFreePct) { "$($Model.RamFreePct)%" } else { "N/A" }

    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host "  RESUMEN EJECUTIVO: $($Model.Hostname)" -ForegroundColor White
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  SO       : $($Model.OsEdition)" -ForegroundColor Gray
    Write-Host "  CPU      : $($Model.CpuName) (Carga: $cpuLoadStr)" -ForegroundColor Gray
    Write-Host "  GPU      : $($Model.Gpus -join ' | ')" -ForegroundColor Gray
    Write-Host "  RAM      : $ramTotStr (Libre: $ramFreeStr)" -ForegroundColor Gray
    Write-Host "  Alertas  : $critCount Criticas | $warnCount Advertencias" -ForegroundColor $(if ($critCount -gt 0) { "Red" } elseif ($warnCount -gt 0) { "Yellow" } else { "Green" })
    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan

    foreach ($f in $Findings) {
        $col = switch ($f.Severity) {
            "CRITICAL" { "Red" }
            "WARNING"  { "Yellow" }
            "INFO"     { "Cyan" }
            default    { "Green" }
        }
        Write-Host "  [$($f.Severity)] $($f.Category): $($f.Title)" -ForegroundColor $col
        Write-Host "      -> $($f.Evidence)" -ForegroundColor DarkGray
    }

    Write-Host "`n  TOP 5 CONSUMIDORES REALES DE RAM (Agrupados):" -ForegroundColor White
    foreach ($p in ($TopProcesses | Select-Object -First 5)) {
        Write-Host ("    - {0,-24} {1,7} MB ({2} inst.)" -f $p.Name, $p.TotalMB, $p.Instances) -ForegroundColor Gray
    }
    Write-Host "============================================================`n" -ForegroundColor Cyan
}

function Export-HtmlReport {
    param($Model, $Findings, $TopProcesses)

    $critCount = @($Findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    $warnCount = @($Findings | Where-Object { $_.Severity -eq "WARNING" }).Count

    $healthLabel = "SALUDABLE"; $healthClass = "badge-ok"
    if ($critCount -gt 0) { $healthLabel = "ATENCION CRITICA ($critCount)"; $healthClass = "badge-crit" }
    elseif ($warnCount -gt 0) { $healthLabel = "MEJORABLE ($warnCount ALERTAS)"; $healthClass = "badge-warn" }

    # Tarjetas de hallazgos
    $cardsHtml = New-Object System.Text.StringBuilder
    foreach ($f in $Findings) {
        $css = switch ($f.Severity) {
            "CRITICAL" { "card-crit" }
            "WARNING"  { "card-warn" }
            "INFO"     { "card-info" }
            default    { "card-ok" }
        }
        [void]$cardsHtml.AppendLine("<div class='card $css'>")
        [void]$cardsHtml.AppendLine("  <div class='card-head'><span class='sev'>$(ConvertTo-HtmlSafe $f.Severity)</span> <span class='cat'>$(ConvertTo-HtmlSafe $f.Category)</span></div>")
        [void]$cardsHtml.AppendLine("  <h3>$(ConvertTo-HtmlSafe $f.Title)</h3>")
        [void]$cardsHtml.AppendLine("  <p class='ev'><strong>Evidencia:</strong> $(ConvertTo-HtmlSafe $f.Evidence)</p>")
        [void]$cardsHtml.AppendLine("  <p class='rec'><strong>Accion recomendada:</strong> $(ConvertTo-HtmlSafe $f.Recommendation)</p>")
        [void]$cardsHtml.AppendLine("</div>")
    }

    # Tabla Top 10 procesos
    $maxMem = 1
    if ($TopProcesses.Count -gt 0 -and $TopProcesses[0].TotalMB -gt 0) { $maxMem = $TopProcesses[0].TotalMB }
    $procRows = New-Object System.Text.StringBuilder
    foreach ($p in $TopProcesses) {
        $pct = [math]::Min(100, [math]::Round(($p.TotalMB / $maxMem) * 100, 0))
        [void]$procRows.AppendLine("<tr><td>$(ConvertTo-HtmlSafe $p.Name)</td><td>$($p.Instances)</td><td><strong>$($p.TotalMB) MB</strong></td><td><div class='bar-bg'><div class='bar-fill' style='width:${pct}%'></div></div></td></tr>")
    }

    # Tabla discos y volumenes
    $diskRows = New-Object System.Text.StringBuilder
    foreach ($d in $Model.PhysicalDisks) {
        $tStr  = if ($null -ne $d.TempC -and $d.TempC -gt 0) { "$($d.TempC) C" } else { "N/A" }
        $wStr  = if ($null -ne $d.WearPct) { "$($d.WearPct)%" } else { "N/A" }
        $rwStr = if ($null -ne $d.ReadErrors -or $null -ne $d.WriteErrors) {
            $rVal = if ($null -ne $d.ReadErrors)  { $d.ReadErrors }  else { "N/A" }
            $wVal = if ($null -ne $d.WriteErrors) { $d.WriteErrors } else { "N/A" }
            "$rVal / $wVal"
        } else { "N/A" }
        [void]$diskRows.AppendLine("<tr><td>$(ConvertTo-HtmlSafe $d.Model)</td><td>$(ConvertTo-HtmlSafe $d.MediaType) / $(ConvertTo-HtmlSafe $d.BusType)</td><td>$($d.SizeGB) GB</td><td>$(ConvertTo-HtmlSafe $d.HealthStatus)</td><td>$tStr</td><td>$wStr</td><td>$rwStr</td></tr>")
    }
    if ($Model.PhysicalDisks.Count -eq 0) { [void]$diskRows.AppendLine("<tr><td colspan='7'>Sin lectura de discos fisicos (ejecuta como Administrador).</td></tr>") }

    $volRows = New-Object System.Text.StringBuilder
    foreach ($v in $Model.Volumes) {
        [void]$volRows.AppendLine("<tr><td><strong>$(ConvertTo-HtmlSafe $v.Drive)</strong> $(ConvertTo-HtmlSafe $v.Label)</td><td>$($v.SizeGB) GB</td><td>$($v.FreeGB) GB</td><td>$($v.FreePct)%</td><td>$(ConvertTo-HtmlSafe $v.Health)</td></tr>")
    }
    if ($Model.Volumes.Count -eq 0) { [void]$volRows.AppendLine("<tr><td colspan='5'>Sin lectura de volumenes.</td></tr>") }

    # Tabla arranque
    $startRows = New-Object System.Text.StringBuilder
    foreach ($s in $Model.StartupTasks) {
        [void]$startRows.AppendLine("<tr><td>$(ConvertTo-HtmlSafe $s.AppName)</td><td><code>$(ConvertTo-HtmlSafe $s.ImagePath)</code></td></tr>")
    }
    if ($Model.StartupTasks.Count -eq 0) { [void]$startRows.AppendLine("<tr><td colspan='2'>Sin elementos de inicio detectados.</td></tr>") }

    # Tabla eventos criticos
    $evRows = New-Object System.Text.StringBuilder
    foreach ($e in $Model.CriticalEvents) {
        [void]$evRows.AppendLine("<tr><td>$(ConvertTo-HtmlSafe $e.Time)</td><td>$($e.Id)</td><td>$(ConvertTo-HtmlSafe $e.Provider)</td><td>$(ConvertTo-HtmlSafe $e.Summary)</td></tr>")
    }
    if ($Model.CriticalEvents.Count -eq 0) { [void]$evRows.AppendLine("<tr><td colspan='4'>Sin eventos criticos BSOD/Kernel-Power/WHEA en los ultimos 14 dias.</td></tr>") }

    $adminBadge  = if ($Model.IsAdminCapture) { "Administrador: SI" } else { "Administrador: NO (Captura limitada)" }
    $jsonFooter  = if ($Model.SourceJsonPath) { "JSON crudo guardado en: $(ConvertTo-HtmlSafe $Model.SourceJsonPath)" } else { "Modo nativo offline (sin JSON externo)" }
    $ramStatStr  = if ($null -ne $Model.RamTotalGB) { "$($Model.RamTotalGB) GB" } else { "N/A" }
    $freeStatStr = if ($null -ne $Model.RamFreePct) { "$($Model.RamFreePct)%" } else { "N/A" }
    $upStatStr   = if ($null -ne $Model.UptimeHours) { "$($Model.UptimeHours) horas" } else { "N/A" }

    $html = @"
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Win-DiagKit - $(ConvertTo-HtmlSafe $Model.Hostname)</title>
<style>
  :root { --bg:#0d1117; --panel:#161b22; --border:#30363d; --text:#e6edf3; --muted:#8b949e; --crit:#f85149; --warn:#d29922; --ok:#3fb950; --info:#58a6ff; }
  * { box-sizing:border-box; }
  body { margin:0; padding:24px; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:var(--bg); color:var(--text); line-height:1.5; }
  .wrap { max-width:1100px; margin:0 auto; }
  header { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:20px 24px; margin-bottom:20px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:14px; }
  header h1 { margin:0; font-size:1.45rem; }
  .meta { color:var(--muted); font-size:0.88rem; margin-top:4px; }
  .badge { padding:8px 14px; border-radius:20px; font-weight:700; font-size:0.85rem; }
  .badge-crit { background:rgba(248,81,73,.18); color:var(--crit); border:1px solid var(--crit); }
  .badge-warn { background:rgba(210,153,34,.18); color:var(--warn); border:1px solid var(--warn); }
  .badge-ok   { background:rgba(63,185,80,.18); color:var(--ok); border:1px solid var(--ok); }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:12px; margin-bottom:22px; }
  .stat { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:14px; }
  .stat label { display:block; font-size:0.75rem; text-transform:uppercase; color:var(--muted); letter-spacing:.04em; }
  .stat span { font-size:0.95rem; font-weight:600; word-break:break-word; }
  h2 { font-size:1.1rem; margin:24px 0 12px; border-bottom:1px solid var(--border); padding-bottom:6px; }
  .card { background:var(--panel); border:1px solid var(--border); border-left:4px solid var(--border); border-radius:8px; padding:14px 18px; margin-bottom:12px; }
  .card-crit { border-left-color:var(--crit); }
  .card-warn { border-left-color:var(--warn); }
  .card-info { border-left-color:var(--info); }
  .card-ok   { border-left-color:var(--ok); }
  .card-head { font-size:0.75rem; font-weight:700; margin-bottom:4px; display:flex; gap:10px; }
  .card-crit .sev { color:var(--crit); } .card-warn .sev { color:var(--warn); } .card-info .sev { color:var(--info); } .card-ok .sev { color:var(--ok); }
  .cat { color:var(--muted); text-transform:uppercase; }
  .card h3 { margin:2px 0 8px; font-size:1rem; }
  .card p { margin:4px 0; font-size:0.9rem; }
  .ev { color:#c9d1d9; } .rec { color:#a5d6ff; }
  table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--border); border-radius:8px; overflow:hidden; font-size:0.88rem; margin-bottom:16px; }
  th, td { text-align:left; padding:10px 12px; border-bottom:1px solid var(--border); }
  th { background:#1c2128; color:var(--muted); font-size:0.78rem; text-transform:uppercase; }
  .bar-bg { background:#21262d; border-radius:4px; height:10px; width:100%; min-width:100px; }
  .bar-fill { background:var(--info); height:100%; border-radius:4px; }
  details { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:12px 16px; margin-bottom:12px; }
  summary { cursor:pointer; font-weight:600; color:var(--text); }
  code { font-family:Consolas,monospace; font-size:0.82rem; color:#79c0ff; word-break:break-all; }
  footer { margin-top:26px; color:var(--muted); font-size:0.8rem; text-align:center; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>Win-DiagKit v$($Config.Version) &mdash; $(ConvertTo-HtmlSafe $Model.Hostname)</h1>
      <div class="meta">$(ConvertTo-HtmlSafe $Model.SourceMode) &bull; $adminBadge &bull; $(ConvertTo-HtmlSafe $Model.GeneratedAt)</div>
    </div>
    <div class="badge $healthClass">$healthLabel</div>
  </header>

  <div class="grid">
    <div class="stat"><label>Sistema Operativo</label><span>$(ConvertTo-HtmlSafe $Model.OsEdition)</span></div>
    <div class="stat"><label>Procesador</label><span>$(ConvertTo-HtmlSafe $Model.CpuName)</span></div>
    <div class="stat"><label>Grafica(s)</label><span>$(ConvertTo-HtmlSafe ($Model.Gpus -join ' | '))</span></div>
    <div class="stat"><label>Placa Base / Plan</label><span>$(ConvertTo-HtmlSafe $Model.Motherboard) ($(ConvertTo-HtmlSafe $Model.PowerPlan))</span></div>
    <div class="stat"><label>Memoria RAM</label><span>$ramStatStr (Libre: $freeStatStr)</span></div>
    <div class="stat"><label>Uptime Exacto</label><span>$upStatStr</span></div>
  </div>

  <h2>Hallazgos del Motor Heuristico</h2>
  $($cardsHtml.ToString())

  <h2>Top 10 Consumidores Reales de RAM (Procesos Agrupados)</h2>
  <table>
    <thead><tr><th>Aplicacion</th><th>Instancias</th><th>RAM Total</th><th>Uso Relativo</th></tr></thead>
    <tbody>$($procRows.ToString())</tbody>
  </table>

  <details open>
    <summary>Almacenamiento: Discos Fisicos (S.M.A.R.T.) y Volumenes</summary>
    <br>
    <table>
      <thead><tr><th>Modelo</th><th>Tipo / Bus</th><th>Capacidad</th><th>Salud</th><th>Temp</th><th>Desgaste</th><th>Errores R/W</th></tr></thead>
      <tbody>$($diskRows.ToString())</tbody>
    </table>
    <table>
      <thead><tr><th>Volumen</th><th>Tamano</th><th>Libre</th><th>% Libre</th><th>Salud</th></tr></thead>
      <tbody>$($volRows.ToString())</tbody>
    </table>
  </details>

  <details>
    <summary>Eventos Criticos Recientes (BSOD / Kernel-Power 41 / WHEA) ($($Model.CriticalEvents.Count))</summary>
    <br>
    <table>
      <thead><tr><th>Fecha</th><th>ID</th><th>Proveedor</th><th>Resumen</th></tr></thead>
      <tbody>$($evRows.ToString())</tbody>
    </table>
  </details>

  <details>
    <summary>Programas en el Arranque de Windows ($($Model.StartupTasks.Count))</summary>
    <br>
    <table>
      <thead><tr><th>Aplicacion</th><th>Ruta de ejecucion</th></tr></thead>
      <tbody>$($startRows.ToString())</tbody>
    </table>
  </details>

  <footer>$jsonFooter</footer>
</div>
</body>
</html>
"@

    $stamp      = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $safeHost   = ($Model.Hostname -replace '[^a-zA-Z0-9_-]', '')
    if ([string]::IsNullOrWhiteSpace($safeHost)) { $safeHost = "EQUIPO" }
    $outputPath = Join-Path $Config.DesktopDir "Diagnostico_PC_${safeHost}_${stamp}.html"

    $utf8NoBom  = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($outputPath, $html, $utf8NoBom)
    return $outputPath
}

# ==============================================================================
# CAPA 6: CASOS DE USO DEL MENU (Opciones 1 a 5)
# ==============================================================================
function Invoke-InstallKit {
    Write-Host "`n[+] Preparando directorio aislado fuera de OneDrive: $($Config.BinDir)" -ForegroundColor Cyan
    New-Item -ItemType Directory -Force -Path $Config.BinDir -ErrorAction Stop | Out-Null

    # 1. Specify (noring0)
    try {
        $rel = Invoke-RestMethod -Uri $Config.Urls.SpecifyApi -Headers $Config.Headers -ErrorAction Stop
        $asset = $rel.assets | Where-Object { $_.name -like "*noring0*.exe" } | Select-Object -First 1
        if (-not $asset) { $asset = $rel.assets | Where-Object { $_.name -like "*.exe" } | Select-Object -First 1 }
        if ($asset) {
            $specOut = Join-Path $Config.BinDir $asset.name
            if (Invoke-VerifiedDownload -Uri $asset.browser_download_url -OutFile $specOut -Label "Specify ($($asset.name))") {
                Get-ChildItem -Path $Config.BinDir -Filter "Specify*.exe" -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -ne $asset.name } |
                    Remove-Item -Force -ErrorAction SilentlyContinue
            }
        } else {
            Write-Host "    [ERROR] No se encontro ejecutable en el release de Specify." -ForegroundColor Red
        }
    } catch {
        Write-Host "    [ERROR] Fallo consultando GitHub API para Specify: $($_.Exception.Message)" -ForegroundColor Red
    }

    # 2. Sysinternals directos (con validacion de firma digital Microsoft)
    Invoke-VerifiedDownload -Uri $Config.Urls.ProcExp  -OutFile (Join-Path $Config.BinDir "procexp64.exe")  -Label "Process Explorer (x64)" -RequireMicrosoftSignature | Out-Null
    Invoke-VerifiedDownload -Uri $Config.Urls.Autoruns -OutFile (Join-Path $Config.BinDir "autoruns64.exe") -Label "Autoruns (x64)"         -RequireMicrosoftSignature | Out-Null

    Write-Host "`n[+] Despliegue finalizado en $($Config.BinDir)." -ForegroundColor Green
}

function Invoke-FullDiagnostic {
    $specExe = Get-ToolPath -Tool "Specify"
    if (-not $specExe) {
        Write-Host "`n[!] Specify no esta instalado en $($Config.BinDir)." -ForegroundColor Yellow
        $ans = Read-Host "Deseas instalar el kit ahora? (S/N)"
        if ($ans -match "^[sS]$") {
            Invoke-InstallKit
            $specExe = Get-ToolPath -Tool "Specify"
        }
    }
    if (-not $specExe) {
        Write-Host "[!] No se puede continuar sin Specify. Puedes usar la Opcion [4] (Auditoria Nativa)." -ForegroundColor Yellow
        return
    }

    Write-Host "`n[+] Iniciando $($specExe.Name)..." -ForegroundColor Cyan
    Write-Host "    1. Marca la casilla 'Don't Upload'." -ForegroundColor Yellow
    Write-Host "    2. Haz clic en 'Start' y espera a que finalice." -ForegroundColor Yellow
    Write-Host "    3. Cierra la ventana de Specify para generar el analisis automatico." -ForegroundColor Yellow

    $scanStart = Get-Date
    try {
        Start-Process -FilePath $specExe.FullName -WorkingDirectory $Config.BinDir -Wait -ErrorAction Stop
    }
    catch {
        Write-Host "`n[ERROR] No se pudo ejecutar Specify (UAC cancelado o bloqueado por seguridad): $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $jsonFile = Get-ChildItem -Path $Config.BinDir -Filter "*.json" -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $scanStart } |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if (-not $jsonFile) {
        Write-Host "`n[!] No se detecto un JSON nuevo (Specify se cerro antes de completar el escaneo)." -ForegroundColor Yellow
        return
    }

    Write-Host "`n[+] Cruzando datos de Specify con S.M.A.R.T. y eventos nativos..." -ForegroundColor Cyan
    $htmlPath = $null
    try {
        $rawJson    = Get-Content -Path $jsonFile.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        $nativeData = Get-NativeStorageAndEvents
        $model      = ConvertFrom-SpecifyToCanonical -SpecJson $rawJson -NativeExtra $nativeData -JsonPath $jsonFile.FullName
        $findings   = Invoke-HeuristicAnalysis -Model $model
        $topProcs   = Get-AggregatedTopProcesses -Processes $model.Processes -Top 10

        Show-ConsoleSummary -Model $model -Findings $findings -TopProcesses $topProcs
        $htmlPath = Export-HtmlReport -Model $model -Findings $findings -TopProcesses $topProcs
        Write-Host "[OK] Reporte visual generado en el Escritorio: $htmlPath" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] No se pudo procesar el reporte: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if ($htmlPath) {
        try { Start-Process -FilePath $htmlPath -ErrorAction Stop }
        catch { Write-Host "[!] Reporte guardado, pero no se pudo abrir el navegador automaticamente: $($_.Exception.Message)" -ForegroundColor Yellow }
    }
}

function Invoke-LiveInspection {
    Write-Host "`n--- INSPECCION EN VIVO (SYSINTERNALS) ---" -ForegroundColor Cyan
    Write-Host "  [A] Process Explorer (CPU, RAM, Red, Handles y VirusTotal)" -ForegroundColor White
    Write-Host "  [B] Autoruns (Auditoria profunda de arranque, servicios y tareas)" -ForegroundColor White
    Write-Host "  [0] Volver" -ForegroundColor DarkGray
    $sub = Read-Host "Elige una herramienta [A/B/0]"

    $toolName = $null; $url = $null; $file = $null
    switch ($sub.ToUpper()) {
        "A" { $toolName = "ProcExp";  $url = $Config.Urls.ProcExp;  $file = "procexp64.exe" }
        "B" { $toolName = "Autoruns"; $url = $Config.Urls.Autoruns; $file = "autoruns64.exe" }
        default { return }
    }

    $exe = Get-ToolPath -Tool $toolName
    if (-not $exe) {
        New-Item -ItemType Directory -Force -Path $Config.BinDir | Out-Null
        $out = Join-Path $Config.BinDir $file
        if (Invoke-VerifiedDownload -Uri $url -OutFile $out -Label $toolName -RequireMicrosoftSignature) {
            $exe = Get-Item $out
        }
    }

    if ($exe) {
        Write-Host "[+] Lanzando $($exe.Name)..." -ForegroundColor Green
        try {
            if (Test-IsAdmin) {
                Start-Process -FilePath $exe.FullName -ArgumentList "/accepteula" -ErrorAction Stop
            } else {
                Start-Process -FilePath $exe.FullName -ArgumentList "/accepteula" -Verb RunAs -ErrorAction Stop
            }
        }
        catch {
            Write-Host "[ERROR] No se pudo iniciar $($exe.Name): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

function Invoke-NativeOfflineAudit {
    Write-Host "`n[+] Ejecutando auditoria 100% nativa (sin descargas externas)..." -ForegroundColor Cyan
    $htmlPath = $null
    try {
        $nativeData = Get-NativeStorageAndEvents
        $model      = New-NativeOnlyCanonical -NativeExtra $nativeData
        $findings   = Invoke-HeuristicAnalysis -Model $model
        $topProcs   = Get-AggregatedTopProcesses -Processes $model.Processes -Top 10

        Show-ConsoleSummary -Model $model -Findings $findings -TopProcesses $topProcs
        $htmlPath = Export-HtmlReport -Model $model -Findings $findings -TopProcesses $topProcs
        Write-Host "[OK] Reporte visual generado en el Escritorio: $htmlPath" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Fallo en auditoria nativa: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if ($htmlPath) {
        try { Start-Process -FilePath $htmlPath -ErrorAction Stop }
        catch { Write-Host "[!] Reporte guardado, pero no se pudo abrir el navegador automaticamente: $($_.Exception.Message)" -ForegroundColor Yellow }
    }
}

function Invoke-ForensicCleanup {
    Write-Host "`n[!] Esta accion detendra las herramientas del kit y eliminara:" -ForegroundColor Yellow
    Write-Host "    - Carpeta $($Config.WorkDir)" -ForegroundColor Gray
    Write-Host "    - Reportes Diagnostico_PC_*.html en el Escritorio" -ForegroundColor Gray
    Write-Host "    - Claves de registro de Process Explorer y Autoruns" -ForegroundColor Gray
    $confirm = Read-Host "Confirmas que deseas realizar la limpieza integral? (S/N)"
    if ($confirm -notmatch "^[sS]$") {
        Write-Host "[i] Limpieza cancelada por el usuario." -ForegroundColor Cyan
        return
    }

    Write-Host "`n[+] Deteniendo herramientas activas del kit..." -ForegroundColor Cyan
    Get-Process -Name "Specify*", "procexp*", "autoruns*" -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 600

    # 1. Eliminar carpeta de trabajo C:\WinDiagKit
    if (Test-Path $Config.WorkDir) {
        try {
            Remove-Item -Path $Config.WorkDir -Recurse -Force -ErrorAction Stop
            Write-Host "    [OK] Eliminado: $($Config.WorkDir)" -ForegroundColor Green
        } catch {
            Write-Host "    [ERROR] No se pudo borrar $($Config.WorkDir): $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # 2. Limpiar reportes en Escritorio y carpeta legacy DiagKit si existiera
    $legacyDir = Join-Path $Config.DesktopDir "DiagKit"
    if (Test-Path $legacyDir) {
        Remove-Item -Path $legacyDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "    [OK] Eliminada carpeta previa: $legacyDir" -ForegroundColor Green
    }
    Get-ChildItem -Path $Config.DesktopDir -Filter "Diagnostico_PC_*.html" -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
        Write-Host "    [OK] Eliminado reporte: $($_.Name)" -ForegroundColor Green
    }

    # 3. Limpiar solo claves de registro creadas por Process Explorer y Autoruns
    $sysIntRoot = "HKCU:\Software\Sysinternals"
    foreach ($subName in @("Process Explorer", "Autoruns")) {
        $subKey = Join-Path $sysIntRoot $subName
        if (Test-Path $subKey) {
            Remove-Item -Path $subKey -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "    [OK] Limpiado registro: $subKey" -ForegroundColor Green
        }
    }
    if (Test-Path $sysIntRoot) {
        $remSub = @(Get-ChildItem -Path $sysIntRoot -ErrorAction SilentlyContinue)
        $remVal = (Get-Item -Path $sysIntRoot -ErrorAction SilentlyContinue).Property
        if ($remSub.Count -eq 0 -and (-not $remVal -or $remVal.Count -eq 0)) {
            Remove-Item -Path $sysIntRoot -Force -ErrorAction SilentlyContinue
            Write-Host "    [OK] Limpiada clave raiz vacia: $sysIntRoot" -ForegroundColor Green
        }
    }

    Write-Host "`n[+] Limpieza integral completada." -ForegroundColor Green
}

# ==============================================================================
# INTERFAZ DE MENU Y BUCLE PRINCIPAL
# ==============================================================================
function Show-MainMenu {
    Clear-Host
    $isAdmin  = Test-IsAdmin
    $specOk   = if (Get-ToolPath -Tool "Specify")  { "LISTO" } else { "NO INSTALADO" }
    $peOk     = if (Get-ToolPath -Tool "ProcExp")  { "LISTO" } else { "NO INSTALADO" }
    $arOk     = if (Get-ToolPath -Tool "Autoruns") { "LISTO" } else { "NO INSTALADO" }

    Write-Host "=============================================================" -ForegroundColor Cyan
    Write-Host "             WIN-DIAGKIT v$($Config.Version) - AUDITORIA PC             " -ForegroundColor White
    Write-Host "=============================================================" -ForegroundColor Cyan
    Write-Host "  Binarios         : $($Config.BinDir)" -ForegroundColor Gray
    Write-Host "  Reportes         : $($Config.DesktopDir)" -ForegroundColor Gray
    Write-Host "  Administrador    : $(if ($isAdmin) { 'SI (Acceso completo)' } else { 'NO (Modo limitado)' })" -ForegroundColor $(if ($isAdmin) { "Green" } else { "Yellow" })
    Write-Host "  Specify          : $specOk" -ForegroundColor $(if ($specOk -eq "LISTO") { "Green" } else { "DarkGray" })
    Write-Host "  Process Explorer : $peOk" -ForegroundColor $(if ($peOk -eq "LISTO") { "Green" } else { "DarkGray" })
    Write-Host "  Autoruns         : $arOk" -ForegroundColor $(if ($arOk -eq "LISTO") { "Green" } else { "DarkGray" })
    Write-Host "=============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Instalar / Actualizar kit portable (C:\WinDiagKit)" -ForegroundColor White
    Write-Host "  [2] Diagnostico completo (Specify + Motor Heuristico + HTML)" -ForegroundColor White
    Write-Host "  [3] Inspeccion en vivo (Process Explorer / Autoruns)" -ForegroundColor White
    Write-Host "  [4] Auditoria rapida nativa (Cero descargas + HTML)" -ForegroundColor White
    Write-Host "  [5] Limpieza integral (Borrar kit, reportes y registro)" -ForegroundColor White
    Write-Host "  [0] Salir" -ForegroundColor DarkGray
    Write-Host ""
}

# --- Punto de entrada ---
if ((Request-ElevationIfNeeded) -eq "ELEVATED") { return }

$running = $true
while ($running) {
    Show-MainMenu
    $choice = Read-Host "Selecciona una opcion [0-5]"

    switch ($choice) {
        "1" { Invoke-InstallKit;         Read-Host "`nPresiona Enter para volver al menu" }
        "2" { Invoke-FullDiagnostic;     Read-Host "`nPresiona Enter para volver al menu" }
        "3" { Invoke-LiveInspection;     Read-Host "`nPresiona Enter para volver al menu" }
        "4" { Invoke-NativeOfflineAudit; Read-Host "`nPresiona Enter para volver al menu" }
        "5" { Invoke-ForensicCleanup;    Read-Host "`nPresiona Enter para volver al menu" }
        "0" { $running = $false }
        default { Write-Host "`nOpcion invalida." -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }
}
}
