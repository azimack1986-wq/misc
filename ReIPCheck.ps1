<#
.SYNOPSIS
    Capture and compare server state around a re-IP change.

.DESCRIPTION
    Runs locally on Windows Server 2019/2022 (PowerShell 5.1 compatible, no external
    modules). Use Pre mode before changing the server's IP address, Post mode
    after the change, and Compare mode to diff the two captures and surface
    anything that regressed.

    Captured artefacts (one CSV per area) live in:
        <OutputPath>\<hostname>_<Mode>_<yyyyMMdd-HHmm>\

.PARAMETER Mode
    Pre, Post or Compare. Mandatory.

.PARAMETER OutputPath
    Root folder for capture sub-folders. Default: C:\Temp\ReIP.

.PARAMETER ReportPath
    Compare mode only. If supplied, the text report is also written to this file
    in addition to the colour-coded console output.

.PARAMETER PrePath
    Compare mode only. Override auto-detected Pre capture folder.

.PARAMETER PostPath
    Compare mode only. Override auto-detected Post capture folder.

.EXAMPLE
    .\ReIPCheck.ps1 -Mode Pre

.EXAMPLE
    .\ReIPCheck.ps1 -Mode Post

.EXAMPLE
    .\ReIPCheck.ps1 -Mode Compare -ReportPath C:\Temp\ReIP\report.txt
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Pre', 'Post', 'Compare')]
    [string]$Mode,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = 'C:\Temp\ReIP',

    [Parameter(Mandatory = $false)]
    [string]$ReportPath,

    [Parameter(Mandatory = $false)]
    [string]$PrePath,

    [Parameter(Mandatory = $false)]
    [string]$PostPath
)

#region Helpers -----------------------------------------------------------

$Script:ReportLines = New-Object System.Collections.Generic.List[string]

function Write-Section {
    param([string]$Title)
    $line = "=== $Title ==="
    Write-Host ''
    Write-Host $line -ForegroundColor White
    $Script:ReportLines.Add('')
    $Script:ReportLines.Add($line)
}

function Write-Line {
    param(
        [string]$Text,
        [string]$Color = 'Gray'
    )
    Write-Host $Text -ForegroundColor $Color
    $Script:ReportLines.Add($Text)
}

function Invoke-Capture {
    param(
        [string]$Name,
        [scriptblock]$Block
    )
    try {
        & $Block
        Write-Host ("  [{0}] captured." -f $Name) -ForegroundColor DarkGray
    }
    catch {
        Write-Warning ("  [{0}] capture failed: {1}" -f $Name, $_.Exception.Message)
    }
}

# Cache PID -> process name. Dead PIDs become <unknown>.
$Script:ProcessCache = @{}
function Get-ProcNameByPid {
    param([int]$ProcId)
    if ($null -eq $ProcId -or $ProcId -le 0) { return '<unknown>' }
    if ($Script:ProcessCache.ContainsKey($ProcId)) {
        return $Script:ProcessCache[$ProcId]
    }
    $name = '<unknown>'
    try {
        $p = Get-Process -Id $ProcId -ErrorAction Stop
        if ($p -and $p.ProcessName) { $name = $p.ProcessName }
    }
    catch {
        $name = '<unknown>'
    }
    $Script:ProcessCache[$ProcId] = $name
    return $name
}

function Get-LatestCaptureFolder {
    param(
        [string]$Root,
        [string]$HostName,
        [string]$Kind  # Pre or Post
    )
    if (-not (Test-Path $Root)) { return $null }
    $pattern = "{0}_{1}_*" -f $HostName, $Kind
    $candidates = Get-ChildItem -Path $Root -Directory -Filter $pattern -ErrorAction SilentlyContinue
    if (-not $candidates) { return $null }
    # Sort by the timestamp suffix yyyyMMdd-HHmm
    $sorted = $candidates | Sort-Object {
        $n = $_.Name
        $idx = $n.LastIndexOf('_')
        if ($idx -ge 0) { $n.Substring($idx + 1) } else { $n }
    }
    return $sorted[-1].FullName
}

#endregion ---------------------------------------------------------------

#region Capture (Pre / Post) ---------------------------------------------

function Invoke-Capture-Mode {
    param([string]$Mode, [string]$Root)

    $hostName = $env:COMPUTERNAME
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmm')
    $folderName = "{0}_{1}_{2}" -f $hostName, $Mode, $stamp
    $captureDir = Join-Path $Root $folderName

    if (-not (Test-Path $Root)) {
        New-Item -ItemType Directory -Path $Root -Force | Out-Null
    }
    New-Item -ItemType Directory -Path $captureDir -Force | Out-Null

    Write-Host ("Capturing {0} state to: {1}" -f $Mode, $captureDir) -ForegroundColor Cyan

    $counts = [ordered]@{
        Connections = 0
        Listeners   = 0
        Services    = 0
        Events      = 0
    }

    # --- connections.csv -------------------------------------------------
    Invoke-Capture -Name 'connections' -Block {
        $rows = @(Get-NetTCPConnection -State Established -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Process       = Get-ProcNameByPid $_.OwningProcess
                RemoteAddress = $_.RemoteAddress
                RemotePort    = $_.RemotePort
                LocalAddress  = $_.LocalAddress
                LocalPort     = $_.LocalPort
            }
        })
        $rows = $rows | Sort-Object Process, RemoteAddress, RemotePort
        $rows | Export-Csv -Path (Join-Path $captureDir 'connections.csv') -NoTypeInformation -Encoding UTF8
        $counts.Connections = $rows.Count
    }

    # --- listeners.csv ---------------------------------------------------
    Invoke-Capture -Name 'listeners' -Block {
        $rows = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Process      = Get-ProcNameByPid $_.OwningProcess
                LocalAddress = $_.LocalAddress
                LocalPort    = $_.LocalPort
            }
        })
        $rows = $rows | Sort-Object Process, LocalPort
        $rows | Export-Csv -Path (Join-Path $captureDir 'listeners.csv') -NoTypeInformation -Encoding UTF8
        $counts.Listeners = $rows.Count
    }

    # --- services.csv ----------------------------------------------------
    Invoke-Capture -Name 'services' -Block {
        $rows = @(Get-Service -ErrorAction Stop |
            Where-Object { $_.StartType -in 'Automatic', 'AutomaticDelayedStart' } |
            Select-Object Name, DisplayName, Status, StartType)
        $rows | Export-Csv -Path (Join-Path $captureDir 'services.csv') -NoTypeInformation -Encoding UTF8
        $counts.Services = ($rows | Where-Object { $_.Status -eq 'Running' }).Count
    }

    # --- ipconfig.csv ----------------------------------------------------
    Invoke-Capture -Name 'ipconfig' -Block {
        $rows = @(Get-NetIPAddress -ErrorAction Stop |
            Where-Object { $_.AddressFamily -eq 'IPv4' } |
            Select-Object InterfaceAlias, IPAddress, PrefixLength)
        $rows | Export-Csv -Path (Join-Path $captureDir 'ipconfig.csv') -NoTypeInformation -Encoding UTF8
    }

    # --- dns.csv ---------------------------------------------------------
    Invoke-Capture -Name 'dns' -Block {
        $rows = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                InterfaceAlias  = $_.InterfaceAlias
                ServerAddresses = ($_.ServerAddresses -join ',')
            }
        })
        $rows | Export-Csv -Path (Join-Path $captureDir 'dns.csv') -NoTypeInformation -Encoding UTF8
    }

    # --- events.csv ------------------------------------------------------
    Invoke-Capture -Name 'events' -Block {
        $since = (Get-Date).AddMinutes(-30)
        $filter = @{
            LogName   = 'Application', 'System'
            Level     = 1, 2, 3
            StartTime = $since
        }
        $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue)
        $rows = $events | ForEach-Object {
            $msg = $_.Message
            if ($null -ne $msg -and $msg.Length -gt 500) { $msg = $msg.Substring(0, 500) }
            [PSCustomObject]@{
                TimeCreated      = $_.TimeCreated
                LogName          = $_.LogName
                Id               = $_.Id
                LevelDisplayName = $_.LevelDisplayName
                ProviderName     = $_.ProviderName
                Message          = $msg
            }
        }
        $rows | Export-Csv -Path (Join-Path $captureDir 'events.csv') -NoTypeInformation -Encoding UTF8
        $counts.Events = @($rows).Count
    }

    # --- Summary ---------------------------------------------------------
    Write-Host ''
    Write-Host '=== CAPTURE SUMMARY ===' -ForegroundColor White
    Write-Host ("  Established connections : {0}" -f $counts.Connections) -ForegroundColor Gray
    Write-Host ("  Listening ports         : {0}" -f $counts.Listeners)   -ForegroundColor Gray
    Write-Host ("  Running auto services   : {0}" -f $counts.Services)    -ForegroundColor Gray
    Write-Host ("  Recent events (30m)     : {0}" -f $counts.Events)      -ForegroundColor Gray
    Write-Host ''
    Write-Host ("Capture folder: {0}" -f $captureDir) -ForegroundColor Cyan
}

#endregion ---------------------------------------------------------------

#region Compare ----------------------------------------------------------

function Import-CaptureCsv {
    param([string]$Folder, [string]$Name)
    $path = Join-Path $Folder $Name
    if (-not (Test-Path $path)) {
        Write-Warning ("Missing capture file: {0}" -f $path)
        return @()
    }
    try {
        return @(Import-Csv -Path $path)
    }
    catch {
        Write-Warning ("Failed to import {0}: {1}" -f $path, $_.Exception.Message)
        return @()
    }
}

function Invoke-Compare-Mode {
    param([string]$Root, [string]$PrePathOverride, [string]$PostPathOverride, [string]$ReportFile)

    $hostName = $env:COMPUTERNAME

    if ($PrePathOverride) { $preDir = $PrePathOverride }
    else { $preDir = Get-LatestCaptureFolder -Root $Root -HostName $hostName -Kind 'Pre' }

    if ($PostPathOverride) { $postDir = $PostPathOverride }
    else { $postDir = Get-LatestCaptureFolder -Root $Root -HostName $hostName -Kind 'Post' }

    if (-not $preDir -or -not (Test-Path $preDir)) {
        Write-Error ("Pre capture folder not found for host '{0}' under '{1}'." -f $hostName, $Root)
        return
    }
    if (-not $postDir -or -not (Test-Path $postDir)) {
        Write-Error ("Post capture folder not found for host '{0}' under '{1}'." -f $hostName, $Root)
        return
    }

    Write-Line ("Pre  capture: {0}" -f $preDir)  'Gray'
    Write-Line ("Post capture: {0}" -f $postDir) 'Gray'

    $reasons = New-Object System.Collections.Generic.List[string]

    # ----- Connection delta ---------------------------------------------
    Write-Section 'CONNECTION DELTA'
    $preConn  = Import-CaptureCsv -Folder $preDir  -Name 'connections.csv'
    $postConn = Import-CaptureCsv -Folder $postDir -Name 'connections.csv'

    $preKeys  = @($preConn  | ForEach-Object { "{0}|{1}|{2}" -f $_.Process, $_.RemoteAddress, $_.RemotePort })
    $postKeys = @($postConn | ForEach-Object { "{0}|{1}|{2}" -f $_.Process, $_.RemoteAddress, $_.RemotePort })

    $missing = @($preKeys  | Sort-Object -Unique | Where-Object { $postKeys -notcontains $_ })
    $newOnes = @($postKeys | Sort-Object -Unique | Where-Object { $preKeys  -notcontains $_ })

    if ($missing.Count -eq 0) {
        Write-Line 'No missing connections.' 'Green'
    }
    else {
        Write-Line ("Missing in Post ({0}):" -f $missing.Count) 'Yellow'
        $missing | ForEach-Object {
            $parts = $_ -split '\|', 3
            Write-Line ("  - {0,-25} -> {1}:{2}" -f $parts[0], $parts[1], $parts[2]) 'Yellow'
        }
        $reasons.Add(("{0} connection(s) missing in Post" -f $missing.Count))
    }

    if ($newOnes.Count -gt 0) {
        Write-Line ("New in Post ({0}):" -f $newOnes.Count) 'Cyan'
        $newOnes | ForEach-Object {
            $parts = $_ -split '\|', 3
            Write-Line ("  + {0,-25} -> {1}:{2}" -f $parts[0], $parts[1], $parts[2]) 'Cyan'
        }
    }

    # ----- Listener delta -----------------------------------------------
    Write-Section 'LISTENER DELTA'
    $preList  = Import-CaptureCsv -Folder $preDir  -Name 'listeners.csv'
    $postList = Import-CaptureCsv -Folder $postDir -Name 'listeners.csv'

    $preListKeys  = @($preList  | ForEach-Object { "{0}|{1}" -f $_.Process, $_.LocalPort })
    $postListKeys = @($postList | ForEach-Object { "{0}|{1}" -f $_.Process, $_.LocalPort })

    $missListen = @($preListKeys  | Sort-Object -Unique | Where-Object { $postListKeys -notcontains $_ })
    $newListen  = @($postListKeys | Sort-Object -Unique | Where-Object { $preListKeys  -notcontains $_ })

    if ($missListen.Count -eq 0) {
        Write-Line 'No missing listeners.' 'Green'
    }
    else {
        Write-Line ("Missing listeners ({0}):" -f $missListen.Count) 'Red'
        $missListen | ForEach-Object {
            $parts = $_ -split '\|', 2
            Write-Line ("  - {0,-25} :{1}" -f $parts[0], $parts[1]) 'Red'
        }
        $reasons.Add(("{0} listener(s) missing in Post" -f $missListen.Count))
    }

    if ($newListen.Count -gt 0) {
        Write-Line ("New listeners ({0}):" -f $newListen.Count) 'Cyan'
        $newListen | ForEach-Object {
            $parts = $_ -split '\|', 2
            Write-Line ("  + {0,-25} :{1}" -f $parts[0], $parts[1]) 'Cyan'
        }
    }

    # ----- Service delta -------------------------------------------------
    Write-Section 'SERVICE DELTA'
    $preSvc  = Import-CaptureCsv -Folder $preDir  -Name 'services.csv'
    $postSvc = Import-CaptureCsv -Folder $postDir -Name 'services.csv'

    $preSvcMap = @{}
    foreach ($s in $preSvc)  { $preSvcMap[$s.Name]  = $s.Status }
    $postSvcMap = @{}
    foreach ($s in $postSvc) { $postSvcMap[$s.Name] = $s.Status }

    $allNames = @($preSvcMap.Keys + $postSvcMap.Keys | Sort-Object -Unique)
    $regressed = New-Object System.Collections.Generic.List[string]
    $recovered = New-Object System.Collections.Generic.List[string]

    foreach ($n in $allNames) {
        $pre  = $preSvcMap[$n]
        $post = $postSvcMap[$n]
        if ($pre -eq 'Running' -and $post -ne 'Running') {
            $regressed.Add(("  - {0}: {1} -> {2}" -f $n, $pre, ($(if ($post) { $post } else { '<absent>' }))))
        }
        elseif ($pre -ne 'Running' -and $post -eq 'Running') {
            $recovered.Add(("  + {0}: {1} -> Running" -f $n, ($(if ($pre) { $pre } else { '<absent>' }))))
        }
    }

    if ($regressed.Count -eq 0) {
        Write-Line 'No service regressions.' 'Green'
    }
    else {
        Write-Line ("Stopped after re-IP ({0}):" -f $regressed.Count) 'Red'
        foreach ($l in $regressed) { Write-Line $l 'Red' }
        $reasons.Add(("{0} service(s) stopped after re-IP" -f $regressed.Count))
    }

    if ($recovered.Count -gt 0) {
        Write-Line ("Started after re-IP ({0}):" -f $recovered.Count) 'Yellow'
        foreach ($l in $recovered) { Write-Line $l 'Yellow' }
    }

    # ----- IP / DNS delta ------------------------------------------------
    Write-Section 'IP / DNS DELTA'
    $preIp   = Import-CaptureCsv -Folder $preDir  -Name 'ipconfig.csv'
    $postIp  = Import-CaptureCsv -Folder $postDir -Name 'ipconfig.csv'
    $preDns  = Import-CaptureCsv -Folder $preDir  -Name 'dns.csv'
    $postDns = Import-CaptureCsv -Folder $postDir -Name 'dns.csv'

    $ifaces = @(
        ($preIp   | ForEach-Object InterfaceAlias) +
        ($postIp  | ForEach-Object InterfaceAlias) +
        ($preDns  | ForEach-Object InterfaceAlias) +
        ($postDns | ForEach-Object InterfaceAlias)
    ) | Where-Object { $_ } | Sort-Object -Unique

    Write-Line ("{0,-30} {1,-22} {2,-22} {3,-22} {4,-22}" -f 'Interface', 'IP (Pre)', 'IP (Post)', 'DNS (Pre)', 'DNS (Post)') 'White'
    foreach ($if in $ifaces) {
        $ipPre   = ($preIp   | Where-Object InterfaceAlias -eq $if | ForEach-Object { "{0}/{1}" -f $_.IPAddress, $_.PrefixLength }) -join ','
        $ipPost  = ($postIp  | Where-Object InterfaceAlias -eq $if | ForEach-Object { "{0}/{1}" -f $_.IPAddress, $_.PrefixLength }) -join ','
        $dnsPre  = ($preDns  | Where-Object InterfaceAlias -eq $if | ForEach-Object ServerAddresses) -join ','
        $dnsPost = ($postDns | Where-Object InterfaceAlias -eq $if | ForEach-Object ServerAddresses) -join ','

        $color = 'Gray'
        if ($ipPre -ne $ipPost -or $dnsPre -ne $dnsPost) { $color = 'Yellow' }

        Write-Line ("{0,-30} {1,-22} {2,-22} {3,-22} {4,-22}" -f $if, $ipPre, $ipPost, $dnsPre, $dnsPost) $color
    }

    # ----- Event log delta ----------------------------------------------
    Write-Section 'EVENT LOG DELTA'
    $preEv  = Import-CaptureCsv -Folder $preDir  -Name 'events.csv'
    $postEv = Import-CaptureCsv -Folder $postDir -Name 'events.csv'

    $preEvKeys = @{}
    foreach ($e in $preEv) {
        $k = "{0}|{1}|{2}" -f $e.Id, $e.ProviderName, $e.Message
        $preEvKeys[$k] = $true
    }

    $newEvents = @($postEv | Where-Object {
        $k = "{0}|{1}|{2}" -f $_.Id, $_.ProviderName, $_.Message
        -not $preEvKeys.ContainsKey($k)
    })

    $newCritErr = @($newEvents | Where-Object { $_.LevelDisplayName -in 'Critical', 'Error' })

    if ($newEvents.Count -eq 0) {
        Write-Line 'No new events in Post.' 'Green'
    }
    else {
        $grouped = $newEvents |
            Group-Object ProviderName, Id |
            Sort-Object Count -Descending |
            Select-Object -First 10

        Write-Line ("New events in Post: {0} (top 10 groups)" -f $newEvents.Count) 'Yellow'
        Write-Line ("{0,-6} {1,-40} {2,-8} {3,-10}" -f 'Count', 'Provider', 'Id', 'Level') 'White'
        foreach ($g in $grouped) {
            $first = $g.Group[0]
            $color = switch ($first.LevelDisplayName) {
                'Critical' { 'Red' }
                'Error'    { 'Red' }
                'Warning'  { 'Yellow' }
                default    { 'Gray' }
            }
            Write-Line ("{0,-6} {1,-40} {2,-8} {3,-10}" -f $g.Count, $first.ProviderName, $first.Id, $first.LevelDisplayName) $color
        }
    }

    if ($newCritErr.Count -gt 0) {
        $reasons.Add(("{0} new Critical/Error event(s) in Post" -f $newCritErr.Count))
    }

    # ----- PASS / REVIEW -------------------------------------------------
    Write-Section 'RESULT'
    if ($reasons.Count -eq 0) {
        Write-Line 'PASS' 'Green'
    }
    else {
        Write-Line 'REVIEW' 'Red'
        foreach ($r in $reasons) {
            Write-Line ("  - {0}" -f $r) 'Red'
        }
    }

    if ($ReportFile) {
        try {
            $dir = Split-Path -Parent $ReportFile
            if ($dir -and -not (Test-Path $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }
            $Script:ReportLines | Out-File -FilePath $ReportFile -Encoding UTF8
            Write-Host ''
            Write-Host ("Report written to: {0}" -f $ReportFile) -ForegroundColor Cyan
        }
        catch {
            Write-Warning ("Failed to write report file '{0}': {1}" -f $ReportFile, $_.Exception.Message)
        }
    }
}

#endregion ---------------------------------------------------------------

#region Main -------------------------------------------------------------

switch ($Mode) {
    'Pre'     { Invoke-Capture-Mode -Mode 'Pre'  -Root $OutputPath }
    'Post'    { Invoke-Capture-Mode -Mode 'Post' -Root $OutputPath }
    'Compare' {
        Invoke-Compare-Mode -Root $OutputPath `
                            -PrePathOverride $PrePath `
                            -PostPathOverride $PostPath `
                            -ReportFile $ReportPath
    }
}

#endregion ---------------------------------------------------------------
