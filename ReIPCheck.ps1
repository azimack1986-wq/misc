<#
.SYNOPSIS
    Capture and compare server state around a re-IP change.

.DESCRIPTION
    Runs locally on Windows Server 2019/2022 (PowerShell 5.1 compatible, no external
    modules). Use Pre mode before changing the server's IP address, Post mode
    after the change, and Compare mode to diff the two captures and surface
    anything that regressed.

    Captured artefacts (one CSV per area) live in:
        <OutputPath>\<hostname>_<Mode>_<yyyyMMdd-HHmmss>\

    Post mode also writes oldip_refs.txt — a grep of well-known config locations
    for any IP that disappeared between Pre and Post (the killer feature for
    catching hardcoded references).

.PARAMETER Mode
    Pre, Post or Compare. Mandatory.

.PARAMETER OutputPath
    Root folder for capture sub-folders. Default: C:\Temp\ReIP.

.PARAMETER ReportPath
    Compare mode only. Tee the text report to this file in addition to console.

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

#region Constants --------------------------------------------------------

# Well-known port -> application label. Extend freely.
$Script:PortMap = @{
    20    = 'FTP-Data';     21    = 'FTP';           22    = 'SSH'
    23    = 'Telnet';       25    = 'SMTP';          53    = 'DNS'
    80    = 'HTTP';         88    = 'Kerberos';      110   = 'POP3'
    135   = 'RPC-EPM';      139   = 'NetBIOS-SSN';   143   = 'IMAP'
    389   = 'LDAP';         443   = 'HTTPS';         445   = 'SMB'
    465   = 'SMTPS';        514   = 'Syslog';        587   = 'SMTP-Submit'
    636   = 'LDAPS';        993   = 'IMAPS';         995   = 'POP3S'
    1433  = 'MSSQL';        1434  = 'MSSQL-Browser'; 1521  = 'Oracle'
    2049  = 'NFS';          3268  = 'GC-LDAP';       3269  = 'GC-LDAPS'
    3306  = 'MySQL';        3389  = 'RDP';           5432  = 'PostgreSQL'
    5722  = 'AD-DFSR';      5985  = 'WinRM-HTTP';    5986  = 'WinRM-HTTPS'
    8080  = 'HTTP-Alt';     8443  = 'HTTPS-Alt';     9389  = 'AD-WebSvc'
}

# Providers known to churn on every boot — suppressed from event delta
# unless we also see novel IDs from them.
$Script:NoiseProviders = @(
    'Microsoft-Windows-DNS-Client'
    'Microsoft-Windows-Time-Service'
    'Microsoft-Windows-GroupPolicy'
    'Microsoft-Windows-Kerberos-Key-Distribution-Center'
    'Microsoft-Windows-WLAN-AutoConfig'
)

# Canned guidance keyed by check name. Printed under RESULT when REVIEW.
$Script:Hints = @{
    'MissingConnection' = 'An outbound endpoint is no longer reachable. Likely cause: firewall on the *remote* side filters by source IP. Contact the team that owns the remote address.'
    'MissingListener'   = 'A service is no longer listening on an expected port. Check the app config for a bind-address / listen directive pinned to the old IP, or check that the service started cleanly.'
    'StoppedService'    = 'An auto-start service is no longer running. Try Start-Service; if it fails, look for an IP binding in the service config (SQL Configuration Manager TCP/IP, IIS site binding, vendor config files).'
    'StoppedSite'       = 'An IIS site is no longer Started. Most common cause: a binding pinned to the old IP. In IIS Manager, edit the site bindings and switch the IP to All Unassigned or the new IP.'
    'NewError'          = 'New Critical/Error events in the post-change window. Open events.csv and filter by ProviderName to read full messages.'
    'OldIpRef'          = 'The old IP is still referenced somewhere on this server. See oldip_refs.txt in the Post folder for exact locations — these are likely the source of any continuing issues.'
}

#endregion ---------------------------------------------------------------

#region Helpers ----------------------------------------------------------

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
    param([string]$Text, [string]$Color = 'Gray')
    Write-Host $Text -ForegroundColor $Color
    $Script:ReportLines.Add($Text)
}

function Invoke-Capture {
    param([string]$Name, [scriptblock]$Block)
    try {
        & $Block
        Write-Host ("  [{0}] captured." -f $Name) -ForegroundColor DarkGray
    }
    catch {
        Write-Warning ("  [{0}] capture failed: {1}" -f $Name, $_.Exception.Message)
    }
}

$Script:ProcessCache = @{}
function Get-ProcNameByPid {
    param([int]$ProcId)
    if ($null -eq $ProcId -or $ProcId -le 0) { return '<unknown>' }
    if ($Script:ProcessCache.ContainsKey($ProcId)) { return $Script:ProcessCache[$ProcId] }
    $name = '<unknown>'
    try {
        $p = Get-Process -Id $ProcId -ErrorAction Stop
        if ($p -and $p.ProcessName) { $name = $p.ProcessName }
    } catch { $name = '<unknown>' }
    $Script:ProcessCache[$ProcId] = $name
    return $name
}

function Get-AppType {
    param([int]$Port)
    if ($Script:PortMap.ContainsKey($Port)) { return $Script:PortMap[$Port] }
    if ($Port -ge 49152) { return 'Ephemeral' }
    return 'Other'
}

function Get-BindScope {
    param([string]$Address)
    if ($Address -eq '0.0.0.0' -or $Address -eq '::' -or $Address -eq '*') { return 'All' }
    return ("Specific:{0}" -f $Address)
}

function Get-LatestCaptureFolder {
    param([string]$Root, [string]$HostName, [string]$Kind)
    if (-not (Test-Path $Root)) { return $null }
    $pattern = "{0}_{1}_*" -f $HostName, $Kind
    $candidates = Get-ChildItem -Path $Root -Directory -Filter $pattern -ErrorAction SilentlyContinue
    if (-not $candidates) { return $null }
    $sorted = $candidates | Sort-Object {
        $n = $_.Name; $idx = $n.LastIndexOf('_')
        if ($idx -ge 0) { $n.Substring($idx + 1) } else { $n }
    }
    return $sorted[-1].FullName
}

function Import-CaptureCsv {
    param([string]$Folder, [string]$Name)
    $path = Join-Path $Folder $Name
    if (-not (Test-Path $path)) { return @() }
    try { return @(Import-Csv -Path $path) }
    catch {
        Write-Warning ("Failed to import {0}: {1}" -f $path, $_.Exception.Message)
        return @()
    }
}

# Grep well-known config locations for any of the supplied IPs.
# Returns an array of "<source>: <evidence>" strings.
function Find-OldIpRefs {
    param([string[]]$OldIps)
    $hits = New-Object System.Collections.Generic.List[string]
    if (-not $OldIps -or $OldIps.Count -eq 0) { return $hits.ToArray() }

    $escaped = $OldIps | ForEach-Object { [regex]::Escape($_) }
    $pattern = '(?<![\d.])(' + ($escaped -join '|') + ')(?![\d.])'

    # 1. hosts file
    $hostsFile = "$env:WinDir\System32\drivers\etc\hosts"
    if (Test-Path $hostsFile) {
        try {
            $i = 0
            Get-Content $hostsFile -ErrorAction Stop | ForEach-Object {
                $i++
                $line = $_
                if ($line -match '^\s*#') { return }
                if ($line -match $pattern) { $hits.Add("hosts:${i}: $($line.Trim())") }
            }
        } catch {}
    }

    # 2. IIS applicationHost.config
    $appHost = "$env:WinDir\System32\inetsrv\config\applicationHost.config"
    if (Test-Path $appHost) {
        try {
            $i = 0
            Get-Content $appHost -ErrorAction Stop | ForEach-Object {
                $i++
                if ($_ -match $pattern) { $hits.Add("applicationHost.config:${i}: $($_.Trim())") }
            }
        } catch {}
    }

    # 3. Scheduled task XMLs
    try {
        Get-ChildItem -Path "$env:WinDir\System32\Tasks" -Recurse -File -ErrorAction SilentlyContinue |
            ForEach-Object {
                $f = $_
                try {
                    $content = Get-Content $f.FullName -Raw -ErrorAction Stop
                    if ($content -match $pattern) {
                        $hits.Add("scheduledtask: $($f.FullName.Substring($env:WinDir.Length + 16))")
                    }
                } catch {}
            }
    } catch {}

    # 4. netsh portproxy
    try {
        $pp = & netsh interface portproxy show all 2>$null
        if ($pp) {
            $pp | Where-Object { $_ -match $pattern } | ForEach-Object {
                $hits.Add("portproxy: $($_.Trim())")
            }
        }
    } catch {}

    # 5. Static routes
    try {
        Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
            if ("$($_.NextHop) $($_.DestinationPrefix)" -match $pattern) {
                $hits.Add(("route: Dest={0} NextHop={1} If={2}" -f $_.DestinationPrefix, $_.NextHop, $_.InterfaceAlias))
            }
        }
    } catch {}

    # 6. Firewall rules (best effort — can be slow on heavily-policied boxes)
    try {
        Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue | ForEach-Object {
            $af = $_
            $la = ($af.LocalAddress  | ForEach-Object { "$_" }) -join ','
            $ra = ($af.RemoteAddress | ForEach-Object { "$_" }) -join ','
            if ("$la $ra" -match $pattern) {
                $ruleName = '<unresolved>'
                try { $ruleName = ($af | Get-NetFirewallRule -ErrorAction Stop).DisplayName } catch {}
                $hits.Add(("firewall: '{0}' Local={1} Remote={2}" -f $ruleName, $la, $ra))
            }
        }
    } catch {}

    return $hits.ToArray()
}

#endregion ---------------------------------------------------------------

#region Capture (Pre / Post) ---------------------------------------------

function Invoke-Capture-Mode {
    param([string]$Mode, [string]$Root)

    $hostName = $env:COMPUTERNAME
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $folderName = "{0}_{1}_{2}" -f $hostName, $Mode, $stamp
    $captureDir = Join-Path $Root $folderName

    if (-not (Test-Path $Root)) { New-Item -ItemType Directory -Path $Root -Force | Out-Null }
    New-Item -ItemType Directory -Path $captureDir -Force | Out-Null

    Write-Host ("Capturing {0} state to: {1}" -f $Mode, $captureDir) -ForegroundColor Cyan

    $counts = [ordered]@{
        Connections = 0
        Listeners   = 0
        Services    = 0
        Sites       = 0
        Events      = 0
        OldIpRefs   = 0
    }

    # --- connections.csv -------------------------------------------------
    Invoke-Capture -Name 'connections' -Block {
        $rows = @(Get-NetTCPConnection -State Established -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Process         = Get-ProcNameByPid $_.OwningProcess
                ApplicationType = Get-AppType ([int]$_.RemotePort)
                RemoteAddress   = $_.RemoteAddress
                RemotePort      = $_.RemotePort
                LocalAddress    = $_.LocalAddress
                LocalPort       = $_.LocalPort
            }
        })
        $rows = $rows | Sort-Object Process, RemoteAddress, RemotePort
        $rows | Export-Csv -Path (Join-Path $captureDir 'connections.csv') -NoTypeInformation -Encoding UTF8
        $counts.Connections = @($rows).Count
    }

    # --- listeners.csv ---------------------------------------------------
    Invoke-Capture -Name 'listeners' -Block {
        $rows = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Process         = Get-ProcNameByPid $_.OwningProcess
                ApplicationType = Get-AppType ([int]$_.LocalPort)
                LocalAddress    = $_.LocalAddress
                LocalPort       = $_.LocalPort
                BindScope       = Get-BindScope $_.LocalAddress
            }
        })
        $rows = $rows | Sort-Object Process, LocalPort
        $rows | Export-Csv -Path (Join-Path $captureDir 'listeners.csv') -NoTypeInformation -Encoding UTF8
        $counts.Listeners = @($rows).Count
    }

    # --- services.csv ----------------------------------------------------
    Invoke-Capture -Name 'services' -Block {
        $rows = @(Get-Service -ErrorAction Stop |
            Where-Object { $_.StartType -in 'Automatic', 'AutomaticDelayedStart' } |
            Select-Object Name, DisplayName, Status, StartType)
        $rows | Export-Csv -Path (Join-Path $captureDir 'services.csv') -NoTypeInformation -Encoding UTF8
        $counts.Services = @($rows | Where-Object { $_.Status -eq 'Running' }).Count
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

    # --- websites.csv (conditional — only if IIS present) ----------------
    Invoke-Capture -Name 'websites' -Block {
        $rows = @()
        if (Get-Module -ListAvailable -Name WebAdministration) {
            Import-Module WebAdministration -ErrorAction Stop
            $rows = @(Get-Website | ForEach-Object {
                $site = $_
                $bindings = @($site.Bindings.Collection) | ForEach-Object {
                    "{0}|{1}" -f $_.protocol, $_.bindingInformation
                }
                [PSCustomObject]@{
                    Name         = $site.Name
                    State        = $site.State
                    AppPool      = $site.applicationPool
                    PhysicalPath = $site.PhysicalPath
                    Bindings     = ($bindings -join ';')
                }
            })
        }
        $rows | Export-Csv -Path (Join-Path $captureDir 'websites.csv') -NoTypeInformation -Encoding UTF8
        $counts.Sites = @($rows).Count
    }

    # --- events.csv (Post mode filters to post-boot only) ----------------
    Invoke-Capture -Name 'events' -Block {
        $since = (Get-Date).AddMinutes(-30)
        if ($Mode -eq 'Post') {
            try {
                $boot = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
                if ($boot -and $boot -gt $since) { $since = $boot }
            } catch {}
        }
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

    # --- oldip_refs.txt (Post mode only) ---------------------------------
    if ($Mode -eq 'Post') {
        Invoke-Capture -Name 'oldip_refs' -Block {
            $latestPre = Get-LatestCaptureFolder -Root $Root -HostName $hostName -Kind 'Pre'
            if (-not $latestPre) {
                Write-Warning '  [oldip_refs] no Pre capture found; skipping.'
                return
            }
            $preIps  = @(Import-CaptureCsv -Folder $latestPre   -Name 'ipconfig.csv' | ForEach-Object IPAddress)
            $postIps = @(Import-CaptureCsv -Folder $captureDir  -Name 'ipconfig.csv' | ForEach-Object IPAddress)
            $oldIps = @($preIps | Where-Object { $postIps -notcontains $_ -and $_ -notmatch '^169\.254\.' -and $_ -ne '127.0.0.1' })

            $outFile = Join-Path $captureDir 'oldip_refs.txt'
            $header = @(
                "Old IP reference scan on $hostName at $(Get-Date)"
                ("Old IPs scanned: " + ($(if ($oldIps) { $oldIps -join ', ' } else { '<none>' })))
                ''
            )
            if (-not $oldIps) {
                ($header + 'No IPs removed between Pre and Post — nothing to scan.') |
                    Out-File -FilePath $outFile -Encoding UTF8
                return
            }
            $refs = Find-OldIpRefs -OldIps $oldIps
            $body = if ($refs.Count -gt 0) { $refs } else { @('No references found in scanned locations.') }
            ($header + $body) | Out-File -FilePath $outFile -Encoding UTF8
            $counts.OldIpRefs = $refs.Count
        }
    }

    # --- Summary ---------------------------------------------------------
    Write-Host ''
    Write-Host '=== CAPTURE SUMMARY ===' -ForegroundColor White
    Write-Host ("  Established connections : {0}" -f $counts.Connections) -ForegroundColor Gray
    Write-Host ("  Listening ports         : {0}" -f $counts.Listeners)   -ForegroundColor Gray
    Write-Host ("  Running auto services   : {0}" -f $counts.Services)    -ForegroundColor Gray
    if ($counts.Sites -gt 0) {
        Write-Host ("  IIS sites               : {0}" -f $counts.Sites)   -ForegroundColor Gray
    }
    Write-Host ("  Recent events in window : {0}" -f $counts.Events)      -ForegroundColor Gray
    if ($Mode -eq 'Post') {
        $color = if ($counts.OldIpRefs -gt 0) { 'Red' } else { 'Green' }
        Write-Host ("  Old-IP references found : {0}" -f $counts.OldIpRefs) -ForegroundColor $color
    }
    Write-Host ''
    Write-Host ("Capture folder: {0}" -f $captureDir) -ForegroundColor Cyan
}

#endregion ---------------------------------------------------------------

#region Compare ----------------------------------------------------------

function Invoke-Compare-Mode {
    param([string]$Root, [string]$PrePathOverride, [string]$PostPathOverride, [string]$ReportFile)

    $hostName = $env:COMPUTERNAME

    $preDir  = if ($PrePathOverride)  { $PrePathOverride }  else { Get-LatestCaptureFolder -Root $Root -HostName $hostName -Kind 'Pre' }
    $postDir = if ($PostPathOverride) { $PostPathOverride } else { Get-LatestCaptureFolder -Root $Root -HostName $hostName -Kind 'Post' }

    if (-not $preDir  -or -not (Test-Path $preDir))  { Write-Error ("Pre capture not found for '{0}' under '{1}'."  -f $hostName, $Root); return }
    if (-not $postDir -or -not (Test-Path $postDir)) { Write-Error ("Post capture not found for '{0}' under '{1}'." -f $hostName, $Root); return }

    # Parse timestamps from folder names for the window display
    $preStamp  = Split-Path $preDir  -Leaf
    $postStamp = Split-Path $postDir -Leaf
    $preTime   = ($preStamp  -split '_')[-1]
    $postTime  = ($postStamp -split '_')[-1]

    # Load all CSVs upfront
    $preConn  = Import-CaptureCsv -Folder $preDir  -Name 'connections.csv'
    $postConn = Import-CaptureCsv -Folder $postDir -Name 'connections.csv'
    $preList  = Import-CaptureCsv -Folder $preDir  -Name 'listeners.csv'
    $postList = Import-CaptureCsv -Folder $postDir -Name 'listeners.csv'
    $preSvc   = Import-CaptureCsv -Folder $preDir  -Name 'services.csv'
    $postSvc  = Import-CaptureCsv -Folder $postDir -Name 'services.csv'
    $preIp    = Import-CaptureCsv -Folder $preDir  -Name 'ipconfig.csv'
    $postIp   = Import-CaptureCsv -Folder $postDir -Name 'ipconfig.csv'
    $preDns   = Import-CaptureCsv -Folder $preDir  -Name 'dns.csv'
    $postDns  = Import-CaptureCsv -Folder $postDir -Name 'dns.csv'
    $preSite  = Import-CaptureCsv -Folder $preDir  -Name 'websites.csv'
    $postSite = Import-CaptureCsv -Folder $postDir -Name 'websites.csv'
    $preEv    = Import-CaptureCsv -Folder $preDir  -Name 'events.csv'
    $postEv   = Import-CaptureCsv -Folder $postDir -Name 'events.csv'

    # Detect old/new IPs by diffing ipconfig
    $preIps  = @($preIp  | ForEach-Object IPAddress)
    $postIps = @($postIp | ForEach-Object IPAddress)
    $oldIps  = @($preIps  | Where-Object { $postIps -notcontains $_ -and $_ -notmatch '^169\.254\.' -and $_ -ne '127.0.0.1' })
    $newIps  = @($postIps | Where-Object { $preIps  -notcontains $_ -and $_ -notmatch '^169\.254\.' -and $_ -ne '127.0.0.1' })

    # Addresses to ignore in connection delta (loopback + self, both Pre and Post)
    $selfIps = @('127.0.0.1', '::1') + $preIps + $postIps | Sort-Object -Unique

    $reasons = New-Object System.Collections.Generic.List[string]
    $hintsToShow = New-Object System.Collections.Generic.HashSet[string]

    # ----- Connection delta ---------------------------------------------
    $preConnFilt  = @($preConn  | Where-Object { $selfIps -notcontains $_.RemoteAddress })
    $postConnFilt = @($postConn | Where-Object { $selfIps -notcontains $_.RemoteAddress })
    $preKeys      = @($preConnFilt  | ForEach-Object { "{0}|{1}|{2}" -f $_.Process, $_.RemoteAddress, $_.RemotePort } | Sort-Object -Unique)
    $postKeys     = @($postConnFilt | ForEach-Object { "{0}|{1}|{2}" -f $_.Process, $_.RemoteAddress, $_.RemotePort } | Sort-Object -Unique)
    $missingConn  = @($preKeys  | Where-Object { $postKeys -notcontains $_ })
    $newConn      = @($postKeys | Where-Object { $preKeys  -notcontains $_ })

    # ----- Listener delta ------------------------------------------------
    $preLKeys    = @($preList  | ForEach-Object { "{0}|{1}" -f $_.Process, $_.LocalPort } | Sort-Object -Unique)
    $postLKeys   = @($postList | ForEach-Object { "{0}|{1}" -f $_.Process, $_.LocalPort } | Sort-Object -Unique)
    $missListen  = @($preLKeys  | Where-Object { $postLKeys -notcontains $_ })
    $newListen   = @($postLKeys | Where-Object { $preLKeys  -notcontains $_ })

    # ----- Service delta -------------------------------------------------
    $preSvcMap = @{}; foreach ($s in $preSvc)  { $preSvcMap[$s.Name]  = $s.Status }
    $postSvcMap = @{}; foreach ($s in $postSvc) { $postSvcMap[$s.Name] = $s.Status }
    $allSvcNames = @(@($preSvcMap.Keys) + @($postSvcMap.Keys)) | Sort-Object -Unique
    $svcRegressed = New-Object System.Collections.Generic.List[object]
    $svcRecovered = New-Object System.Collections.Generic.List[object]
    foreach ($n in $allSvcNames) {
        $pre  = $preSvcMap[$n]
        $post = $postSvcMap[$n]
        if ($pre -eq 'Running' -and $post -ne 'Running') {
            $svcRegressed.Add([PSCustomObject]@{ Name = $n; Pre = $pre; Post = ($(if ($post) { $post } else { '<absent>' })) })
        } elseif ($pre -ne 'Running' -and $post -eq 'Running') {
            $svcRecovered.Add([PSCustomObject]@{ Name = $n; Pre = ($(if ($pre) { $pre } else { '<absent>' })); Post = 'Running' })
        }
    }

    # ----- Website delta -------------------------------------------------
    $preSiteMap  = @{}; foreach ($s in $preSite)  { $preSiteMap[$s.Name]  = $s }
    $postSiteMap = @{}; foreach ($s in $postSite) { $postSiteMap[$s.Name] = $s }
    $allSiteNames = @(@($preSiteMap.Keys) + @($postSiteMap.Keys)) | Sort-Object -Unique
    $siteRegressed   = New-Object System.Collections.Generic.List[object]
    $siteBindingChg  = New-Object System.Collections.Generic.List[object]
    foreach ($n in $allSiteNames) {
        $a = $preSiteMap[$n]; $b = $postSiteMap[$n]
        if ($a -and $b) {
            if ($a.State -eq 'Started' -and $b.State -ne 'Started') {
                $siteRegressed.Add([PSCustomObject]@{ Name = $n; Pre = $a.State; Post = $b.State })
            }
            if ($a.Bindings -ne $b.Bindings) {
                $siteBindingChg.Add([PSCustomObject]@{ Name = $n; Pre = $a.Bindings; Post = $b.Bindings })
            }
        }
    }

    # ----- Event delta (key = Id|Provider; track count) ------------------
    function Get-EventKeyCounts {
        param($Events)
        $map = @{}
        foreach ($e in $Events) {
            $k = "{0}|{1}" -f $e.Id, $e.ProviderName
            if ($map.ContainsKey($k)) { $map[$k].Count++ }
            else { $map[$k] = [PSCustomObject]@{ Id = $e.Id; Provider = $e.ProviderName; Level = $e.LevelDisplayName; Count = 1 } }
        }
        return $map
    }
    $preEvMap  = Get-EventKeyCounts $preEv
    $postEvMap = Get-EventKeyCounts $postEv
    $novelEvents     = New-Object System.Collections.Generic.List[object]
    $escalatedEvents = New-Object System.Collections.Generic.List[object]
    foreach ($k in $postEvMap.Keys) {
        $p = $postEvMap[$k]
        if (-not $preEvMap.ContainsKey($k)) {
            if ($Script:NoiseProviders -notcontains $p.Provider) {
                $novelEvents.Add($p)
            }
        } else {
            $preCount = $preEvMap[$k].Count
            if ($p.Count -ge ($preCount * 3) -and $p.Count -ge 5) {
                $escalatedEvents.Add([PSCustomObject]@{
                    Id = $p.Id; Provider = $p.Provider; Level = $p.Level
                    PreCount = $preCount; PostCount = $p.Count
                })
            }
        }
    }
    $newCritErr = @($novelEvents | Where-Object { $_.Level -in 'Critical', 'Error' })

    # ----- Old IP refs (from Post folder) --------------------------------
    $oldIpRefsFile = Join-Path $postDir 'oldip_refs.txt'
    $oldIpRefs = @()
    if (Test-Path $oldIpRefsFile) {
        $oldIpRefs = @(Get-Content $oldIpRefsFile | Where-Object {
            $_ -and $_ -notmatch '^Old IP' -and $_ -notmatch '^No ' -and $_ -notmatch '^\s*$'
        })
    }

    # ----- Build reason list --------------------------------------------
    if ($missingConn.Count -gt 0) { $reasons.Add(("{0} connection(s) missing in Post" -f $missingConn.Count)); $hintsToShow.Add('MissingConnection') | Out-Null }
    if ($missListen.Count  -gt 0) { $reasons.Add(("{0} listener(s) missing in Post"   -f $missListen.Count));  $hintsToShow.Add('MissingListener')   | Out-Null }
    if ($svcRegressed.Count -gt 0) { $reasons.Add(("{0} service(s) stopped after re-IP" -f $svcRegressed.Count)); $hintsToShow.Add('StoppedService') | Out-Null }
    if ($siteRegressed.Count -gt 0) { $reasons.Add(("{0} IIS site(s) not Started"        -f $siteRegressed.Count)); $hintsToShow.Add('StoppedSite')    | Out-Null }
    if ($newCritErr.Count -gt 0) { $reasons.Add(("{0} new Critical/Error event type(s)" -f $newCritErr.Count)); $hintsToShow.Add('NewError')        | Out-Null }
    if ($oldIpRefs.Count -gt 0) { $reasons.Add(("{0} old-IP reference(s) on box"        -f $oldIpRefs.Count));  $hintsToShow.Add('OldIpRef')        | Out-Null }

    $result = if ($reasons.Count -eq 0) { 'PASS' } else { 'REVIEW' }

    # ====================================================================
    # OUTPUT
    # ====================================================================

    Write-Section 'SUMMARY'
    $ipDelta = if ($oldIps -or $newIps) {
        "{0} -> {1}" -f ($(if ($oldIps) { $oldIps -join ',' } else { '<none>' })), ($(if ($newIps) { $newIps -join ',' } else { '<none>' }))
    } else { '<no IP change detected>' }
    Write-Line ("{0}: {1}" -f $hostName, $ipDelta) 'White'
    Write-Line ("Pre {0}  ->  Post {1}" -f $preTime, $postTime) 'Gray'
    Write-Line ''

    function Format-Delta { param($PreCount, $PostCount, $Bad)
        $arrow = if ($PreCount -eq $PostCount) { '=' } else { '->' }
        $line  = "{0,4} {1} {2,-4}" -f $PreCount, $arrow, $PostCount
        if ($Bad) { return ,$line, 'Red' }
        return ,$line, 'Gray'
    }

    $svcPreRunning  = @($preSvc  | Where-Object { $_.Status -eq 'Running' }).Count
    $svcPostRunning = @($postSvc | Where-Object { $_.Status -eq 'Running' }).Count

    Write-Line ("  Connections : {0,4} -> {1,-4}    ({2} missing, {3} new)" -f $preKeys.Count,  $postKeys.Count,  $missingConn.Count, $newConn.Count)   ($(if ($missingConn.Count -gt 0) { 'Red' } else { 'Green' }))
    Write-Line ("  Listeners   : {0,4} -> {1,-4}    ({2} missing, {3} new)" -f $preLKeys.Count, $postLKeys.Count, $missListen.Count,  $newListen.Count) ($(if ($missListen.Count  -gt 0) { 'Red' } else { 'Green' }))
    Write-Line ("  Services    : {0,4} -> {1,-4}    ({2} regressed, {3} recovered)" -f $svcPreRunning, $svcPostRunning, $svcRegressed.Count, $svcRecovered.Count) ($(if ($svcRegressed.Count -gt 0) { 'Red' } else { 'Green' }))
    if (@($preSite).Count -gt 0 -or @($postSite).Count -gt 0) {
        Write-Line ("  IIS sites   : {0,4} -> {1,-4}    ({2} stopped, {3} binding-changed)" -f @($preSite).Count, @($postSite).Count, $siteRegressed.Count, $siteBindingChg.Count) ($(if ($siteRegressed.Count -gt 0) { 'Red' } else { 'Green' }))
    }
    Write-Line ("  Events      : {0,4} -> {1,-4}    ({2} novel types, {3} Error/Critical)" -f @($preEv).Count, @($postEv).Count, $novelEvents.Count, $newCritErr.Count) ($(if ($newCritErr.Count -gt 0) { 'Red' } else { 'Green' }))
    Write-Line ("  Old IP refs : {0,4}                  (see oldip_refs.txt)" -f $oldIpRefs.Count) ($(if ($oldIpRefs.Count -gt 0) { 'Red' } else { 'Green' }))
    Write-Line ''
    Write-Line ("RESULT: {0}" -f $result) ($(if ($result -eq 'PASS') { 'Green' } else { 'Red' }))
    if ($reasons.Count -gt 0) {
        foreach ($r in $reasons) { Write-Line ("  - {0}" -f $r) 'Red' }
    }

    # ----- Sections (drill-down) ----------------------------------------

    Write-Section 'CONNECTION DELTA'
    if ($missingConn.Count -eq 0) {
        Write-Line 'No missing connections.' 'Green'
    } else {
        Write-Line ("Missing in Post ({0}):" -f $missingConn.Count) 'Yellow'
        $missingConn | Select-Object -First 25 | ForEach-Object {
            $p = $_ -split '\|', 3
            $app = Get-AppType ([int]$p[2])
            Write-Line ("  - {0,-22} -> {1}:{2} ({3})" -f $p[0], $p[1], $p[2], $app) 'Yellow'
        }
        if ($missingConn.Count -gt 25) { Write-Line ("  ... and {0} more (see connections.csv)" -f ($missingConn.Count - 25)) 'DarkGray' }
    }
    if ($newConn.Count -gt 0) {
        Write-Line ("New in Post ({0}):" -f $newConn.Count) 'Cyan'
        $newConn | Select-Object -First 10 | ForEach-Object {
            $p = $_ -split '\|', 3
            $app = Get-AppType ([int]$p[2])
            Write-Line ("  + {0,-22} -> {1}:{2} ({3})" -f $p[0], $p[1], $p[2], $app) 'Cyan'
        }
        if ($newConn.Count -gt 10) { Write-Line ("  ... and {0} more" -f ($newConn.Count - 10)) 'DarkGray' }
    }

    Write-Section 'LISTENER DELTA'
    if ($missListen.Count -eq 0) {
        Write-Line 'No missing listeners.' 'Green'
    } else {
        Write-Line ("Missing listeners ({0}):" -f $missListen.Count) 'Red'
        foreach ($k in $missListen) {
            $p = $k -split '\|', 2
            $app = Get-AppType ([int]$p[1])
            Write-Line ("  - {0,-22} :{1} ({2})" -f $p[0], $p[1], $app) 'Red'
        }
    }
    if ($newListen.Count -gt 0) {
        Write-Line ("New listeners ({0}):" -f $newListen.Count) 'Cyan'
        foreach ($k in $newListen) {
            $p = $k -split '\|', 2
            $app = Get-AppType ([int]$p[1])
            Write-Line ("  + {0,-22} :{1} ({2})" -f $p[0], $p[1], $app) 'Cyan'
        }
    }
    # Flag listeners bound to old IP
    $stuckListeners = @($postList | Where-Object { $oldIps -contains $_.LocalAddress })
    if ($stuckListeners.Count -gt 0) {
        Write-Line ''
        Write-Line ("WARNING: {0} listener(s) still bound to the OLD IP:" -f $stuckListeners.Count) 'Red'
        foreach ($l in $stuckListeners) {
            Write-Line ("  ! {0} bound to {1}:{2}" -f $l.Process, $l.LocalAddress, $l.LocalPort) 'Red'
        }
        $reasons.Add(("{0} listener(s) still bound to old IP" -f $stuckListeners.Count))
    }

    Write-Section 'SERVICE DELTA'
    if ($svcRegressed.Count -eq 0) {
        Write-Line 'No service regressions.' 'Green'
    } else {
        Write-Line ("Stopped after re-IP ({0}):" -f $svcRegressed.Count) 'Red'
        foreach ($s in $svcRegressed) { Write-Line ("  - {0}: {1} -> {2}" -f $s.Name, $s.Pre, $s.Post) 'Red' }
    }
    if ($svcRecovered.Count -gt 0) {
        Write-Line ("Started after re-IP ({0}):" -f $svcRecovered.Count) 'Yellow'
        foreach ($s in $svcRecovered) { Write-Line ("  + {0}: {1} -> {2}" -f $s.Name, $s.Pre, $s.Post) 'Yellow' }
    }

    Write-Section 'IP / DNS DELTA'
    $ifaces = @(
        ($preIp   | ForEach-Object InterfaceAlias) + ($postIp  | ForEach-Object InterfaceAlias) +
        ($preDns  | ForEach-Object InterfaceAlias) + ($postDns | ForEach-Object InterfaceAlias)
    ) | Where-Object { $_ } | Sort-Object -Unique
    Write-Line ("{0,-28} {1,-20} {2,-20} {3,-22} {4,-22}" -f 'Interface', 'IP (Pre)', 'IP (Post)', 'DNS (Pre)', 'DNS (Post)') 'White'
    foreach ($if in $ifaces) {
        $ipPreV   = ($preIp   | Where-Object InterfaceAlias -eq $if | ForEach-Object { "{0}/{1}" -f $_.IPAddress, $_.PrefixLength }) -join ','
        $ipPostV  = ($postIp  | Where-Object InterfaceAlias -eq $if | ForEach-Object { "{0}/{1}" -f $_.IPAddress, $_.PrefixLength }) -join ','
        $dnsPreV  = ($preDns  | Where-Object InterfaceAlias -eq $if | ForEach-Object ServerAddresses) -join ','
        $dnsPostV = ($postDns | Where-Object InterfaceAlias -eq $if | ForEach-Object ServerAddresses) -join ','
        $color = if ($ipPreV -ne $ipPostV -or $dnsPreV -ne $dnsPostV) { 'Yellow' } else { 'Gray' }
        Write-Line ("{0,-28} {1,-20} {2,-20} {3,-22} {4,-22}" -f $if, $ipPreV, $ipPostV, $dnsPreV, $dnsPostV) $color
    }

    if (@($preSite).Count -gt 0 -or @($postSite).Count -gt 0) {
        Write-Section 'WEBSITES DELTA'
        if ($siteRegressed.Count -eq 0 -and $siteBindingChg.Count -eq 0) {
            Write-Line 'No IIS site regressions or binding changes.' 'Green'
        }
        foreach ($s in $siteRegressed) {
            Write-Line ("  - Site '{0}': {1} -> {2}" -f $s.Name, $s.Pre, $s.Post) 'Red'
        }
        foreach ($s in $siteBindingChg) {
            Write-Line ("  ~ Site '{0}' bindings changed:" -f $s.Name) 'Yellow'
            Write-Line ("      Pre : {0}" -f $s.Pre)  'DarkGray'
            Write-Line ("      Post: {0}" -f $s.Post) 'DarkGray'
        }
        # Flag IIS bindings still referencing the old IP literally
        $stuckBindings = @($postSite | Where-Object {
            $b = $_.Bindings
            ($oldIps | ForEach-Object { if ($b -match [regex]::Escape($_)) { $true } }) -contains $true
        })
        if ($stuckBindings.Count -gt 0) {
            Write-Line ''
            Write-Line ("WARNING: {0} IIS site(s) have bindings referencing the OLD IP:" -f $stuckBindings.Count) 'Red'
            foreach ($s in $stuckBindings) { Write-Line ("  ! {0}: {1}" -f $s.Name, $s.Bindings) 'Red' }
            $reasons.Add(("{0} IIS site binding(s) still reference old IP" -f $stuckBindings.Count))
            $hintsToShow.Add('StoppedSite') | Out-Null
        }
    }

    Write-Section 'EVENT LOG DELTA'
    if ($novelEvents.Count -eq 0 -and $escalatedEvents.Count -eq 0) {
        Write-Line 'No novel event types or count escalations in Post.' 'Green'
    } else {
        if ($novelEvents.Count -gt 0) {
            $top = $novelEvents | Sort-Object Count -Descending | Select-Object -First 10
            Write-Line ("Novel event types in Post ({0}, top 10):" -f $novelEvents.Count) 'Yellow'
            Write-Line ("{0,-6} {1,-42} {2,-8} {3,-10}" -f 'Count', 'Provider', 'Id', 'Level') 'White'
            foreach ($g in $top) {
                $color = switch ($g.Level) { 'Critical' { 'Red' } 'Error' { 'Red' } 'Warning' { 'Yellow' } default { 'Gray' } }
                Write-Line ("{0,-6} {1,-42} {2,-8} {3,-10}" -f $g.Count, $g.Provider, $g.Id, $g.Level) $color
            }
        }
        if ($escalatedEvents.Count -gt 0) {
            Write-Line ("Escalated event types (>=3x and >=5 in Post):") 'Yellow'
            foreach ($g in $escalatedEvents) {
                Write-Line ("  {0,-42} Id={1,-6} {2}: {3} -> {4}" -f $g.Provider, $g.Id, $g.Level, $g.PreCount, $g.PostCount) 'Yellow'
            }
        }
    }

    Write-Section 'OLD IP REFERENCES'
    if ($oldIpRefs.Count -eq 0) {
        Write-Line 'No old-IP references found (or scan not run).' 'Green'
    } else {
        Write-Line ("Found {0} reference(s) to old IP on this box:" -f $oldIpRefs.Count) 'Red'
        $oldIpRefs | Select-Object -First 25 | ForEach-Object { Write-Line ("  ! {0}" -f $_) 'Red' }
        if ($oldIpRefs.Count -gt 25) { Write-Line ("  ... and {0} more (see oldip_refs.txt in Post folder)" -f ($oldIpRefs.Count - 25)) 'DarkGray' }
    }

    # ----- Final RESULT with hints --------------------------------------
    Write-Section 'RESULT'
    if ($reasons.Count -eq 0) {
        Write-Line 'PASS' 'Green'
    } else {
        Write-Line 'REVIEW' 'Red'
        foreach ($r in $reasons) { Write-Line ("  - {0}" -f $r) 'Red' }
        Write-Line ''
        Write-Line 'What to check next:' 'White'
        foreach ($h in $hintsToShow) {
            if ($Script:Hints.ContainsKey($h)) {
                Write-Line ("  * {0}" -f $Script:Hints[$h]) 'Yellow'
            }
        }
    }

    if ($ReportFile) {
        try {
            $dir = Split-Path -Parent $ReportFile
            if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            $Script:ReportLines | Out-File -FilePath $ReportFile -Encoding UTF8
            Write-Host ''
            Write-Host ("Report written to: {0}" -f $ReportFile) -ForegroundColor Cyan
        } catch {
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
                            -PrePathOverride  $PrePath `
                            -PostPathOverride $PostPath `
                            -ReportFile       $ReportPath
    }
}

#endregion ---------------------------------------------------------------
