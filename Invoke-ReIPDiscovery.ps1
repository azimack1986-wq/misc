<#
.SYNOPSIS
    Guided, interactive re-IP discovery audit for the local machine.

.DESCRIPTION
    Runs 13 checks covering common locations where an IP address gets
    hardcoded on a Windows server, then writes per-check JSON evidence
    files and a final text summary. Designed for Windows Server 2012 R2
    and above (PowerShell 4.0 minimum, built-in cmdlets and .NET only —
    no external modules).

    All checks run unattended, top to bottom, with no prompts.

.PARAMETER ScopeIPs
    Override auto-detected scope IPs. Use for clustered IPs / VIPs that
    are not currently bound to a local NIC.

.PARAMETER AppPaths
    Additional root paths for the [03] App Config scan.

.PARAMETER Quick
    Skip [03] App Config (the slowest check).

.PARAMETER OutputPath
    Root output folder. Defaults to C:\Temp. An evidence folder named
    ReIPDiscovery_<hostname>_<yyyyMMdd-HHmm> is created beneath it.

.EXAMPLE
    .\Invoke-ReIPDiscovery.ps1

.EXAMPLE
    .\Invoke-ReIPDiscovery.ps1 -ScopeIPs '10.1.2.50','10.1.2.51' -Quick
#>
#Requires -Version 4.0
[CmdletBinding()]
param(
    [string[]]$ScopeIPs,
    [string[]]$AppPaths,
    [switch]$Quick,
    [string]$OutputPath = 'C:\Temp'
)

# =============================================================================
# Global state
# =============================================================================

$Script:Warnings   = New-Object System.Collections.Generic.List[string]
$Script:Results    = New-Object System.Collections.Generic.List[object]
$Script:HostName   = $env:COMPUTERNAME
$Script:OutputDir  = $null
$Script:ScopeIPs   = @()

# =============================================================================
# Helpers
# =============================================================================

function Write-Color { param([string]$Text, [string]$Color = 'Gray')
    Write-Host $Text -ForegroundColor $Color
}

function Write-CheckHeader { param([int]$Number, [string]$Name)
    Write-Host ''
    Write-Host ('--------------------------------------------------------------------------------') -ForegroundColor Cyan
    Write-Host (' [{0:D2}/13] {1}' -f $Number, $Name) -ForegroundColor Cyan
    Write-Host ('--------------------------------------------------------------------------------') -ForegroundColor Cyan
}

function Get-StatusColor { param([string]$Status)
    switch ($Status) {
        'CHECKED-CLEAN' { 'Green' }
        'ISSUE FOUND'   { 'Red' }
        'N/A'           { 'DarkGray' }
        'PARTIAL'       { 'Yellow' }
        'MANUAL'        { 'Yellow' }
        'Not Run'       { 'DarkGray' }
        default         { 'Gray' }
    }
}

function Write-StatusLine { param([string]$Status)
    Write-Host ('STATUS: {0}' -f $Status) -ForegroundColor (Get-StatusColor $Status)
}

function Write-Finding { param([string]$Text)
    Write-Host ('  ! {0}' -f $Text) -ForegroundColor Red
}

function Write-Clean { param([string]$Text)
    Write-Host ('  - {0}' -f $Text) -ForegroundColor Green
}

function Write-Info { param([string]$Text)
    Write-Host ('  - {0}' -f $Text) -ForegroundColor Gray
}

function Write-WarnLine { param([string]$Text)
    Write-Host ('  ~ {0}' -f $Text) -ForegroundColor Yellow
    $Script:Warnings.Add($Text) | Out-Null
}

function Save-Evidence {
    param([int]$Number, [string]$Name, [object]$Result)
    $safeName = ($Name -replace '[^a-zA-Z0-9]', '') -replace '\s+',''
    $file = Join-Path $Script:OutputDir ('{0:D2}_{1}.json' -f $Number, $safeName.ToLower())
    try {
        $Result | ConvertTo-Json -Depth 5 | Out-File -FilePath $file -Encoding UTF8
    } catch {
        $Script:Warnings.Add(("Evidence write failed for check {0}: {1}" -f $Number, $_.Exception.Message)) | Out-Null
    }
    Write-Host ('Evidence: {0}' -f $file) -ForegroundColor DarkYellow
    return $file
}

function Get-LocalIPv4Addresses {
    $addrs = New-Object System.Collections.Generic.List[string]
    try {
        $nics = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
        foreach ($nic in $nics) {
            if ($nic.NetworkInterfaceType -eq 'Loopback') { continue }
            if ($nic.OperationalStatus -ne 'Up') { continue }
            $props = $nic.GetIPProperties()
            foreach ($u in $props.UnicastAddresses) {
                if ($u.Address.AddressFamily -eq 'InterNetwork') {
                    $ip = $u.Address.ToString()
                    if ($ip -ne '127.0.0.1' -and $ip -notmatch '^169\.254\.') {
                        $addrs.Add($ip) | Out-Null
                    }
                }
            }
        }
    } catch {
        $Script:Warnings.Add(("Local IP detection failed: {0}" -f $_.Exception.Message)) | Out-Null
    }
    return ($addrs | Sort-Object -Unique)
}

function Test-IsAdmin {
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

# Split "10.0.0.1:443" or "[::1]:443" into (ip, port)
function Split-AddrPort { param([string]$s)
    if ([string]::IsNullOrEmpty($s)) { return @('', '') }
    $idx = $s.LastIndexOf(':')
    if ($idx -lt 0) { return @($s, '') }
    $ip = $s.Substring(0, $idx)
    $port = $s.Substring($idx + 1)
    $ip = $ip -replace '^\[','' -replace '\]$',''
    return @($ip, $port)
}

# Parse `netstat -ano` into objects. Returns TCP entries only.
function Get-NetstatTcp {
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        $out = & netstat -ano 2>$null
        foreach ($line in $out) {
            if ($line -match '^\s+TCP\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s*$') {
                $localIp, $localPort   = Split-AddrPort $matches[1]
                $remoteIp, $remotePort = Split-AddrPort $matches[2]
                $rows.Add([PSCustomObject]@{
                    Protocol   = 'TCP'
                    LocalIP    = $localIp
                    LocalPort  = $localPort
                    RemoteIP   = $remoteIp
                    RemotePort = $remotePort
                    State      = $matches[3]
                    PID        = [int]$matches[4]
                }) | Out-Null
            }
        }
    } catch {
        $Script:Warnings.Add(("netstat parse failed: {0}" -f $_.Exception.Message)) | Out-Null
    }
    return $rows
}

$Script:ProcCache = @{}
function Get-ProcName { param([int]$ProcId)
    if ($ProcId -le 0) { return '<unknown>' }
    if ($Script:ProcCache.ContainsKey($ProcId)) { return $Script:ProcCache[$ProcId] }
    $n = '<unknown>'
    try { $p = Get-Process -Id $ProcId -ErrorAction Stop; if ($p) { $n = $p.ProcessName } } catch {}
    $Script:ProcCache[$ProcId] = $n
    return $n
}

function Test-IPv4InScope { param([string]$Ip)
    if ([string]::IsNullOrEmpty($Ip)) { return $false }
    return ($Script:ScopeIPs -contains $Ip)
}

function New-CheckResult {
    param([int]$Number, [string]$Name, [string]$Status, [array]$Findings = @(), [string]$EvidencePath = '')
    return [PSCustomObject]@{
        CheckNumber  = $Number
        CheckName    = $Name
        Status       = $Status
        Findings     = @($Findings)
        EvidencePath = $EvidencePath
        Timestamp    = (Get-Date).ToString('o')
    }
}

# =============================================================================
# Check 01 — Certificates
# =============================================================================

function Invoke-Check01Certificates {
    Write-CheckHeader 1 'Certificates'
    $findings = New-Object System.Collections.Generic.List[object]

    $stores = @('Cert:\LocalMachine\My', 'Cert:\LocalMachine\WebHosting')
    $certData = New-Object System.Collections.Generic.List[object]

    foreach ($store in $stores) {
        if (-not (Test-Path $store)) { continue }
        try {
            $certs = Get-ChildItem -Path $store -ErrorAction Stop
        } catch {
            Write-WarnLine ("Cert store {0} not readable: {1}" -f $store, $_.Exception.Message)
            continue
        }
        foreach ($c in $certs) {
            $sanIps = @()
            foreach ($ext in $c.Extensions) {
                if ($ext.Oid.Value -eq '2.5.29.17') {
                    $txt = $ext.Format($true)
                    $regex = [regex]'IP\s*Address[=:]\s*(\d{1,3}(?:\.\d{1,3}){3})'
                    foreach ($m in $regex.Matches($txt)) { $sanIps += $m.Groups[1].Value }
                }
            }
            $sanIps = $sanIps | Sort-Object -Unique
            $hit = @($sanIps | Where-Object { Test-IPv4InScope $_ })
            $certData.Add([PSCustomObject]@{
                Store      = $store
                Subject    = "$($c.Subject)"
                Thumbprint = $c.Thumbprint
                SANIPs     = $sanIps
                InScope    = $hit
            }) | Out-Null
            foreach ($ip in $hit) {
                $findings.Add([PSCustomObject]@{
                    Type = 'CertificateSAN'; Thumbprint = $c.Thumbprint; Subject = "$($c.Subject)"; IP = $ip
                }) | Out-Null
            }
        }
    }

    # SSL bindings via netsh http show sslcert
    $sslBindings = New-Object System.Collections.Generic.List[object]
    try {
        $out = & netsh http show sslcert 2>$null
        $current = $null
        foreach ($line in $out) {
            if ($line -match '^\s*IP:port\s*:\s*(.+?)\s*$') {
                if ($current) { $sslBindings.Add($current) | Out-Null }
                $current = [PSCustomObject]@{ IPPort = $matches[1].Trim(); Hash = ''; LocalIP = ''; LocalPort = '' }
                $ip, $port = Split-AddrPort $current.IPPort
                $current.LocalIP = $ip; $current.LocalPort = $port
            } elseif ($line -match '^\s*Certificate Hash\s*:\s*(.+?)\s*$' -and $current) {
                $current.Hash = $matches[1].Trim()
            }
        }
        if ($current) { $sslBindings.Add($current) | Out-Null }
    } catch {
        Write-WarnLine ("netsh http show sslcert failed: {0}" -f $_.Exception.Message)
    }

    foreach ($b in $sslBindings) {
        if (Test-IPv4InScope $b.LocalIP) {
            $findings.Add([PSCustomObject]@{
                Type = 'SSLBinding'; IPPort = $b.IPPort; Hash = $b.Hash; IP = $b.LocalIP
            }) | Out-Null
        }
    }

    if ($findings.Count -eq 0) {
        Write-Clean ("Scanned {0} certificate(s) and {1} SSL binding(s) — no scope IP references." -f $certData.Count, $sslBindings.Count)
        $status = 'CHECKED-CLEAN'
    } else {
        foreach ($f in $findings) {
            if ($f.Type -eq 'CertificateSAN') {
                Write-Finding ("Cert SAN contains scope IP {0}: {1} (thumb {2})" -f $f.IP, $f.Subject, $f.Thumbprint)
            } else {
                Write-Finding ("SSL binding on scope IP {0}: {1} (cert hash {2})" -f $f.IP, $f.IPPort, $f.Hash)
            }
        }
        $status = 'ISSUE FOUND'
    }

    Write-StatusLine $status
    $result = New-CheckResult -Number 1 -Name 'Certificates' -Status $status -Findings $findings
    $result.EvidencePath = Save-Evidence -Number 1 -Name 'Certificates' -Result ([PSCustomObject]@{
        Status = $status; ScopeIPs = $Script:ScopeIPs; Certificates = $certData; SSLBindings = $sslBindings; Findings = $findings
    })
    return $result
}

# =============================================================================
# Check 02 — IIS Bindings
# =============================================================================

function Invoke-Check02IIS {
    Write-CheckHeader 2 'IIS Bindings'
    $findings = New-Object System.Collections.Generic.List[object]
    $bindings = New-Object System.Collections.Generic.List[object]

    $svc = Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Info 'IIS (W3SVC) is not installed on this server.'
        Write-StatusLine 'N/A'
        $result = New-CheckResult -Number 2 -Name 'IIS Bindings' -Status 'N/A' -Findings @()
        $result.EvidencePath = Save-Evidence -Number 2 -Name 'IIS Bindings' -Result ([PSCustomObject]@{ Status='N/A'; Reason='W3SVC not installed' })
        return $result
    }

    $usedModule = $false
    if (Get-Module -ListAvailable -Name WebAdministration) {
        try {
            Import-Module WebAdministration -ErrorAction Stop
            $sites = Get-Website
            foreach ($site in $sites) {
                foreach ($b in $site.Bindings.Collection) {
                    $bi = "$($b.bindingInformation)"
                    $parts = $bi -split ':', 3
                    $bindings.Add([PSCustomObject]@{
                        Site = "$($site.Name)"; State = "$($site.State)"; Protocol = "$($b.protocol)"
                        IP = $parts[0]; Port = $parts[1]; HostHeader = $parts[2]
                    }) | Out-Null
                }
            }
            $usedModule = $true
        } catch {
            Write-WarnLine ("WebAdministration module failed: {0}" -f $_.Exception.Message)
        }
    }

    if (-not $usedModule) {
        # Fallback to applicationHost.config XML
        $cfg = "$env:WinDir\System32\inetsrv\config\applicationHost.config"
        if (Test-Path $cfg) {
            try {
                [xml]$xml = Get-Content $cfg -ErrorAction Stop
                foreach ($site in $xml.configuration.'system.applicationHost'.sites.site) {
                    foreach ($b in $site.bindings.binding) {
                        $bi = "$($b.bindingInformation)"
                        $parts = $bi -split ':', 3
                        $bindings.Add([PSCustomObject]@{
                            Site = "$($site.name)"; State = 'Unknown'; Protocol = "$($b.protocol)"
                            IP = $parts[0]; Port = $parts[1]; HostHeader = $parts[2]
                        }) | Out-Null
                    }
                }
            } catch {
                Write-WarnLine ("applicationHost.config parse failed: {0}" -f $_.Exception.Message)
            }
        } else {
            Write-WarnLine ("applicationHost.config not found at {0}" -f $cfg)
        }
    }

    foreach ($b in $bindings) {
        if ($b.IP -and $b.IP -ne '*' -and (Test-IPv4InScope $b.IP)) {
            $findings.Add($b) | Out-Null
        }
    }

    if ($bindings.Count -eq 0) {
        Write-Info 'No IIS sites configured.'
        $status = 'CHECKED-CLEAN'
    } elseif ($findings.Count -eq 0) {
        Write-Clean ("Scanned {0} binding(s) — none pinned to a scope IP." -f $bindings.Count)
        $status = 'CHECKED-CLEAN'
    } else {
        foreach ($f in $findings) {
            Write-Finding ("Site '{0}' bound to scope IP {1}:{2} ({3})" -f $f.Site, $f.IP, $f.Port, $f.Protocol)
        }
        $status = 'ISSUE FOUND'
    }

    Write-StatusLine $status
    $result = New-CheckResult -Number 2 -Name 'IIS Bindings' -Status $status -Findings $findings
    $result.EvidencePath = Save-Evidence -Number 2 -Name 'IIS Bindings' -Result ([PSCustomObject]@{
        Status = $status; UsedModule = $usedModule; AllBindings = $bindings; Findings = $findings
    })
    return $result
}

# =============================================================================
# Check 03 — App Config Files
# =============================================================================

function Invoke-Check03AppConfig {
    Write-CheckHeader 3 'App Config Files'
    if ($Quick) {
        Write-Info 'Skipped via -Quick switch.'
        Write-StatusLine 'N/A'
        $result = New-CheckResult -Number 3 -Name 'App Config Files' -Status 'N/A' -Findings @()
        $result.EvidencePath = Save-Evidence -Number 3 -Name 'App Config Files' -Result ([PSCustomObject]@{ Status='N/A'; Reason='-Quick' })
        return $result
    }

    $findings = New-Object System.Collections.Generic.List[object]
    $roots = @('C:\Program Files', 'C:\Program Files (x86)', 'C:\inetpub', 'C:\Apps', 'D:\Apps')
    if ($AppPaths) { $roots = $roots + $AppPaths | Sort-Object -Unique }
    $extensions = @('.config', '.xml', '.json', '.ini', '.properties', '.yml', '.yaml', '.conf', '.ps1', '.bat', '.cmd', '.vbs')
    $ipRegex = [regex]'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    $scanned = 0; $skipped = 0

    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        Write-Host ('  Scanning {0}...' -f $root) -ForegroundColor DarkGray
        $files = $null
        try {
            $files = Get-ChildItem -Path $root -Recurse -Force -File -ErrorAction SilentlyContinue |
                Where-Object { $extensions -contains $_.Extension.ToLower() }
        } catch {
            Write-WarnLine ("Enumeration failed for {0}: {1}" -f $root, $_.Exception.Message)
            continue
        }
        if (-not $files) { continue }
        Write-Host ('    {0} candidate file(s) found' -f @($files).Count) -ForegroundColor DarkGray
        foreach ($f in $files) {
            $scanned++
            try {
                $lineNum = 0
                Get-Content -Path $f.FullName -ErrorAction Stop | ForEach-Object {
                    $lineNum++
                    $ln = $_
                    foreach ($m in $ipRegex.Matches($ln)) {
                        if (Test-IPv4InScope $m.Value) {
                            $findings.Add([PSCustomObject]@{
                                File = $f.FullName; Line = $lineNum; Content = $ln.Trim(); IP = $m.Value
                            }) | Out-Null
                        }
                    }
                }
            } catch {
                $skipped++
                $Script:Warnings.Add(("Access denied or read failure: {0}" -f $f.FullName)) | Out-Null
            }
        }
    }

    if ($findings.Count -eq 0) {
        Write-Clean ("Scanned {0} file(s), {1} skipped — no scope IPs found." -f $scanned, $skipped)
        $status = if ($skipped -gt 0) { 'PARTIAL' } else { 'CHECKED-CLEAN' }
    } else {
        $byFile = $findings | Group-Object File
        Write-Host ('  {0} reference(s) found in {1} file(s):' -f $findings.Count, $byFile.Count) -ForegroundColor Red
        foreach ($g in $byFile | Select-Object -First 20) {
            Write-Finding ("{0} ({1} hit(s))" -f $g.Name, $g.Count)
            foreach ($h in $g.Group | Select-Object -First 3) {
                Write-Host ('      line {0,5}: {1}' -f $h.Line, $h.Content) -ForegroundColor DarkGray
            }
            if ($g.Count -gt 3) { Write-Host ('      ... and {0} more in this file' -f ($g.Count - 3)) -ForegroundColor DarkGray }
        }
        if ($byFile.Count -gt 20) { Write-Host ('  ... and {0} more file(s) (see evidence)' -f ($byFile.Count - 20)) -ForegroundColor DarkGray }
        $status = 'ISSUE FOUND'
    }

    Write-StatusLine $status
    $result = New-CheckResult -Number 3 -Name 'App Config Files' -Status $status -Findings $findings
    $result.EvidencePath = Save-Evidence -Number 3 -Name 'App Config Files' -Result ([PSCustomObject]@{
        Status = $status; FilesScanned = $scanned; FilesSkipped = $skipped; Roots = $roots; Findings = $findings
    })
    return $result
}

# =============================================================================
# Check 04 — SQL Config
# =============================================================================

function Invoke-Check04SQLConfig {
    Write-CheckHeader 4 'SQL Config'
    $findings  = New-Object System.Collections.Generic.List[object]
    $aliases   = New-Object System.Collections.Generic.List[object]
    $instances = @()
    $linked    = New-Object System.Collections.Generic.List[object]
    $partial   = $false

    $aliasPaths = @(
        'HKLM:\SOFTWARE\Microsoft\MSSQLServer\Client\ConnectTo',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\MSSQLServer\Client\ConnectTo'
    )
    foreach ($p in $aliasPaths) {
        if (Test-Path $p) {
            try {
                $key = Get-Item $p -ErrorAction Stop
                foreach ($name in $key.GetValueNames()) {
                    $val = $key.GetValue($name)
                    $entry = [PSCustomObject]@{ Path = $p; Alias = $name; Target = "$val" }
                    $aliases.Add($entry) | Out-Null
                    foreach ($m in [regex]::Matches("$val", '\b(?:\d{1,3}\.){3}\d{1,3}\b')) {
                        if (Test-IPv4InScope $m.Value) {
                            $findings.Add([PSCustomObject]@{ Type = 'SQLAlias'; Alias = $name; Target = "$val"; IP = $m.Value }) | Out-Null
                        }
                    }
                }
            } catch {
                Write-WarnLine ("Could not read {0}: {1}" -f $p, $_.Exception.Message); $partial = $true
            }
        }
    }

    $instKey = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
    if (Test-Path $instKey) {
        try {
            $k = Get-Item $instKey -ErrorAction Stop
            $instances = @($k.GetValueNames())
        } catch { Write-WarnLine ("Could not enumerate SQL instances: {0}" -f $_.Exception.Message); $partial = $true }
    }

    foreach ($inst in $instances) {
        $connStr = if ($inst -eq 'MSSQLSERVER') { "Server=$env:COMPUTERNAME;Integrated Security=SSPI;Connect Timeout=5" }
                   else                         { "Server=$env:COMPUTERNAME\$inst;Integrated Security=SSPI;Connect Timeout=5" }
        try {
            $cn = New-Object System.Data.SqlClient.SqlConnection $connStr
            $cn.Open()
            $cmd = $cn.CreateCommand()
            $cmd.CommandText = "SELECT name, ISNULL(data_source,'') AS data_source FROM sys.servers WHERE server_id <> 0"
            $rdr = $cmd.ExecuteReader()
            while ($rdr.Read()) {
                $entry = [PSCustomObject]@{ Instance = $inst; LinkedServer = "$($rdr['name'])"; DataSource = "$($rdr['data_source'])" }
                $linked.Add($entry) | Out-Null
                foreach ($m in [regex]::Matches($entry.DataSource, '\b(?:\d{1,3}\.){3}\d{1,3}\b')) {
                    if (Test-IPv4InScope $m.Value) {
                        $findings.Add([PSCustomObject]@{ Type = 'LinkedServer'; Instance = $inst; Name = $entry.LinkedServer; DataSource = $entry.DataSource; IP = $m.Value }) | Out-Null
                    }
                }
            }
            $rdr.Close(); $cn.Close()
        } catch {
            Write-WarnLine ("SQL instance '{0}' query failed: {1}" -f $inst, $_.Exception.Message); $partial = $true
        }
    }

    if ($aliases.Count -eq 0 -and $instances.Count -eq 0) {
        Write-Info 'No SQL aliases configured and no local SQL instances detected.'
        $status = 'N/A'
    } elseif ($findings.Count -eq 0) {
        Write-Clean ("Scanned {0} alias(es), {1} instance(s), {2} linked server(s) — no scope IP references." -f $aliases.Count, $instances.Count, $linked.Count)
        $status = if ($partial) { 'PARTIAL' } else { 'CHECKED-CLEAN' }
    } else {
        foreach ($f in $findings) {
            if ($f.Type -eq 'SQLAlias') {
                Write-Finding ("SQL alias '{0}' -> '{1}' (scope IP {2})" -f $f.Alias, $f.Target, $f.IP)
            } else {
                Write-Finding ("Linked server '{0}' on {1} -> '{2}' (scope IP {3})" -f $f.Name, $f.Instance, $f.DataSource, $f.IP)
            }
        }
        $status = 'ISSUE FOUND'
    }

    Write-StatusLine $status
    $result = New-CheckResult -Number 4 -Name 'SQL Config' -Status $status -Findings $findings
    $result.EvidencePath = Save-Evidence -Number 4 -Name 'SQL Config' -Result ([PSCustomObject]@{
        Status = $status; Aliases = $aliases; Instances = $instances; LinkedServers = $linked; Findings = $findings
    })
    return $result
}

# =============================================================================
# Check 05 — Scheduled Tasks
# =============================================================================

function Invoke-Check05ScheduledTasks {
    Write-CheckHeader 5 'Scheduled Tasks'
    $findings = New-Object System.Collections.Generic.List[object]
    $tasks    = @()
    $ipRegex  = [regex]'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    try {
        $csv = & schtasks /query /fo CSV /v 2>$null
        $tasks = @($csv | ConvertFrom-Csv | Where-Object { $_.HostName -ne 'HostName' -and $_.TaskName -ne 'TaskName' })
    } catch {
        Write-WarnLine ("schtasks query failed: {0}" -f $_.Exception.Message)
    }

    foreach ($t in $tasks) {
        $action = "$($t.'Task To Run')"
        if ([string]::IsNullOrWhiteSpace($action) -or $action -eq 'N/A') { continue }

        foreach ($m in $ipRegex.Matches($action)) {
            if (Test-IPv4InScope $m.Value) {
                $findings.Add([PSCustomObject]@{
                    Type = 'TaskAction'; Task = "$($t.TaskName)"; Action = $action; IP = $m.Value; Line = ''
                }) | Out-Null
            }
        }

        # If action references a script file, grep it too
        $scriptPath = $null
        if ($action -match '"([A-Z]:\\[^"]+\.(ps1|bat|cmd|vbs|js))"') { $scriptPath = $matches[1] }
        elseif ($action -match '([A-Z]:\\\S+\.(ps1|bat|cmd|vbs|js))') { $scriptPath = $matches[1] }
        if ($scriptPath -and (Test-Path $scriptPath)) {
            try {
                $i = 0
                Get-Content $scriptPath -ErrorAction Stop | ForEach-Object {
                    $i++
                    foreach ($m in $ipRegex.Matches($_)) {
                        if (Test-IPv4InScope $m.Value) {
                            $findings.Add([PSCustomObject]@{
                                Type = 'TaskScript'; Task = "$($t.TaskName)"; Action = $scriptPath; IP = $m.Value; Line = "${i}: $($_.Trim())"
                            }) | Out-Null
                        }
                    }
                }
            } catch {}
        }
    }

    if ($tasks.Count -eq 0) {
        Write-Info 'No scheduled tasks enumerated.'
        $status = 'N/A'
    } elseif ($findings.Count -eq 0) {
        Write-Clean ("Scanned {0} task(s) — no scope IP references." -f $tasks.Count)
        $status = 'CHECKED-CLEAN'
    } else {
        foreach ($f in $findings) {
            if ($f.Type -eq 'TaskAction') {
                Write-Finding ("Task '{0}': action contains scope IP {1}" -f $f.Task, $f.IP)
                Write-Host ('      action: {0}' -f $f.Action) -ForegroundColor DarkGray
            } else {
                Write-Finding ("Task '{0}' script {1} contains scope IP {2}" -f $f.Task, $f.Action, $f.IP)
                Write-Host ('      line {0}' -f $f.Line) -ForegroundColor DarkGray
            }
        }
        $status = 'ISSUE FOUND'
    }

    Write-StatusLine $status
    $result = New-CheckResult -Number 5 -Name 'Scheduled Tasks' -Status $status -Findings $findings
    $result.EvidencePath = Save-Evidence -Number 5 -Name 'Scheduled Tasks' -Result ([PSCustomObject]@{
        Status = $status; TasksScanned = $tasks.Count; Findings = $findings
    })
    return $result
}

# =============================================================================
# Check 06 — Hosts File
# =============================================================================

function Invoke-Check06HostsFile {
    Write-CheckHeader 6 'Hosts File'
    $findings = New-Object System.Collections.Generic.List[object]
    $path = "$env:WinDir\System32\drivers\etc\hosts"
    $lines = @()
    if (Test-Path $path) {
        try { $lines = Get-Content $path -ErrorAction Stop } catch { Write-WarnLine ("hosts read failed: {0}" -f $_.Exception.Message) }
    } else {
        Write-WarnLine 'hosts file not present.'
    }

    $i = 0
    foreach ($l in $lines) {
        $i++
        if ($l -match '^\s*#') { continue }
        if ($l -match '^\s*$') { continue }
        if ($l -match '^\s*(\S+)\s+\S+') {
            $ip = $matches[1]
            if (Test-IPv4InScope $ip) {
                $findings.Add([PSCustomObject]@{ Line = $i; Content = $l.Trim(); IP = $ip }) | Out-Null
            }
        }
    }

    if ($findings.Count -eq 0) {
        Write-Clean ("Scanned {0} line(s) — no scope IP entries." -f $lines.Count)
        $status = 'CHECKED-CLEAN'
    } else {
        foreach ($f in $findings) {
            Write-Finding ("hosts:{0}: {1}" -f $f.Line, $f.Content)
        }
        $status = 'ISSUE FOUND'
    }

    Write-StatusLine $status
    $result = New-CheckResult -Number 6 -Name 'Hosts File' -Status $status -Findings $findings
    $result.EvidencePath = Save-Evidence -Number 6 -Name 'Hosts File' -Result ([PSCustomObject]@{
        Status = $status; Path = $path; Findings = $findings
    })
    return $result
}

# =============================================================================
# Check 07 — DNS
# =============================================================================

function Invoke-Check07DNS {
    Write-CheckHeader 7 'DNS'
    $findings = New-Object System.Collections.Generic.List[object]
    $entries  = New-Object System.Collections.Generic.List[object]

    $myFqdn = $env:COMPUTERNAME
    try {
        $sys = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)
        if ($sys.HostName) { $myFqdn = $sys.HostName }
    } catch {}

    # Forward lookup of own hostname
    $forwardIPs = @()
    try {
        $addrs = [System.Net.Dns]::GetHostAddresses($myFqdn)
        $forwardIPs = @($addrs | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.ToString() })
    } catch {
        Write-WarnLine ("Forward lookup failed for {0}: {1}" -f $myFqdn, $_.Exception.Message)
    }
    $entries.Add([PSCustomObject]@{ Type = 'Forward'; Query = $myFqdn; Result = ($forwardIPs -join ',') }) | Out-Null

    foreach ($ip in $forwardIPs) {
        if (-not (Test-IPv4InScope $ip)) {
            $findings.Add([PSCustomObject]@{ Type = 'ForwardMismatch'; Detail = ("Forward lookup of {0} returned {1} (not in scope IPs)" -f $myFqdn, $ip) }) | Out-Null
        }
    }
    foreach ($s in $Script:ScopeIPs) {
        if ($forwardIPs -notcontains $s) {
            $findings.Add([PSCustomObject]@{ Type = 'ForwardMissing'; Detail = ("Scope IP {0} is not returned by forward lookup of {1}" -f $s, $myFqdn) }) | Out-Null
        }
    }

    # Reverse lookup for each scope IP
    foreach ($ip in $Script:ScopeIPs) {
        $rev = '<failed>'
        try {
            $he = [System.Net.Dns]::GetHostEntry($ip)
            $rev = $he.HostName
        } catch {
            $findings.Add([PSCustomObject]@{ Type = 'ReverseFailed'; Detail = ("Reverse lookup for {0} failed: {1}" -f $ip, $_.Exception.Message) }) | Out-Null
        }
        $entries.Add([PSCustomObject]@{ Type = 'Reverse'; Query = $ip; Result = $rev }) | Out-Null
        if ($rev -ne '<failed>' -and $rev -notlike "$($env:COMPUTERNAME)*" -and $rev -ne $myFqdn) {
            $findings.Add([PSCustomObject]@{ Type = 'ReverseMismatch'; Detail = ("Reverse lookup of {0} returned '{1}', expected hostname matching '{2}'" -f $ip, $rev, $env:COMPUTERNAME) }) | Out-Null
        }
    }

    foreach ($e in $entries) {
        Write-Info ("{0,-8} {1,-30} -> {2}" -f $e.Type, $e.Query, $e.Result)
    }
    if ($findings.Count -eq 0) {
        Write-Clean 'Forward and reverse DNS resolve consistently with detected hostname and scope IPs.'
        $status = 'CHECKED-CLEAN'
    } else {
        foreach ($f in $findings) { Write-Finding $f.Detail }
        $status = 'ISSUE FOUND'
    }

    Write-StatusLine $status
    $result = New-CheckResult -Number 7 -Name 'DNS' -Status $status -Findings $findings
    $result.EvidencePath = Save-Evidence -Number 7 -Name 'DNS' -Result ([PSCustomObject]@{
        Status = $status; Hostname = $myFqdn; Entries = $entries; Findings = $findings
    })
    return $result
}

# =============================================================================
# Check 08 — Service Bindings
# =============================================================================

function Invoke-Check08ServiceBindings {
    Write-CheckHeader 8 'Service Bindings'
    $findings = New-Object System.Collections.Generic.List[object]
    $rows = Get-NetstatTcp
    $listeners = @($rows | Where-Object { $_.State -eq 'LISTENING' })

    foreach ($l in $listeners) {
        if ($l.LocalIP -eq '0.0.0.0' -or $l.LocalIP -eq '::' -or $l.LocalIP -eq '*') { continue }
        if (Test-IPv4InScope $l.LocalIP) {
            $findings.Add([PSCustomObject]@{
                Process = (Get-ProcName $l.PID); PID = $l.PID
                LocalIP = $l.LocalIP; LocalPort = $l.LocalPort
            }) | Out-Null
        }
    }

    if ($listeners.Count -eq 0) {
        Write-WarnLine 'No listeners parsed from netstat output.'
        $status = 'PARTIAL'
    } elseif ($findings.Count -eq 0) {
        Write-Clean ("Scanned {0} listener(s) — none pinned to a scope IP." -f $listeners.Count)
        $status = 'CHECKED-CLEAN'
    } else {
        foreach ($f in $findings) {
            Write-Finding ("Listener pinned to scope IP: {0}:{1} ({2}, PID {3})" -f $f.LocalIP, $f.LocalPort, $f.Process, $f.PID)
        }
        $status = 'ISSUE FOUND'
    }

    Write-StatusLine $status
    $result = New-CheckResult -Number 8 -Name 'Service Bindings' -Status $status -Findings $findings
    $result.EvidencePath = Save-Evidence -Number 8 -Name 'Service Bindings' -Result ([PSCustomObject]@{
        Status = $status; TotalListeners = $listeners.Count; Findings = $findings
    })
    return $result
}

# =============================================================================
# Check 09 — ODBC DSNs
# =============================================================================

function Invoke-Check09ODBC {
    Write-CheckHeader 9 'ODBC DSNs'
    $findings = New-Object System.Collections.Generic.List[object]
    $dsns = New-Object System.Collections.Generic.List[object]

    $roots = @(
        'HKLM:\SOFTWARE\ODBC\ODBC.INI',
        'HKLM:\SOFTWARE\Wow6432Node\ODBC\ODBC.INI',
        'HKCU:\SOFTWARE\ODBC\ODBC.INI'
    )
    foreach ($r in $roots) {
        if (-not (Test-Path $r)) { continue }
        try {
            $subs = Get-ChildItem -Path $r -ErrorAction Stop | Where-Object { $_.PSChildName -ne 'ODBC Data Sources' }
            foreach ($s in $subs) {
                try {
                    $props = Get-ItemProperty -Path $s.PSPath -ErrorAction Stop
                    $server = "$($props.Server)"
                    $driver = "$($props.Driver)"
                    $dsn = [PSCustomObject]@{
                        Root = $r; Name = $s.PSChildName; Driver = $driver; Server = $server
                    }
                    $dsns.Add($dsn) | Out-Null
                    foreach ($m in [regex]::Matches($server, '\b(?:\d{1,3}\.){3}\d{1,3}\b')) {
                        if (Test-IPv4InScope $m.Value) {
                            $findings.Add([PSCustomObject]@{
                                DSN = $s.PSChildName; Driver = $driver; Server = $server; IP = $m.Value
                            }) | Out-Null
                        }
                    }
                } catch {}
            }
        } catch { Write-WarnLine ("Could not enumerate {0}: {1}" -f $r, $_.Exception.Message) }
    }

    if ($dsns.Count -eq 0) {
        Write-Info 'No ODBC DSNs found.'
        $status = 'N/A'
    } elseif ($findings.Count -eq 0) {
        Write-Clean ("Scanned {0} DSN(s) — no scope IP references." -f $dsns.Count)
        $status = 'CHECKED-CLEAN'
    } else {
        foreach ($f in $findings) {
            Write-Finding ("DSN '{0}' targets scope IP {1} (Server={2}, Driver={3})" -f $f.DSN, $f.IP, $f.Server, $f.Driver)
        }
        $status = 'ISSUE FOUND'
    }

    Write-StatusLine $status
    $result = New-CheckResult -Number 9 -Name 'ODBC DSNs' -Status $status -Findings $findings
    $result.EvidencePath = Save-Evidence -Number 9 -Name 'ODBC DSNs' -Result ([PSCustomObject]@{
        Status = $status; DSNs = $dsns; Findings = $findings
    })
    return $result
}

# =============================================================================
# Check 10 — Inter-App Connections (inbound)
# =============================================================================

function Invoke-Check10InterApp {
    Write-CheckHeader 10 'Inter-App Connections (Inbound)'
    $findings = New-Object System.Collections.Generic.List[object]
    $rows = Get-NetstatTcp
    $est = @($rows | Where-Object { $_.State -eq 'ESTABLISHED' -and (Test-IPv4InScope $_.LocalIP) })

    foreach ($c in $est) {
        $rname = ''
        try { $rname = [System.Net.Dns]::GetHostEntry($c.RemoteIP).HostName } catch { $rname = '<unresolved>' }
        $findings.Add([PSCustomObject]@{
            Process = (Get-ProcName $c.PID); PID = $c.PID
            LocalIP = $c.LocalIP; LocalPort = $c.LocalPort
            RemoteIP = $c.RemoteIP; RemotePort = $c.RemotePort
            RemoteName = $rname
        }) | Out-Null
    }

    Write-Host '  These connections are currently established. Verify that the' -ForegroundColor Yellow
    Write-Host '  remote endpoints use DNS, not hardcoded IPs — this check cannot' -ForegroundColor Yellow
    Write-Host '  be performed locally.' -ForegroundColor Yellow
    Write-Host ''

    if ($findings.Count -eq 0) {
        Write-Clean 'No established inbound connections on scope IPs at this moment.'
        $status = 'CHECKED-CLEAN'
    } else {
        foreach ($f in $findings | Select-Object -First 30) {
            Write-Host ('  > {0,-22} {1}:{2} <- {3}:{4} ({5})' -f $f.Process, $f.LocalIP, $f.LocalPort, $f.RemoteIP, $f.RemotePort, $f.RemoteName) -ForegroundColor Gray
        }
        if ($findings.Count -gt 30) {
            Write-Host ('  ... and {0} more (see evidence)' -f ($findings.Count - 30)) -ForegroundColor DarkGray
        }
        $status = 'PARTIAL'
    }

    Write-StatusLine $status
    $result = New-CheckResult -Number 10 -Name 'Inter-App Connections' -Status $status -Findings $findings
    $result.EvidencePath = Save-Evidence -Number 10 -Name 'Inter-App Connections' -Result ([PSCustomObject]@{
        Status = $status; Findings = $findings
    })
    return $result
}

# =============================================================================
# Check 11 — SMB / UNC References
# =============================================================================

function Invoke-Check11SMB {
    Write-CheckHeader 11 'SMB / UNC References'
    $findings = New-Object System.Collections.Generic.List[object]
    $drives = New-Object System.Collections.Generic.List[object]
    $persisted = New-Object System.Collections.Generic.List[object]
    $dfs = New-Object System.Collections.Generic.List[object]

    try {
        $live = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue
        foreach ($d in $live) {
            $root = "$($d.Root)"
            if ($root -match '\\\\') {
                $drives.Add([PSCustomObject]@{ Name = $d.Name; Root = $root }) | Out-Null
                foreach ($m in [regex]::Matches($root, '\b(?:\d{1,3}\.){3}\d{1,3}\b')) {
                    if (Test-IPv4InScope $m.Value) {
                        $findings.Add([PSCustomObject]@{ Type = 'MappedDrive'; Name = $d.Name; Path = $root; IP = $m.Value }) | Out-Null
                    }
                }
            }
        }
    } catch {}

    if (Test-Path 'HKCU:\Network') {
        try {
            Get-ChildItem 'HKCU:\Network' -ErrorAction Stop | ForEach-Object {
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                $remote = "$($props.RemotePath)"
                $persisted.Add([PSCustomObject]@{ Letter = $_.PSChildName; Remote = $remote }) | Out-Null
                foreach ($m in [regex]::Matches($remote, '\b(?:\d{1,3}\.){3}\d{1,3}\b')) {
                    if (Test-IPv4InScope $m.Value) {
                        $findings.Add([PSCustomObject]@{ Type = 'PersistedMap'; Name = $_.PSChildName; Path = $remote; IP = $m.Value }) | Out-Null
                    }
                }
            }
        } catch {}
    }

    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Dfs') {
        try {
            $dfsKey = Get-Item 'HKLM:\SOFTWARE\Microsoft\Dfs' -ErrorAction Stop
            $dfs.Add([PSCustomObject]@{ Path = $dfsKey.PSPath; ValueNames = ($dfsKey.GetValueNames() -join ',') }) | Out-Null
        } catch {}
    }

    Write-Host '  Cannot detect UNC references on other servers pointing at this' -ForegroundColor Yellow
    Write-Host '  machine — manual check required on dependent servers.' -ForegroundColor Yellow
    Write-Host ''

    if ($drives.Count -eq 0 -and $persisted.Count -eq 0) {
        Write-Info 'No mapped drives or persisted SMB mappings found.'
        $status = 'N/A'
    } elseif ($findings.Count -eq 0) {
        Write-Clean ("Scanned {0} mapped drive(s) and {1} persisted mapping(s) — no scope IP references." -f $drives.Count, $persisted.Count)
        $status = 'CHECKED-CLEAN'
    } else {
        foreach ($f in $findings) {
            Write-Finding ("{0} '{1}' -> {2} (scope IP {3})" -f $f.Type, $f.Name, $f.Path, $f.IP)
        }
        $status = 'ISSUE FOUND'
    }

    Write-StatusLine $status
    $result = New-CheckResult -Number 11 -Name 'SMB / UNC' -Status $status -Findings $findings
    $result.EvidencePath = Save-Evidence -Number 11 -Name 'SMB' -Result ([PSCustomObject]@{
        Status = $status; LiveDrives = $drives; Persisted = $persisted; DFS = $dfs; Findings = $findings
    })
    return $result
}

# =============================================================================
# Check 12 — Firewall (manual)
# =============================================================================

function Invoke-Check12Firewall {
    Write-CheckHeader 12 'Firewall Audit'
    Write-Host ''
    Write-Host '  This check is owned by the Comms team.' -ForegroundColor Yellow
    Write-Host '  Confirm with Comms that firewall rule audit is complete' -ForegroundColor Yellow
    Write-Host '  and new IPs have been prepped before marking this check.' -ForegroundColor Yellow
    Write-Host ''
    Write-StatusLine 'MANUAL'
    $result = New-CheckResult -Number 12 -Name 'Firewall' -Status 'MANUAL' -Findings @()
    $result.EvidencePath = Save-Evidence -Number 12 -Name 'Firewall' -Result ([PSCustomObject]@{
        Status = 'MANUAL'; Owner = 'Comms team'; Note = 'No automated check'
    })
    return $result
}

# =============================================================================
# Check 13 — Load Balancer (manual)
# =============================================================================

function Invoke-Check13LoadBalancer {
    Write-CheckHeader 13 'Load Balancer'
    Write-Host ''
    Write-Host '  This check is owned by the Comms team.' -ForegroundColor Yellow
    Write-Host '  Confirm with Comms that load balancer pools have been' -ForegroundColor Yellow
    Write-Host '  updated to reference the new IPs before marking this check.' -ForegroundColor Yellow
    Write-Host ''
    Write-StatusLine 'MANUAL'
    $result = New-CheckResult -Number 13 -Name 'Load Balancer' -Status 'MANUAL' -Findings @()
    $result.EvidencePath = Save-Evidence -Number 13 -Name 'Load Balancer' -Result ([PSCustomObject]@{
        Status = 'MANUAL'; Owner = 'Comms team'; Note = 'No automated check'
    })
    return $result
}

# =============================================================================
# Main
# =============================================================================

# PS version gate
if ($PSVersionTable.PSVersion.Major -lt 4) {
    Write-Error "PowerShell 4.0 or higher required. Current version: $($PSVersionTable.PSVersion)"
    exit 1
}

# Elevation check
if (-not (Test-IsAdmin)) {
    Write-Host 'WARNING: not running as local Administrator. Some checks (certs, SQL, registry, scheduled tasks) may return incomplete results.' -ForegroundColor Yellow
}

# Scope IPs
if ($ScopeIPs -and $ScopeIPs.Count -gt 0) {
    $Script:ScopeIPs = @($ScopeIPs)
} else {
    $Script:ScopeIPs = @(Get-LocalIPv4Addresses)
}

# Output folder
$stamp = (Get-Date).ToString('yyyyMMdd-HHmm')
$Script:OutputDir = Join-Path $OutputPath ("ReIPDiscovery_{0}_{1}" -f $Script:HostName, $stamp)
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
New-Item -ItemType Directory -Path $Script:OutputDir -Force | Out-Null

# Banner
Write-Host ''
Write-Host '================================================================================' -ForegroundColor Cyan
Write-Host (' RE-IP DISCOVERY - {0}' -f $Script:HostName) -ForegroundColor Cyan
Write-Host (' Date/Time: {0}' -f (Get-Date)) -ForegroundColor Cyan
Write-Host '================================================================================' -ForegroundColor Cyan
Write-Host ''
Write-Host ' Detected scope IPs:'
if ($Script:ScopeIPs.Count -eq 0) {
    Write-Host '   (none detected — re-run with -ScopeIPs)' -ForegroundColor Yellow
} else {
    foreach ($ip in $Script:ScopeIPs) { Write-Host ('   -> {0}' -f $ip) -ForegroundColor White }
}
Write-Host ''
Write-Host (' Evidence folder: {0}' -f $Script:OutputDir) -ForegroundColor DarkCyan
Write-Host ''
Write-Host ' If scope IPs are incorrect, re-run with the -ScopeIPs override.' -ForegroundColor Yellow
Write-Host ' Running all checks...' -ForegroundColor Cyan
Write-Host ''

# Check registry — function objects keyed by number
$checks = @(
    @{ Num = 1;  Fn = { Invoke-Check01Certificates } }
    @{ Num = 2;  Fn = { Invoke-Check02IIS } }
    @{ Num = 3;  Fn = { Invoke-Check03AppConfig } }
    @{ Num = 4;  Fn = { Invoke-Check04SQLConfig } }
    @{ Num = 5;  Fn = { Invoke-Check05ScheduledTasks } }
    @{ Num = 6;  Fn = { Invoke-Check06HostsFile } }
    @{ Num = 7;  Fn = { Invoke-Check07DNS } }
    @{ Num = 8;  Fn = { Invoke-Check08ServiceBindings } }
    @{ Num = 9;  Fn = { Invoke-Check09ODBC } }
    @{ Num = 10; Fn = { Invoke-Check10InterApp } }
    @{ Num = 11; Fn = { Invoke-Check11SMB } }
    @{ Num = 12; Fn = { Invoke-Check12Firewall } }
    @{ Num = 13; Fn = { Invoke-Check13LoadBalancer } }
)

$checkNames = @{
    1='Certificates'; 2='IIS Bindings'; 3='App Config'; 4='SQL Config'
    5='Scheduled Tasks'; 6='Hosts File'; 7='DNS'; 8='Service Bindings'
    9='ODBC DSNs'; 10='Inter-App'; 11='SMB / UNC'; 12='Firewall'; 13='Load Balancer'
}

foreach ($entry in $checks) {
    $num = $entry.Num
    try {
        $res = & $entry.Fn
    } catch {
        $res = New-CheckResult -Number $num -Name $checkNames[$num] -Status 'ISSUE FOUND' -Findings @(
            [PSCustomObject]@{ Type='Exception'; Detail = "$($_.Exception.Message)" }
        )
        Write-WarnLine ("Check {0} threw: {1}" -f $num, $_.Exception.Message)
        Write-StatusLine 'ISSUE FOUND'
    }
    $Script:Results.Add($res) | Out-Null
}

# =============================================================================
# Summary
# =============================================================================

$sorted = $Script:Results | Sort-Object CheckNumber

$summaryLines = New-Object System.Collections.Generic.List[string]
function Add-Sum { param([string]$Line) $summaryLines.Add($Line) | Out-Null }

Write-Host ''
Write-Host '================================================================================' -ForegroundColor Cyan
Write-Host (' DISCOVERY SUMMARY - {0}' -f $Script:HostName) -ForegroundColor Cyan
Write-Host '================================================================================' -ForegroundColor Cyan
Write-Host ''
Add-Sum '================================================================================'
Add-Sum (" DISCOVERY SUMMARY - {0}" -f $Script:HostName)
Add-Sum '================================================================================'
Add-Sum ''

foreach ($r in $sorted) {
    $extra = ''
    if ($r.Status -eq 'ISSUE FOUND' -and $r.Findings) {
        $extra = "    <- {0} finding(s)" -f @($r.Findings).Count
    }
    $line = ("  [{0:D2}] {1,-22}  {2}{3}" -f $r.CheckNumber, $r.CheckName, $r.Status, $extra)
    Write-Host $line -ForegroundColor (Get-StatusColor $r.Status)
    Add-Sum $line
}

$clean   = @($sorted | Where-Object { $_.Status -eq 'CHECKED-CLEAN' }).Count
$issue   = @($sorted | Where-Object { $_.Status -eq 'ISSUE FOUND' }).Count
$na      = @($sorted | Where-Object { $_.Status -eq 'N/A' }).Count
$manual  = @($sorted | Where-Object { $_.Status -eq 'MANUAL' }).Count
$partial = @($sorted | Where-Object { $_.Status -eq 'PARTIAL' }).Count
$notrun  = @($sorted | Where-Object { $_.Status -eq 'Not Run' }).Count

Write-Host ''
Add-Sum ''
$tally = @(
    "  Checked-Clean:  $clean"
    "  Issue Found:    $issue"
    "  N/A / Skipped:  $na"
    "  Manual:         $manual"
    "  Partial:        $partial"
    "  Not Run:        $notrun"
)
foreach ($t in $tally) {
    Write-Host $t
    Add-Sum $t
}

Write-Host ''
Write-Host ('  Evidence folder: {0}' -f $Script:OutputDir) -ForegroundColor DarkCyan
Add-Sum ''
Add-Sum ("  Evidence folder: {0}" -f $Script:OutputDir)
$summaryFile = Join-Path $Script:OutputDir '_summary.txt'
Add-Sum ("  Summary file:    {0}" -f $summaryFile)
Write-Host ('  Summary file:    {0}' -f $summaryFile) -ForegroundColor DarkCyan
Write-Host ''
Add-Sum ''
$action = @(
    '  ACTION REQUIRED:'
    '  -> Update the Discovery sheet in the audit workbook for this app'
    '  -> Set Status per check using the results above'
    '  -> Paste evidence folder path into Evidence column for each row'
    '  -> For ISSUE FOUND items - create a row in the Findings sheet'
)
foreach ($a in $action) {
    Write-Host $a -ForegroundColor White
    Add-Sum $a
}
Write-Host '================================================================================' -ForegroundColor Cyan
Add-Sum '================================================================================'

if ($Script:Warnings.Count -gt 0) {
    Write-Host ''
    Write-Host '  Warnings encountered during run:' -ForegroundColor Yellow
    Add-Sum ''
    Add-Sum '  Warnings encountered during run:'
    foreach ($w in ($Script:Warnings | Select-Object -Unique)) {
        Write-Host ('    - {0}' -f $w) -ForegroundColor Yellow
        Add-Sum ('    - ' + $w)
    }
}

try {
    $summaryLines | Out-File -FilePath $summaryFile -Encoding UTF8
} catch {
    Write-Host ('Failed to write summary: {0}' -f $_.Exception.Message) -ForegroundColor Red
}
