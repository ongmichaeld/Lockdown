#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Lockdown baseline for a standalone Windows 11 24H2 box that needs Wi-Fi
  for a small, explicit set of destinations (SDR loading + allowlisted sites).

.DESCRIPTION
  1. Default-deny firewall (both directions) written to the LOCAL GROUP POLICY
     store, with local rules ignored, so installers/updaters cannot add exceptions.
  2. Narrow allow rules built from the CONFIG block below.
  3. Suppresses OS / Chrome / Edge / Office / Acrobat updaters and telemetry.
  4. Does NOT touch your existing Chrome/Edge URLAllowlist / URLBlocklist.

.USAGE
  .\Lockdown.ps1 -Mode Audit      # read-only: status + what is being blocked (default)
  .\Lockdown.ps1 -Mode Apply      # apply everything (reboot afterwards)
  .\Lockdown.ps1 -Mode Rollback   # remove firewall lockdown, restore services/tasks
#>
[CmdletBinding()]
param([ValidateSet('Audit','Apply','Rollback')][string]$Mode = 'Audit')

# =====================  CONFIG - EDIT THIS  =====================
$Cfg = @{
  DnsServers       = @()   # e.g. @('192.168.1.1'). Needed if browsers use hostnames.
  NtpServers       = @()   # optional, e.g. @('192.168.1.1')
  WebAddresses     = @()   # IPs/CIDRs browsers may reach, e.g. @('203.0.113.10','198.51.100.0/24')
  WebFqdns         = @()   # optional hostnames (uses firewall dynamic keywords; TEST this, see notes)
  WebPorts         = @('80','443')
  Browsers         = @('C:\Program Files\Google\Chrome\Application\chrome.exe',
                       'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe')
  # One hashtable per SDR rule. Direction: Outbound or Inbound.
  SdrRules         = @(
    # @{ Name='SDR load'; Direction='Outbound'; Protocol='TCP'; RemoteAddress='192.168.1.50'; RemotePort='22'; LocalPort='Any'; Program='Any' }
    # @{ Name='SDR data in'; Direction='Inbound'; Protocol='UDP'; RemoteAddress='192.168.1.50'; RemotePort='Any'; LocalPort='49152-49200'; Program='C:\Path\to\sdr.exe' }
  )
  EnableIPv6       = $false  # $false: disables IPv6 stack + Teredo/6to4/ISATAP (reboot needed)
  AllowIcmpEchoOut = $false
  AuditDrops       = $true   # log WFP drops (Security event 5157 names the process)
}
# ================================================================

$Group    = 'SYSLOCK'
$Store    = 'localhost'                  # Local Group Policy store
$StateDir = 'C:\ProgramData\SysLock'
$State    = Join-Path $StateDir 'state.json'
$FwLog    = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
New-Item -ItemType Directory -Path $StateDir -Force | Out-Null

function Say($m, $c = 'Cyan') { Write-Host "[*] $m" -ForegroundColor $c }

function Set-Reg($Path, $Name, $Value, $Type = 'DWord') {
  if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
  New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

function Invoke-ForUserHives([scriptblock]$Action) {
  Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } |
    ForEach-Object { & $Action "Registry::HKEY_USERS\$($_.PSChildName)" }
  $def = 'C:\Users\Default\NTUSER.DAT'
  if (Test-Path $def) {
    reg load HKU\SysLockDefault $def | Out-Null
    try { & $Action 'Registry::HKEY_USERS\SysLockDefault' }
    finally { [gc]::Collect(); Start-Sleep 1; reg unload HKU\SysLockDefault | Out-Null }
  }
}

function New-FwRule {
  param($Name, $Direction, $Protocol = 'Any', $Remote = 'Any', $RemotePort = 'Any',
        $LocalPort = 'Any', $Program = 'Any', $Service = $null, $IcmpType = $null, $Dyn = $null)
  $h = @{ PolicyStore = $Store; DisplayName = "$Group - $Name"; Direction = $Direction
          Action = 'Allow'; Profile = 'Any'; Enabled = 'True' }
  if ($Protocol   -ne 'Any') { $h.Protocol      = $Protocol }
  if ($Remote     -ne 'Any') { $h.RemoteAddress = [string[]]$Remote }
  if ($RemotePort -ne 'Any') { $h.RemotePort    = [string[]]$RemotePort }
  if ($LocalPort  -ne 'Any') { $h.LocalPort     = [string[]]$LocalPort }
  if ($Program    -ne 'Any') { $h.Program       = $Program }
  if ($Service)              { $h.Service       = $Service }
  if ($IcmpType)             { $h.IcmpType      = [string[]]$IcmpType }
  if ($Dyn)                  { $h.RemoteDynamicKeywordAddresses = $Dyn }
  New-NetFirewallRule @h | Out-Null
}

function Remove-SysLockRules {
  Remove-NetFirewallRule -PolicyStore $Store -DisplayName "$Group - *" -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------- AUDIT
function Invoke-Audit {
  Say 'Firewall profiles (Local GPO store):'
  Get-NetFirewallProfile -PolicyStore $Store |
    Select Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowLocalFirewallRules, LogBlocked | Format-Table -Auto
  Say 'SYSLOCK allow rules:'
  Get-NetFirewallRule -PolicyStore $Store -ErrorAction SilentlyContinue |
    Where-Object DisplayName -like "$Group - *" | Select DisplayName, Direction, Enabled | Format-Table -Auto
  Say 'Live TCP connections (non-loopback):'
  Get-NetTCPConnection -State Established, SynSent -ErrorAction SilentlyContinue |
    Where-Object { $_.RemoteAddress -notin '127.0.0.1', '::1' } |
    Select LocalPort, RemoteAddress, RemotePort, State,
      @{n = 'Process'; e = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } } | Format-Table -Auto
  Say 'Top blocked destinations (pfirewall.log):'
  if (Test-Path $FwLog) {
    Get-Content $FwLog | Select-String ' DROP ' | ForEach-Object {
      $f = $_.Line -split ' '
      [pscustomobject]@{ Proto = $f[3]; Dst = $f[5]; DPort = $f[7]; Dir = $f[16] } } |
      Group-Object Proto, Dst, DPort, Dir | Sort-Object Count -Descending | Select -First 25 Count, Name | Format-Table -Auto
  } else { Say 'No firewall log yet.' 'Yellow' }
  Say 'Top blocked apps (Security 5157):'
  try {
    Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5157 } -MaxEvents 3000 -ErrorAction Stop | ForEach-Object {
      $d = @{}; ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
      [pscustomobject]@{ App = $d.Application; Dst = $d.DestAddress; Port = $d.DestPort } } |
      Group-Object App, Dst, Port | Sort-Object Count -Descending | Select -First 25 Count, Name | Format-Table -Auto
  } catch { Say 'No 5157 events (auditing off or nothing blocked yet).' 'Yellow' }
}

# ---------------------------------------------------------------- ROLLBACK
function Invoke-Rollback {
  Say 'Removing SYSLOCK rules and resetting profiles to Not Configured'
  Remove-SysLockRules
  Set-NetFirewallProfile -PolicyStore $Store -Profile Domain, Private, Public `
    -DefaultInboundAction NotConfigured -DefaultOutboundAction NotConfigured `
    -AllowLocalFirewallRules NotConfigured -AllowLocalIPsecRules NotConfigured
  if (Test-Path $State) {
    $s = Get-Content $State -Raw | ConvertFrom-Json
    foreach ($p in $s.Services.PSObject.Properties) {
      Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\$($p.Name)" 'Start' ([int]$p.Value)
    }
    foreach ($t in $s.Tasks) {
      $path = (Split-Path $t -Parent) + '\'; $name = Split-Path $t -Leaf
      Enable-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction SilentlyContinue | Out-Null
    }
    Say 'Services/tasks restored from saved state.'
  }
  Say "Registry policy values are NOT auto-reverted. Restore from the .reg backups in $StateDir" 'Yellow'
}

# ---------------------------------------------------------------- APPLY
function Invoke-Apply {
  # ---- backups
  $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
  netsh advfirewall export "$StateDir\fw-$stamp.wfw" | Out-Null
  foreach ($k in 'HKLM\SOFTWARE\Policies', 'HKLM\SYSTEM\CurrentControlSet\Services') {
    reg export $k "$StateDir\$(($k -replace '\\','_'))-$stamp.reg" /y | Out-Null
  }
  Say "Backups written to $StateDir"

  # ---- FIREWALL
  Say 'Configuring firewall (default deny, local rules ignored)'
  Set-NetFirewallProfile -PolicyStore $Store -Profile Domain, Private, Public -Enabled True `
    -DefaultInboundAction Block -DefaultOutboundAction Block `
    -AllowLocalFirewallRules False -AllowLocalIPsecRules False -NotifyOnListen False `
    -LogBlocked True -LogAllowed False -LogFileName $FwLog -LogMaxSizeKilobytes 32767
  Remove-SysLockRules
  $svchost = "$env:SystemRoot\System32\svchost.exe"

  New-FwRule 'DHCP out' Outbound UDP -LocalPort 68 -RemotePort 67 -Program $svchost -Service Dhcp
  New-FwRule 'DHCP in'  Inbound  UDP -LocalPort 68 -RemotePort 67 -Program $svchost -Service Dhcp
  if ($Cfg.EnableIPv6) {
    New-FwRule 'ICMPv6 ND out' Outbound ICMPv6 -IcmpType @('133','134','135','136')
    New-FwRule 'ICMPv6 ND in'  Inbound  ICMPv6 -IcmpType @('133','134','135','136')
    New-FwRule 'DHCPv6 out' Outbound UDP -LocalPort 546 -RemotePort 547 -Program $svchost -Service Dhcp
  }
  if ($Cfg.DnsServers.Count) {
    New-FwRule 'DNS udp' Outbound UDP -Remote $Cfg.DnsServers -RemotePort 53 -Program $svchost -Service Dnscache
    New-FwRule 'DNS tcp' Outbound TCP -Remote $Cfg.DnsServers -RemotePort 53 -Program $svchost -Service Dnscache
  }
  if ($Cfg.NtpServers.Count) {
    New-FwRule 'NTP' Outbound UDP -Remote $Cfg.NtpServers -RemotePort 123 -Program $svchost -Service w32time
  }
  if ($Cfg.AllowIcmpEchoOut) { New-FwRule 'ICMP echo out' Outbound ICMPv4 -IcmpType 8 }

  foreach ($r in $Cfg.SdrRules) {
    New-FwRule "SDR - $($r.Name)" $r.Direction $r.Protocol $r.RemoteAddress $r.RemotePort $r.LocalPort $r.Program
  }

  $browsers = $Cfg.Browsers | Where-Object { Test-Path $_ }
  foreach ($b in $browsers) {
    $leaf = Split-Path $b -Leaf
    if ($Cfg.WebAddresses.Count) {
      New-FwRule "Web $leaf (IP)" Outbound TCP -Remote $Cfg.WebAddresses -RemotePort $Cfg.WebPorts -Program $b
    }
    if ($Cfg.WebFqdns.Count) {
      try {
        $ids = foreach ($f in $Cfg.WebFqdns) {
          $id = '{' + [guid]::NewGuid().ToString() + '}'
          New-NetFirewallDynamicKeywordAddress -Id $id -Keyword $f -AutoResolve $true | Out-Null
          $id
        }
        New-FwRule "Web $leaf (FQDN)" Outbound TCP -RemotePort $Cfg.WebPorts -Program $b -Dyn ($ids -join ',')
      } catch { Say "FQDN rules failed ($($_.Exception.Message)). Use WebAddresses instead." 'Yellow' }
    }
  }

  if ($Cfg.AuditDrops) {
    auditpol /set /subcategory:"Filtering Platform Packet Drop" /failure:enable | Out-Null
  }

  # ---- IPv6
  if (-not $Cfg.EnableIPv6) {
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisabledComponents' 255
    try { Set-NetTeredoConfiguration -Type Disabled; Set-Net6to4Configuration -State Disabled; Set-NetIsatapConfiguration -State Disabled } catch {}
  }

  # ---- WINDOWS POLICY (written straight to HKLM\...\Policies)
  Say 'Windows policy settings'
  $P = 'HKLM:\SOFTWARE\Policies\Microsoft'
  $win = @(
    @("$P\Windows\WindowsUpdate", 'DoNotConnectToWindowsUpdateInternetLocations', 1),
    @("$P\Windows\WindowsUpdate", 'SetDisableUXWindowsUpdateAccess', 1),
    @("$P\Windows\WindowsUpdate\AU", 'NoAutoUpdate', 1),
    @("$P\Windows\DeliveryOptimization", 'DODownloadMode', 100),
    @("$P\Windows\DataCollection", 'AllowTelemetry', 0),
    @("$P\Windows\DataCollection", 'DoNotShowFeedbackNotifications', 1),
    @("$P\Windows\NetworkConnectivityStatusIndicator", 'NoActiveProbe', 1),
    @("$P\Windows\NetworkConnectivityStatusIndicator", 'DisablePassivePolling', 1),
    @("$P\Windows\System", 'EnableSmartScreen', 0),
    @("$P\Windows\System", 'EnableActivityFeed', 0),
    @("$P\Windows\System", 'PublishUserActivities', 0),
    @("$P\Windows\System", 'UploadUserActivities', 0),
    @("$P\Windows Defender\Spynet", 'SpynetReporting', 0),
    @("$P\Windows Defender\Spynet", 'SubmitSamplesConsent', 2),
    @("$P\MRT", 'DontReportInfectionInformation', 1),
    @("$P\Windows\Windows Error Reporting", 'Disabled', 1),
    @("$P\SQMClient\Windows", 'CEIPEnable', 0),
    @("$P\Windows\AppCompat", 'AITEnable', 0),
    @("$P\Windows\AppCompat", 'DisableInventory', 1),
    @("$P\Windows\CloudContent", 'DisableWindowsConsumerFeatures', 1),
    @("$P\Windows\Windows Search", 'DisableWebSearch', 1),
    @("$P\Windows\Windows Search", 'ConnectedSearchUseWeb', 0),
    @("$P\Windows\Windows Search", 'AllowCortana', 0),
    @("$P\Windows\WindowsCopilot", 'TurnOffWindowsCopilot', 1),
    @("$P\Dsh", 'AllowNewsAndInterests', 0),
    @("$P\WindowsStore", 'AutoDownload', 2),
    @("$P\PushToInstall", 'DisablePushToInstall', 1),
    @("$P\Windows\LocationAndSensors", 'DisableLocation', 1),
    @("$P\Windows\OneDrive", 'DisableFileSyncNGSC', 1),
    @("$P\Windows NT\DNSClient", 'EnableMulticast', 0),
    @('HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config', 'AutoConnectAllowedOEM', 0)
  )
  foreach ($e in $win) { Set-Reg $e[0] $e[1] $e[2] }

  # ---- CHROME / EDGE hardening + updaters (URL allow/blocklists untouched)
  Say 'Chrome / Edge hardening'
  $C = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
  $EdgeKey = "$P\Edge"
  $chrome = @(
    @('ComponentUpdatesEnabled', 0), @('MetricsReportingEnabled', 0), @('SafeBrowsingProtectionLevel', 0),
    @('BackgroundModeEnabled', 0), @('SyncDisabled', 1), @('BrowserSignin', 0), @('NetworkPredictionOptions', 2),
    @('BuiltInDnsClientEnabled', 0), @('CloudReportingEnabled', 0), @('PromotionalTabsEnabled', 0),
    @('UrlKeyedAnonymizedDataCollectionEnabled', 0), @('SearchSuggestEnabled', 0), @('QuicAllowed', 0)
  )
  foreach ($e2 in $chrome) { Set-Reg $C $e2[0] $e2[1] }
  Set-Reg $C 'DnsOverHttpsMode' 'off' 'String'
  $edge = @(
    @('DiagnosticData', 0), @('MetricsReportingEnabled', 0), @('SmartScreenEnabled', 0), @('BackgroundModeEnabled', 0),
    @('StartupBoostEnabled', 0), @('SyncDisabled', 1), @('BrowserSignin', 0), @('NetworkPredictionOptions', 2),
    @('BuiltInDnsClientEnabled', 0), @('EdgeShoppingAssistantEnabled', 0), @('HubsSidebarEnabled', 0),
    @('NewTabPageContentEnabled', 0), @('ShowRecommendationsEnabled', 0), @('SearchSuggestEnabled', 0),
    @('PersonalizationReportingEnabled', 0), @('EdgeFollowEnabled', 0), @('QuicAllowed', 0)
  )
  foreach ($e2 in $edge) { Set-Reg $EdgeKey $e2[0] $e2[1] }
  Set-Reg $EdgeKey 'DnsOverHttpsMode' 'off' 'String'

  # updaters: 0 = updates disabled
  $gu = 'HKLM:\SOFTWARE\Policies\Google\Update'
  Set-Reg $gu 'UpdateDefault' 0; Set-Reg $gu 'AutoUpdateCheckPeriodMinutes' 0
  Set-Reg $gu 'Update{8A69D345-D564-463C-AFF1-A69D9E530F96}' 0
  $eu = "$P\EdgeUpdate"
  Set-Reg $eu 'UpdateDefault' 0; Set-Reg $eu 'AutoUpdateCheckPeriodMinutes' 0
  Set-Reg $eu 'Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}' 0   # Edge stable
  Set-Reg $eu 'Update{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' 0   # WebView2

  # ---- OFFICE 2024
  Say 'Office hardening'
  $o = 'HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate'
  Set-Reg $o 'enableautomaticupdates' 0; Set-Reg $o 'hideenabledisableupdates' 1
  Invoke-ForUserHives {
    param($root)
    $b = "$root\Software\Policies\Microsoft\office"
    foreach ($n in 'disconnectedstate', 'usercontentdisabled', 'downloadcontentdisabled', 'controllerconnectedservicesenabled') {
      Set-Reg "$b\16.0\common\privacy" $n 2
    }
    Set-Reg "$b\common\clienttelemetry" 'sendtelemetry' 3
    Set-Reg "$b\16.0\common" 'qmenable' 0
    Set-Reg "$b\16.0\common" 'sendcustomerdata' 0
    Set-Reg "$b\16.0\common\internet" 'useonlinecontent' 0
  }

  # ---- ACROBAT
  Say 'Acrobat hardening'
  $a = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'
  foreach ($n in 'bUpdater') { Set-Reg $a $n 0 }
  Set-Reg $a 'bUsageMeasurement' 0
  foreach ($n in 'bAcroSuppressUpsell', 'bToggleAdobeDocumentServices', 'bToggleAdobeSign',
                 'bToggleWebConnectors', 'bToggleShareFeature', 'bToggleAdobeReview') { Set-Reg $a $n 1 }

  # ---- SERVICES + SCHEDULED TASKS (state saved for rollback)
  Say 'Disabling updater/telemetry services and tasks'
  $saved = @{ Services = @{}; Tasks = @() }
  # wuauserv is deliberately left alone: wusa/DISM offline patching may need it on demand.
  foreach ($s in 'gupdate', 'gupdatem', 'edgeupdate', 'edgeupdatem', 'AdobeARMservice', 'AGSService', 'AGMService',
                 'DoSvc', 'DiagTrack', 'dmwappushservice') {
    $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$s"
    if (Test-Path $k) {
      $saved.Services[$s] = (Get-ItemProperty $k).Start
      Set-Reg $k 'Start' 4
      Stop-Service $s -Force -ErrorAction SilentlyContinue
    }
  }
  $patterns = '\GoogleUpdateTaskMachine*', '\MicrosoftEdgeUpdateTaskMachine*', '\Adobe Acrobat Update Task',
              '\Microsoft\Office\*', '\Microsoft\Windows\Application Experience\*',
              '\Microsoft\Windows\Customer Experience Improvement Program\*',
              '\Microsoft\Windows\Windows Error Reporting\*', '\Microsoft\Windows\Feedback\*',
              '\Microsoft\Windows\WindowsUpdate\*', '\Microsoft\Windows\UpdateOrchestrator\*'
  foreach ($t in Get-ScheduledTask -ErrorAction SilentlyContinue) {
    $full = "$($t.TaskPath)$($t.TaskName)"
    if ($t.State -ne 'Disabled' -and ($patterns | Where-Object { $full -like $_ })) {
      try { Disable-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName -ErrorAction Stop | Out-Null; $saved.Tasks += $full } catch {}
    }
  }
  $saved | ConvertTo-Json -Depth 4 | Set-Content $State
  gpupdate /force | Out-Null
  Say 'Done. Reboot, use the system for a day, then run -Mode Audit to see what is still being blocked.' 'Green'
}

switch ($Mode) { 'Audit' { Invoke-Audit } 'Apply' { Invoke-Apply } 'Rollback' { Invoke-Rollback } }