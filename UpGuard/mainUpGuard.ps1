# Dot-sourced configurable variables
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $scriptDir
. $scriptDir\variablesUpGuard.ps1

try {
    # Import UpGuard modules (delivery split for easier troubleshooting)
    $moduleName = $modulesPathUpGuard + "variablesUpGuard.ps1"; Import-Module -Name $moduleName -Force
    $moduleName = $modulesPathUpGuard + "apiUpGuardAuthentication.ps1"; Import-Module -Name $moduleName -Force
    $moduleName = $modulesPathUpGuard + "initialDomainCompliance.ps1"; Import-Module -Name $moduleName -Force
    $moduleName = $modulesPathUpGuard + "compareUpGuardCloudFlareDomains.ps1"; Import-Module -Name $moduleName -Force
    $moduleName = $modulesPathUpGuard + "notificationsUpGuard.ps1"; Import-Module -Name $moduleName -Force
    $moduleName = $modulesPathUpGuard + "getRiskDiffs.ps1"; Import-Module -Name $moduleName -Force
    $moduleName = $modulesPathUpGuard + "getUpGuardVulnerabilityData.ps1"; Import-Module -Name $moduleName -Force
    $moduleName = $modulesPathUpGuard + "reportUpGuardExceptions.ps1"; Import-Module -Name $moduleName -Force
    $moduleName = $modulesPathUpGuard + "reportUpGuardMetrics.ps1"; Import-Module -Name $moduleName -Force
    $moduleName = $modulesPathUpGuard + "reportNotificationsUpGuard.ps1"; Import-Module -Name $moduleName -Force
    $moduleName = $modulesPathUpGuard + "reportRiskDifferentials.ps1"; Import-Module -Name $moduleName -Force

    # Import CloudFlare modules for domain coverage in UpGuard comparison (delivery split for easier troubleshooting)
    $moduleName = $modulesPathCloudFlare + "apiCloudFlareAuthentication.ps1"; Import-Module -Name $moduleName -Force
    $moduleName = $modulesPathCloudFlare + "getAllZones.ps1"; Import-Module -Name $moduleName -Force
    $moduleName = $modulesPathCloudFlare + "getDNSRecords.ps1"; Import-Module -Name $moduleName -Force
}

catch {
    Write-Error "One or more modules failed to import: $_"
    exit # Preference to hard fail than give misleading metrics
}

try {
  # API Data gathering and data manipulation
    $headers, $testCase = apiCloudFlareAuthentication; if ($testCase.Success -eq $False) { exit }
    $allZones = getAllZones $headers; if (-not $allZones) { Write-Warning "No zones found in CloudFlare." }
    $dnsRecords = getDNSRecords $headers $allZones
}

catch {
    Write-Error "An error occurred with the CloudFlare processing: $_"
    exit # Preference to hard fail than give misleading metrics
}

# Authenticate with UpGuard API and check headers validity
$headers = apiUpGuardAuthentication
if (-not $headers) {
    Write-Error "Failed to authenticate with UpGuard API."
    exit
}

# Gather data from UpGuard APIs
$automatedScore, $allDomains, $activeDomains, $unmodifiedAverageScore = initialDomainCompliance $headers
$missingDomainsFromUpGuard = compareUpGuardCloudFlareDomains $dnsRecords $allDomains

$notificationsUpGuard = notificationsUpGuard $headers
$riskDifferentials = getRiskDiffs $headers

$vulnerabilitiesUpGuard = getUpGuardVulnerabilityData $headers

try {
    # Reporting
    if ($notificationsUpGuard) { reportNotificationsUpGuard $notificationsUpGuard }
    if ($riskDifferentials) { reportRiskDifferentials $riskDifferentials }
    if ($missingDomainsFromUpGuard -or $vulnerabilitiesUpGuard) { reportUpGuardExceptions $missingDomainsFromUpGuard $vulnerabilitiesUpGuard }

    # reportUpGuardLogging
    reportUpGuardMetrics $activeDomains $missingDomainsFromUpGuard $vulnerabilitiesUpGuard
}

catch {
    Write-Error "An error occurred during reporting: $_"
    exit
}
