## Dot-sourcing file

# mainUpGuard.ps1
$modulesPathUpGuard = "<FILE PATH REDACTED>"
$modulesPathCloudFlare = "<FILE PATH REDACTED>"

# apiUpGuardAuthentication.ps1
function apiUpGuardAuthenticationVariables {
    $envFolderPath = "<FILE PATH REDACTED>"
    $apiKeyUpGuard = "UpGuardKey"

    return $envFolderPath, $apiKeyUpGuard
}

# compareUpGuardCloudFlareDomains.ps1
function compareUpGuardCloudFlareDomainsVariables {
    $excludeList_compareUpGuardCloudFlareDomains = "<DOMAIN EXCLUSIONS REDACTED>"

    return $excludeList_compareUpGuardCloudFlareDomains
}

# getRiskDiffs.ps1 and reportRiskDifferentials.ps1
function getRiskDiffsVariables{
    $differentialPeriod = -3

    return $differentialPeriod
}

# reportNotificationsUpGuard.ps1
function reportNotificationsUpGuardVariables {
    $fromAddress = '<REDACTED>'
    $toAddress = '<REDACTED>'
    #$toAddress = '<REDACTED>'
    $SMTPServer = '<REDACTED>'

    return $SMTPServer, $fromAddress, $toAddress
}

# reportRiskDifferentials.ps1
function reportRiskDifferentialsVariables {
    $fromAddress = '<REDACTED>'
    $toAddress = '<REDACTED>'
    #$toAddress = '<REDACTED>'
    $SMTPServer = '<REDACTED>'

    return $SMTPServer, $fromAddress, $toAddress
}

# reportUpGuardExceptions.ps1
function reportUpGuardExceptionsVariables {
    $fromAddress = '<REDACTED>'
    $toAddress = '<REDACTED>'
    #$toAddress = '<REDACTED>'
    $SMTPServer = '<REDACTED>'

    return $SMTPServer, $fromAddress, $toAddress
}

# reportUpGuardMetrics.ps1
function reportUpGuardMetricsVariables {
    $domainCoverageGreenThreshold = 100
    $domainCoverageAmberThreshold = 95
    $automatedScoreGreenThreshold = 920
    $automatedScoreAmberThreshold = 900
    $lowestDomainScoreGreenThreshold = 900
    $lowestDomainScoreAmberThreshold = 850

    $fromAddress = '<REDACTED>'
    $toAddress = '<REDACTED>'
    #$toAddress = '<REDACTED>'
    $SMTPServer = '<REDACTED>'

    return $domainCoverageGreenThreshold, $domainCoverageAmberThreshold, $automatedScoreGreenThreshold, $automatedScoreAmberThreshold, $lowestDomainScoreGreenThreshold, $lowestDomainScoreAmberThreshold, $SMTPServer, $fromAddress, $toAddress
}
