function reportUpGuardMetrics {
    <#
    .SYNOPSIS
        Generates and sends an email report of UpGuard metrics.
    .OUTPUTS
        A sent email via SMTP protocol.
    #>

    [CmdletBinding()]
    [OutputType([Void])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [array]$activeDomains,

		[Parameter(Mandatory = $false)]
        [array]$missingDomainsFromUpGuard,

        [Parameter(Mandatory = $false)]
        [array]$vulnerabilitiesUpGuard
    )

    # Retrieve configuration file values
    $domainCoverageGreenThreshold, $domainCoverageAmberThreshold, $automatedScoreGreenThreshold, $automatedScoreAmberThreshold, $lowestDomainScoreGreenThreshold, $lowestDomainScoreAmberThreshold, $SMTPServer, $fromAddress, $toAddress = reportUpGuardMetricsVariables

    # Validate necessary variables
    if (-not $activeDomains -or -not $automatedScore) {
        throw "Required data is missing."
    }

    #Domain Coverage
    $domainCoveragePercentage = ($activeDomains).count / (($missingDomainsFromUpGuard).count + ($activeDomains).count) * 100
    #$domainCoverageThresholdActual = "{0:N2}" -f $domainCoveragePercentage

    if ($domainCoveragePercentage -lt $domainCoverageAmberThreshold) {
        $domainCoverageTrafficLight = "Red"
    } elseif ($domainCoveragePercentage -lt $domainCoverageGreenThreshold) {
        $domainCoverageTrafficLight = "Amber"
    } else {
        $domainCoverageTrafficLight = "Green"
    }
        
    #Automated Score
    if ($automatedScore.automatedScore -lt $automatedScoreAmberThreshold) {
        $automatedScoreTrafficLight = "Red"
    } elseif ($automatedScore.automatedScore -lt $automatedScoreGreenThreshold) {
        $automatedScoreTrafficLight = "Amber"
    } else {
        $automatedScoreTrafficLight = "Green"
    }

    #Lowest Domain Score
    $lowestDomainScore = ($activeDomains | Measure-Object -Property automated_score -Minimum).Minimum

    if ($lowestDomainScore -lt $lowestDomainScoreAmberThreshold) {
        $lowestDomainScoreTrafficLight = "Red"
    } elseif ($lowestDomainScore -lt $lowestDomainScoreGreenThreshold) {
        $lowestDomainScoreTrafficLight = "Amber"`
    } else {
        $lowestDomainScoreTrafficLight = "Green"
    }

    #$totalVulnerabilitiesUpGuard = ($vulnerabilitiesUpGuard).count
    
    $countCriticalVulnerabilitiesUpGuard = ($vulnerabilitiesUpGuard | Where-Object {$_.epssScore -ge 0.2 -and $_.cveSeverity -ge 6}).count
    $countHighVulnerabilitiesUpGuard = ($vulnerabilitiesUpGuard | Where-Object {$_.epssScore -lt 0.2 -and $_.cveSeverity -ge 6}).count
    #$countMediumVulnerabilitiesUpGuard = ($vulnerabilitiesUpGuard | Where-Object {$_.epssScore -ge 0.2 -and $_.cveSeverity -lt 6}).count
    #$countLowVulnerabilitiesUpGuard = ($vulnerabilitiesUpGuard | Where-Object {$_.epssScore -lt 0.2 -and $_.cveSeverity -lt 6}).count
    
    #Critical or High CVE
    $cveTotal = $countCriticalVulnerabilitiesUpGuard + $countHighVulnerabilitiesUpGuard
    if ($cveTotal -eq "0") {
        $cveFindingsTrafficLight = "Green"
    } else {
        $cveFindingsTrafficLight = "Red"
    }

    if ($domainCoverageTrafficLight -eq "Red" -or $automatedScoreTrafficLight -eq "Red" -or $lowestDomainScoreTrafficLight -eq "Red" -or $cveFindingsTrafficLight -eq "Red") {
        $aggregatedUpGuardIndex = "Red"
    } elseif ($domainCoverageTrafficLight -eq "Amber" -or $vautomatedScoreTrafficLightar2 -eq "Amber" -or $lowestDomainScoreTrafficLight -eq "Amber" -or $cveFindingsTrafficLight -eq "Amber") {
        $aggregatedUpGuardIndex = "Amber"
    } else {
        $aggregatedUpGuardIndex = "Green"
    }

$body = @"
<html>  
  <body>
	  <b><u>UpGuard Aggregated Metrics Index</b></u>
	  <br />
	  <br />
	  The aggregated metrics index for UpGuard is: $aggregatedUpGuardIndex
	  <br />
	  <br />
      The domain coverage compliance is: $domainCoverageTrafficLight
      <br />
      The overall UpGuard score is: $automatedScoreTrafficLight
      <br />
      The lowest UpGuard domain score is: $lowestDomainScoreTrafficLight
      <br />
      The Critical or High CVE findings score is: $cveFindingsTrafficLight
    <br />
    <br />
  </body>  
</html>  
"@

    # Email results
    $params = @{ 
		    Body = $body 
		    BodyAsHtml = $true
		    Subject = "UpGuard Aggregated Index Score"
		    From = $fromAddress
		    To = $toAddress
		    SmtpServer = $SMTPServer
		    Port = 25
    }
	 
    Send-MailMessage @params
}
