function reportRiskDifferentials {
    <#
    .SYNOPSIS
        Generates and sends an email report of UpGuard risk differentials.
    .OUTPUTS
        A sent email via SMTP protocol.
    #>

	  [CmdletBinding()]
    [OutputType([Void])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [array]$riskDifferentials
    )
	  
    # Retrieve configuration file values
    $SMTPServer, $fromAddress, $toAddress = reportRiskDifferentialsVariables
    $differentialPeriod = getRiskDiffsVariables

    # Validate risk differentials
    if (-not $riskDifferentials -or $riskDifferentials.Count -eq 0) {
        Write-Warning "No risk differentials to report."
		    return
    }

    try {
		# Construct HTML table
        $table = "<table border='1'><tr>"
        $table += "<th>Risk Category</th><th>Risk Description</th><th>Risk Severity</th><th>Risk Name</th><th>Risk Hostname</th><th>Risk Property</th><th>Risk Expected</th><th>Risk Date A</th><th>Risk Date B</th><th>Risk Status A</th><th>Risk Status B</th><th>Risk Meta Value A</th><th>Risk Meta Value B</th></tr>"
    
        foreach ($item in $riskDifferentials) {
            $table += "<tr>"
            $table += "<td>$($item.riskCategory)</td>"
            $table += "<td>$($item.riskDescription)</td>"
            $table += "<td>$($item.riskSeverityName)</td>"
            $table += "<td>$($item.riskName)</td>"
            $table += "<td>$($item.riskHostname)</td>"
            $table += "<td>$($item.riskProperty)</td>"
            $table += "<td>$($item.riskExpected)</td>"
            $table += "<td>$($item.riskDateA)</td>"
            $table += "<td>$($item.riskDateB)</td>"
            $table += "<td>$($item.riskStatusA)</td>"
            $table += "<td>$($item.riskStatusB)</td>"
            $table += "<td>$($item.riskMetaValueA)</td>"
            $table += "<td>$($item.riskMetaValueB)</td>"
            $table += "</tr>"
        }
    
        $table += "</table>"
    
    $body = @"
<html>  
	<body>
		<b><u>UpGuard Risk Differentials</b></u>
		<br />
		<br />
		The following is an automated report of the risk differentials in the last $differentialPeriod days period:
		<br />
		<br />
		$table
		<br />
		<br />
	</body>  
</html>  
"@

    # Email results
		$params = @{ 
		    Body = $body 
		    BodyAsHtml = $true
			  Subject = "UpGuard Risk Differentials"
			  From = $fromAddress
			  To = $toAddress
			  SmtpServer = $SMTPServer
			  Port = 25
		}
		 
		Send-MailMessage @params   
    }

	catch {
      Write-Error "An error occurred while sending the email: $_"
  }
}
