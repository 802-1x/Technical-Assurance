function reportUpGuardExceptions {
    <#
    .SYNOPSIS
        Generates and sends an email report of UpGuard exceptions, including missing domains and vulnerabilities.
    .OUTPUTS
        A sent email via SMTP protocol.
    #>

    [CmdletBinding()]
    [OutputType([Void])]
    param (
        [Parameter(Mandatory = $false)]
        [array]$missingDomainsFromUpGuard,

		    [Parameter(Mandatory = $false)]
        [array]$vulnerabilitiesUpGuard
    )

    # Retrieve configuration file values
    $SMTPServer, $fromAddress, $toAddress = reportUpGuardExceptionsVariables

    # Verifying domain consistency between CloudFlare and UpGuard
    if ($missingDomainsFromUpGuard) {
		    $table = "<table border='1'><tr>"
   		  foreach ($item in $missingDomainsFromUpGuard) {
            $table += "<tr>$item</tr>"
   		  }

        $table += "</tr></table>"

$body = @"
<html>  
	<body>
		<b><u>Missing Domains From UpGuard</b></u>
		<br />
		<br />
		The following domains are configured within CloudFlare, but are missing from UpGuard:
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
			      Subject = "Missing Domains from UpGuard"
			      From = $fromAddress
			      To = $toAddress
			      SmtpServer = $SMTPServer
			      Port = 25
		    }
		 
		    Send-MailMessage @params
    }

	  # Vulnerabilities reporting from UpGuard
    if ($vulnerabilitiesUpGuard) {
		    $criticalVulnerabilitiesUpGuard = $vulnerabilitiesUpGuard | Where-Object {$_.epssScore -ge 0.2 -and $_.cveSeverity -ge 6}
		    $highVulnerabilitiesUpGuard = $vulnerabilitiesUpGuard | Where-Object {$_.epssScore -lt 0.2 -and $_.cveSeverity -ge 6}
		    $mediumVulnerabilitiesUpGuard = $vulnerabilitiesUpGuard | Where-Object {$_.epssScore -ge 0.2 -and $_.cveSeverity -lt 6}
		    $lowVulnerabilitiesUpGuard = $vulnerabilitiesUpGuard | Where-Object {$_.epssScore -lt 0.2 -and $_.cveSeverity -lt 6}

    if ($criticalVulnerabilitiesUpGuard -or $highVulnerabilitiesUpGuard) {

        if ($criticalVulnerabilitiesUpGuard) {
				    $table1 = "<table border='1'><tr>"
				    $table1 += "<th>Hostname</th><th>IP Addresses</th><th>CVE</th><th>Description</th><th>CVE Severity</th><th>EPSS Score</th></tr>"
			
				    foreach ($item in $criticalVulnerabilitiesUpGuard) {
					      $table1 += "<tr>"
					      $table1 += "<td>$($item.hostname)</td>"
					      $table1 += "<td>$($item.ipAddresses -join ', ')</td>"
				      	$table1 += "<td>$($item.cve)</td>"
			      		$table1 += "<td>$($item.description)</td>"
			      		$table1 += "<td>$($item.cveSeverity)</td>"
				      	$table1 += "<td>$($item.epssScore)</td>"
			      		$table1 += "</tr>"
				    }
			
				    $table1 += "</table>"
        }
			
			  # High Vulnerabilities Table
		  	if ($highVulnerabilitiesUpGuard) {
			      $table2 = "<table border='1'><tr>"
			    	$table2 += "<th>Hostname</th><th>IP Addresses</th><th>CVE</th><th>Description</th><th>CVE Severity</th><th>EPSS Score</th></tr>"
			
				    foreach ($item in $highVulnerabilitiesUpGuard) {
					      $table2 += "<tr>"
					      $table2 += "<td>$($item.hostname)</td>"
					      $table2 += "<td>$($item.ipAddresses -join ', ')</td>"
				      	$table2 += "<td>$($item.cve)</td>"
					      $table2 += "<td>$($item.description)</td>"
					      $table2 += "<td>$($item.cveSeverity)</td>"
				      	$table2 += "<td>$($item.epssScore)</td>"
				      	$table2 += "</tr>"
				    }
			
			    	$table2 += "</table>"
        }
			
			  # Medium Vulnerabilities Table
			  if ($mediumVulnerabilitiesUpGuard) {
				    $table3 = "<table border='1'><tr>"
				    $table3 += "<th>Hostname</th><th>IP Addresses</th><th>CVE</th><th>Description</th><th>CVE Severity</th><th>EPSS Score</th></tr>"
			
				    foreach ($item in $mediumVulnerabilitiesUpGuard) {
					      $table3 += "<tr>"
					      $table3 += "<td>$($item.hostname)</td>"
				      	$table3 += "<td>$($item.ipAddresses -join ', ')</td>"
				      	$table3 += "<td>$($item.cve)</td>"
				      	$table3 += "<td>$($item.description)</td>"
				      	$table3 += "<td>$($item.cveSeverity)</td>"
				      	$table3 += "<td>$($item.epssScore)</td>"
			      		$table3 += "</tr>"
				    }
			
				    $table3 += "</table>"
        }
			
			  # Low Vulnerabilities Table
			  if ($lowVulnerabilitiesUpGuard) {
				    $table4 = "<table border='1'><tr>"
				    $table4 += "<th>Hostname</th><th>IP Addresses</th><th>CVE</th><th>Description</th><th>CVE Severity</th><th>EPSS Score</th></tr>"
			
				    foreach ($item in $lowVulnerabilitiesUpGuard) {
					      $table4 += "<tr>"
					      $table4 += "<td>$($item.hostname)</td>"
				      	$table4 += "<td>$($item.ipAddresses -join ', ')</td>"
				      	$table4 += "<td>$($item.cve)</td>"
				      	$table4 += "<td>$($item.description)</td>"
				      	$table4 += "<td>$($item.cveSeverity)</td>"
				      	$table4 += "<td>$($item.epssScore)</td>"
				      	$table4 += "</tr>"
            }
			
				    $table4 += "</table>"
        }

$body = @"
<html>  
  <body>
  	  This email is triggered when there are Critical or High UpGuard vulnerabilities.
  	  <br />
  	  <br />
	  <b><u>Critical</b></u>
	  <br />
	  <br />
	  $table1
	  <br />
	  <br />
	  <b><u>High</b></u>
	  <br />
	  <br />
	  $table2
	  <br />
	  <br />
	  <b><u>Medium</b></u>
	  <br />
	  <br />
	  $table3
	  <br />
	  <br />
	  <b><u>Low</b></u>
	  <br />
	  <br />
	  $table4
	  <br />
	  <br />
  </body>  
</html>  
"@

        # Email results
        $params = @{ 
            Body = $body 
			      BodyAsHtml = $true
			      Subject = "Critical or High UpGuard Vulnerabilities"
			      From = $fromAddress
			      To = $toAddress
			      SmtpServer = $SMTPServer
			      Port = 25
		    }
		
		    Send-MailMessage @params
		    }
    }
}
