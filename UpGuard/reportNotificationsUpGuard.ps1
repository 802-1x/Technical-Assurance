function reportNotificationsUpGuard {
    <#
    .SYNOPSIS
        Generates and sends an email report of UpGuard notifications.
    .OUTPUTS
        A sent email via SMTP protocol.
    #>

    [CmdletBinding()]
    [OutputType([Void])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [array]$notificationsUpGuard
    )

	# Retrieve configuration file values
	$SMTPServer, $fromAddress, $toAddress = reportNotificationsUpGuardVariables

	# Validate notifications
	if (-not $notificationsUpGuard -or $notificationsUpGuard.Count -eq 0) {
		Write-Warning "No notifications to report."
		return
	}
	
	try {
		# Construct HTML table
        $table = "<table border='1'><tr>"
        $table += "<th>Notification ID</th><th>Type</th><th>Description</th><th>Occurred At</th><th>Context</th></tr>"
    
        foreach ($item in $notificationsUpGuard) {
            $table += "<tr>"
            $table += "<td>$($item.notification_id)</td>"
            $table += "<td>$($item.type)</td>"
            $table += "<td>$($item.description)</td>"
            $table += "<td>$($item.occurred_at)</td>"
            $table += "<td>$($item.context)</td>"
            $table += "</tr>"
        }
    
        $table += "</table>"
    
		$body = @"
<html>  
	<body>
		<b><u>UpGuard Notifications</b></u>
		<br />
		<br />
		The following is an automated report of the main SaaS portal landing page notifications:
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
			Subject = "UpGuard Landing Page Notifications"
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
