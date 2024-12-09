function getRiskDiffs {
    <#
    .SYNOPSIS
        Retrieves risk differentials from UpGuard API.
    .OUTPUTS
        An array of PSCustomObjects representing the risk differentials.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
        [hashtable]$headers
    )

    # Retrieve configuration file values
	$differentialPeriod = getRiskDiffsVariables

    # Validate headers
    if (-not $headers -or -not $headers.ContainsKey("Authorization")) {
        throw "Headers must contain an 'Authorization' key and cannot be null or empty."
    }

    $currentDate = Get-Date
    $oneDayAgo = $currentDate.AddDays($differentialPeriod)
    $rfc3339FormattedDate = $oneDayAgo.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffK")

    try {
        $uri = "https://cyber-risk.upguard.com/api/public/risks/diff?start_date=$rfc3339FormattedDate"
        $riskDifferenceResponse = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ErrorAction Stop

        $riskDifferentials = @()

        # Process the response
        foreach ($riskItem in $riskDifferenceResponse.risksIntroduced.diffs) {
            foreach ($item in $riskItem.cloudscanDiffs) {
                $obj = [PSCustomObject]@{
                    riskCategory = if ($riskItem.category) { $riskItem.category } else { $null }
                    riskDescription = if ($riskItem.description) { $riskItem.description } else { $null }
                    riskSeverityName = if ($riskItem.severityName) { $riskItem.severityName } else { $null }
                    riskName = if ($riskItem.name) { $riskItem.name } else { $null }
                    riskHostname = if ($item.Hostname) { $item.Hostname } else { $null }
                    riskProperty = if ($item.Property) { $item.Property } else { $null }
                    riskExpected = if ($item.Expected) { $item.Expected } else { $null }
                    riskDateA = if ($item.DateA) { $item.DateA } else { $null }
                    riskDateB = if ($item.DateB) { $item.DateB } else { $null }
                    riskStatusA = if ($item.StatusA) { $item.StatusA } else { $null }
                    riskStatusB = if ($item.StatusB) { $item.StatusB } else { $null }
                    riskMetaValueA = if ($item.MetaValueA) { $item.MetaValueA } else { $null }
                    riskMetaValueB = if ($item.MetaValueB) { $item.MetaValueB } else { $null }
                }

                $riskDifferentials += $obj
            }
        }

        return $riskDifferentials
    }

    catch {
        Write-Error "An error occurred while retrieving risk differentials: $_"
        return $null
    }
}
