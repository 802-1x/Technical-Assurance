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
        [hashtable]$headers
    )

    # Retrieve configuration file values
	  $differentialPeriod = getRiskDiffsVariables

    # Validate headers
    if (-not $headers.ContainsKey("Authorization")) {
        throw "Headers must contain an 'Authorization' key."
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
                    riskCategory = $riskItem.category
                    riskDescription = $riskItem.description
                    riskSeverityName = $riskItem.severityName
                    riskName = $riskItem.name
                    riskHostname = $item.Hostname
                    riskProperty = $item.Property
                    riskExpected = $item.Expected
                    riskDateA = $item.DateA
                    riskDateB = $item.DateB
                    riskStatusA = $item.StatusA
                    riskStatusB = $item.StatusB
                    riskMetaValueA = $item.MetaValueA
                    riskMetaValueB = $item.MetaValueB
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
