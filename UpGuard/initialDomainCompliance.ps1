function initialDomainCompliance {
    <#
    .SYNOPSIS
        Retrieves domain compliance scores from UpGuard API.
    .OUTPUTS
        The current automated score, all domains, active domains, and unmodified average score as various data types.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [hashtable]$headers
    )

    # Validate headers
    if (-not $headers -or -not $headers.ContainsKey("Authorization")) {
        throw "Headers must contain an 'Authorization' key and cannot be null or empty."
    }

    try {
        #Current Automated Score
        $uri = "https://cyber-risk.upguard.com/api/public/organisation"
        $automatedScore = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ErrorAction Stop

        #Get Active Domains
        $uri = "https://cyber-risk.upguard.com/api/public/domains"
        $allDomainsResponse = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ErrorAction Stop

        # Process all and active domains respectively
        $allDomains = $allDomainsResponse.domains | Select-Object hostname, automated_score, scanned_at | Sort-Object automated_score -Descending
        $activeDomains = $allDomainsResponse.domains | Where-Object {$_.active -eq $true} | Select-Object hostname, automated_score, scanned_at | Sort-Object automated_score -Descending

        #Unmodified Average Score
        if ($activeDomains.Count -gt 0) {
            $sum = ($activeDomains | Measure-Object -Property automated_score -Sum).Sum
            $unmodifiedAverageScore = [int]($sum / $activeDomains.automated_score.Count)
        } else {
            $unmodifiedAverageScore = 0
        }

        return $automatedScore, $allDomains, $activeDomains, $unmodifiedAverageScore
    }

    catch {
        Write-Error "An error occurred while retrieving domain compliance data: $_"
        return $null
    }
}
