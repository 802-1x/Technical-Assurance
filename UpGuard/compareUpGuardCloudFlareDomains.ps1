function compareUpGuardCloudFlareDomains {
    <#
    .SYNOPSIS
        Compares UpGuard and CloudFlare platforms to identify missing domains.
    .OUTPUTS
        A list of domains missing from UpGuard.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [array]$dnsRecords,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [array]$allDomains
    )

    # Validate input paramters
    if (-not $dnsRecords -or -not $allDomains) {
        throw "DNS records or all domains cannot be null or empty."
    }

    try {
        # Retrieve configuration file values
        $excludeList_compareUpGuardCloudFlareDomains = compareUpGuardCloudFlareDomainsVariables

        $platformDomainComparison = $dnsRecords | Where-Object { $_.Type -eq "A" -or $_.Type -eq "CNAME" }
        $platformDomainComparison = $platformDomainComparison.Record | Sort-Object -Unique
        $platformDomainComparison = $platformDomainComparison | Where-Object { $item = $_
            -not ($excludeList_compareUpGuardCloudFlareDomains | Where-Object { $item -like $_ }) }

        $UpGuardDomains = $allDomains.hostname | Sort-Object

        # Compare domains and find missing ones
        $missingDomainsFromUpGuard = Compare-Object -ReferenceObject $platformDomainComparison -DifferenceObject $UpGuardDomains |
            Where-Object { $_.SideIndicator -eq '<=' } |
            ForEach-Object { $_.InputObject } |
            Sort-Object
            
        return $missingDomainsFromUpGuard
    }

    catch {
        Write-Error "An error occurred during domain comparison: $_"
        exit 1
    }
}
