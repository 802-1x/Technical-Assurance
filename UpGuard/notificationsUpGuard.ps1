function notificationsUpGuard {
    <#
    .SYNOPSIS
        Retrieves and sorts notifications from UpGuard API.
    .OUTPUTS
        An array of notifications sorted by occurrence date in descending order.
    #>

    [CmdletBinding()]
    [OutputType([array])]
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
        $uri = "https://cyber-risk.upguard.com/api/public/notifications"
        $notificationsUpGuard = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ErrorAction Stop

        if (-not $notificationsUpGuard.notifications) {
            Write-Warning "No notifications found."
            return
        }

        $notificationsUpGuard = $notificationsUpGuard.notifications | Sort-Object occurred_at -Descending

        return $notificationsUpGuard
    }

    catch {
        Write-Error "An error occurred while retrieving notifications: $_"
        return $null
    }
}
