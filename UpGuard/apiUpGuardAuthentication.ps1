function apiUpGuardAuthentication {
    <#
    .SYNOPSIS
        Retrieves API authentication headers from an environment configuration file.
    .OUTPUTS
        A hashtable containing the Authorization header.
    #>

    # Retrieve configuration file values
    $envFolderPath, $apiKeyUpGuard = apiUpGuardAuthenticationVariables

    if ([string]::IsNullOrEmpty($envFolderPath) -or [string]::IsNullOrEmpty($apiKeyUpGuard)) {
        Write-Error "Environment folder path or API key variable name is not set."
        exit
    }

    try {
        # Read the API keys file content
        $apiKeyLine = Get-Content "$envFolderPath\APIKeys.env" -ErrorAction Stop | Select-String -Pattern "^\s*$apiKeyUpGuard\s*=\s*(.+)$"

        if ($null -eq $apiKeyLine) {
            Write-Error "API key '$apiKeyUpGuard' not found in the environment file."
            exit
        }

        # Extract the API key value and set the headers for the API request
        $apiKeyValue = $apiKeyLine.Matches.Groups[1].Value.Trim()

        $headers = @{
            "Authorization" = $apiKeyValue;
        }

        return $headers
    }

    catch {
        Write-Error "An error occurred: $_"
    }
}
