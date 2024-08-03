# Function to check and install or update Microsoft.Graph module
function Ensure-Module {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        [Parameter(Mandatory = $true)]
        [string]$Scope
    )

    $currentModule = Get-InstalledModule -Name $ModuleName -ErrorAction SilentlyContinue

    if ($null -eq $currentModule) {
        Write-Output "Module $ModuleName is not installed. Installing..."
        Install-Module -Name $ModuleName -Scope $Scope -Force
    } else {
        $currentVersion = $currentModule.Version
        $latestVersion = Find-Module -Name $ModuleName | Select-Object -ExpandProperty Version

        if ($currentVersion -lt $latestVersion) {
            Write-Output "Updating $ModuleName from version $currentVersion to $latestVersion..."
            Uninstall-Module -Name $ModuleName -AllVersions -Force
            Install-Module -Name $ModuleName -Scope $Scope -Force
        } else {
            Write-Output "$ModuleName is up-to-date (version $currentVersion)."
        }
    }
}

# Ensure the Microsoft.Graph module is installed and up-to-date
Ensure-Module -ModuleName "Microsoft.Graph" -Scope "CurrentUser"

# Prompt for the UPN of the user
$UserPrincipalName = Read-Host -Prompt "Enter the UPN of the user to gather sign-in information for"

# Connect to Microsoft Graph interactively
try {
    Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All"
    Write-Output "Successfully connected to Microsoft Graph."
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit
}

# Function to get user sign-in data from beta endpoint
function Get-UserSignInData {
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )

    try {
        $signIns = @()
        $filter = "userPrincipalName eq '$UserPrincipalName'"
        $top = 1000

        $requestUrl = "https://graph.microsoft.com/beta/auditLogs/signIns?\$filter=$filter&\$top=$top"

        $response = Invoke-MgGraphRequest -Method GET -Uri $requestUrl

        $signIns += $response.value

        while ($null -ne $response.'@odata.nextLink') {
            $response = Invoke-MgGraphRequest -Method GET -Uri $response.'@odata.nextLink'
            $signIns += $response.value
        }

        return $signIns
    } catch {
        Write-Error "Failed to retrieve sign-in data: $_"
        exit
    }
}

# Function to analyze user sign-in data
function Analyze-SignInData {
    param (
        [Parameter(Mandatory = $true)]
        [array]$SignInData
    )

    $analysis = @{}

    # Extract relevant data
    $ips = $SignInData | ForEach-Object { $_.ipAddress }
    $locations = $SignInData | ForEach-Object { "$($_.location.city), $($_.location.state), $($_.location.countryOrRegion)" }
    $asns = $SignInData | ForEach-Object { if ($_.autonomousSystemNumber) { $_.autonomousSystemNumber } else { "Unknown" } }
    $times = $SignInData | ForEach-Object { $_.createdDateTime }
    $osTypes = $SignInData | ForEach-Object { if ($_.deviceDetail.operatingSystem) { $_.deviceDetail.operatingSystem } else { "Unknown" } }
    $browserTypes = $SignInData | ForEach-Object { if ($_.deviceDetail.browser) { $_.deviceDetail.browser } else { "Unknown" } }
    $userAgent = $SignInData | ForEach-Object { if ($_.userAgent) { $_.userAgent } else { "Unknown" } }
    $appDisplayNames = $SignInData | ForEach-Object { if ($_.appDisplayName) { $_.appDisplayName } else { "Unknown" } }
    $deviceIds = $SignInData | ForEach-Object { if ($_.deviceDetail.deviceId) { $_.deviceDetail.deviceId } else { "NULL" } }

    # Statistical analysis
    $analysis.IPs = $ips | Group-Object | Sort-Object Count -Descending
    $analysis.Locations = $locations | Group-Object | Sort-Object Count -Descending
    $analysis.ASNs = $asns | Group-Object | Sort-Object Count -Descending
    $analysis.Times = $times | Group-Object { $_.ToString("HH") } | Sort-Object Name
    $analysis.OSTypes = $osTypes | Group-Object | Sort-Object Count -Descending
    $analysis.BrowserTypes = $browserTypes | Group-Object | Sort-Object Count -Descending
    $analysis.UserAgent = $userAgent | Group-Object | Sort-Object Count -Descending
    $analysis.AppDisplayNames = $appDisplayNames | Group-Object | Sort-Object Count -Descending
    $analysis.DeviceIds = $deviceIds | Group-Object | Sort-Object Count -Descending

    return $analysis
}

# Function to format and display analysis results
function Display-Analysis {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Analysis
    )

    foreach ($key in $Analysis.Keys) {
        Write-Output ""
        Write-Output "$($key):"
        $Analysis[$key] | ForEach-Object {
            Write-Output "  $($_.Name): $($_.Count)"
        }
    }
}

# Main script execution
$signInData = Get-UserSignInData -UserPrincipalName $UserPrincipalName

if ($signInData -ne $null -and $signInData.Count -gt 0) {
    $analysis = Analyze-SignInData -SignInData $signInData

    # Output analysis in a readable format
    Display-Analysis -Analysis $analysis
} else {
    Write-Output "No sign-in data found for user $UserPrincipalName."
}
