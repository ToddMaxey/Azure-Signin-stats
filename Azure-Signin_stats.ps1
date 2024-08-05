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
$UserPrincipalName = Read-Host -Prompt "To retrieve sign-in information, input the User Principal Name (UPN) of the user"

# Connect to Microsoft Graph interactively
try {
    Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All" -NoWelcome
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

        $encodedFilter = [System.Web.HttpUtility]::UrlEncode($filter)
        $requestUrl = "https://graph.microsoft.com/beta/auditLogs/signIns?\$filter=$encodedFilter&\$top=$top"
        Write-Output "Request URL: $requestUrl"  # Debug output to verify the filter

        $response = Invoke-MgGraphRequest -Method GET -Uri $requestUrl
        Write-Output "Response received: $($response | ConvertTo-Json -Depth 5)"  # Debug output to verify the response

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

# Function to categorize sign-in data into successful and failed pools
function Categorize-SignInData {
    param (
        [Parameter(Mandatory = $true)]
        [array]$SignInData
    )

    $successfulSignIns = @()
    $failedSignIns = @()

    foreach ($signIn in $SignInData) {
        if ($signIn.status.errorCode -eq 0 -or $signIn.status.errorCode -in @(50053,50055,50056,50057,50059,50072,50074,50125,50128,50129,50131,81010,81011,81012,81013,81014,81015,81016,81017,81018,81019)) {
            $successfulSignIns += $signIn
        } else {
            $failedSignIns += $signIn
        }
    }

    return @{ Successful = $successfulSignIns; Failed = $failedSignIns }
}

# Function to analyze sign-in data
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
    $userAgents = $SignInData | ForEach-Object { if ($_.deviceDetail.userAgent) { $_.deviceDetail.userAgent } else { "Unknown" } }
    $appDisplayNames = $SignInData | ForEach-Object { if ($_.appDisplayName) { $_.appDisplayName } else { "Unknown" } }
    $deviceIds = $SignInData | ForEach-Object { if ($_.deviceDetail.deviceId) { $_.deviceDetail.deviceId } else { "NULL" } }
    $errorCodes = $SignInData | ForEach-Object { $_.status.errorCode }
    $accountNames = $SignInData | ForEach-Object { $_.userPrincipalName }
    $resultCodes = $SignInData | ForEach-Object { $_.status.additionalDetails }

    # Statistical analysis
    $analysis.IPs = $ips | Group-Object | Sort-Object Count -Descending
    $analysis.Locations = $locations | Group-Object | Sort-Object Count -Descending
    $analysis.ASNs = $asns | Group-Object | Sort-Object Count -Descending
    $analysis.Times = $times | Group-Object { $_.ToString("HH") } | Sort-Object Name
    $analysis.OSTypes = $osTypes | Group-Object | Sort-Object Count -Descending
    $analysis.BrowserTypes = $browserTypes | Group-Object | Sort-Object Count -Descending
    $analysis.UserAgents = $userAgents | Group-Object | Sort-Object Count -Descending
    $analysis.AppDisplayNames = $appDisplayNames | Group-Object | Sort-Object Count -Descending
    $analysis.DeviceIds = $deviceIds | Group-Object | Sort-Object Count -Descending
    $analysis.ErrorCodes = $errorCodes | Group-Object | Sort-Object Count -Descending
    $analysis.AccountNames = $accountNames | Group-Object | Sort-Object Count -Descending
    $analysis.ResultCodes = $resultCodes | Group-Object | Sort-Object Count -Descending

    return $analysis
}

# Function to format and display analysis results
function Display-Analysis {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Analysis,
        [Parameter(Mandatory = $false)]
        [string]$SectionTitle
    )

    if ($SectionTitle) {
        Write-Output ""
        Write-Output "$SectionTitle"
        Write-Output "====================================="
    }

    foreach ($key in $Analysis.Keys) {
        Write-Output ""
        Write-Output "$($key):"
        $Analysis[$key] | ForEach-Object {
            Write-Output "  $($_.Name): $($_.Count)"
        }
    }
}

# Main script execution
# Get all sign-in data
$allSignIns = Get-UserSignInData -UserPrincipalName $UserPrincipalName

# Categorize sign-in data into successful and failed pools
$categorizedSignIns = Categorize-SignInData -SignInData $allSignIns

# Analyze and display failed sign-in data
if ($categorizedSignIns.Failed -ne $null -and $categorizedSignIns.Failed.Count -gt 0) {
    $analysisFailures = Analyze-SignInData -SignInData $categorizedSignIns.Failed
    Display-Analysis -Analysis $analysisFailures -SectionTitle "Sign-In Failures"
} else {
    Write-Output "No sign-in failure data found for user $UserPrincipalName."
}

# Analyze and display successful sign-in data
if ($categorizedSignIns.Successful -ne $null -and $categorizedSignIns.Successful.Count -gt 0) {
    $analysisSuccesses = Analyze-SignInData -SignInData $categorizedSignIns.Successful
    Display-Analysis -Analysis $analysisSuccesses -SectionTitle "Successful Sign-Ins"
} else {
    Write-Output "No successful sign-in data found for user $UserPrincipalName."
}
