# Function to check and install or update Microsoft.Graph module
function Ensure-Module {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ModuleName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("CurrentUser", "AllUsers")]
        [string]$Scope
    )

    $currentModule = Get-InstalledModule -Name $ModuleName -ErrorAction SilentlyContinue

    if (-not $currentModule) {
        Install-Module -Name $ModuleName -Scope $Scope -Force -ErrorAction Stop
    } else {
        $currentVersion = $currentModule.Version
        $latestVersion = (Find-Module -Name $ModuleName).Version

        if ($currentVersion -lt $latestVersion) {
            Uninstall-Module -Name $ModuleName -AllVersions -Force -ErrorAction Stop
            Install-Module -Name $ModuleName -Scope $Scope -Force -ErrorAction Stop
        }
    }
}

# Ensure the Microsoft.Graph module is installed and up-to-date
Ensure-Module -ModuleName "Microsoft.Graph" -Scope "CurrentUser"

# Prompt for the UPN of the user
$UserPrincipalName = Read-Host -Prompt "To retrieve sign-in information, input the User Principal Name (UPN) of the user"

# Connect to Microsoft Graph interactively
try {
    Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All" -NoWelcome -ErrorAction Stop
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit
}

# Function to get user sign-in data from beta endpoint
function Get-UserSignInData {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$UserPrincipalName
    )

    try {
        $signIns = @()
        $filter = "userPrincipalName eq '$UserPrincipalName'"
        $top = 1000

        $encodedFilter = [System.Web.HttpUtility]::UrlEncode($filter)
        $requestUrl = "https://graph.microsoft.com/beta/auditLogs/signIns?\$filter=$encodedFilter&\$top=$top"

        $response = Invoke-MgGraphRequest -Method GET -Uri $requestUrl -ErrorAction Stop
        $signIns += $response.value

        while ($null -ne $response.'@odata.nextLink') {
            $response = Invoke-MgGraphRequest -Method GET -Uri $response.'@odata.nextLink' -ErrorAction Stop
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

    $analysis = @{
        IPs = @{}
        Locations = @{}
        ASNs = @{}
    }

    # Extract relevant data and build analysis
    foreach ($signIn in $SignInData) {
        $ip = $signIn.ipAddress
        $location = "$($signIn.location.city), $($signIn.location.state), $($signIn.location.countryOrRegion)"
        $asn = $signIn.autonomousSystemNumber

        if ($ip) {
            if (-not $analysis.IPs.ContainsKey($ip)) {
                $analysis.IPs[$ip] = 0
            }
            $analysis.IPs[$ip]++
        }

        if ($location -ne ", , ") {
            if (-not $analysis.Locations.ContainsKey($ip)) {
                $analysis.Locations[$ip] = $location
            }
        }

        if ($asn) {
            if (-not $analysis.ASNs.ContainsKey($ip)) {
                $analysis.ASNs[$ip] = $asn
            }
        }
    }

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
        Write-ColoredOutput -Text "$SectionTitle" -Color Green
        Write-ColoredOutput -Text "=====================================" -Color Green
    }

    $yellowASNs = @()

    foreach ($key in $Analysis.Keys) {
        if ($key -in @("IPs", "ASNs", "Locations")) { continue }

        Write-Output ""
        Write-ColoredOutput -Text "${key}:" -Color Green
        Write-ColoredOutput -Text "=====================================" -Color Green

        $Analysis[$key].GetEnumerator() | ForEach-Object {
            $isYellow = $false

            if ($_.Value -lt 10) {
                $isYellow = $true
            }

            if ($isYellow -and -not ($yellowASNs -contains $_.Key)) {
                Write-ColoredOutput -Text "${key}: $($_.Key): $($_.Value)" -Color Yellow
            } else {
                Write-Output "${key}: $($_.Key): $($_.Value)"
            }
        }
    }

    Write-Output ""
    Write-ColoredOutput -Text "ASN, IP, and Location Analysis" -Color Green
    Write-ColoredOutput -Text "=====================================" -Color Green

    $combinedAnalysis = @()

    foreach ($ip in $Analysis.IPs.Keys) {
        $count = $Analysis.IPs[$ip]
        $asn = if ($Analysis.ASNs.ContainsKey($ip)) { $Analysis.ASNs[$ip] } else { "Unknown" }
        $location = if ($Analysis.Locations.ContainsKey($ip)) { $Analysis.Locations[$ip] } else { "Unknown" }

        $combinedAnalysis += @{
            IP       = $ip
            ASN      = $asn
            Location = $location
            Count    = $count
        }
    }

    $combinedAnalysis | Sort-Object -Property Count -Descending | ForEach-Object {
        $formattedASN = "ASN: $($_.ASN)".PadRight(10)
        $formattedIP = "IP: $($_.IP)".PadRight(40)
        $formattedLocation = "Location: $($_.Location)".PadRight(35)
        $line = "$formattedASN $formattedIP $formattedLocation Count: $($_.Count)"

        $isYellow = ($_.Count -lt 10)

        if ($isYellow) {
            Write-ColoredOutput -Text $line -Color Yellow
        } else {
            Write-Output $line
        }
    }
         Write-Output ""
}

# Function to build a baseline from historical sign-in data
function Build-Baseline {
    param (
        [Parameter(Mandatory = $true)]
        [array]$SignInData
    )

    $baseline = @{
        IPs          = @{}
        Locations    = @{}
        Devices      = @{}
        Browsers     = @{}
        UserAgents   = @{}
        OSTypes      = @{}
        Apps         = @{}
        ASNs         = @{}
    }

    foreach ($signIn in $SignInData) {
        # Collect IP addresses
        if ($signIn.ipAddress -ne $null) {
            if (-not $baseline.IPs.ContainsKey($signIn.ipAddress)) {
                $baseline.IPs[$signIn.ipAddress] = 1
            } else {
                $baseline.IPs[$signIn.ipAddress]++
            }
        }

        # Collect Locations
        $location = "$($signIn.location.city), $($signIn.location.state), $($signIn.location.countryOrRegion)"
        if ($location -ne ", , ") {
            if (-not $baseline.Locations.ContainsKey($location)) {
                $baseline.Locations[$location] = 1
            } else {
                $baseline.Locations[$location]++
            }
        }

        # Collect Devices
        if ($signIn.deviceDetail.deviceId -ne $null) {
            if (-not $baseline.Devices.ContainsKey($signIn.deviceDetail.deviceId)) {
                $baseline.Devices[$signIn.deviceDetail.deviceId] = 1
            } else {
                $baseline.Devices[$signIn.deviceDetail.deviceId]++
            }
        }

        # Collect Browsers
        if ($signIn.deviceDetail.browser -ne $null) {
            if (-not $baseline.Browsers.ContainsKey($signIn.deviceDetail.browser)) {
                $baseline.Browsers[$signIn.deviceDetail.browser] = 1
            } else {
                $baseline.Browsers[$signIn.deviceDetail.browser]++
            }
        }

        # Collect UserAgents
        if ($signIn.deviceDetail.userAgent -ne $null) {
            if (-not $baseline.UserAgents.ContainsKey($signIn.deviceDetail.userAgent)) {
                $baseline.UserAgents[$signIn.deviceDetail.userAgent] = 1
            } else {
                $baseline.UserAgents[$signIn.deviceDetail.userAgent]++
            }
        }

        # Collect OS Types
        if ($signIn.deviceDetail.operatingSystem -ne $null) {
            if (-not $baseline.OSTypes.ContainsKey($signIn.deviceDetail.operatingSystem)) {
                $baseline.OSTypes[$signIn.deviceDetail.operatingSystem] = 1
            } else {
                $baseline.OSTypes[$signIn.deviceDetail.operatingSystem]++
            }
        }

        # Collect Applications
        if ($signIn.appDisplayName -ne $null) {
            if (-not $baseline.Apps.ContainsKey($signIn.appDisplayName)) {
                $baseline.Apps[$signIn.appDisplayName] = 1
            } else {
                $baseline.Apps[$signIn.appDisplayName]++
            }
        }

        # Collect ASNs
        if ($signIn.autonomousSystemNumber -ne $null) {
            if (-not $baseline.ASNs.ContainsKey($signIn.autonomousSystemNumber)) {
                $baseline.ASNs[$signIn.autonomousSystemNumber] = 1
            } else {
                $baseline.ASNs[$signIn.autonomousSystemNumber]++
            }
        }
    }

    return $baseline
}

# Function to detect potential unauthorized sign-ins
function Detect-UnauthorizedSignIns {
    param (
        [Parameter(Mandatory = $true)]
        [array]$SignInData,
        [Parameter(Mandatory = $true)]
        [hashtable]$Baseline
    )

    $suspiciousSignIns = @()

    foreach ($signIn in $SignInData) {
        $isSuspicious = $false
        $suspiciousCriteriaCount = 0

        # Check if the sign-in has associated risk data
        if (($signIn.riskLevel -ne $null -and $signIn.riskLevel -ne "none") -or ($signIn.riskState -ne $null -and $signIn.riskState -ne "none")) {
            $isSuspicious = $true
        }

        # Check if the ASN is unusual
        if ($signIn.autonomousSystemNumber -ne $null) {
            $asnCount = if ($Baseline.ASNs.ContainsKey($signIn.autonomousSystemNumber)) { $Baseline.ASNs[$signIn.autonomousSystemNumber] } else { 0 }
            if ($asnCount -lt 10) {
                $ipCount = if ($Baseline.IPs.ContainsKey($signIn.ipAddress)) { $Baseline.IPs[$signIn.ipAddress] } else { 0 }
                if ($ipCount -lt 10) {
                    $suspiciousCriteriaCount++
                }
            }
        }

        # Check if the state location is unusual
        $state = $signIn.location.state
        if ($state -ne $null) {
            $baselineStates = $Baseline.Locations.Keys | ForEach-Object { $_.Split(', ')[1] }
            if (-not ($baselineStates -contains $state -and ($Baseline.Locations[$signIn.location.city + ", " + $state + ", " + $signIn.location.countryOrRegion] -ge 5))) {
                $suspiciousCriteriaCount++
            }
        }

        # Check if the device is unusual
        if ($signIn.deviceDetail.deviceId -ne $null) {
            if (-not $Baseline.Devices.ContainsKey($signIn.deviceDetail.deviceId) -or $Baseline.Devices[$signIn.deviceDetail.deviceId] -lt 5) {
                $suspiciousCriteriaCount++
            }
        }

        # Check if the browser is unusual
        if ($signIn.deviceDetail.browser -ne $null) {
            if (-not $Baseline.Browsers.ContainsKey($signIn.deviceDetail.browser) -or $Baseline.Browsers[$signIn.deviceDetail.browser] -lt 5) {
                $suspiciousCriteriaCount++
            }
        }

        # Check if the user agent is unusual
        if ($signIn.deviceDetail.userAgent -ne $null) {
            if (-not $Baseline.UserAgents.ContainsKey($signIn.deviceDetail.userAgent) -or $Baseline.UserAgents[$signIn.deviceDetail.userAgent] -lt 5) {
                $suspiciousCriteriaCount++
            }
        }

        # Check if the OS type is unusual
        if ($signIn.deviceDetail.operatingSystem -ne $null) {
            if (-not $Baseline.OSTypes.ContainsKey($signIn.deviceDetail.operatingSystem) -or $Baseline.OSTypes[$signIn.deviceDetail.operatingSystem] -lt 5) {
                $suspiciousCriteriaCount++
            }
        }

        # Check if the application is unusual
        if ($signIn.appDisplayName -ne $null) {
            if (-not $Baseline.Apps.ContainsKey($signIn.appDisplayName) -or $Baseline.Apps[$signIn.appDisplayName] -lt 5) {
                $suspiciousCriteriaCount++
            }
        }

        # Check if 4 or more criteria are met
        if ($suspiciousCriteriaCount -ge 4) {
            $isSuspicious = $true
        }

        if ($isSuspicious) {
            $suspiciousSignIns += $signIn
        }
    }

    return $suspiciousSignIns
}

# Function to output colored text
function Write-ColoredOutput {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Text,
        [Parameter(Mandatory = $true)]
        [string]$Color
    )

    $colorMap = @{
        'Red' = 'Red'
        'Green' = 'Green'
        'Yellow' = 'Yellow'
        'Blue' = 'Blue'
        'Magenta' = 'Magenta'
        'Cyan' = 'Cyan'
        'White' = 'White'
    }

    if ($colorMap.ContainsKey($Color)) {
        Write-Host $Text -ForegroundColor $colorMap[$Color]
    } else {
        Write-Host $Text
    }
}

# Main script execution
# Get all sign-in data
$allSignIns = Get-UserSignInData -UserPrincipalName $UserPrincipalName

# Build a baseline from the historical sign-in data
$baseline = Build-Baseline -SignInData $allSignIns

# Categorize sign-in data into successful and failed pools
$categorizedSignIns = Categorize-SignInData -SignInData $allSignIns

# Analyze and display failed sign-in data
if ($categorizedSignIns.Failed -and $categorizedSignIns.Failed.Count -gt 0) {
    $analysisFailures = Analyze-SignInData -SignInData $categorizedSignIns.Failed
    Display-Analysis -Analysis $analysisFailures -SectionTitle "Sign-In Failures"
}

# Analyze and display successful sign-in data
if ($categorizedSignIns.Successful -and $categorizedSignIns.Successful.Count -gt 0) {
    $analysisSuccesses = Analyze-SignInData -SignInData $categorizedSignIns.Successful
    Display-Analysis -Analysis $analysisSuccesses -SectionTitle "Successful Sign-Ins"
}

# Detect and display suspicious sign-ins
$suspiciousSignIns = Detect-UnauthorizedSignIns -SignInData $allSignIns -Baseline $baseline

if ($suspiciousSignIns -and $suspiciousSignIns.Count -gt 0) {
    Write-Output ""
    Write-ColoredOutput -Text "Suspicious Sign-Ins Detected" -Color Green
    Write-ColoredOutput -Text "===========================" -Color Green
    $suspiciousSignIns | ForEach-Object {
        $suspiciousText = "Sign-In at $($_.createdDateTime) from IP $($_.ipAddress) in location $($_.location.city), $($_.location.state), $($_.location.countryOrRegion) with risk level $($_.riskLevel) and risk state $($_.riskState), OS: $($_.deviceDetail.operatingSystem), App: $($_.appDisplayName)"
        Write-ColoredOutput -Text $suspiciousText -Color Red
    }
} else {
    Write-Output ""
    Write-ColoredOutput -Text "No suspicious sign-ins detected for user $UserPrincipalName." -Color Green
}

# Display baseline details for context
Write-Output ""
Write-ColoredOutput -Text "Baseline Summary" -Color Green
Write-ColoredOutput -Text "===========================" -Color Green
Write-Output "IPs, Locations, Devices, Browsers, UserAgents, OSTypes, Apps, ASNs in the baseline data:"
foreach ($key in $baseline.Keys) {
    Write-Output ""
    Write-ColoredOutput -Text "${key}:" -Color Green
    Write-ColoredOutput -Text "=====================================" -Color Green
    $baseline[$key].GetEnumerator() | Sort-Object -Property Value -Descending | ForEach-Object {
        $asnCount = if ($key -eq "IPs" -and $baseline.ASNs.ContainsKey($_.Name)) { 
            $baseline.ASNs[$_.Name] 
        } else { 
            $null 
        }
        
        if ($_.Value -lt 10 -and ($key -ne "IPs" -or ($key -eq "IPs" -and $asnCount -lt 10))) {
            Write-ColoredOutput -Text "${key}: $($_.Name): $($_.Value)" -Color Yellow
        } else {
            Write-Output "${key}: $($_.Name): $($_.Value)"
        }
    }
}
