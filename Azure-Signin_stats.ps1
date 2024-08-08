# Null out all variables to avoid stale data
$allSignIns = $null
$signInErrors = $null
$errorCounts = $null
$user = $null
$baseline = $null
$suspiciousSignIns = $null

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

# Connect to Microsoft Graph interactively
try {
    Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All" -NoWelcome -ErrorAction Stop
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit
}

# Function to get valid user account (UserPrincipalName or UserId)
function Get-ValidUserAccount {
    param (
        [Parameter(Mandatory = $true)]
        [string]$PromptMessage
    )

    while ($true) {
        $input = Read-Host -Prompt $PromptMessage
        
        # Try to get the user by UserPrincipalName
        try {
            $user = Get-MgUser -UserPrincipalName $input -ErrorAction Stop
            if ($user) {
                return $user
            }
        } catch {
            # Continue to the next check
        }
        
        # Try to get the user by Id
        try {
            $user = Get-MgUser -UserId $input -ErrorAction Stop
            if ($user) {
                return $user
            }
        } catch {
            # Continue to prompt for input
        }

        Write-Host "User not found or an error occurred. Please enter a valid User Principal Name (UPN) or User ID." -ForegroundColor Red
    }
}

# Function to get user metadata
function Get-UserMetadata {
    param (
        [Parameter(Mandatory = $true)]
        $User
    )

    Write-Output ""
    Write-Output "User Metadata:"
    Write-Output "================="

    # Basic Information
    Write-Output "Basic Information:"
    Write-Output "------------------"
    $basicProperties = @('DisplayName', 'GivenName', 'Surname', 'JobTitle', 'Mail', 'UserPrincipalName')
    foreach ($property in $basicProperties) {
        $value = $User.$property
        if ($value) {
            Write-Output "${property}: ${value}"
        }
    }

    # Location Information
    Write-Output ""
    Write-Output "Location Information:"
    Write-Output "----------------------"
    $locationProperties = @('Country', 'State', 'City', 'StreetAddress', 'PostalCode', 'BusinessPhones', 'MobilePhone', 'PreferredLanguage')
    foreach ($property in $locationProperties) {
        $value = $User.$property
        if ($value) {
            Write-Output "${property}: ${value}"
            if ($property -eq 'MobilePhone' -or $property -eq 'BusinessPhones') {
                foreach ($phone in $value) {
                    Parse-PhoneNumber -PhoneNumber $phone
                }
            }
        }
    }

    # Authentication Information
    Write-Output ""
    Write-Output "Authentication Information:"
    Write-Output "---------------------------"
    $authProperties = @('Authentication', 'AuthorizationInfo')
    foreach ($property in $authProperties) {
        $value = $User.$property
        if ($value) {
            Write-Output "${property}: $(${value} | Out-String)"
        }
    }

    # Security Attributes
    Write-Output ""
    Write-Output "Security Attributes:"
    Write-Output "---------------------"
    $securityProperties = @('CustomSecurityAttributes', 'PasswordProfile', 'SignInActivity')
    foreach ($property in $securityProperties) {
        $value = $User.$property
        if ($value) {
            Write-Output "${property}: $(${value} | Out-String)"
        }
    }

    Write-Output "================="
    Write-Output ""
}

# Example: Query additional details for nested objects
function Expand-NestedProperty {
    param (
        [Parameter(Mandatory = $true)]
        [Object]$PropertyValue,
        [string]$PropertyName
    )

    Write-Output ""
    Write-Output "${PropertyName} Details:"
    Write-Output "----------------------"

    $properties = $PropertyValue | Get-Member -MemberType Properties
    foreach ($property in $properties) {
        $value = $PropertyValue.$($property.Name)
        if ($value) {
            Write-Output "$($property.Name): ${value}"
        }
    }
}

# Function to get user sign-in data with retry logic
function Get-UserSignInDataWithRetry {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$UserPrincipalName
    )
    
    $retryCount = 0
    $maxRetries = 2
    $signInData = $null

    while ($retryCount -le $maxRetries -and -not $signInData) {
        try {
            $signInData = Get-UserSignInData -UserPrincipalName $UserPrincipalName -ErrorAction Stop
        } catch {
            Write-Warning "Failed to retrieve sign-in data: $_. Retrying ($($retryCount + 1)/$maxRetries)..."
            $retryCount++
            Start-Sleep -Seconds 5
        }
    }

    if (-not $signInData) {
        Write-Error "Failed to retrieve sign-in data after $maxRetries attempts."
        exit
    }

    return $signInData
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

# Define a hashtable to store commonly seen Azure Sign-in error codes and their descriptions
$AzureSigninErrorCodes = @{
    "AADSTS650053" = "The application '{name}' asked for scope '{scope}' that doesn't exist on the resource '{resource}'. Contact the app vendor."
    "AADSTS70037" = "Incorrect challenge response provided. Remote auth session denied"
}

# Function to get the description of an error code
function Get-ErrorDescription {
    param (
        [string]$ErrorCode
    )

    $lookupCode = "AADSTS$($ErrorCode.Trim())"
    if ($AzureSigninErrorCodes.ContainsKey($lookupCode)) {
        return $AzureSigninErrorCodes[$lookupCode]
    } else {
        return "Error code not found."
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
        ErrorCodes = @{}
    }

    # Extract relevant data and build analysis
    foreach ($signIn in $SignInData) {
        $ip = $signIn.ipAddress
        $location = "$($signIn.location.city), $($signIn.location.state), $($signIn.location.countryOrRegion)"
        $asn = $signIn.autonomousSystemNumber
        $errorCode = $signIn.status.errorCode

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

        if ($errorCode) {
            if (-not $analysis.ErrorCodes.ContainsKey($errorCode)) {
                $analysis.ErrorCodes[$errorCode] = 0
            }
            $analysis.ErrorCodes[$errorCode]++
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
        if ($key -in @("IPs", "ASNs", "Locations", "ErrorCodes")) { continue }

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

# Function to display error codes analysis results
function Display-ErrorCodesAnalysis {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$ErrorCodes,
        [Parameter(Mandatory = $false)]
        [string]$SectionTitle
    )

    if ($SectionTitle) {
        Write-ColoredOutput -Text "$SectionTitle" -Color Green
        Write-ColoredOutput -Text "=====================================" -Color Green
    }

    foreach ($errorCode in $ErrorCodes.Keys) {
        Write-Output "Processing Error Code: $errorCode" # Debugging line
        $description = Get-ErrorDescription -ErrorCode $errorCode
        Write-Output "Error Code: $errorCode"
        Write-Output "Description: $description"
        Write-Output "Count: $($ErrorCodes[$errorCode])"
        Write-Output ""
    }
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
$user = Get-ValidUserAccount -PromptMessage "To retrieve sign-in information, input the User Principal Name (UPN) or User ID of the user"
Get-UserMetadata -User $user

# Get all sign-in data
$allSignIns = Get-UserSignInDataWithRetry -UserPrincipalName $user.UserPrincipalName

# Build a baseline from the historical sign-in data
$baseline = Build-Baseline -SignInData $allSignIns

# Categorize sign-in data into successful and failed pools
$categorizedSignIns = Categorize-SignInData -SignInData $allSignIns

# Analyze and display failed sign-in data
if ($categorizedSignIns.Failed -and $categorizedSignIns.Failed.Count -gt 0) {
    $analysisFailures = Analyze-SignInData -SignInData $categorizedSignIns.Failed
    Display-Analysis -Analysis $analysisFailures -SectionTitle "Sign-In Failures"
    Display-ErrorCodesAnalysis -ErrorCodes $analysisFailures.ErrorCodes -SectionTitle "Failed Sign-In Error Codes"
}

# Analyze and display successful sign-in data
if ($categorizedSignIns.Successful -and $categorizedSignIns.Successful.Count -gt 0) {
    $analysisSuccesses = Analyze-SignInData -SignInData $categorizedSignIns.Successful
    Display-Analysis -Analysis $analysisSuccesses -SectionTitle "Successful Sign-Ins"
    Display-ErrorCodesAnalysis -ErrorCodes $analysisSuccesses.ErrorCodes -SectionTitle "Successful Sign-In Error Codes"
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
    Write-ColoredOutput -Text "No suspicious sign-ins detected for user $($user.UserPrincipalName)." -Color Green
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

# Function to parse and display phone number details
function Parse-PhoneNumber {
    param (
        [string]$PhoneNumber
    )
    if ($PhoneNumber) {
        $regex = "^\+(\d+)\s?(\d{1,3})(\d{7})$"
        if ($PhoneNumber -match $regex) {
            $countryCode = $matches[1]
            $areaCode = $matches[2]
            $localNumber = $matches[3]

$countryName = switch ($countryCode) {
    "1" { "United States/Canada" }
    "7" { "Russia/Kazakhstan" }
    "20" { "Egypt" }
    "27" { "South Africa" }
    "30" { "Greece" }
    "31" { "Netherlands" }
    "32" { "Belgium" }
    "33" { "France" }
    "34" { "Spain" }
    "36" { "Hungary" }
    "39" { "Italy" }
    "40" { "Romania" }
    "41" { "Switzerland" }
    "43" { "Austria" }
    "44" { "United Kingdom" }
    "45" { "Denmark" }
    "46" { "Sweden" }
    "47" { "Norway" }
    "48" { "Poland" }
    "49" { "Germany" }
    "51" { "Peru" }
    "52" { "Mexico" }
    "53" { "Cuba" }
    "54" { "Argentina" }
    "55" { "Brazil" }
    "56" { "Chile" }
    "57" { "Colombia" }
    "58" { "Venezuela" }
    "60" { "Malaysia" }
    "61" { "Australia" }
    "62" { "Indonesia" }
    "63" { "Philippines" }
    "64" { "New Zealand" }
    "65" { "Singapore" }
    "66" { "Thailand" }
    "81" { "Japan" }
    "82" { "South Korea" }
    "84" { "Vietnam" }
    "86" { "China" }
    "90" { "Turkey" }
    "91" { "India" }
    "92" { "Pakistan" }
    "93" { "Afghanistan" }
    "94" { "Sri Lanka" }
    "95" { "Myanmar" }
    "98" { "Iran" }
    "212" { "Morocco" }
    "213" { "Algeria" }
    "216" { "Tunisia" }
    "218" { "Libya" }
    "220" { "Gambia" }
    "221" { "Senegal" }
    "222" { "Mauritania" }
    "223" { "Mali" }
    "224" { "Guinea" }
    "225" { "Ivory Coast" }
    "226" { "Burkina Faso" }
    "227" { "Niger" }
    "228" { "Togo" }
    "229" { "Benin" }
    "230" { "Mauritius" }
    "231" { "Liberia" }
    "232" { "Sierra Leone" }
    "233" { "Ghana" }
    "234" { "Nigeria" }
    "235" { "Chad" }
    "236" { "Central African Republic" }
    "237" { "Cameroon" }
    "238" { "Cape Verde" }
    "239" { "São Tomé and Príncipe" }
    "240" { "Equatorial Guinea" }
    "241" { "Gabon" }
    "242" { "Republic of the Congo" }
    "243" { "Democratic Republic of the Congo" }
    "244" { "Angola" }
    "245" { "Guinea-Bissau" }
    "246" { "British Indian Ocean Territory" }
    "248" { "Seychelles" }
    "249" { "Sudan" }
    "250" { "Rwanda" }
    "251" { "Ethiopia" }
    "252" { "Somalia" }
    "253" { "Djibouti" }
    "254" { "Kenya" }
    "255" { "Tanzania" }
    "256" { "Uganda" }
    "257" { "Burundi" }
    "258" { "Mozambique" }
    "260" { "Zambia" }
    "261" { "Madagascar" }
    "262" { "Réunion" }
    "263" { "Zimbabwe" }
    "264" { "Namibia" }
    "265" { "Malawi" }
    "266" { "Lesotho" }
    "267" { "Botswana" }
    "268" { "Eswatini" }
    "269" { "Comoros" }
    "290" { "Saint Helena" }
    "291" { "Eritrea" }
    "297" { "Aruba" }
    "298" { "Faroe Islands" }
    "299" { "Greenland" }
    "350" { "Gibraltar" }
    "351" { "Portugal" }
    "352" { "Luxembourg" }
    "353" { "Ireland" }
    "354" { "Iceland" }
    "355" { "Albania" }
    "356" { "Malta" }
    "357" { "Cyprus" }
    "358" { "Finland" }
    "359" { "Bulgaria" }
    "370" { "Lithuania" }
    "371" { "Latvia" }
    "372" { "Estonia" }
    "373" { "Moldova" }
    "374" { "Armenia" }
    "375" { "Belarus" }
    "376" { "Andorra" }
    "377" { "Monaco" }
    "378" { "San Marino" }
    "379" { "Vatican City" }
    "380" { "Ukraine" }
    "381" { "Serbia" }
    "382" { "Montenegro" }
    "383" { "Kosovo" }
    "385" { "Croatia" }
    "386" { "Slovenia" }
    "387" { "Bosnia and Herzegovina" }
    "389" { "North Macedonia" }
    "420" { "Czech Republic" }
    "421" { "Slovakia" }
    "423" { "Liechtenstein" }
    "500" { "Falkland Islands" }
    "501" { "Belize" }
    "502" { "Guatemala" }
    "503" { "El Salvador" }
    "504" { "Honduras" }
    "505" { "Nicaragua" }
    "506" { "Costa Rica" }
    "507" { "Panama" }
    "508" { "Saint Pierre and Miquelon" }
    "509" { "Haiti" }
    "590" { "Saint Barthélemy" }
    "591" { "Bolivia" }
    "592" { "Guyana" }
    "593" { "Ecuador" }
    "594" { "French Guiana" }
    "595" { "Paraguay" }
    "596" { "Martinique" }
    "597" { "Suriname" }
    "598" { "Uruguay" }
    "599" { "Curaçao" }
    "670" { "East Timor" }
    "672" { "Norfolk Island" }
    "673" { "Brunei" }
    "674" { "Nauru" }
    "675" { "Papua New Guinea" }
    "676" { "Tonga" }
    "677" { "Solomon Islands" }
    "678" { "Vanuatu" }
    "679" { "Fiji" }
    "680" { "Palau" }
    "681" { "Wallis and Futuna" }
    "682" { "Cook Islands" }
    "683" { "Niue" }
    "685" { "Samoa" }
    "686" { "Kiribati" }
    "687" { "New Caledonia" }
    "688" { "Tuvalu" }
    "689" { "French Polynesia" }
    "690" { "Tokelau" }
    "691" { "Federated States of Micronesia" }
    "692" { "Marshall Islands" }
    "850" { "North Korea" }
    "852" { "Hong Kong" }
    "853" { "Macau" }
    "855" { "Cambodia" }
    "856" { "Laos" }
    "880" { "Bangladesh" }
    "886" { "Taiwan" }
    "960" { "Maldives" }
    "961" { "Lebanon" }
    "962" { "Jordan" }
    "963" { "Syria" }
    "964" { "Iraq" }
    "965" { "Kuwait" }
    "966" { "Saudi Arabia" }
    "967" { "Yemen" }
    "968" { "Oman" }
    "970" { "Palestinian Territory" }
    "971" { "United Arab Emirates" }
    "972" { "Israel" }
    "973" { "Bahrain" }
    "974" { "Qatar" }
    "975" { "Bhutan" }
    "976" { "Mongolia" }
    "977" { "Nepal" }
    "992" { "Tajikistan" }
    "993" { "Turkmenistan" }
    "994" { "Azerbaijan" }
    "995" { "Georgia" }
    "996" { "Kyrgyzstan" }
    "998" { "Uzbekistan" }
    default { "Unknown" }
}
          
            Write-Output "Phone Number Details:"
            Write-Output "  Country Code: $countryCode ($countryName)"
            if ($areaCode) {
                $areaName = switch ($areaCode) {
                    # United States Area Codes
                    "205" { "Alabama" }
                    "251" { "Alabama" }
                    "256" { "Alabama" }
                    "334" { "Alabama" }
                    "938" { "Alabama" }
                    "907" { "Alaska" }
                    "480" { "Arizona" }
                    "520" { "Arizona" }
                    "602" { "Arizona" }
                    "623" { "Arizona" }
                    "928" { "Arizona" }
                    "327" { "Arkansas" }
                    "479" { "Arkansas" }
                    "501" { "Arkansas" }
                    "870" { "Arkansas" }
                    "209" { "California" }
                    "213" { "California" }
                    "279" { "California" }
                    "310" { "California" }
                    "323" { "California" }
                    "341" { "California" }
                    "408" { "California" }
                    "415" { "California" }
                    "424" { "California" }
                    "442" { "California" }
                    "510" { "California" }
                    "530" { "California" }
                    "559" { "California" }
                    "562" { "California" }
                    "619" { "California" }
                    "626" { "California" }
                    "628" { "California" }
                    "650" { "California" }
                    "657" { "California" }
                    "661" { "California" }
                    "669" { "California" }
                    "707" { "California" }
                    "714" { "California" }
                    "747" { "California" }
                    "752" { "California" }
                    "760" { "California" }
                    "805" { "California" }
                    "818" { "California" }
                    "820" { "California" }
                    "831" { "California" }
                    "858" { "California" }
                    "909" { "California" }
                    "916" { "California" }
                    "925" { "California" }
                    "949" { "California" }
                    "951" { "California" }
                    "303" { "Colorado" }
                    "719" { "Colorado" }
                    "720" { "Colorado" }
                    "970" { "Colorado" }
                    "203" { "Connecticut" }
                    "475" { "Connecticut" }
                    "860" { "Connecticut" }
                    "959" { "Connecticut" }
                    "302" { "Delaware" }
                    "202" { "District of Columbia" }
                    "239" { "Florida" }
                    "305" { "Florida" }
                    "321" { "Florida" }
                    "352" { "Florida" }
                    "386" { "Florida" }
                    "407" { "Florida" }
                    "561" { "Florida" }
                    "689" { "Florida" }
                    "727" { "Florida" }
                    "754" { "Florida" }
                    "772" { "Florida" }
                    "786" { "Florida" }
                    "813" { "Florida" }
                    "850" { "Florida" }
                    "863" { "Florida" }
                    "904" { "Florida" }
                    "941" { "Florida" }
                    "954" { "Florida" }
                    "229" { "Georgia" }
                    "404" { "Georgia" }
                    "470" { "Georgia" }
                    "478" { "Georgia" }
                    "678" { "Georgia" }
                    "706" { "Georgia" }
                    "762" { "Georgia" }
                    "770" { "Georgia" }
                    "912" { "Georgia" }
                    "808" { "Hawaii" }
                    "208" { "Idaho" }
                    "986" { "Idaho" }
                    "217" { "Illinois" }
                    "224" { "Illinois" }
                    "309" { "Illinois" }
                    "312" { "Illinois" }
                    "331" { "Illinois" }
                    "447" { "Illinois" }
                    "464" { "Illinois" }
                    "618" { "Illinois" }
                    "630" { "Illinois" }
                    "708" { "Illinois" }
                    "773" { "Illinois" }
                    "779" { "Illinois" }
                    "815" { "Illinois" }
                    "847" { "Illinois" }
                    "872" { "Illinois" }
                    "219" { "Indiana" }
                    "260" { "Indiana" }
                    "317" { "Indiana" }
                    "463" { "Indiana" }
                    "574" { "Indiana" }
                    "765" { "Indiana" }
                    "812" { "Indiana" }
                    "930" { "Indiana" }
                    "319" { "Iowa" }
                    "515" { "Iowa" }
                    "563" { "Iowa" }
                    "641" { "Iowa" }
                    "712" { "Iowa" }
                    "316" { "Kansas" }
                    "620" { "Kansas" }
                    "785" { "Kansas" }
                    "913" { "Kansas" }
                    "270" { "Kentucky" }
                    "364" { "Kentucky" }
                    "502" { "Kentucky" }
                    "606" { "Kentucky" }
                    "859" { "Kentucky" }
                    "225" { "Louisiana" }
                    "318" { "Louisiana" }
                    "337" { "Louisiana" }
                    "504" { "Louisiana" }
                    "985" { "Louisiana" }
                    "207" { "Maine" }
                    "240" { "Maryland" }
                    "301" { "Maryland" }
                    "410" { "Maryland" }
                    "443" { "Maryland" }
                    "667" { "Maryland" }
                    "339" { "Massachusetts" }
                    "351" { "Massachusetts" }
                    "413" { "Massachusetts" }
                    "508" { "Massachusetts" }
                    "617" { "Massachusetts" }
                    "774" { "Massachusetts" }
                    "781" { "Massachusetts" }
                    "857" { "Massachusetts" }
                    "978" { "Massachusetts" }
                    "231" { "Michigan" }
                    "248" { "Michigan" }
                    "269" { "Michigan" }
                    "313" { "Michigan" }
                    "517" { "Michigan" }
                    "586" { "Michigan" }
                    "616" { "Michigan" }
                    "734" { "Michigan" }
                    "810" { "Michigan" }
                    "906" { "Michigan" }
                    "947" { "Michigan" }
                    "989" { "Michigan" }
                    "218" { "Minnesota" }
                    "320" { "Minnesota" }
                    "507" { "Minnesota" }
                    "612" { "Minnesota" }
                    "651" { "Minnesota" }
                    "763" { "Minnesota" }
                    "952" { "Minnesota" }
                    "228" { "Mississippi" }
                    "601" { "Mississippi" }
                    "662" { "Mississippi" }
                    "769" { "Mississippi" }
                    "314" { "Missouri" }
                    "417" { "Missouri" }
                    "573" { "Missouri" }
                    "636" { "Missouri" }
                    "660" { "Missouri" }
                    "816" { "Missouri" }
                    "975" { "Missouri" }
                    "406" { "Montana" }
                    "308" { "Nebraska" }
                    "402" { "Nebraska" }
                    "531" { "Nebraska" }
                    "702" { "Nevada" }
                    "725" { "Nevada" }
                    "775" { "Nevada" }
                    "603" { "New Hampshire" }
                    "201" { "New Jersey" }
                    "551" { "New Jersey" }
                    "609" { "New Jersey" }
                    "732" { "New Jersey" }
                    "848" { "New Jersey" }
                    "856" { "New Jersey" }
                    "862" { "New Jersey" }
                    "908" { "New Jersey" }
                    "973" { "New Jersey" }
                    "505" { "New Mexico" }
                    "575" { "New Mexico" }
                    "212" { "New York" }
                    "315" { "New York" }
                    "332" { "New York" }
                    "347" { "New York" }
                    "516" { "New York" }
                    "518" { "New York" }
                    "607" { "New York" }
                    "631" { "New York" }
                    "646" { "New York" }
                    "680" { "New York" }
                    "716" { "New York" }
                    "718" { "New York" }
                    "838" { "New York" }
                    "845" { "New York" }
                    "914" { "New York" }
                    "917" { "New York" }
                    "929" { "New York" }
                    "252" { "North Carolina" }
                    "336" { "North Carolina" }
                    "704" { "North Carolina" }
                    "743" { "North Carolina" }
                    "828" { "North Carolina" }
                    "910" { "North Carolina" }
                    "919" { "North Carolina" }
                    "980" { "North Carolina" }
                    "984" { "North Carolina" }
                    "701" { "North Dakota" }
                    "216" { "Ohio" }
                    "220" { "Ohio" }
                    "234" { "Ohio" }
                    "283" { "Ohio" }
                    "326" { "Ohio" }
                    "330" { "Ohio" }
                    "380" { "Ohio" }
                    "419" { "Ohio" }
                    "440" { "Ohio" }
                    "513" { "Ohio" }
                    "567" { "Ohio" }
                    "614" { "Ohio" }
                    "740" { "Ohio" }
                    "937" { "Ohio" }
                    "405" { "Oklahoma" }
                    "539" { "Oklahoma" }
                    "572" { "Oklahoma" }
                    "580" { "Oklahoma" }
                    "918" { "Oklahoma" }
                    "458" { "Oregon" }
                    "503" { "Oregon" }
                    "541" { "Oregon" }
                    "971" { "Oregon" }
                    "215" { "Pennsylvania" }
                    "223" { "Pennsylvania" }
                    "267" { "Pennsylvania" }
                    "272" { "Pennsylvania" }
                    "412" { "Pennsylvania" }
                    "445" { "Pennsylvania" }
                    "484" { "Pennsylvania" }
                    "570" { "Pennsylvania" }
                    "610" { "Pennsylvania" }
                    "717" { "Pennsylvania" }
                    "724" { "Pennsylvania" }
                    "814" { "Pennsylvania" }
                    "878" { "Pennsylvania" }
                    "401" { "Rhode Island" }
                    "803" { "South Carolina" }
                    "839" { "South Carolina" }
                    "843" { "South Carolina" }
                    "854" { "South Carolina" }
                    "864" { "South Carolina" }
                    "605" { "South Dakota" }
                    "423" { "Tennessee" }
                    "615" { "Tennessee" }
                    "629" { "Tennessee" }
                    "731" { "Tennessee" }
                    "865" { "Tennessee" }
                    "901" { "Tennessee" }
                    "931" { "Tennessee" }
                    "210" { "Texas" }
                    "214" { "Texas" }
                    "254" { "Texas" }
                    "281" { "Texas" }
                    "325" { "Texas" }
                    "346" { "Texas" }
                    "361" { "Texas" }
                    "409" { "Texas" }
                    "430" { "Texas" }
                    "432" { "Texas" }
                    "469" { "Texas" }
                    "512" { "Texas" }
                    "682" { "Texas" }
                    "713" { "Texas" }
                    "726" { "Texas" }
                    "737" { "Texas" }
                    "806" { "Texas" }
                    "817" { "Texas" }
                    "830" { "Texas" }
                    "832" { "Texas" }
                    "903" { "Texas" }
                    "915" { "Texas" }
                    "936" { "Texas" }
                    "940" { "Texas" }
                    "945" { "Texas" }
                    "956" { "Texas" }
                    "972" { "Texas" }
                    "979" { "Texas" }
                    "385" { "Utah" }
                    "435" { "Utah" }
                    "801" { "Utah" }
                    "802" { "Vermont" }
                    "276" { "Virginia" }
                    "434" { "Virginia" }
                    "540" { "Virginia" }
                    "571" { "Virginia" }
                    "703" { "Virginia" }
                    "757" { "Virginia" }
                    "804" { "Virginia" }
                    "206" { "Washington" }
                    "253" { "Washington" }
                    "360" { "Washington" }
                    "425" { "Washington" }
                    "509" { "Washington" }
                    "564" { "Washington" }
                    "304" { "West Virginia" }
                    "681" { "West Virginia" }
                    "262" { "Wisconsin" }
                    "274" { "Wisconsin" }
                    "414" { "Wisconsin" }
                    "534" { "Wisconsin" }
                    "608" { "Wisconsin" }
                    "715" { "Wisconsin" }
                    "920" { "Wisconsin" }
                    "307" { "Wyoming" }

                    # United Kingdom Area Codes
                    "20" { "London" }
                    "121" { "Birmingham" }
                    "161" { "Manchester" }
                    "141" { "Glasgow" }
                    "151" { "Liverpool" }
                    "113" { "Leeds" }
                    "114" { "Sheffield" }
                    "117" { "Bristol" }
                    "131" { "Edinburgh" }
                    "29" { "Cardiff" }
                    "28" { "Belfast" }
                    "191" { "Newcastle" }
                    "115" { "Nottingham" }

                    # Canada Area Codes
                    "416" { "Toronto" }
                    "437" { "Toronto" }
                    "647" { "Toronto" }
                    "236" { "Vancouver" }
                    "250" { "Vancouver" }
                    "604" { "Vancouver" }
                    "778" { "Vancouver" }
                    "438" { "Montreal" }
                    "514" { "Montreal" }
                    "403" { "Calgary" }
                    "587" { "Calgary" }
                    "780" { "Calgary" }
                    "825" { "Calgary" }
                    "343" { "Ottawa" }
                    "613" { "Ottawa" }
                    "418" { "Quebec City" }
                    "581" { "Quebec City" }

                    # Australia Area Codes
                    "2" { "Sydney/Canberra" }
                    "3" { "Melbourne/Hobart" }
                    "7" { "Brisbane" }
                    "8" { "Perth/Adelaide/Darwin" }

                    # Germany Area Codes
                    "30" { "Berlin" }
                    "89" { "Munich" }
                    "69" { "Frankfurt" }
                    "40" { "Hamburg" }
                    "221" { "Cologne" }
                    "711" { "Stuttgart" }
                    "211" { "Düsseldorf" }
                    "231" { "Dortmund" }
                    "201" { "Essen" }
                    "341" { "Leipzig" }

                    # France Area Codes
                    "1" { "Paris" }
                    "4" { "Marseille/Nice/Lyon" }
                    "5" { "Toulouse/Bordeaux" }
                    "2" { "Nantes" }
                    "3" { "Strasbourg/Lille" }

                    # India Area Codes
                    "11" { "Delhi" }
                    "22" { "Mumbai" }
                    "33" { "Kolkata" }
                    "44" { "Chennai" }
                    "80" { "Bangalore" }
                    "40" { "Hyderabad" }
                    "79" { "Ahmedabad" }
                    "20" { "Pune" }
                    "141" { "Jaipur" }
                    "522" { "Lucknow" }

                    # China Area Codes
                    "10" { "Beijing" }
                    "21" { "Shanghai" }
                    "22" { "Tianjin" }
                    "23" { "Chongqing" }
                    "20" { "Guangzhou" }
                    "755" { "Shenzhen" }
                    "27" { "Wuhan" }
                    "28" { "Chengdu" }
                    "571" { "Hangzhou" }
                    "29" { "Xi'an" }

                    # Japan Area Codes
                    "3" { "Tokyo" }
                    "6" { "Osaka" }
                    "52" { "Nagoya" }
                    "11" { "Sapporo" }
                    "92" { "Fukuoka" }
                    "78" { "Kobe" }
                    "75" { "Kyoto" }
                    "22" { "Sendai" }
                    "82" { "Hiroshima" }
                    "45" { "Yokohama" }

                    # Russia Area Codes
                    "495" { "Moscow" }
                    "499" { "Moscow" }
                    "812" { "Saint Petersburg" }
                    "383" { "Novosibirsk" }
                    "343" { "Yekaterinburg" }
                    "831" { "Nizhny Novgorod" }
                    "846" { "Samara" }
                    "381" { "Omsk" }
                    "843" { "Kazan" }
                    "351" { "Chelyabinsk" }
                    "863" { "Rostov-on-Don" }

                    # Brazil Area Codes
                    "11" { "São Paulo" }
                    "21" { "Rio de Janeiro" }
                    "61" { "Brasília" }
                    "71" { "Salvador" }
                    "85" { "Fortaleza" }
                    "31" { "Belo Horizonte" }
                    "92" { "Manaus" }
                    "41" { "Curitiba" }
                    "81" { "Recife" }
                    "51" { "Porto Alegre" }

                    # South Africa Area Codes
                    "11" { "Johannesburg" }
                    "21" { "Cape Town" }
                    "31" { "Durban" }
                    "12" { "Pretoria" }
                    "41" { "Port Elizabeth" }
                    "51" { "Bloemfontein" }
                    "43" { "East London" }

                    # Italy Area Codes
                    "6" { "Rome" }
                    "2" { "Milan" }
                    "81" { "Naples" }
                    "11" { "Turin" }
                    "91" { "Palermo" }
                    "10" { "Genoa" }
                    "51" { "Bologna" }
                    "55" { "Florence" }
                    "80" { "Bari" }
                    "95" { "Catania" }

                    # Mexico Area Codes
                    "55" { "Mexico City" }
                    "33" { "Guadalajara" }
                    "81" { "Monterrey" }
                    "222" { "Puebla" }
                    "664" { "Tijuana" }
                    "477" { "León" }
                    "998" { "Cancún" }
                    "999" { "Mérida" }
                    "449" { "Aguascalientes" }
                    "229" { "Veracruz" }

                    # Nigeria Area Codes
                    "1" { "Lagos" }
                    "9" { "Abuja" }
                    "64" { "Kano" }
                    "2" { "Ibadan" }
                    "84" { "Port Harcourt" }
                    "52" { "Benin City" }
                    "73" { "Jos" }
                    "62" { "Kaduna" }
                    "42" { "Enugu" }
                    "76" { "Maiduguri" }

                    # Egypt Area Codes
                    "2" { "Cairo/Giza/Shubra El-Kheima" }
                    "3" { "Alexandria" }
                    "66" { "Port Said" }
                    "62" { "Suez" }
                    "50" { "Mansoura" }
                    "40" { "Tanta" }
                    "88" { "Asyut" }
                    "64" { "Ismailia" }

                    # Pakistan Area Codes
                    "21" { "Karachi" }
                    "42" { "Lahore" }
                    "51" { "Islamabad/Rawalpindi" }
                    "41" { "Faisalabad" }
                    "61" { "Multan" }
                    "91" { "Peshawar" }
                    "81" { "Quetta" }
                    "52" { "Sialkot" }
                    "55" { "Gujranwala" }

                    # Indonesia Area Codes
                    "21" { "Jakarta" }
                    "31" { "Surabaya" }
                    "22" { "Bandung" }
                    "61" { "Medan" }
                    "24" { "Semarang" }
                    "71" { "Palembang" }
                    "411" { "Makassar" }
                    "778" { "Batam" }
                    "542" { "Balikpapan" }
                    "761" { "Pekanbaru" }

                    # Philippines Area Codes
                    "2" { "Manila" }
                    "32" { "Cebu" }
                    "82" { "Davao" }
                    "62" { "Zamboanga" }
                    "33" { "Iloilo" }
                    "88" { "Cagayan de Oro" }
                    "74" { "Baguio" }
                    "34" { "Bacolod" }
                    "83" { "General Santos" }
                    "85" { "Butuan" }

                    # Vietnam Area Codes
                    "28" { "Ho Chi Minh City" }
                    "24" { "Hanoi" }
                    "236" { "Da Nang" }
                    "225" { "Hai Phong" }
                    "292" { "Can Tho" }
                    "258" { "Nha Trang" }
                    "234" { "Hue" }
                    "251" { "Bien Hoa" }
                    "254" { "Vung Tau" }
                    "256" { "Quy Nhon" }

                    # Thailand Area Codes
                    "2" { "Bangkok" }
                    "53" { "Chiang Mai" }
                    "38" { "Pattaya" }
                    "76" { "Phuket" }
                    "43" { "Khon Kaen" }
                    "74" { "Hat Yai" }
                    "42" { "Udon Thani" }
                    "44" { "Nakhon Ratchasima" }
                    "45" { "Ubon Ratchathani" }
                    "77" { "Surat Thani" }

                    # Malaysia Area Codes
                    "3" { "Kuala Lumpur" }
                    "4" { "George Town/Alor Setar" }
                    "5" { "Ipoh" }
                    "6" { "Malacca City" }
                    "7" { "Johor Bahru" }
                    "9" { "Kuantan/Kuala Terengganu" }
                    "88" { "Kota Kinabalu" }
                    "82" { "Kuching" }

                    # New Zealand Area Codes
                    "9" { "Auckland" }
                    "4" { "Wellington" }
                    "3" { "Christchurch" }
                    "7" { "Hamilton/Tauranga/Rotorua" }
                    "6" { "New Plymouth/Palmerston North" }
                    default { "Unknown Area" }
                }
                Write-Output "  Area Code: $areaCode ($areaName)"
            }
            Write-Output "  Local Number: $localNumber"
        } else {
            Write-Output "Phone Number: $PhoneNumber (unparsed)"
        }
    }
}

# Function to get user metadata
function Get-UserMetadata {
    param (
        [Parameter(Mandatory = $true)]
        $User
    )

    Write-Output ""
    Write-Output "User Metadata:"
    Write-Output "================="

    # Basic Information
    Write-Output "Basic Information:"
    Write-Output "------------------"
    $basicProperties = @('DisplayName', 'GivenName', 'Surname', 'JobTitle', 'Mail', 'UserPrincipalName')
    foreach ($property in $basicProperties) {
        $value = $User.$property
        if ($value) {
            Write-Output "${property}: ${value}"
        }
    }

    # Location Information
    Write-Output ""
    Write-Output "Location Information:"
    Write-Output "----------------------"
    $locationProperties = @('Country', 'State', 'City', 'StreetAddress', 'PostalCode', 'BusinessPhones', 'MobilePhone', 'PreferredLanguage')
    foreach ($property in $locationProperties) {
        $value = $User.$property
        if ($value) {
            Write-Output "${property}: ${value}"
            if ($property -eq 'MobilePhone' -or $property -eq 'BusinessPhones') {
                foreach ($phone in $value) {
                    Parse-PhoneNumber -PhoneNumber $phone
                }
            }
        }
    }

    # Authentication Information
    Write-Output ""
    Write-Output "Authentication Information:"
    Write-Output "---------------------------"
    $authProperties = @('Authentication', 'AuthorizationInfo')
    foreach ($property in $authProperties) {
        $value = $User.$property
        if ($value) {
            Write-Output "${property}: $(${value} | Out-String)"
        }
    }

    # Security Attributes
    Write-Output ""
    Write-Output "Security Attributes:"
    Write-Output "---------------------"
    $securityProperties = @('CustomSecurityAttributes', 'PasswordProfile', 'SignInActivity')
    foreach ($property in $securityProperties) {
        $value = $User.$property
        if ($value) {
            Write-Output "${property}: $(${value} | Out-String)"
        }
    }

    Write-Output "================="
    Write-Output ""
}

# Example: Query additional details for nested objects
function Expand-NestedProperty {
    param (
        [Parameter(Mandatory = $true)]
        [Object]$PropertyValue,
        [string]$PropertyName
    )

    Write-Output ""
    Write-Output "${PropertyName} Details:"
    Write-Output "----------------------"

    $properties = $PropertyValue | Get-Member -MemberType Properties
    foreach ($property in $properties) {
        $value = $PropertyValue.$($property.Name)
        if ($value) {
            Write-Output "$($property.Name): ${value}"
        }
    }
}

# Define a hashtable to store commonly seen Azure Sign-in error codes and their descriptions
$AzureSigninErrorCodes = @{
    "AADSTS16000" = "InteractionRequired - User account '{EmailHidden}' from identity provider '{idp}' doesn't exist in tenant '{tenant}' and can't access the application '{appid}'({appName}) in that tenant. This account needs to be added as an external user in the tenant first. Sign out and sign in again with a different Microsoft Entra user account."
    "AADSTS16001" = "UserAccountSelectionInvalid - You see this error if the user selects on a tile that the session select logic has rejected. When triggered, this error allows the user to recover by picking from an updated list of tiles/sessions, or by choosing another account."
    "AADSTS16002" = "AppSessionSelectionInvalid - The app-specified SID requirement wasn't met."
    "AADSTS160021" = "AppSessionSelectionInvalidSessionNotExist - Application requested a user session that doesn't exist. This issue can be resolved by creating new Azure account."
    "AADSTS16003" = "SsoUserAccountNotFoundInResourceTenant - Indicates that the user hasn't been explicitly added to the tenant."
    "AADSTS17003" = "CredentialKeyProvisioningFailed - Microsoft Entra ID can't provision the user key."
    "AADSTS20001" = "WsFedSignInResponseError - There's an issue with your federated Identity Provider. Contact your IDP to resolve this issue."
    "AADSTS20012" = "WsFedMessageInvalid - There's an issue with your federated Identity Provider. Contact your IDP to resolve this issue."
    "AADSTS20033" = "FedMetadataInvalidTenantName - There's an issue with your federated Identity Provider. Contact your IDP to resolve this issue."
    "AADSTS230109" = "CachedCredentialNonGWAuthNRequestsNotSupported - Backup Auth Service only allows AuthN requests from Microsoft Entra Gateway. This error is returned when traffic targets the backup auth service directly instead of going through the reverse proxy."
    "AADSTS28002" = "Provided value for the input parameter scope '{scope}' isn't valid when requesting an access token. Specify a valid scope."
    "AADSTS28003" = "Provided value for the input parameter scope can't be empty when requesting an access token using the provided authorization code. Specify a valid scope."
    "AADSTS40008" = "OAuth2IdPUnretryableServerError - There's an issue with your federated Identity Provider. Contact your IDP to resolve this issue."
    "AADSTS40009" = "OAuth2IdPRefreshTokenRedemptionUserError - There's an issue with your federated Identity Provider. Contact your IDP to resolve this issue."
    "AADSTS40010" = "OAuth2IdPRetryableServerError - There's an issue with your federated Identity Provider. Contact your IDP to resolve this issue."
    "AADSTS40015" = "OAuth2IdPAuthCodeRedemptionUserError - There's an issue with your federated Identity Provider. Contact your IDP to resolve this issue."
    "AADSTS50000" = "TokenIssuanceError - There's an issue with the sign-in service. Open a support ticket to resolve this issue."
    "AADSTS50001" = "InvalidResource - The resource is disabled or doesn't exist. Check your app's code to ensure that you have specified the exact resource URL for the resource you're trying to access."
    "AADSTS50002" = "NotAllowedTenant - Sign-in failed because of a restricted proxy access on the tenant. If it's your own tenant policy, you can change your restricted tenant settings to fix this issue."
    "AADSTS50003" = "MissingSigningKey - Sign-in failed because of a missing signing key or certificate. This might be because there was no signing key configured in the app."
    "AADSTS50005" = "DevicePolicyError - User tried to sign in to a device from a platform not currently supported through Conditional Access policy."
    "AADSTS50006" = "InvalidSignature - Signature verification failed because of an invalid signature."
    "AADSTS50007" = "PartnerEncryptionCertificateMissing - The partner encryption certificate wasn't found for this app. Open a support ticket with Microsoft to get this fixed."
    "AADSTS50008" = "InvalidSamlToken - SAML assertion is missing or misconfigured in the token. Contact your federation provider."
    "AADSTS50010" = "AudienceUriValidationFailed - Audience URI validation for the app failed since no token audiences were configured."
    "AADSTS50011" = "InvalidReplyTo - The reply address is missing, misconfigured, or doesn't match reply addresses configured for the app."
    "AADSTS50012" = "AuthenticationFailed - Authentication failed for one of the following reasons: The subject name of the signing certificate isn't authorized, A matching trusted authority policy wasn't found for the authorized subject name, The certificate chain isn't valid, The signing certificate isn't valid, Policy isn't configured on the tenant, Thumbprint of the signing certificate isn't authorized, Client assertion contains an invalid signature."
    "AADSTS50013" = "InvalidAssertion - Assertion is invalid because of various reasons - The token issuer doesn't match the API version within its valid time range, expired, malformed, or refresh token in the assertion isn't a primary refresh token. Contact the app developer."
    "AADSTS50014" = "GuestUserInPendingState - The user account doesn’t exist in the directory."
    "AADSTS50015" = "ViralUserLegalAgeConsentRequiredState - The user requires legal age group consent."
    "AADSTS50017" = "CertificateValidationFailed - Certification validation failed."
    "AADSTS50020" = "UserUnauthorized - Users are unauthorized to call this endpoint. User account '{email}' from identity provider '{idp}' does not exist in tenant '{tenant}' and cannot access the application '{appid}'({appName}) in that tenant. This account needs to be added as an external user in the tenant first. Sign out and sign in again with a different Microsoft Entra user account."
    "AADSTS50021" = "Access to '{tenant}' tenant is denied. The tenant restriction feature is configured and the user is trying to access a tenant that isn't in the list of allowed tenants."
    "AADSTS50022" = "Access to '{tenant}' tenant is denied. The tenant restriction feature is configured and the user is trying to access a tenant that isn't in the list of allowed tenants."
    "AADSTS50027" = "InvalidJwtToken - Invalid JWT token because it doesn't contain nonce claim, sub claim, subject identifier mismatch, duplicate claim in idToken claims, unexpected issuer, unexpected audience, not within its valid time range, or token format isn't proper."
    "AADSTS50029" = "Invalid URI - domain name contains invalid characters. Contact the tenant admin."
    "AADSTS50032" = "WeakRsaKey - Indicates the erroneous user attempt to use a weak RSA key."
    "AADSTS50033" = "RetryableError - Indicates a transient error not related to the database operations."
    "AADSTS50034" = "UserAccountNotFound - To sign into this application, the account must be added to the directory. This error can occur because the user mistyped their username, or isn't in the tenant."
    "AADSTS50042" = "UnableToGeneratePairwiseIdentifierWithMissingSalt - The salt required to generate a pairwise identifier is missing in principle. Contact the tenant admin."
    "AADSTS50043" = "UnableToGeneratePairwiseIdentifierWithMultipleSalts."
    "AADSTS50048" = "SubjectMismatchesIssuer - Subject mismatches Issuer claim in the client assertion. Contact the tenant admin."
    "AADSTS50049" = "NoSuchInstanceForDiscovery - Unknown or invalid instance."
    "AADSTS50050" = "MalformedDiscoveryRequest - The request is malformed."
    "AADSTS50053" = "This error can result from two different reasons: IdsLocked - The account is locked because the user tried to sign in too many times with an incorrect user ID or password. The user is blocked due to repeated sign-in attempts. See Remediate risks and unblock users. Or, sign-in was blocked because it came from an IP address with malicious activity. To determine which failure reason caused this error, sign in to the Microsoft Entra admin center as at least a Cloud Application Administrator. Navigate to your Microsoft Entra tenant and then Monitoring & health -> Sign-in logs. Find the failed user sign-in with Sign-in error code 50053 and check the Failure reason."
    "AADSTS50055" = "InvalidPasswordExpiredPassword - The password is expired. The user's password is expired, and therefore their login or session was ended."
    "AADSTS50056" = "Invalid or null password: password doesn't exist in the directory for this user."
    "AADSTS50057" = "UserDisabled - The user account is disabled. The user object in Active Directory backing this account has been disabled."
    "AADSTS50058" = "UserInformationNotProvided - Session information isn't sufficient for single-sign-on."
    "AADSTS50059" = "MissingTenantRealmAndNoUserInformationProvided - Tenant-identifying information wasn't found in either the request or implied by any provided credentials."
    "AADSTS50061" = "SignoutInvalidRequest - Unable to complete sign out. The request was invalid."
    "AADSTS50064" = "CredentialAuthenticationError - Credential validation on username or password has failed."
    "AADSTS50068" = "SignoutInitiatorNotParticipant - Sign out has failed. The app that initiated sign out isn't a participant in the current session."
    "AADSTS50070" = "SignoutUnknownSessionIdentifier - Sign out has failed. The sign out request specified a name identifier that didn't match the existing session(s)."
    "AADSTS50071" = "SignoutMessageExpired - The logout request has expired."
    "AADSTS50072" = "UserStrongAuthEnrollmentRequiredInterrupt - User needs to enroll for second factor authentication (interactive)."
    "AADSTS50074" = "UserStrongAuthClientAuthNRequiredInterrupt - Strong authentication is required and the user did not pass the MFA challenge."
    "AADSTS50076" = "UserStrongAuthClientAuthNRequired - Due to a configuration change made by the admin such as a Conditional Access policy, per-user enforcement, or because you moved to a new location, the user must use multifactor authentication to access the resource."
    "AADSTS50078" = "UserStrongAuthExpired - Presented multifactor authentication has expired due to policies configured by your administrator. You must refresh your multifactor authentication to access '{resource}'."
    "AADSTS50079" = "UserStrongAuthEnrollmentRequired - Due to a configuration change made by the admin such as a Conditional Access policy, per-user enforcement, or because the user moved to a new location, the user is required to use multifactor authentication. Either a managed user needs to register security info to complete multifactor authentication, or a federated user needs to get the multifactor claim from the federated identity provider."
    "AADSTS50085" = "Refresh token needs social IDP login. Have user try signing-in again with username and password."
    "AADSTS50086" = "SasNonRetryableError."
    "AADSTS50087" = "SasRetryableError - A transient error has occurred during strong authentication. Please try again."
    "AADSTS50088" = "Limit on telecom MFA calls reached. Please try again in a few minutes."
    "AADSTS50089" = "Authentication failed due to flow token expired. Expected - auth codes, refresh tokens, and sessions expire over time or are revoked by the user or an admin. The app will request a new login from the user."
    "AADSTS50097" = "DeviceAuthenticationRequired - Device authentication is required."
    "AADSTS50099" = "PKeyAuthInvalidJwtUnauthorized - The JWT signature is invalid."
    "AADSTS50105" = "EntitlementGrantsNotFound - The signed in user isn't assigned to a role for the signed in app. Assign the user to the app."
    "AADSTS50107" = "InvalidRealmUri - The requested federation realm object doesn't exist."
    "AADSTS50120" = "ThresholdJwtInvalidJwtFormat - Issue with JWT header. Contact the tenant admin."
    "AADSTS50124" = "ClaimsTransformationInvalidInputParameter - Claims Transformation contains invalid input parameter. Contact the tenant admin to update the policy."
    "AADSTS501241" = "Mandatory Input '{paramName}' missing from transformation ID '{transformId}'. This error is returned while Microsoft Entra ID is trying to build a SAML response to the application. NameID claim or NameIdentifier is mandatory in SAML response and if Microsoft Entra ID failed to get source attribute for NameID claim, it returns this error. As a resolution, ensure that you add claim rules. To add claim rules, sign in to the Microsoft Entra admin center as at least a Cloud Application Administrator, and then browse to Identity > Applications > Enterprise applications. Select your application, select Single Sign-On and then in User Attributes & Claims enter the Unique User Identifier (Name ID)."
    "AADSTS50125" = "PasswordResetRegistrationRequiredInterrupt - Sign-in was interrupted because of a password reset or password registration entry."
    "AADSTS50126" = "InvalidUserNameOrPassword - Error validating credentials due to invalid username or password. The user didn't enter the right credentials. Expect to see some number of these errors in your logs due to users making mistakes."
    "AADSTS50127" = "BrokerAppNotInstalled - User needs to install a broker app to gain access to this content."
    "AADSTS50128" = "Invalid domain name - No tenant-identifying information found in either the request or implied by any provided credentials."
    "AADSTS50129" = "DeviceIsNotWorkplaceJoined - Workplace join is required to register the device."
    "AADSTS50131" = "ConditionalAccessFailed - Indicates various Conditional Access errors such as bad Windows device state, request blocked due to suspicious activity, access policy, or security policy decisions."
    "AADSTS50132" = "SsoArtifactInvalidOrExpired - The session isn't valid due to password expiration or recent password change."
    "AADSTS50133" = "SsoArtifactRevoked - The session isn't valid due to password expiration or recent password change."
    "AADSTS50134" = "DeviceFlowAuthorizeWrongDatacenter - Wrong data center. To authorize a request that was initiated by an app in the OAuth 2.0 device flow, the authorizing party must be in the same data center where the original request resides."
    "AADSTS50135" = "PasswordChangeCompromisedPassword - Password change is required due to account risk."
    "AADSTS50136" = "RedirectMsaSessionToApp - Single MSA session detected."
    "AADSTS50139" = "SessionMissingMsaOAuth2RefreshToken - The session is invalid due to a missing external refresh token."
    "AADSTS50140" = "KmsiInterrupt - This error occurred due to 'Keep me signed in' interrupt when the user was signing-in. This is an expected part of the sign in flow, where a user is asked if they want to remain signed into their current browser to make further logins easier. For more information, see The new Microsoft Entra sign-in and 'Keep me signed in' experiences rolling out now!. You can open a support ticket with Correlation ID, Request ID, and Error code to get more details."
    "AADSTS50143" = "Session mismatch - Session is invalid because user tenant doesn't match the domain hint due to different resource. Open a support ticket with Correlation ID, Request ID, and Error code to get more details."
    "AADSTS50144" = "InvalidPasswordExpiredOnPremPassword - User's Active Directory password has expired. Generate a new password for the user or have the user use the self-service reset tool to reset their password."
    "AADSTS50146" = "MissingCustomSigningKey - This app is required to be configured with an app-specific signing key. It's either not configured with one, or the key has expired or isn't yet valid. Please contact the owner of the application."
    "AADSTS501461" = "AcceptMappedClaims is only supported for a token audience matching the application GUID or an audience within the tenant's verified domains. Either change the resource identifier, or use an application-specific signing key."
    "AADSTS50147" = "MissingCodeChallenge - The size of the code challenge parameter isn't valid."
    "AADSTS501481" = "The Code_Verifier doesn't match the code_challenge supplied in the authorization request."
    "AADSTS501491" = "InvalidCodeChallengeMethodInvalidSize - Invalid size of Code_Challenge parameter."
    "AADSTS50155" = "DeviceAuthenticationFailed - Device authentication failed for this user."
    "AADSTS50158" = "ExternalSecurityChallenge - External security challenge was not satisfied."
    "AADSTS50161" = "InvalidExternalSecurityChallengeConfiguration - Claims sent by external provider isn't enough or Missing claim requested to external provider."
    "AADSTS50166" = "ExternalClaimsProviderThrottled - Failed to send the request to the claims provider."
    "AADSTS50168" = "ChromeBrowserSsoInterruptRequired - The client is capable of obtaining an SSO token through the Windows 10 Accounts extension, but the token was not found in the request or the supplied token was expired."
    "AADSTS50169" = "InvalidRequestBadRealm - The realm isn't a configured realm of the current service namespace."
    "AADSTS50170" = "MissingExternalClaimsProviderMapping - The external controls mapping is missing."
    "AADSTS50173" = "FreshTokenNeeded - The provided grant has expired due to it being revoked, and a fresh auth token is needed. Either an admin or a user revoked the tokens for this user, causing subsequent token refreshes to fail and require reauthentication. Have the user sign in again."
    "AADSTS50177" = "ExternalChallengeNotSupportedForPassthroughUsers - External challenge isn't supported for passthrough users."
    "AADSTS50178" = "SessionControlNotSupportedForPassthroughUsers - Session control isn't supported for passthrough users."
    "AADSTS50180" = "WindowsIntegratedAuthMissing - Integrated Windows authentication is needed. Enable the tenant for Seamless SSO."
    "AADSTS50187" = "DeviceInformationNotProvided - The service failed to perform device authentication."
    "AADSTS50192" = "Invalid Request - RawCredentialExpectedNotFound - No Credential was included in the sign-in request. Example: user is performing certificate-based authentication (CBA) and no certificate is sent (or Proxy removes) the user's certificate in the sign-in request."
    "AADSTS50194" = "Application '{appId}'({appName}) isn't configured as a multitenant application. Usage of the /common endpoint isn't supported for such applications created after '{time}'. Use a tenant-specific endpoint or configure the application to be multitenant."
    "AADSTS50196" = "LoopDetected - A client loop has been detected. Check the app’s logic to ensure that token caching is implemented, and that error conditions are handled correctly. The app has made too many of the same request in too short a period, indicating that it is in a faulty state or is abusively requesting tokens."
    "AADSTS50197" = "ConflictingIdentities - The user could not be found. Try signing in again."
    "AADSTS50199" = "CmsiInterrupt - For security reasons, user confirmation is required for this request. Interrupt is shown for all scheme redirects in mobile browsers. No action required. The user was asked to confirm that this app is the application they intended to sign into. This is a security feature that helps prevent spoofing attacks. This occurs because a system webview has been used to request a token for a native application. To avoid this prompt, the redirect URI should be part of the following safe list: http://, https://, chrome-extension:// (desktop Chrome browser only)"
    "AADSTS51000" = "RequiredFeatureNotEnabled - The feature is disabled."
    "AADSTS51001" = "DomainHintMustbePresent - Domain hint must be present with on-premises security identifier or on-premises UPN."
    "AADSTS51004" = "UserAccountNotInDirectory - The user account doesn’t exist in the directory. An application likely chose the wrong tenant to sign into, and the currently logged in user was prevented from doing so since they did not exist in your tenant. If this user should be able to log in, add them as a guest. For further information, please visit add B2B users."
    "AADSTS51005" = "TemporaryRedirect - Equivalent to HTTP status 307, which indicates that the requested information is located at the URI specified in the location header. When you receive this status, follow the location header associated with the response. When the original request method was POST, the redirected request will also use the POST method."
    "AADSTS51006" = "ForceReauthDueToInsufficientAuth - Integrated Windows authentication is needed. User logged in using a session token that is missing the integrated Windows authentication claim. Request the user to log in again."
    "AADSTS52004" = "DelegationDoesNotExistForLinkedIn - The user has not provided consent for access to LinkedIn resources."
    "AADSTS53000" = "DeviceNotCompliant - Conditional Access policy requires a compliant device, and the device isn't compliant. The user must enroll their device with an approved MDM provider like Intune. For additional information, please visit Conditional Access device remediation."
    "AADSTS53001" = "DeviceNotDomainJoined - Conditional Access policy requires a domain joined device, and the device isn't domain joined. Have the user use a domain joined device."
    "AADSTS53002" = "ApplicationUsedIsNotAnApprovedApp - The app used isn't an approved app for Conditional Access. User needs to use one of the apps from the list of approved apps to use in order to get access."
    "AADSTS53003" = "BlockedByConditionalAccess - Access has been blocked by Conditional Access policies. The access policy does not allow token issuance. If this is unexpected, see the Conditional Access policy that applied to this request or contact your administrator. For additional information, please visit troubleshooting sign-in with Conditional Access."
    "AADSTS53004" = "ProofUpBlockedDueToRisk - User needs to complete the multifactor authentication registration process before accessing this content. User should register for multifactor authentication."
    "AADSTS53010" = "ProofUpBlockedDueToSecurityInfoAcr - Cannot configure multifactor authentication methods because the organization requires this information to be set from specific locations or devices."
    "AADSTS53011" = "User blocked due to risk on home tenant."
    "AADSTS530032" = "BlockedByConditionalAccessOnSecurityPolicy - The tenant admin has configured a security policy that blocks this request. Check the security policies that are defined on the tenant level to determine if your request meets the policy requirements."
    "AADSTS530034" = "DelegatedAdminBlockedDueToSuspiciousActivity - A delegated administrator was blocked from accessing the tenant due to account risk in their home tenant."
    "AADSTS530035" = "BlockedBySecurityDefaults - Access has been blocked by security defaults. This is due to the request using legacy auth or being deemed unsafe by security defaults policies. For additional information, please visit enforced security policies."
    "AADSTS54000" = "MinorUserBlockedLegalAgeGroupRule."
    "AADSTS54005" = "OAuth2 Authorization code was already redeemed, please retry with a new valid code or use an existing refresh token."
    "AADSTS65001" = "DelegationDoesNotExist - The user or administrator hasn't consented to use the application with ID X. Send an interactive authorization request for this user and resource."
    "AADSTS65002" = "Consent between first party application '{applicationId}' and first party resource '{resourceId}' must be configured via preauthorization - applications owned and operated by Microsoft must get approval from the API owner before requesting tokens for that API. A developer in your tenant might be attempting to reuse an App ID owned by Microsoft. This error prevents them from impersonating a Microsoft application to call other APIs. They must move to another app ID they register."
    "AADSTS65004" = "UserDeclinedConsent - User declined to consent to access the app. Have the user retry the sign-in and consent to the app."
    "AADSTS65005" = "MisconfiguredApplication - The app required resource access list doesn't contain apps discoverable by the resource, or the client app has requested access to resource, which wasn't specified in its required resource access list or Graph service returned bad request or resource not found. If the app supports SAML, you might have configured the app with the wrong Identifier (Entity). To learn more, see the troubleshooting article for error AADSTS650056."
    "AADSTS650052" = "The app needs access to a service (\{name}\) that your organization \{organization}\ hasn't subscribed to or enabled. Contact your IT Admin to review the configuration of your service subscriptions."
    "AADSTS650054" = "The application asked for permissions to access a resource that has been removed or is no longer available. Make sure that all resources the app is calling are present in the tenant you're operating in."
    "AADSTS650056" = "Misconfigured application. This could be due to one of the following: the client has not listed any permissions for '{name}' in the requested permissions in the client's application registration. Or, the admin has not consented in the tenant. Or, check the application identifier in the request to ensure it matches the configured client application identifier. Or, check the certificate in the request to ensure it's valid. Please contact your admin to fix the configuration or consent on behalf of the tenant. Client app ID: {ID}. Please contact your admin to fix the configuration or consent on behalf of the tenant."
    "AADSTS650057" = "Invalid resource. The client has requested access to a resource which isn't listed in the requested permissions in the client's application registration. Client app ID: {appId}({appName}). Resource value from request: {resource}. Resource app ID: {resourceAppId}. List of valid resources from app registration: {regList}."
    "AADSTS67003" = "ActorNotValidServiceIdentity."
    "AADSTS70000" = "InvalidGrant - Authentication failed. The refresh token isn't valid. Error might be due to the following reasons: Token binding header is empty, Token binding hash does not match."
    "AADSTS70001" = "UnauthorizedClient - The application is disabled."
    "AADSTS700011" = "UnauthorizedClientAppNotFoundInOrgIdTenant - Application with identifier {appIdentifier} was not found in the directory. A client application requested a token from your tenant, but the client app doesn't exist in your tenant, so the call failed."
    "AADSTS70002" = "InvalidClient - Error validating the credentials. The specified client_secret does not match the expected value for this client. Correct the client_secret and try again. For more info, see Use the authorization code to request an access token."
    "AADSTS700025" = "InvalidClientPublicClientWithCredential - Client is public so neither 'client_assertion' nor 'client_secret' should be presented."
    "AADSTS700027" = "Client assertion failed signature validation. Developer error - the app is attempting to sign in without the necessary or correct authentication parameters."
    "AADSTS70003" = "UnsupportedGrantType - The app returned an unsupported grant type."
    "AADSTS700030" = "Invalid certificate - subject name in certificate isn't authorized. SubjectNames/SubjectAlternativeNames (up to 10) in token certificate are: {certificateSubjects}."
    "AADSTS70004" = "InvalidRedirectUri - The app returned an invalid redirect URI. The redirect address specified by the client does not match any configured addresses or any addresses on the OIDC approve list."
    "AADSTS70005" = "UnsupportedResponseType - The app returned an unsupported response type due to the following reasons: response type 'token' isn't enabled for the app, response type 'id_token' requires the 'OpenID' scope - contains an unsupported OAuth parameter value in the encoded wctx."
    "AADSTS70007" = "UnsupportedResponseMode - The app returned an unsupported value of response_mode when requesting a token."
    "AADSTS70008" = "ExpiredOrRevokedGrant - The refresh token has expired due to inactivity. The token was issued on XXX and was inactive for a certain amount of time."
    "AADSTS700082" = "ExpiredOrRevokedGrantInactiveToken - The refresh token has expired due to inactivity. The token was issued on {issueDate} and was inactive for {time}. Expected part of the token lifecycle - the user went an extended period of time without using the application, so the token was expired when the app attempted to refresh it."
    "AADSTS700084" = "The refresh token was issued to a single page app (SPA), and therefore has a fixed, limited lifetime of {time}, which can't be extended. It is now expired and a new sign in request must be sent by the SPA to the sign in page. The token was issued on {issueDate}."
    "AADSTS70011" = "InvalidScope - The scope requested by the app is invalid."
    "AADSTS70012" = "MsaServerError - A server error occurred while authenticating an MSA (consumer) user. Try again. If it continues to fail, open a support ticket."
    "AADSTS70016" = "AuthorizationPending - OAuth 2.0 device flow error. Authorization is pending."
    "AADSTS70018" = "BadVerificationCode - Invalid verification code due to User typing in wrong user code for device code flow. Authorization isn't approved."
    "AADSTS70019" = "CodeExpired - Verification code expired. Have the user retry the sign-in."
    "AADSTS70043" = "BadTokenDueToSignInFrequency - The refresh token has expired or is invalid due to sign-in frequency checks by Conditional Access. The token was issued on {issueDate} and the maximum allowed lifetime for this request is {time}."
    "AADSTS75001" = "BindingSerializationError - An error occurred during SAML message binding."
    "AADSTS75003" = "UnsupportedBindingError - The app returned an error related to unsupported binding (SAML protocol response can't be sent via bindings other than HTTP POST)."
    "AADSTS75005" = "Saml2MessageInvalid - Microsoft Entra doesn’t support the SAML request sent by the app for SSO."
    "AADSTS7500514" = "A supported type of SAML response was not found. The supported response types are 'Response' (in XML namespace 'urn:oasis:names:tc:SAML:2.0:protocol') or 'Assertion' (in XML namespace 'urn:oasis:names:tc:SAML:2.0:assertion'). Application error - the developer will handle this error."
    "AADSTS750054" = "SAMLRequest or SAMLResponse must be present as query string parameters in HTTP request for SAML Redirect binding."
    "AADSTS75008" = "RequestDeniedError - The request from the app was denied since the SAML request had an unexpected destination."
    "AADSTS75011" = "NoMatchedAuthnContextInOutputClaims - The authentication method by which the user authenticated with the service doesn't match requested authentication method."
    "AADSTS75016" = "Saml2AuthenticationRequestInvalidNameIDPolicy - SAML2 Authentication Request has invalid NameIdPolicy."
    "AADSTS76021" = "ApplicationRequiresSignedRequests - The request sent by client is not signed while the application requires signed requests."
    "AADSTS76026" = "RequestIssueTimeExpired - IssueTime in an SAML2 Authentication Request is expired."
    "AADSTS80001" = "OnPremiseStoreIsNotAvailable - The Authentication Agent is unable to connect to Active Directory. Make sure that agent servers are members of the same AD forest as the users whose passwords need to be validated and they are able to connect to Active Directory."
    "AADSTS80002" = "OnPremisePasswordValidatorRequestTimedout - Password validation request timed out. Make sure that Active Directory is available and responding to requests from the agents."
    "AADSTS80005" = "OnPremisePasswordValidatorUnpredictableWebException - An unknown error occurred while processing the response from the Authentication Agent. Retry the request. If it continues to fail, open a support ticket to get more details on the error."
    "AADSTS80007" = "OnPremisePasswordValidatorErrorOccurredOnPrem - The Authentication Agent is unable to validate user's password. Check the agent logs for more info and verify that Active Directory is operating as expected."
    "AADSTS80010" = "OnPremisePasswordValidationEncryptionException - The Authentication Agent is unable to decrypt password."
    "AADSTS80012" = "OnPremisePasswordValidationAccountLogonInvalidHours - The users attempted to log on outside of the allowed hours (this is specified in AD)."
    "AADSTS80013" = "OnPremisePasswordValidationTimeSkew - The authentication attempt couldn't be completed due to time skew between the machine running the authentication agent and AD. Fix time sync issues."
    "AADSTS80014" = "OnPremisePasswordValidationAuthenticationAgentTimeout - Validation request responded after maximum elapsed time exceeded. Open a support ticket with the error code, correlation ID, and timestamp to get more details on this error."
    "AADSTS81004" = "DesktopSsoIdentityInTicketIsNotAuthenticated - Kerberos authentication attempt failed."
    "AADSTS81005" = "DesktopSsoAuthenticationPackageNotSupported - The authentication package isn't supported."
    "AADSTS81006" = "DesktopSsoNoAuthorizationHeader - No authorization header was found."
    "AADSTS81007" = "DesktopSsoTenantIsNotOptIn - The tenant isn't enabled for Seamless SSO."
    "AADSTS81009" = "DesktopSsoAuthorizationHeaderValueWithBadFormat - Unable to validate user's Kerberos ticket."
    "AADSTS81010" = "DesktopSsoAuthTokenInvalid - Seamless SSO failed because the user's Kerberos ticket has expired or is invalid."
    "AADSTS81011" = "DesktopSsoLookupUserBySidFailed - Unable to find user object based on information in the user's Kerberos ticket."
    "AADSTS81012" = "DesktopSsoMismatchBetweenTokenUpnAndChosenUpn - The user trying to sign in to Microsoft Entra ID is different from the user signed into the device."
    "AADSTS90002" = "InvalidTenantName - The tenant name wasn't found in the data store. Check to make sure you have the correct tenant ID. The application developer will receive this error if their app attempts to sign into a tenant that we cannot find. Often, this is because a cross-cloud app was used against the wrong cloud, or the developer attempted to sign in to a tenant derived from an email address, but the domain isn't registered."
    "AADSTS90004" = "InvalidRequestFormat - The request isn't properly formatted."
    "AADSTS90005" = "InvalidRequestWithMultipleRequirements - Unable to complete the request. The request isn't valid because the identifier and login hint can't be used together."
    "AADSTS90006" = "ExternalServerRetryableError - The service is temporarily unavailable."
    "AADSTS90007" = "InvalidSessionId - Bad request. The passed session ID can't be parsed."
    "AADSTS90008" = "TokenForItselfRequiresGraphPermission - The user or administrator hasn't consented to use the application. At the minimum, the application requires access to Microsoft Entra ID by specifying the sign-in and read user profile permission."
    "AADSTS90009" = "TokenForItselfMissingIdenticalAppIdentifier - The application is requesting a token for itself. This scenario is supported only if the resource that's specified is using the GUID-based application ID."
    "AADSTS90010" = "NotSupported - Unable to create the algorithm."
    "AADSTS9001023" = "The grant type isn't supported over the /common or /consumers endpoints. Please use the /organizations or tenant-specific endpoint."
    "AADSTS90012" = "RequestTimeout - The requested has timed out."
    "AADSTS90013" = "InvalidUserInput - The input from the user isn't valid."
    "AADSTS90014" = "MissingRequiredField - This error code might appear in various cases when an expected field isn't present in the credential."
    "AADSTS900144" = "The request body must contain the following parameter: '{name}'. Developer error - the app is attempting to sign in without the necessary or correct authentication parameters."
    "AADSTS90015" = "QueryStringTooLong - The query string is too long."
    "AADSTS90016" = "MissingRequiredClaim - The access token isn't valid. The required claim is missing."
    "AADSTS90019" = "MissingTenantRealm - Microsoft Entra ID was unable to determine the tenant identifier from the request."
    "AADSTS90020" = "The SAML 1.1 Assertion is missing ImmutableID of the user. Developer error - the app is attempting to sign in without the necessary or correct authentication parameters."
    "AADSTS90022" = "AuthenticatedInvalidPrincipalNameFormat - The principal name format isn't valid, or doesn't meet the expected name[/host][@realm] format. The principal name is required, host, and realm are optional and can be set to null."
    "AADSTS90023" = "InvalidRequest - The authentication service request isn't valid."
    "AADSTS900236" = "InvalidRequestSamlPropertyUnsupported - The SAML authentication request property '{propertyName}' isn't supported and must not be set."
    "AADSTS9002313" = "InvalidRequest - Request is malformed or invalid. - The issue arises because there was something wrong with the request to a certain endpoint. The suggestion to this issue is to get a fiddler trace of the error occurring and looking to see if the request is properly formatted or not."
    "AADSTS9002332" = "Application '{principalId}'({principalName}) is configured for use by Microsoft Entra users only. Please do not use the /consumers endpoint to serve this request."
    "AADSTS90024" = "RequestBudgetExceededError - A transient error has occurred. Try again."
    "AADSTS90027" = "We are unable to issue tokens from this API version on the MSA tenant. Please contact the application vendor as they need to use version 2.0 of the protocol to support this."
    "AADSTS90033" = "MsodsServiceUnavailable - The Microsoft Online Directory Service (MSODS) isn't available."
    "AADSTS90036" = "MsodsServiceUnretryableFailure - An unexpected, non-retryable error from the WCF service hosted by MSODS has occurred. Open a support ticket to get more details on the error."
    "AADSTS90038" = "NationalCloudTenantRedirection - The specified tenant 'Y' belongs to the National Cloud 'X'. Current cloud instance 'Z' does not federate with X. A cloud redirect error is returned."
    "AADSTS900384" = "JWT token failed signature validation. Actual message content is runtime specific, there are a variety of causes for this error. Please see the returned exception message for details."
    "AADSTS90043" = "NationalCloudAuthCodeRedirection - The feature is disabled."
    "AADSTS900432" = "Confidential Client isn't supported in Cross Cloud request."
    "AADSTS90051" = "InvalidNationalCloudId - The national cloud identifier contains an invalid cloud identifier."
    "AADSTS90055" = "TenantThrottlingError - There are too many incoming requests. This exception is thrown for blocked tenants."
    "AADSTS90056" = "BadResourceRequest - To redeem the code for an access token, the app should send a POST request to the /token endpoint. Also, prior to this, you should provide an authorization code and send it in the POST request to the /token endpoint. Refer to this article for an overview of OAuth 2.0 authorization code flow. Direct the user to the /authorize endpoint, which will return an authorization_code. By posting a request to the /token endpoint, the user gets the access token. Check App registrations > Endpoints to confirm that the two endpoints were configured correctly."
    "AADSTS900561" = "BadResourceRequestInvalidRequest - The endpoint only accepts {valid_verbs} requests. Received a {invalid_verb} request. {valid_verbs} represents a list of HTTP verbs supported by the endpoint (for example, POST), {invalid_verb} is an HTTP verb used in the current request (for example, GET). This can be due to developer error, or due to users pressing the back button in their browser, triggering a bad request. It can be ignored."
    "AADSTS90072" = "PassThroughUserMfaError - The external account that the user signs in with doesn't exist on the tenant that they signed into; so the user can't satisfy the MFA requirements for the tenant. This error also might occur if the users are synced, but there is a mismatch in the ImmutableID (sourceAnchor) attribute between Active Directory and Microsoft Entra ID. The account must be added as an external user in the tenant first. Sign out and sign in with a different Microsoft Entra user account. For more information, please visit configuring external identities."
    "AADSTS90081" = "OrgIdWsFederationMessageInvalid - An error occurred when the service tried to process a WS-Federation message. The message isn't valid."
    "AADSTS90082" = "OrgIdWsFederationNotSupported - The selected authentication policy for the request isn't currently supported."
    "AADSTS90084" = "OrgIdWsFederationGuestNotAllowed - Guest accounts aren't allowed for this site."
    "AADSTS90085" = "OrgIdWsFederationSltRedemptionFailed - The service is unable to issue a token because the company object hasn't been provisioned yet."
    "AADSTS90086" = "OrgIdWsTrustDaTokenExpired - The user DA token is expired."
    "AADSTS90087" = "OrgIdWsFederationMessageCreationFromUriFailed - An error occurred while creating the WS-Federation message from the URI."
    "AADSTS90090" = "GraphRetryableError - The service is temporarily unavailable."
    "AADSTS90091" = "GraphServiceUnreachable."
    "AADSTS90092" = "GraphNonRetryableError."
    "AADSTS90093" = "GraphUserUnauthorized - Graph returned with a forbidden error code for the request."
    "AADSTS90094" = "AdminConsentRequired - Administrator consent is required."
    "AADSTS90095" = "AdminConsentRequiredRequestAccess - In the Admin Consent Workflow experience, an interrupt that appears when the user is told they need to ask the admin for consent."
    "AADSTS90099" = "The application '{appId}' ({appName}) has not been authorized in the tenant '{tenant}'. Applications must be authorized to access the external tenant before partner delegated administrators can use them. Provide pre-consent or execute the appropriate Partner Center API to authorize the application."
    "AADSTS900971" = "No reply address provided."
    "AADSTS90100" = "InvalidRequestParameter - The parameter is empty or not valid."
    "AADSTS901002" = "AADSTS901002: The 'resource' request parameter isn't supported."
    "AADSTS90101" = "InvalidEmailAddress - The supplied data isn't a valid email address. The email address must be in the format someone@example.com."
    "AADSTS90102" = "InvalidUriParameter - The value must be a valid absolute URI."
    "AADSTS90107" = "InvalidXml - The request isn't valid. Make sure your data doesn't have invalid characters."
    "AADSTS90114" = "InvalidExpiryDate - The bulk token expiration timestamp will cause an expired token to be issued."
    "AADSTS90117" = "InvalidRequestInput."
    "AADSTS90119" = "InvalidUserCode - The user code is null or empty."
    "AADSTS90120" = "InvalidDeviceFlowRequest - The request was already authorized or declined."
    "AADSTS90121" = "InvalidEmptyRequest - Invalid empty request."
    "AADSTS90123" = "IdentityProviderAccessDenied - The token can't be issued because the identity or claim issuance provider denied the request."
    "AADSTS90124" = "V1ResourceV2GlobalEndpointNotSupported - The resource isn't supported over the /common or /consumers endpoints. Use the /organizations or tenant-specific endpoint instead."
    "AADSTS90125" = "DebugModeEnrollTenantNotFound - The user isn't in the system. Make sure you entered the user name correctly."
    "AADSTS90126" = "DebugModeEnrollTenantNotInferred - The user type isn't supported on this endpoint. The system can't infer the user's tenant from the user name."
    "AADSTS90130" = "NonConvergedAppV2GlobalEndpointNotSupported - The application isn't supported over the /common or /consumers endpoints. Use the /organizations or tenant-specific endpoint instead."
    "AADSTS1000000" = "UserNotBoundError - The Bind API requires the Microsoft Entra user to also authenticate with an external IDP, which hasn't happened yet."
    "AADSTS1000002" = "BindCompleteInterruptError - The bind completed successfully, but the user must be informed."
    "AADSTS100007" = "Microsoft Entra Regional ONLY supports auth either for MSIs OR for requests from MSAL using SN+I for 1P apps or 3P apps in Microsoft infrastructure tenants."
    "AADSTS1000031" = "Application {appDisplayName} can't be accessed at this time. Contact your administrator."
    "AADSTS1000104" = "XCB2BResourceCloudNotAllowedOnIdentityTenant - Resource cloud {resourceCloud} isn't allowed on identity tenant {identityTenant}. {resourceCloud} - cloud instance which owns the resource. {identityTenant} - is the tenant where signing-in identity is originated from."
    "AADSTS120000" = "PasswordChangeIncorrectCurrentPassword."
    "AADSTS120002" = "PasswordChangeInvalidNewPasswordWeak."
    "AADSTS120003" = "PasswordChangeInvalidNewPasswordContainsMemberName."
    "AADSTS120004" = "PasswordChangeOnPremComplexity."
    "AADSTS120005" = "PasswordChangeOnPremSuccessCloudFail."
    "AADSTS120008" = "PasswordChangeAsyncJobStateTerminated - A non-retryable error has occurred."
    "AADSTS120011" = "PasswordChangeAsyncUpnInferenceFailed."
    "AADSTS120012" = "PasswordChangeNeedsToHappenOnPrem."
    "AADSTS120013" = "PasswordChangeOnPremisesConnectivityFailure."
    "AADSTS120014" = "PasswordChangeOnPremUserAccountLockedOutOrDisabled."
    "AADSTS120015" = "PasswordChangeADAdminActionRequired."
    "AADSTS120016" = "PasswordChangeUserNotFoundBySspr."
    "AADSTS120018" = "PasswordChangePasswordDoesnotComplyFuzzyPolicy."
    "AADSTS120020" = "PasswordChangeFailure."
    "AADSTS120021" = "PartnerServiceSsprInternalServiceError."
    "AADSTS130004" = "NgcKeyNotFound - The user principal doesn't have the NGC ID key configured."
    "AADSTS130005" = "NgcInvalidSignature - NGC key signature verified failed."
    "AADSTS130006" = "NgcTransportKeyNotFound - The NGC transport key isn't configured on the device."
    "AADSTS130007" = "NgcDeviceIsDisabled - The device is disabled."
    "AADSTS130008" = "NgcDeviceIsNotFound - The device referenced by the NGC key wasn't found."
    "AADSTS135010" = "KeyNotFound."
    "AADSTS135011" = "Device used during the authentication is disabled."
    "AADSTS140000" = "InvalidRequestNonce - Request nonce isn't provided."
    "AADSTS140001" = "InvalidSessionKey - The session key isn't valid."
    "AADSTS165004" = "Actual message content is runtime specific. Please see returned exception message for details."
    "AADSTS165900" = "InvalidApiRequest - Invalid request."
    "AADSTS220450" = "UnsupportedAndroidWebViewVersion - The Chrome WebView version isn't supported."
    "AADSTS220501" = "InvalidCrlDownload."
    "AADSTS221000" = "DeviceOnlyTokensNotSupportedByResource - The resource isn't configured to accept device-only tokens."
    "AADSTS240001" = "BulkAADJTokenUnauthorized - The user isn't authorized to register devices in Microsoft Entra ID."
    "AADSTS240002" = "RequiredClaimIsMissing - The id_token can't be used as urn:ietf:params:oauth:grant-type:jwt-bearer grant."
    "AADSTS501621" = "ClaimsTransformationTimeoutRegularExpressionTimeout - Regular expression replacement for claims transformation has timed out. This indicates a too complex regular expression may have been configured for this application. A retry of the request may succeed. Otherwise, please contact your admin to fix the configuration."
    "AADSTS700016" = "UnauthorizedClient_DoesNotMatchRequest - The application wasn't found in the directory/tenant. This can happen if the application has not been installed by the administrator of the tenant or consented to by any user in the tenant. You might have misconfigured the identifier value for the application or sent your authentication request to the wrong tenant."
    "AADSTS700020" = "InteractionRequired - The access grant requires interaction."
    "AADSTS7000215" = "Invalid client secret is provided. Developer error - the app is attempting to sign in without the necessary or correct authentication parameters."
    "AADSTS7000222" = "InvalidClientSecretExpiredKeysProvided - The provided client secret keys are expired. Create new keys for your app, or consider using certificate credentials for added security: https://aka.ms/certCreds."
    "AADSTS700022" = "InvalidMultipleResourcesScope - The provided value for the input parameter scope isn't valid because it contains more than one resource."
    "AADSTS700023" = "InvalidResourcelessScope - The provided value for the input parameter scope isn't valid when requesting an access token."
    "AADSTS700229" = "ForbiddenTokenType - Only app-only tokens can be used as Federated Identity Credentials for Microsoft Entra issuer. Use an app-only access token (generated during a client credentials flow) instead of a user-delegated access token (representing a request coming from a user context)."
    "AADSTS700005" = "InvalidGrantRedeemAgainstWrongTenant - Provided Authorization Code is intended to use against other tenant, thus rejected. OAuth2 Authorization Code must be redeemed against same tenant it was acquired for (/common or /{tenant-ID} as appropriate)."
    "AADSTS7500529" = "The value ‘SAMLId-Guid’ isn't a valid SAML ID - Microsoft Entra ID uses this attribute to populate the InResponseTo attribute of the returned response. ID must not begin with a number, so a common strategy is to prepend a string like 'ID' to the string representation of a GUID. For example, id6c1c178c166d486687be4aaf5e482730 is a valid ID."
    "AADSTS9002341" = "V2Error: invalid_grant - The user is required to permit single sign-On (SSO). This error occurs when the user has not granted the necessary permissions for the application to perform SSO. The user should be redirected to the consent screen to grant the necessary permissions. Refer to this announcement for more information."
    "AADSTS650053" = "The application '{name}' asked for scope '{scope}' that doesn't exist on the resource '{resource}'. Contact the app vendor."
    "AADSTS70037" = "Incorrect challenge response provided. Remote auth session denied"
}
