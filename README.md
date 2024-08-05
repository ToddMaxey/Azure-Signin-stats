### Synopsis

The provided PowerShell script is designed to assist with threat hunting and incident response by collecting, categorizing, and analyzing Azure AD sign-in data. The script connects to Microsoft Graph, retrieves all sign-in events for a specified user, and then separates these events into successful and failed sign-ins based on their error codes. This categorization allows security professionals to analyze patterns and detect anomalies in authentication activities, which can be crucial for identifying and mitigating potential security threats.

#Data output example:

### Sign-In Failures

#### BrowserTypes:
- Unknown: 3
- IE 7.0: 3

#### AppDisplayNames:
- Unknown: 3
- Microsoft Graph Command Line Tools: 3

#### Times:
- 22: 4

#### ErrorCodes:
- 650053: 3
- 70037: 1

#### ResultCodes:
- MFA requirement satisfied by strong authentication: 2
- MFA requirement satisfied by claim in the token: 1
- Incorrect challenge response provided. Remote auth session denied: 1

#### Locations:
- Bree, The Shire, Middle-earth: 3
- Minas Tirith, Gondor, Middle-earth: 3

#### IPs:
- 192.168.0.1: 2
- 192.168.0.2: 2

#### ASNs:
- Unknown: 3
- 8075: 3

#### DeviceIds:
- NULL: 6

#### AccountNames:
- frodo.baggins@hobbiton.middleearth: 3
- gandalf.grey@wizard.middleearth: 1

#### UserAgents:
- Unknown: 6

#### OSTypes:
- Windows10: 3
- Unknown: 2
- Darwin: 1

---

### Successful Sign-Ins

#### BrowserTypes:
- Mobile Safari: 1183
- IE 7.0: 8
- Safari 17.6: 7
- Rich Client 4.59.1.0: 3
- Edge 127.0.0: 3

#### AppDisplayNames:
- Outlook Mobile: 1060
- Microsoft Authentication Broker: 84
- Microsoft Authenticator App: 20
- Microsoft Office: 13
- Azure Portal: 9
- Microsoft Graph Command Line Tools: 8
- Microsoft Edge: 6
- Microsoft_Azure_Billing: 3
- Microsoft_AAD_GTM: 1

#### Times:
- 00: 68
- 01: 67
- 02: 72
- 03: 32
- 04: 33
- 05: 29
- 06: 48
- 07: 19
- 08: 15
- 09: 37
- 10: 19
- 11: 91
- 12: 88
- 13: 59
- 14: 68
- 15: 62
- 16: 58
- 17: 49
- 18: 54
- 19: 36
- 20: 52
- 21: 54
- 22: 47
- 23: 47

#### ErrorCodes:
- 0: 1204

#### ResultCodes:
- MFA requirement satisfied by claim in the token: 1201
- MFA requirement satisfied by strong authentication: 3

#### Locations:
- Hobbiton, The Shire, Middle-earth: 641
- Bree, The Shire, Middle-earth: 200
- Rivendell, Eriador, Middle-earth: 192
- Minas Tirith, Gondor, Middle-earth: 52
- Helm's Deep, Rohan, Middle-earth: 44
- Edoras, Rohan, Middle-earth: 33
- Lothlórien, Lothlórien, Middle-earth: 12
- Minas Tirith, Gondor, Middle-earth: 11
- Anduin, Anduin, Middle-earth: 11
- Fangorn Forest, Rohan, Middle-earth: 4
- Isengard, Rohan, Middle-earth: 2
- Mount Doom, Mordor, Middle-earth: 1
- Barad-dûr, Mordor, Middle-earth: 1

#### IPs:
- 10.0.0.1: 1033
- 10.0.0.2: 52
- 10.0.0.3: 16
- 10.0.0.4: 10
- 10.0.0.5: 9
- 10.0.0.6: 8
- 10.0.0.7: 8
- 192.168.0.1: 6
- 10.0.0.8: 6
- 10.0.0.9: 5
- 192.168.0.2: 5
- 10.0.0.10: 5
- 10.0.0.11: 5
- 10.0.0.12: 4
- 10.0.0.13: 4
- 10.0.0.14: 3
- 10.0.0.15: 3
- 10.0.0.16: 3
- 10.0.0.17: 2
- 10.0.0.18: 2
- 10.0.0.19: 2
- 10.0.0.20: 2
- 10.0.0.21: 2
- 10.0.0.22: 1
- 10.0.0.23: 1
- 10.0.0.24: 1
- 10.0.0.25: 1

#### ASNs:
- 5650: 1037
- 20057: 98
- 174: 52
- 8075: 11
- 11427: 5
- 2773: 1

#### DeviceIds:
- 123e4567-e89b-12d3-a456-426614174000: 1193
- NULL: 11

#### AccountNames:
- frodo.baggins@hobbiton.middleearth: 1204

#### UserAgents:
- Unknown: 1204

#### OSTypes:
- Ios 17.5.1: 938
- Ios 17.6: 245
- Windows10: 11
- Ios: 10

---


### Detailed Review of the Code

#### 1. **Module Management**

The script starts with the `Ensure-Module` function, which ensures that the `Microsoft.Graph` module is installed and up-to-date:

```powershell
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
```

#### 2. **User Input and Microsoft Graph Connection**

The script prompts the user to input a User Principal Name (UPN) and then connects to Microsoft Graph using the `Connect-MgGraph` cmdlet:

```powershell
$UserPrincipalName = Read-Host -Prompt "To retrieve sign-in information, input the User Principal Name (UPN) of the user"

try {
    Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All" -NoWelcome
    Write-Output "Successfully connected to Microsoft Graph."
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit
}
```

#### 3. **Retrieving Sign-In Data**

The `Get-UserSignInData` function retrieves all sign-in data for the specified user:

```powershell
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
```

#### 4. **Categorizing Sign-In Data**

The `Categorize-SignInData` function separates the sign-in data into successful and failed sign-ins based on the `errorCode`:

```powershell
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
```

#### 5. **Analyzing Sign-In Data**

The `Analyze-SignInData` function performs statistical analysis on the sign-in data, grouping and sorting it by various attributes:

```powershell
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
```

#### 6. **Displaying Analysis Results**

The `Display-Analysis` function outputs the analysis results in a readable format:

```powershell
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
```

#### 7. **Main Script Execution**

The main script execution block retrieves the sign-in data, categorizes it, analyzes it, and displays the results:

```powershell
# Main script execution
# Get all sign-in data
$allSignIns = Get-UserSignInData -UserPrincipalName $UserPrincipalName

# Categorize sign-in data into successful and failed pools
$categorizedSignIns = Categorize-SignInData -SignInData $allSignIns

# Analyze and display

 failed sign-in data
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
```

### Usage in Threat Hunting and Incident Response

1. **Data Collection**: The script collects detailed sign-in data from Azure AD, which is crucial for understanding user activity and identifying potential security incidents.
2. **Categorization**: By separating successful and failed sign-ins, security professionals can focus on specific patterns that might indicate malicious activity, such as repeated failed sign-ins or unusual success patterns.
3. **Analysis**: The script analyzes the data to provide insights into common locations, devices, browsers, and times of sign-ins, helping identify anomalies.
4. **Incident Response**: Quick identification of suspicious sign-ins allows for faster incident response, such as locking accounts, resetting passwords, or further investigation of compromised accounts.

Overall, this script is a powerful tool for security teams to monitor authentication activities, detect potential threats, and respond to security incidents effectively.
