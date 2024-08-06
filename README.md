PowerShell Script: Azure Sign-In Analysis
Overview
This PowerShell script connects to Microsoft Graph, retrieves user sign-in data, and analyzes it for various parameters like IP addresses, ASNs (Autonomous System Numbers), and locations. The script categorizes sign-ins into successful and failed attempts, performs statistical analysis, and detects potential unauthorized sign-ins. It outputs the results with color-coded information for better readability.

Script Description
Ensure-Module Function: Checks if the Microsoft.Graph module is installed and up-to-date. Installs or updates it if necessary.

Get-UserSignInData Function: Retrieves user sign-in data from the Microsoft Graph beta endpoint based on the provided User Principal Name (UPN).

Categorize-SignInData Function: Categorizes the sign-in data into successful and failed attempts.

Analyze-SignInData Function: Analyzes the sign-in data to extract IP addresses, locations, and ASNs, and groups them for statistical analysis.

Display-Analysis Function: Formats and displays the analyzed data with color-coded output. Headers and underlines are displayed in green, and specific elements are highlighted in yellow if certain conditions are met.

Build-Baseline Function: Builds a baseline of historical sign-in data, including IP addresses, locations, devices, browsers, user agents, OS types, apps, and ASNs.

Detect-UnauthorizedSignIns Function: Detects potential unauthorized sign-ins based on various criteria and highlights them.

Write-ColoredOutput Function: Outputs text with specified foreground colors for better readability.

Main Script Execution:

Retrieves all sign-in data.
Builds a baseline from the historical sign-in data.
Categorizes the sign-in data into successful and failed pools.
Analyzes and displays the categorized data.
Detects and displays suspicious sign-ins.
Outputs a baseline summary for context.
How to Use
Clone or download the script from the GitHub repository.
Ensure you have the required permissions to execute PowerShell scripts and access Microsoft Graph.
Execute the script in a PowerShell environment.
Input the User Principal Name (UPN) when prompted.
Review the output for sign-in analysis, including categorized sign-ins, potential unauthorized sign-ins, and a baseline summary.


Sample output

```plaintext
Sign-In Failures
=====================================

ASN, IP, and Location Analysis
=====================================

ASN: 1111 IP: 1.1.1.1 Location: Bree, Eriador, Middle-earth Count: 2
ASN: 1111 IP: 1.1.1.2 Location: Bree, Eriador, Middle-earth Count: 2

Successful Sign-Ins
=====================================

ASN, IP, and Location Analysis
=====================================

ASN: 2222 IP: 2.2.2.2 Location: Edoras, Rohan, Middle-earth Count: 1
ASN: 3333 IP: 3.3.3.3 Location: Minas Tirith, Gondor, Middle-earth Count: 5
ASN: 4444 IP: 4.4.4.4 Location: Helm's Deep, Rohan, Middle-earth Count: 4
ASN: 4444 IP: 4.4.4.5 Location: Minas Tirith, Gondor, Middle-earth Count: 1
ASN: 4444 IP: 4.4.4.6 Location: Isengard, Rohan, Middle-earth Count: 2
ASN: 4444 IP: 4.4.4.7 Location: Minas Tirith, Gondor, Middle-earth Count: 1
ASN: 4444 IP: 4.4.4.8 Location: Rivendell, Eriador, Middle-earth Count: 5
ASN: 4444 IP: 4.4.4.9 Location: Minas Tirith, Gondor, Middle-earth Count: 9
ASN: 4444 IP: 4.4.4.10 Location: Isengard, Rohan, Middle-earth Count: 10
ASN: 5555 IP: 5.5.5.5 Location: Hobbiton, Shire, Middle-earth Count: 1042
ASN: 5555 IP: 5.5.5.6 Location: Buckland, Shire, Middle-earth Count: 4
ASN: 4444 IP: 4.4.4.11 Location: Isengard, Rohan, Middle-earth Count: 3
ASN: 4444 IP: 4.4.4.12 Location: Minas Tirith, Gondor, Middle-earth Count: 5
ASN: 4444 IP: 4.4.4.13 Location: Rivendell, Eriador, Middle-earth Count: 6
ASN: 4444 IP: 4.4.4.14 Location: Minas Tirith, Gondor, Middle-earth Count: 2
ASN: 4444 IP: 4.4.4.15 Location: Minas Tirith, Gondor, Middle-earth Count: 8
ASN: 4444 IP: 6.6.6.6 Location: Osgiliath, Gondor, Middle-earth Count: 2
ASN: 4444 IP: 4.4.4.16 Location: Minas Tirith, Gondor, Middle-earth Count: 2
ASN: 1111 IP: 1.1.1.3 Location: Bree, Eriador, Middle-earth Count: 6
ASN: 4444 IP: 4.4.4.17 Location: Isengard, Rohan, Middle-earth Count: 16
ASN: 4444 IP: 4.4.4.18 Location: Isengard, Rohan, Middle-earth Count: 2
ASN: 4444 IP: 4.4.4.19 Location: Minas Tirith, Gondor, Middle-earth Count: 5
ASN: 1111 IP: 1.1.1.4 Location: Bree, Eriador, Middle-earth Count: 5
ASN: 4444 IP: 6.6.6.7 Location: Minas Tirith, Gondor, Middle-earth Count: 3
ASN: 6666 IP: 7.7.7.7 Location: Grey Havens, Lindon, Middle-earth Count: 52
ASN: 4444 IP: 4.4.4.20 Location: Bucklebury, Shire, Middle-earth Count: 1

Suspicious Sign-Ins Detected
===========================

Sign-In at: 08/02/2024 22:24:44
From IP: 1.1.1.2
Location: Bree, Eriador, Middle-earth
Risk level:
Risk state: none
OS: Darwin
App:

Baseline Summary
===========================

IPs, Locations, Devices, Browsers, UserAgents, OSTypes, Apps, ASNs in the baseline data:

Locations:
=====================================

Locations: Hobbiton, Shire, Middle-earth: 652
Locations: Buckland, Shire, Middle-earth: 200
Locations: Bywater, Shire, Middle-earth: 190
Locations: Grey Havens, Lindon, Middle-earth: 52
Locations: Minas Tirith, Gondor, Middle-earth: 38
Locations: Isengard, Rohan, Middle-earth: 33
Locations: Bree, Eriador, Middle-earth: 14
Locations: Rivendell, Eriador, Middle-earth: 11
Locations: Helm's Deep, Rohan, Middle-earth: 7
Locations: Bucklebury, Shire, Middle-earth: 4
Locations: Osgiliath, Gondor, Middle-earth: 2
Locations: Edoras, Rohan, Middle-earth: 1
Locations: Bucklebury, Shire, Middle-earth: 1

Devices:
=====================================

Devices: ce637a66-1d54-4dc0-82be-ce7a7c5245d5: 1191
Devices: : 15

IPs:
=====================================

IPs: 5.5.5.5: 1042
IPs: 7.7.7.7: 52
IPs: 4.4.4.17: 16
IPs: 4.4.4.10: 10
IPs: 4.4.4.9: 9
IPs: 1.1.1.1: 8
IPs: 4.4.4.15: 8
IPs: 1.1.1.2: 7
IPs: 4.4.4.13: 6
IPs: 4.4.4.12: 5
IPs: 3.3.3.3: 5
IPs: 4.4.4.19: 5
IPs: 4.4.4.8: 5
IPs: 5.5.5.6: 4
IPs: 4.4.4.4: 4
IPs: 6.6.6.7: 3
IPs: 4.4.4.11: 3
IPs: 4.4.4.6: 2
IPs: 6.6.6.6: 2
IPs: 4.4.4.16: 2
IPs: 4.4.4.18: 2
IPs: 4.4.4.14: 2
IPs: 2.2.2.2: 1
IPs: 4.4.4.7: 1
IPs: 4.4.4.5: 1
IPs: 4.4.4.20: 1

Browsers:
=====================================

Browsers: Mobile Safari: 1181
Browsers: IE 7.0: 11
Browsers: Safari 17.6: 7
Browsers: Rich Client 4.59.1.0: 3
Browsers: Edge 127.0.0: 3
Browsers: : 1

ASNs:
=====================================

ASNs: 5555: 1046
ASNs: 4444: 87
ASNs: 6666: 52
ASNs: 1111: 14
ASNs: 3333: 5
ASNs: 2222: 1
ASNs: 0: 1

OSTypes:
=====================================

OSTypes: Ios 17.5.1: 925
OSTypes: Ios 17.6: 256
OSTypes: Windows10: 14
OSTypes: Ios: 10
OSTypes: Darwin: 1

UserAgents:
=====================================

Apps:
=====================================

Apps: Outlook Mobile: 1058
Apps: Microsoft Authentication Broker: 84
Apps: Microsoft Authenticator App: 20
Apps: Microsoft Office: 13
Apps: Microsoft Graph Command Line Tools: 11
Apps: Azure Portal: 9
Apps: Microsoft Edge: 6
Apps: Microsoft_Azure_Billing: 3
Apps: Microsoft_AAD_GTM: 1
Apps: : 1
```
