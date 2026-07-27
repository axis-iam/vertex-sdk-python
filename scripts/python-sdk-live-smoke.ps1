param(
    [string] $IamEndpoint = "http://localhost:30001",
    [string] $PortalEndpoint = "http://localhost:30002",
    [string] $PortalClientId = "iam_bBUvJ4IoeQcN9Qg-flyF6sIh",
    [string] $AdminEmail = "admin@example.com",
    [string] $AdminPassword = "Admin@123456",
    [switch] $AutoProvisionLocal,
    [string] $ClientId,
    [string] $ClientSecret,
    [string] $AccessToken,
    [string] $Audience,
    [string] $Issuer,
    [string] $RequiredPermission = "posts:read"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$LogDir = Join-Path $RepoRoot ".run-logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$RunId = "python-sdk-live-" + (Get-Date -Format "yyyyMMddHHmmss") + "-" + ([guid]::NewGuid().ToString("N").Substring(0, 8))
$ReportPath = Join-Path $LogDir "$RunId-redacted-report.json"

$Report = [ordered]@{
    runId = $RunId
    status = "RUNNING"
    mode = if ($AutoProvisionLocal) { "AUTO_PROVISION_LOCAL" } else { "MANUAL_INPUTS" }
    iamEndpoint = $IamEndpoint
    portalEndpoint = $PortalEndpoint
    checks = [ordered]@{}
    created = [ordered]@{}
}

function ConvertTo-JsonBody {
    param($Value)
    return ($Value | ConvertTo-Json -Depth 80 -Compress)
}

function Invoke-JsonApi {
    param(
        [string] $Method,
        [string] $Uri,
        $Body = $null,
        [string] $Token = $null
    )
    $Headers = @{ Accept = "application/json" }
    if ($Token) {
        $Headers["Authorization"] = "Bearer $Token"
    }
    $Params = @{
        Method = $Method
        Uri = $Uri
        Headers = $Headers
        TimeoutSec = 45
        UseBasicParsing = $true
    }
    if ($null -ne $Body) {
        $Params["ContentType"] = "application/json"
        $Params["Body"] = ConvertTo-JsonBody $Body
    }
    try {
        $Response = Invoke-WebRequest @Params
    } catch {
        $Status = $null
        $Content = $_.Exception.Message
        if ($_.Exception.Response) {
            $Status = [int]$_.Exception.Response.StatusCode
            try {
                $Reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                $Content = $Reader.ReadToEnd()
                $Reader.Dispose()
            } catch {
                $Content = $_.Exception.Message
            }
        }
        throw "$Method $Uri failed with HTTP ${Status}: $Content"
    }
    if ([string]::IsNullOrWhiteSpace([string]$Response.Content)) {
        return $null
    }
    return ([string]$Response.Content | ConvertFrom-Json)
}

function Assert-Required {
    param([string] $Value, [string] $Name)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "$Name is required. Provide it explicitly or run with -AutoProvisionLocal."
    }
}

function Split-Permission {
    param([string] $Permission)
    $parts = $Permission.Split(":", 2)
    if ($parts.Count -ne 2 -or [string]::IsNullOrWhiteSpace($parts[0]) -or [string]::IsNullOrWhiteSpace($parts[1])) {
        throw "RequiredPermission must use resource:action format"
    }
    return $parts
}

$parts = Split-Permission $RequiredPermission
$AppId = $null
$TempPythonScript = $null

try {
    if ($AutoProvisionLocal) {
        $Suffix = $RunId.Replace("python-sdk-live-", "")
        $UserPassword = "SdkLivePass123!"
        $PortalLogin = Invoke-JsonApi `
            -Method Post `
            -Uri "$IamEndpoint/api/v1/auth/login" `
            -Body @{ identifier = $AdminEmail; password = $AdminPassword; client_id = $PortalClientId }
        $PortalToken = [string]$PortalLogin.access_token
        Assert-Required $PortalToken "Portal admin access token"
        $Report.checks.portalLogin = "PASS"

        $App = Invoke-JsonApi `
            -Method Post `
            -Uri "$PortalEndpoint/portal/v1/apps" `
            -Token $PortalToken `
            -Body @{
                name = "python-sdk-live-$Suffix"
                description = "Temporary Python SDK live smoke application"
                frontendOrigins = @("http://localhost:5173")
            }
        $AppId = [string]$App.id
        $Audience = $AppId
        $Report.created.applicationId = $AppId

        $Client = Invoke-JsonApi `
            -Method Post `
            -Uri "$PortalEndpoint/portal/v1/apps/$AppId/clients" `
            -Token $PortalToken `
            -Body @{
                name = "Python SDK Live WEB"
                clientType = "WEB"
                grantTypes = @("authorization_code", "refresh_token")
                redirectUris = @("http://localhost:5173/callback")
                allowedOrigins = @("http://localhost:5173")
                postLogoutRedirectUris = @("http://localhost:5173")
            }
        $ClientId = [string]$Client.client.clientId
        $ClientSecret = [string]$Client.clientSecret
        Assert-Required $ClientId "Provisioned clientId"
        Assert-Required $ClientSecret "Provisioned clientSecret"
        $Report.created.clientId = $ClientId

        $Permission = Invoke-JsonApi `
            -Method Post `
            -Uri "$PortalEndpoint/portal/v1/apps/$AppId/permissions" `
            -Token $PortalToken `
            -Body @{
                resource = $parts[0]
                action = $parts[1]
                name = "Python SDK live $RequiredPermission"
                description = "Temporary permission for Python SDK live smoke"
            }
        $Report.created.permissionId = [string]$Permission.id

        $RoleKey = "sdk_live_reader"
        $Role = Invoke-JsonApi `
            -Method Post `
            -Uri "$PortalEndpoint/portal/v1/apps/$AppId/roles" `
            -Token $PortalToken `
            -Body @{ key = $RoleKey; name = "SDK Live Reader"; description = "Temporary SDK live smoke role" }
        $RoleId = [string]$Role.id
        $Report.created.roleId = $RoleId

        Invoke-JsonApi `
            -Method Put `
            -Uri "$PortalEndpoint/portal/v1/apps/$AppId/roles/$RoleId/permissions" `
            -Token $PortalToken `
            -Body @{ permissionIds = @([string]$Permission.id) } | Out-Null

        $UserEmail = "python-sdk-live-$Suffix@example.com"
        $User = Invoke-JsonApi `
            -Method Post `
            -Uri "$PortalEndpoint/portal/v1/apps/$AppId/users" `
            -Token $PortalToken `
            -Body @{ email = $UserEmail; username = "python_sdk_live_$($Suffix.Replace('-', '_'))"; password = $UserPassword }
        $UserId = [string]$User.id
        $Report.created.userId = $UserId

        Invoke-JsonApi `
            -Method Post `
            -Uri "$PortalEndpoint/portal/v1/apps/$AppId/user-roles" `
            -Token $PortalToken `
            -Body @{ userId = $UserId; roleId = $RoleId; organizationId = $null; condition = $null } | Out-Null

        $Login = Invoke-JsonApi `
            -Method Post `
            -Uri "$IamEndpoint/api/v1/auth/login" `
            -Body @{ identifier = $UserEmail; password = $UserPassword; client_id = $ClientId }
        $AccessToken = [string]$Login.access_token
        Assert-Required $AccessToken "Provisioned user access token"
        $Report.checks.localProvision = "PASS"
    } else {
        Assert-Required $ClientId "ClientId"
        Assert-Required $ClientSecret "ClientSecret"
        Assert-Required $AccessToken "AccessToken"
    }

    $script = @'
import asyncio
import os

from axis_vertex import IamClient, IamConfig


async def main() -> None:
    audience = os.environ.get("IAM_AUDIENCE") or None
    issuer = os.environ.get("IAM_ISSUER") or None
    iam = IamClient(
        IamConfig(
            endpoint=os.environ["IAM_ENDPOINT"],
            client_id=os.environ["IAM_CLIENT_ID"],
            client_secret=os.environ["IAM_CLIENT_SECRET"],
            audience=audience,
            issuer=issuer,
        )
    )
    try:
        ctx = await iam.authenticate(os.environ["IAM_ACCESS_TOKEN"])
        resource = os.environ["IAM_REQUIRED_RESOURCE"]
        action = os.environ["IAM_REQUIRED_ACTION"]
        if not ctx.has_permission(resource, action):
            raise SystemExit(f"missing permission {resource}:{action}")
        profile = await iam.get_me(os.environ["IAM_ACCESS_TOKEN"])
        if not profile.id:
            raise SystemExit("missing profile id")
        print("PASS python SDK live smoke")
    finally:
        await iam.close()


asyncio.run(main())
'@

    $env:IAM_ENDPOINT = $IamEndpoint
    $env:IAM_CLIENT_ID = $ClientId
    $env:IAM_CLIENT_SECRET = $ClientSecret
    $env:IAM_ACCESS_TOKEN = $AccessToken
    $env:IAM_AUDIENCE = if ($Audience) { $Audience } else { "" }
    $env:IAM_ISSUER = if ($Issuer) { $Issuer } else { "" }
    $env:IAM_REQUIRED_RESOURCE = $parts[0]
    $env:IAM_REQUIRED_ACTION = $parts[1]

    $TempPythonScript = Join-Path ([System.IO.Path]::GetTempPath()) "$RunId.py"
    Set-Content -LiteralPath $TempPythonScript -Value $script -Encoding UTF8
    python $TempPythonScript
    if ($LASTEXITCODE -ne 0) {
        throw "python SDK live smoke failed with exit code $LASTEXITCODE"
    }

    $Report.checks.pythonSdkAuthenticate = "PASS"
    $Report.checks.pythonSdkGetMe = "PASS"
    $Report.requiredPermission = $RequiredPermission
    $Report.status = "PASS"
} catch {
    $Report.status = "FAIL"
    $Report.error = $_.Exception.Message
    throw
} finally {
    Remove-Item Env:\IAM_CLIENT_SECRET -ErrorAction SilentlyContinue
    Remove-Item Env:\IAM_ACCESS_TOKEN -ErrorAction SilentlyContinue
    if ($TempPythonScript -and (Test-Path -LiteralPath $TempPythonScript)) {
        Remove-Item -LiteralPath $TempPythonScript -Force -ErrorAction SilentlyContinue
    }
    $Report.finishedAt = (Get-Date).ToString("o")
    $Report | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
    Write-Host "REPORT=$ReportPath"
    Write-Host "RUN_ID=$RunId"
    Write-Host "STATUS=$($Report.status)"
}
