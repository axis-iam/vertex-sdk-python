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
    [string] $ResourceAudience,
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
        throw "AutoProvisionLocal is retired. Supply an OAuth authorization-code AccessToken, ClientId and ClientSecret from an explicitly provisioned application."
    }
    Assert-Required $ClientId "ClientId"
    Assert-Required $ClientSecret "ClientSecret"
    Assert-Required $AccessToken "OAuth AccessToken"
    Assert-Required $ResourceAudience "ResourceAudience"

    $script = @'
import asyncio
import os

from axis_vertex import IamClient, IamConfig


async def main() -> None:
    resource_audience = os.environ["IAM_RESOURCE_AUDIENCE"]
    issuer = os.environ.get("IAM_ISSUER") or None
    iam = IamClient(
        IamConfig(
            endpoint=os.environ["IAM_ENDPOINT"],
            client_id=os.environ["IAM_CLIENT_ID"],
            client_secret=os.environ["IAM_CLIENT_SECRET"],
            resource_audience=resource_audience,
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
    $env:IAM_RESOURCE_AUDIENCE = $ResourceAudience
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
