# Isolated TEST discovery only. Does not change production GitHubReleaseProvider.
# Picks the newest successful prerelease tagged test-<12 hex chars>.
# Never uses /releases/latest. Never returns test-2ar43a-001.
param(
	[string]$Owner = "Infidel-admin",
	[string]$Repo = "Updater",
	[string]$OutFile = ""
)

$ErrorActionPreference = "Stop"
$pattern = "^test-[0-9a-f]{12}$"
$protected = "test-2ar43a-001"
$uri = "https://api.github.com/repos/" + $Owner + "/" + $Repo + "/releases?per_page=30"
$headers = @{
	"User-Agent" = "Pride-IsolatedTest/1.0"
	"Accept" = "application/vnd.github+json"
}

try {
	$releases = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
} catch {
	Write-Output "OK=NO"
	Write-Output "reason=GITHUB_API"
	Write-Output "TEST_CHANNEL_DISCOVERY=NO"
	Write-Output "PRODUCTION_LATEST_USED=NO"
	exit 2
}

$chosen = $null
foreach ($item in @($releases)) {
	if ($item.draft -eq $true) { continue }
	if ($item.prerelease -ne $true) { continue }
	$tag = [string]$item.tag_name
	if ([string]::IsNullOrWhiteSpace($tag)) { continue }
	if ($tag -eq $protected) { continue }
	if ($tag -eq "latest" -or $tag -eq "production") { continue }
	if ($tag -notmatch $pattern) { continue }
	$chosen = $item
	break
}

if ($null -eq $chosen) {
	Write-Output "OK=NO"
	Write-Output "reason=NO_TEST_RELEASE"
	Write-Output "TEST_CHANNEL_DISCOVERY=NO_MATCH"
	Write-Output ("PROTECTED_TAG_EXCLUDED=" + $protected)
	Write-Output "PRODUCTION_LATEST_USED=NO"
	Write-Output "GITHUB_PROVIDER_CHANGED=NO"
	exit 2
}

$tag = [string]$chosen.tag_name
$html = [string]$chosen.html_url
Write-Output "OK=YES"
Write-Output "TEST_CHANNEL_DISCOVERY=YES"
Write-Output ("GITHUB_TAG=" + $tag)
Write-Output ("GITHUB_RELEASE_URL=" + $html)
Write-Output "GITHUB_USE_LATEST=NO"
Write-Output "PRODUCTION_LATEST_USED=NO"
Write-Output ("PROTECTED_TAG_EXCLUDED=" + $protected)
Write-Output "GITHUB_PROVIDER_CHANGED=NO"
Write-Output ("UPDATE_TAG_ARG=" + $tag)
if (-not [string]::IsNullOrWhiteSpace($OutFile)) {
	$dir = Split-Path -Parent $OutFile
	if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir)) {
		New-Item -ItemType Directory -Path $dir | Out-Null
	}
	Set-Content -LiteralPath $OutFile -Value $tag -Encoding ASCII
	Write-Output ("TAG_FILE=" + $OutFile)
}
exit 0
