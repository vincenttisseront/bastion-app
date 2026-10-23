# Build & push bastion-pro-{app,migrate,nginx} to Docker Hub + GHCR.
# Version is read from app/web/constants.py (APP_VERSION) — run bump_version.py first.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$constants = Join-Path $Root "app\web\constants.py"
$match = Select-String -Path $constants -Pattern 'APP_VERSION\s*=\s*"([^"]+)"' | Select-Object -First 1
if (-not $match) { throw "APP_VERSION not found in $constants" }
$semver = $match.Matches.Groups[1].Value.Trim()
if ($semver -notmatch '^\d+\.\d+\.\d+$') { throw "Invalid APP_VERSION: $semver" }

$version = "v$semver"
$sha = (git rev-parse --short HEAD).Trim()
$registries = @("vincenttisseront", "ghcr.io/vincenttisseront")
$images = @(
    @{ name = "bastion-pro-app"; args = @("--target", "runtime", ".") },
    @{ name = "bastion-pro-migrate"; args = @("--target", "migrate", ".") },
    @{ name = "bastion-pro-nginx"; args = @("--build-arg", "BASTION_NGINX_IMAGE_TAG=$version", "docker/nginx") }
)

Write-Host "HEAD=$sha version=$version (from APP_VERSION=$semver)"
foreach ($img in $images) {
    $tags = foreach ($reg in $registries) {
        foreach ($t in @($version, "latest", $sha)) { "$reg/$($img.name):$t" }
    }
    $tagArgs = foreach ($t in $tags) { "-t"; $t }
    Write-Host "=== build $($img.name) ==="
    docker build --platform linux/amd64 `
        --label "org.opencontainers.image.version=$version" `
        --label "org.opencontainers.image.revision=$sha" `
        @tagArgs @($img.args)
    if ($LASTEXITCODE -ne 0) { throw "build failed: $($img.name)" }
}

docker run --rm --entrypoint python "vincenttisseront/bastion-pro-app:$version" -c `
    "from app.web.constants import APP_VERSION; import app.main; print('APP_VERSION', APP_VERSION); assert APP_VERSION == '$semver', APP_VERSION"
if ($LASTEXITCODE -ne 0) { throw "smoke import failed" }

foreach ($img in $images) {
    foreach ($reg in $registries) {
        foreach ($t in @($version, "latest", $sha)) {
            Write-Host "=== push $reg/$($img.name):$t ==="
            docker push --quiet "$reg/$($img.name):$t"
            if ($LASTEXITCODE -ne 0) { throw "push failed: $reg/$($img.name):$t" }
        }
    }
}
Write-Host "PUBLISH OK $version $sha"
