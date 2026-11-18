param(
    [ValidateSet('sanity', 'paper')][string]$Profile = 'sanity',
    [string]$Params = '',
    [string]$Out = 'results',
    [string]$PbcPrefix = ''
)
$ErrorActionPreference = 'Stop'
Push-Location -LiteralPath $PSScriptRoot
try {
    Get-Command go -ErrorAction Stop | Out-Null
    $env:CGO_ENABLED = '1'
    if ($PbcPrefix) {
        $resolvedPrefix = (Resolve-Path -LiteralPath $PbcPrefix).Path
        if (-not (Test-Path -LiteralPath (Join-Path $resolvedPrefix 'include\pbc\pbc.h'))) {
            throw 'PbcPrefix must contain include\pbc\pbc.h and matching native libraries.'
        }
        # cgo reparses these flags. Forward slashes avoid Windows backslashes
        # becoming escapes inside its generated quoted linker directives.
        $compilerPrefix = $resolvedPrefix.Replace('\', '/')
        $env:CGO_CFLAGS = '"-I{0}/include"' -f $compilerPrefix
        $env:CGO_LDFLAGS = '"-L{0}/lib" -lpbc -lgmp' -f $compilerPrefix
        $env:PATH = (Join-Path $resolvedPrefix 'bin') + ';' + $env:PATH
    }
    New-Item -ItemType Directory -Path 'build' -Force | Out-Null
    $ErrorActionPreference = 'Continue'
    & go test ./... -count=1 2>&1 | Tee-Object -FilePath 'build\functional-tests.log'
    $testExit = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($testExit -ne 0) { throw 'Functional test gate failed. Return build\functional-tests.log. No batch was started.' }
    $ErrorActionPreference = 'Continue'
    & go build -o 'build\chare-runner.exe' . 2>&1 | Tee-Object -FilePath 'build\build.log'
    $buildExit = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($buildExit -ne 0) { throw 'Native build failed. Return build\build.log and check GMP/PBC development dependencies.' }
    $runArguments = @('-config', "config/$Profile.json", '-out', $Out)
    if ($Params) { $runArguments += @('-params', $Params) }
    & '.\build\chare-runner.exe' @runArguments
    $runExit = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $runExit
