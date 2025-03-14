# PowerShell < 7 does not handle ZIP files correctly.
if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "This script requires PowerShell 7 or higher."
}

$rootDir = $MyInvocation.MyCommand.Path

if (!$rootDir) {
    $rootDir = $psISE.CurrentFile.Fullpath
}

if ($rootDir)  {
    foreach($i in 1..2) {
        $rootDir = Split-Path $rootDir -Parent
    }
}
else {
    throw 'Could not determine root directory of project.'
}

if (![bool](Get-Command -ErrorAction Stop -Type Application dotnet)) {
    throw 'dotnet SDK could not be found.'
}

$winKitDir = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' 'KitsRoot10'

if (!$winKitDir -or !(Test-Path -Path $winKitDir)) {
    throw 'Windows SDK path is not found.'
}

$sdkVersion = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' | Sort-Object Name -Descending | Select-Object -ExpandProperty PSChildName -First 1
$sdkPath = Join-Path -Path $winKitDir -ChildPath 'bin'
$sdkPath = Join-Path -Path $sdkPath -ChildPath $sdkVersion

$architecture = [System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")
$archDirName = switch ($architecture) {
    'ARM64' { 'arm64' }
    'x86' { 'x86' }
    'AMD64' { 'x64' }
    Default { throw 'Unknown architecture' }
}

$sdkBinPath = Join-Path -Path $sdkPath -ChildPath $archDirName
$objDir = Join-Path -Path $rootDir -ChildPath 'obj'
$outDir = Join-Path -Path $rootDir -ChildPath 'out'

pushd $rootDir

Remove-Item -Path $objDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -Path $objDir -ItemType Directory

Remove-Item -Path $outDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -Path $outDir -ItemType Directory

dotnet pack -p:OutputFileNamesWithoutVersion=true -p:ContinuousIntegrationBuild=true -c Release -o $objDir src\AuthenticodeExaminer\AuthenticodeExaminer.csproj

Expand-Archive -Path $objDir\AuthenticodeExaminer.nupkg -DestinationPath $objDir\AuthenticodeExaminer.nupkg.dir

Remove-Item -Path $objDir\AuthenticodeExaminer.nupkg

& "$sdkBinPath\signtool.exe" sign /d "AuthenticodeExaminer" /sha1 73f0844a95e35441a676cd6be1e79a3cd51d00b4 /fd SHA384 /td SHA384 /tr "http://timestamp.digicert.com" /du "https://github.com/vcsjones/AuthenticodeExaminer" "$objDir\AuthenticodeExaminer.nupkg.dir\lib\netstandard2.0\AuthenticodeExaminer.dll"
& "$sdkBinPath\signtool.exe" sign /d "AuthenticodeExaminer" /sha1 73f0844a95e35441a676cd6be1e79a3cd51d00b4 /fd SHA384 /td SHA384 /tr "http://timestamp.digicert.com" /du "https://github.com/vcsjones/AuthenticodeExaminer" "$objDir\AuthenticodeExaminer.nupkg.dir\lib\net462\AuthenticodeExaminer.dll"

Compress-Archive -Path "$objDir\AuthenticodeExaminer.nupkg.dir\*" -DestinationPath "$objDir\AuthenticodeExaminer.nupkg"

dotnet nuget sign --certificate-fingerprint 68821304869e065c24e0684eb43bf974e124642f3437f2ff494a93bb371d029a --hash-algorithm SHA384 --timestamper "http://timestamp.digicert.com" --overwrite "$objDir\AuthenticodeExaminer.nupkg"

Copy-Item -Path "$objDir\AuthenticodeExaminer.nupkg" -Destination "$outDir\AuthenticodeExaminer.nupkg"

popd