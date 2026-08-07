[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BuildDirectory,

    [Parameter(Mandatory = $true)]
    [string]$DumpDirectory,

    [ValidateRange(1, 1000)]
    [int]$ExitRepetitions = 100,

    [ValidateRange(1, 1000)]
    [int]$InputRepetitions = 200,

    [ValidateRange(1, 1000)]
    [int]$LabelRepetitions = 20,

    [ValidateRange(1, 64)]
    [int]$LabelParallelism = 4
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion.Major -ge 7)
{
    $PSNativeCommandUseErrorActionPreference = $false
}

function Invoke-CheckedCommand
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & $Command @Arguments
    $command_exit = $LASTEXITCODE
    if ($command_exit -ne 0)
    {
        throw "Command '$Command' exited with code $command_exit."
    }
}

function Get-RegistryValueSnapshot
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $registry_key = Get-Item -LiteralPath $Path
    if (@($registry_key.GetValueNames()) -notcontains $Name)
    {
        return [pscustomobject]@{ Exists = $false; Value = $null; Kind = $null }
    }

    $value = $registry_key.GetValue(
        $Name,
        $null,
        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    return [pscustomobject]@{
        Exists = $true
        Value = $value
        Kind = $registry_key.GetValueKind($Name).ToString()
    }
}

function Invoke-CheckedCtest
{
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [string]$RuntimeDirectory
    )

    $saved_path = $env:Path
    try
    {
        if (-not [string]::IsNullOrEmpty($RuntimeDirectory))
        {
            $env:Path = $RuntimeDirectory + [IO.Path]::PathSeparator + $saved_path
        }
        Invoke-CheckedCommand -Command 'ctest' -Arguments $Arguments
    }
    finally
    {
        $env:Path = $saved_path
    }
}

function Test-CompletedMinidump
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try
    {
        $stream = [IO.File]::Open(
            $Path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::None)
        try
        {
            if ($stream.Length -lt 32)
            {
                return $false
            }

            $signature = New-Object byte[] 4
            if ($stream.Read($signature, 0, $signature.Length) -ne $signature.Length)
            {
                return $false
            }
            return [Text.Encoding]::ASCII.GetString($signature) -eq 'MDMP'
        }
        finally
        {
            $stream.Dispose()
        }
    }
    catch [IO.IOException]
    {
        return $false
    }
}

$repository_root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$build_candidate = if ([IO.Path]::IsPathRooted($BuildDirectory))
{
    $BuildDirectory
}
else
{
    Join-Path $repository_root $BuildDirectory
}
$resolved_build = (Resolve-Path -LiteralPath $build_candidate).Path
$repository_prefix = $repository_root.TrimEnd('\') + '\'
if (-not $resolved_build.StartsWith($repository_prefix, [StringComparison]::OrdinalIgnoreCase))
{
    throw "Build directory '$resolved_build' is outside the repository."
}
$relative_build = $resolved_build.Substring($repository_prefix.Length).Replace('\', '/')
if (-not (Test-Path -LiteralPath (Join-Path $resolved_build 'CMakeCache.txt') -PathType Leaf))
{
    throw "Build directory '$resolved_build' is not a configured CMake tree."
}
$compiler_entry = Get-Content -LiteralPath (Join-Path $resolved_build 'CMakeCache.txt') |
    Where-Object { $_ -match '^CMAKE_CXX_COMPILER:[^=]*=' } |
    Select-Object -First 1
$runtime_directory = ''
if ($null -ne $compiler_entry)
{
    $compiler_path = $compiler_entry.Substring($compiler_entry.IndexOf('=') + 1)
    if ([IO.Path]::GetFileName($compiler_path) -ieq 'g++.exe')
    {
        $runtime_directory = [IO.Path]::GetDirectoryName($compiler_path)
    }
}

$dump_candidate = if ([IO.Path]::IsPathRooted($DumpDirectory))
{
    $DumpDirectory
}
else
{
    Join-Path $repository_root $DumpDirectory
}
(New-Item -ItemType Directory -Path $dump_candidate -Force) | Out-Null
$resolved_dump = (Resolve-Path -LiteralPath $dump_candidate).Path
if (@(Get-ChildItem -LiteralPath $resolved_dump -Filter '*.dmp' -File).Count -ne 0)
{
    throw "Dump directory '$resolved_dump' already contains dumps; refusing to confuse old evidence with this run."
}

$inventory_output = & ctest --test-dir $resolved_build --show-only=json-v1 2>&1
$inventory_exit = $LASTEXITCODE
if ($inventory_exit -ne 0)
{
    throw "CTest inventory exited with code $inventory_exit.`n$($inventory_output -join [Environment]::NewLine)"
}
$inventory = ($inventory_output -join [Environment]::NewLine) | ConvertFrom-Json
$lifecycle_tests = @($inventory.tests | Where-Object {
    $labels = @($_.properties | Where-Object { $_.name -eq 'LABELS' } | ForEach-Object { $_.value })
    $labels -contains 'lifecycle-proof'
})
if ($lifecycle_tests.Count -eq 0)
{
    throw "CTest inventory contains no lifecycle-proof tests."
}
if (@($lifecycle_tests | Where-Object { $_.name -eq 'Lifecycle.FullLifecycleExit' }).Count -ne 1)
{
    throw "CTest inventory does not contain exactly one Lifecycle.FullLifecycleExit proof."
}
$input_lifecycle_tests = @($inventory.tests | Where-Object { $_.name -like 'InputLifecycleProof.*' })
if ($input_lifecycle_tests.Count -eq 0)
{
    throw "CTest inventory contains no InputLifecycleProof tests."
}
$input_regression = 'InputLifecycleProof.CardinalityRebindReleasesDroppedNonPrototypeHold'
if (@($input_lifecycle_tests | Where-Object { $_.name -eq $input_regression }).Count -ne 1)
{
    throw "CTest inventory does not contain exactly one $input_regression proof."
}

Invoke-CheckedCommand -Command 'cmake' -Arguments @(
    '--build', $resolved_build, '--target', 'fast_fail_probe', '--parallel', '2')
$control_probes = @(Get-ChildItem -LiteralPath $resolved_build -Recurse -Filter 'fast_fail_probe.exe' -File)
if ($control_probes.Count -ne 1)
{
    throw "Expected one fast_fail_probe.exe below '$resolved_build', found $($control_probes.Count)."
}

$windows_identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$windows_principal = [Security.Principal.WindowsPrincipal]::new($windows_identity)
if (-not $windows_principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    throw 'WER LocalDumps requires an elevated Windows runner.'
}

$aedebug_paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug')
foreach ($aedebug_path in $aedebug_paths)
{
    $aedebug = Get-ItemProperty -LiteralPath $aedebug_path -Name Auto -ErrorAction SilentlyContinue
    if ($null -ne $aedebug -and [string]$aedebug.Auto -eq '1')
    {
        throw "Automatic postmortem debugging is active at '$aedebug_path'; WER would not collect LocalDumps."
    }
}

$wer_root = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'
$wer_root_existed = Test-Path -LiteralPath $wer_root
$value_names = @('DumpFolder', 'DumpType', 'DumpCount')
$wer_executables = @(
    @($lifecycle_tests) +
    @($input_lifecycle_tests) +
    @([pscustomobject]@{ command = @($control_probes[0].FullName) }) |
        ForEach-Object { [IO.Path]::GetFileName([string]$_.command[0]) } |
        Sort-Object -Unique)
if ($wer_executables.Count -eq 0 -or @($wer_executables | Where-Object { -not $_.EndsWith('.exe') }).Count -ne 0)
{
    throw 'CTest inventory contains an invalid lifecycle executable name.'
}

$wer_key_states = @()
$wer_armed = $false
try
{
    $wer_armed = $true
    if (-not $wer_root_existed)
    {
        (New-Item -Path $wer_root -Force) | Out-Null
    }
    foreach ($wer_executable in $wer_executables)
    {
        $wer_path = Join-Path $wer_root $wer_executable
        $wer_key_existed = Test-Path -LiteralPath $wer_path
        if (-not $wer_key_existed)
        {
            (New-Item -Path $wer_path -Force) | Out-Null
        }
        $value_snapshots = @{}
        $wer_key_state = [pscustomobject]@{
            Path = $wer_path
            Existed = $wer_key_existed
            Snapshots = $value_snapshots
        }
        $wer_key_states += $wer_key_state
        foreach ($value_name in $value_names)
        {
            $value_snapshots[$value_name] = Get-RegistryValueSnapshot -Path $wer_path -Name $value_name
        }

        (New-ItemProperty -LiteralPath $wer_path -Name DumpFolder -PropertyType ExpandString -Value $resolved_dump `
            -Force) | Out-Null
        (New-ItemProperty -LiteralPath $wer_path -Name DumpType -PropertyType DWord -Value 1 -Force) | Out-Null
        (New-ItemProperty -LiteralPath $wer_path -Name DumpCount -PropertyType DWord -Value 10 -Force) | Out-Null
    }

    $control_process = Start-Process -FilePath $control_probes[0].FullName -ArgumentList 'wer-crash' -NoNewWindow `
        -PassThru
    try
    {
        if (-not $control_process.WaitForExit(30000))
        {
            Stop-Process -Id $control_process.Id -Force -ErrorAction SilentlyContinue
            throw 'The WER control process did not terminate within 30 seconds.'
        }
        if ($control_process.ExitCode -eq 0)
        {
            throw 'The WER control process returned success instead of failing fast.'
        }
    }
    finally
    {
        $control_process.Dispose()
    }

    $control_deadline = [DateTime]::UtcNow.AddSeconds(30)
    do
    {
        $control_dumps = @(Get-ChildItem -LiteralPath $resolved_dump -Filter 'fast_fail_probe*.dmp' -File)
        if ($control_dumps.Count -eq 1 -and (Test-CompletedMinidump -Path $control_dumps[0].FullName))
        {
            break
        }
        Start-Sleep -Milliseconds 250
    }
    while ([DateTime]::UtcNow -lt $control_deadline)

    if ($control_dumps.Count -ne 1 -or -not (Test-CompletedMinidump -Path $control_dumps[0].FullName))
    {
        throw 'WER did not capture exactly one complete native fail-fast control dump within 30 seconds.'
    }
    Remove-Item -LiteralPath $control_dumps[0].FullName -Force

    Invoke-CheckedCtest -RuntimeDirectory $runtime_directory -Arguments @(
        '--test-dir', $resolved_build,
        '-R', '^InputLifecycleProof[.]',
        '--repeat', "until-fail:$InputRepetitions",
        '--parallel', '1',
        '--stop-on-failure',
        '--output-on-failure')

    $bash = Get-Command bash -ErrorAction Stop
    Push-Location $repository_root
    try
    {
        Invoke-CheckedCommand -Command $bash.Source -Arguments @(
            'scripts/run_lifecycle_proofs.sh',
            $relative_build,
            '-R', '^Lifecycle[.]FullLifecycleExit$',
            '--repeat', "until-fail:$ExitRepetitions",
            '--parallel', '1',
            '--stop-on-failure')
    }
    finally
    {
        Pop-Location
    }

    Invoke-CheckedCtest -RuntimeDirectory $runtime_directory -Arguments @(
        '--test-dir', $resolved_build,
        '-L', 'lifecycle-proof',
        '--repeat', "until-fail:$LabelRepetitions",
        '--parallel', [string]$LabelParallelism,
        '--stop-on-failure',
        '--output-on-failure')

    Write-Host "Lifecycle soak passed: $InputRepetitions serial InputLifecycleProof repetitions, " `
        "$ExitRepetitions serial FullLifecycleExit repetitions, and $LabelRepetitions full-label repetitions " `
        "at parallelism $LabelParallelism."
}
finally
{
    if ($wer_armed)
    {
        foreach ($wer_key_state in $wer_key_states)
        {
            foreach ($value_name in $value_names)
            {
                if (-not $wer_key_state.Snapshots.ContainsKey($value_name))
                {
                    continue
                }
                $snapshot = $wer_key_state.Snapshots[$value_name]
                if ($snapshot.Exists)
                {
                    (New-ItemProperty -LiteralPath $wer_key_state.Path -Name $value_name `
                        -PropertyType $snapshot.Kind -Value $snapshot.Value -Force) | Out-Null
                }
                else
                {
                    Remove-ItemProperty -LiteralPath $wer_key_state.Path -Name $value_name `
                        -ErrorAction SilentlyContinue
                }
            }

            if (-not $wer_key_state.Existed)
            {
                $wer_key = Get-Item -LiteralPath $wer_key_state.Path
                if (@($wer_key.GetValueNames()).Count -eq 0 -and @($wer_key.GetSubKeyNames()).Count -eq 0)
                {
                    Remove-Item -LiteralPath $wer_key_state.Path -Force
                }
            }
        }

        if (-not $wer_root_existed)
        {
            $wer_root_key = Get-Item -LiteralPath $wer_root -ErrorAction SilentlyContinue
            if ($null -ne $wer_root_key -and @($wer_root_key.GetValueNames()).Count -eq 0 -and
                @($wer_root_key.GetSubKeyNames()).Count -eq 0)
            {
                Remove-Item -LiteralPath $wer_root -Force
            }
        }
    }
}
