param([Parameter(Mandatory=$true)][string]$Path)

if (-not (Test-Path $Path)) {
    Write-Error "target not found: $Path"
    exit 1
}

$bytes = [System.IO.File]::ReadAllBytes($Path)
if ($bytes.Length -lt 512) {
    Write-Error "file too small to be a PE"
    exit 2
}

if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
    Write-Error "not a PE (no MZ)"
    exit 3
}

$peOffset = [System.BitConverter]::ToInt32($bytes, 0x3C)
if ($bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset+1] -ne 0x45) {
    Write-Error "not a PE (no PE signature)"
    exit 4
}

$magic = [System.BitConverter]::ToUInt16($bytes, $peOffset + 24)
if ($magic -ne 0x20B) {
    Write-Error "not a PE32+ image (magic=$($magic.ToString('X')))"
    exit 5
}

$optOffset      = $peOffset + 24
$dataDirOffset  = $optOffset + 112
$debugDirEntry  = $dataDirOffset + (6 * 8)
$checkSumOffset = $optOffset + 64

$dbgRva  = [System.BitConverter]::ToUInt32($bytes, $debugDirEntry)
$dbgSize = [System.BitConverter]::ToUInt32($bytes, $debugDirEntry + 4)

if ($dbgRva -ne 0 -and $dbgSize -ne 0) {
    $secTableOff = $optOffset + [System.BitConverter]::ToUInt16($bytes, $peOffset + 20)
    $numSections = [System.BitConverter]::ToUInt16($bytes, $peOffset + 6)

    $dbgFileOff = 0
    for ($i = 0; $i -lt $numSections; $i++) {
        $sec = $secTableOff + ($i * 40)
        $vAddr = [System.BitConverter]::ToUInt32($bytes, $sec + 12)
        $vSize = [System.BitConverter]::ToUInt32($bytes, $sec + 8)
        $rawAddr = [System.BitConverter]::ToUInt32($bytes, $sec + 20)
        if ($dbgRva -ge $vAddr -and $dbgRva -lt ($vAddr + $vSize)) {
            $dbgFileOff = $rawAddr + ($dbgRva - $vAddr)
            break
        }
    }

    if ($dbgFileOff -ne 0) {
        $numEntries = [int]($dbgSize / 28)
        for ($e = 0; $e -lt $numEntries; $e++) {
            $entryOff  = $dbgFileOff + ($e * 28)
            $cvRva     = [System.BitConverter]::ToUInt32($bytes, $entryOff + 20)
            $cvSize    = [System.BitConverter]::ToUInt32($bytes, $entryOff + 16)
            $cvFileOff = [System.BitConverter]::ToUInt32($bytes, $entryOff + 24)

            if ($cvFileOff -ne 0 -and $cvSize -gt 0 -and ($cvFileOff + $cvSize) -le $bytes.Length) {
                for ($j = 0; $j -lt $cvSize; $j++) { $bytes[$cvFileOff + $j] = 0 }
            }
            for ($j = 0; $j -lt 28; $j++) { $bytes[$entryOff + $j] = 0 }
        }
    }

    for ($i = 0; $i -lt 8; $i++) { $bytes[$debugDirEntry + $i] = 0 }
}

for ($i = 0; $i -lt 4; $i++) { $bytes[$checkSumOffset + $i] = 0 }

[System.IO.File]::WriteAllBytes($Path, $bytes)
Write-Host "[strip-pdb] scrubbed debug directory in $Path"
