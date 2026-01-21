

Function Write-GPolFile {
    <#
    .SYNOPSIS
        Writes GPRegistryPolicy objects to a registry.pol file.
    .DESCRIPTION
        Creates a Group Policy registry.pol file from GPRegistryPolicy objects.
        The file format follows Microsoft's PReg specification.
    .PARAMETER Path
        The path to the output .pol file.
    .PARAMETER Policy
        One or more GPRegistryPolicy objects to write to the file.
    .EXAMPLE
        Write_GPolFile -Path "output.pol" -Policy $policy1, $policy2
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Path,


        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$Policy
    )
    begin {
        # Helper function to write null-terminated Unicode string
        function Write-NullTerminatedString([System.IO.BinaryWriter]$writer, [string]$value) {
            if ($null -eq $value) { $value = '' }
            $bytes = [System.Text.Encoding]::Unicode.GetBytes($value)
            $writer.Write($bytes)
            $writer.Write([byte[]]@(0, 0)) # null terminator
        }


        $fs = $null
        $bw = $null
       

        # Unicode bytes for delimiters
        $script:OpenBracket = [System.Text.Encoding]::Unicode.GetBytes('[')   # 2 bytes
        $script:CloseBracket = [System.Text.Encoding]::Unicode.GetBytes(']')  # 2 bytes
        $script:Semicolon = [System.Text.Encoding]::Unicode.GetBytes(';')     # 2 bytes
    }
    process {
        foreach ($p in $Policy) {

        }
    }
    end {
        try {

            $policies = $policy
            #$path = '/home/rslsync/Resilio Sync/Powershell/Modules/ADMXParse/Registry2.pol'
            $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
            $bw = [System.IO.BinaryWriter]::new($fs)
            # $bw = [System.IO.BinaryWriter]::new($fs, [System.Text.Encoding]::Unicode)

            # Write header: "PReg" magic bytes
            $bw.Write([byte[]]@(80, 82, 101, 103))

            # Write version (always 1)
            $bw.Write([int]1)

            foreach ($pol in $policies) {
                # Opening bracket '['
                $bw.Write($script:OpenBracket)

                # KeyName (null-terminated)
                Write-NullTerminatedString $bw $pol.KeyName

                # Semicolon delimiter
                $bw.Write($script:Semicolon)

                # ValueName (null-terminated)
                Write-NullTerminatedString $bw $pol.ValueName

                # Semicolon delimiter
                $bw.Write($script:Semicolon)

                # ValueType (Int32)
                $bw.Write([int]$pol.ValueType)

                # Semicolon delimiter
                $bw.Write($script:Semicolon)

                # Calculate ValueData bytes based on type
                [byte[]]$valueBytes = switch ($pol.ValueType) {
                    ([RegType]::REG_DWORD) {
                        [int]$dword = [int]$pol.ValueData
                        [System.BitConverter]::GetBytes($dword)
                    }
                    ([RegType]::REG_QWORD) {
                        [int64]$qword = [int64]$pol.ValueData
                        [System.BitConverter]::GetBytes($qword)
                    }
                    ([RegType]::REG_BINARY) {
                        if ($pol.ValueData -is [byte[]]) {
                            [byte[]]$pol.ValueData
                        }
                        elseif ($pol.ValueData -is [string]) {
                            $s = ($pol.ValueData -replace '\s', '')
                            if ($s.StartsWith('0x')) { $s = $s.Substring(2) }
                            if ($s.Length -eq 0) { [byte[]]@() } else {
                                $len = [int]($s.Length / 2)
                                $arr = New-Object byte[] $len
                                for ($i = 0; $i -lt $len; $i++) {
                                    $arr[$i] = [Convert]::ToByte($s.Substring($i * 2, 2), 16)
                                }
                                $arr
                            }
                        }
                        elseif ($pol.ValueData -is [int[]]) {
                            [byte[]]$pol.ValueData
                        }
                        else { [byte[]]@() }
                    }
                    ([RegType]::REG_MULTI_SZ) {
                        if ($pol.ValueData -is [System.Collections.IEnumerable] -and -not ($pol.ValueData -is [string])) {
                            $parts = @()
                            foreach ($item in $pol.ValueData) { $parts += [string]$item }
                        }
                        elseif ($pol.ValueData -is [string]) {
                            $parts = ($pol.ValueData -split "\r?\n") | Where-Object { $_ -ne '' }
                        }
                        else { $parts = @() }

                        $multi = ($parts -join [char]0) + [char]0 + [char]0
                        [System.Text.Encoding]::Unicode.GetBytes($multi)
                    }
                    { $_ -in @([RegType]::REG_SZ, [RegType]::REG_EXPAND_SZ) } {
                        $strBytes = [System.Text.Encoding]::Unicode.GetBytes([string]$pol.ValueData)
                        $strBytes + [byte[]]@(0, 0)
                    }
                    default {
                        if ($null -ne $pol.ValueData) { [byte[]]$pol.ValueData } else { [byte[]]@() }
                    }
                }

                # Write ValueLength (Int32 number of bytes)
                $valueLength = [int]$valueBytes.Length
                $bw.Write([int]$valueLength)

                # Semicolon delimiter
                $bw.Write($script:Semicolon)

                # Write ValueData
                if ($valueLength -gt 0) { $bw.Write($valueBytes) }
                

                # Closing bracket ']'
                $bw.Write($script:CloseBracket)
            }
           
            #$bw.Flush()
        }
        catch {
            throw
        }
        finally {
            if ($bw) { $bw.Dispose() }
            if ($fs) { $fs.Dispose() }
        }
    }
}

