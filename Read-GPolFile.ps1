Enum RegType {
    # Unspecified / no value
    REG_NONE = 0

    # Null-terminated string (Unicode or ANSI depending on context)
    REG_SZ = 1

    # Null-terminated string with environment-variable references (e.g. "%PATH%")
    REG_EXPAND_SZ = 2

    # Free-form binary data
    REG_BINARY = 3

    # 32-bit number (little-endian)
    REG_DWORD = 4
    REG_DWORD_LITTLE_ENDIAN = 4

    # 32-bit number (big-endian)
    REG_DWORD_BIG_ENDIAN = 5

    # Symbolic link (unicode)
    REG_LINK = 6

    # Multi-string: array of null-terminated strings, terminated by two nulls
    REG_MULTI_SZ = 7

    # Resource list for a device driver
    REG_RESOURCE_LIST = 8 

    # Hardware resource list (full resource descriptor)
    REG_FULL_RESOURCE_DESCRIPTOR = 9

    # Resource requirements list
    REG_RESOURCE_REQUIREMENT_LIST = 10

    # 64-bit number
    REG_QWORD = 11
    REG_QWORD_LITTLE_ENDIAN = 12
}

Class GPRegistryPolicy {
    [string] $KeyName
    [string] $ValueName
    [RegType] $ValueType
    [int] $ValueLength
    [object] $ValueData

    GPRegistryPolicy () {
        $this.KeyName = $null
        $this.ValueName = $null
        $this.ValueType = [RegType]::REG_NONE
        $this.ValueLength = 0
        $this.ValueData = $null
    
    }

    GPRegistryPolicy ([string] $KeyName, [string] $ValueName, [RegType] $ValueType, [int] $ValueLength, [object] $ValueData) {
        $this.KeyName = $KeyName
        $this.ValueName = $ValueName
        $this.ValueType = $ValueType
        $this.ValueLength = $ValueLength
        $this.ValueData = $ValueData
    }

}

Function Read-GPolFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$Path
    )
    begin {
        # Helper function to read null-terminated Unicode string efficiently
        function Read-NullTerminatedString([System.IO.BinaryReader]$reader) {
            $ms = [System.IO.MemoryStream]::new(256)
            try {
                while ($true) {
                    $b = $reader.ReadBytes(2)
                    if ($b[0] -eq 0 -and $b[1] -eq 0) { break }
                    $ms.Write($b, 0, 2)
                }
                return [System.Text.Encoding]::Unicode.GetString($ms.ToArray())
            }
            finally {
                $ms.Dispose()
            }
        }

        $fs = $null
        $br = $null

        try {
            $fs = [System.IO.File]::Open($Path, 'Open', 'Read')
            $br = [System.IO.BinaryReader]::new($fs)

            $header = $br.ReadBytes(4)
            # "PReg" magic header
            if ($header[0] -ne 80 -or $header[1] -ne 82 -or $header[2] -ne 101 -or $header[3] -ne 103) {
                throw "Invalid registry.pol file header"
            }
            $null = $br.ReadInt32() # version (unused but must be read)
        }
        catch {
            if ($br) { $br.Dispose() }
            if ($fs) { $fs.Dispose() }
            throw
        }
    }
    process {
        try {
            while ($br.BaseStream.Position -lt $br.BaseStream.Length) {
                # Skip opening bracket '[' (2 bytes)
                $null = $br.ReadBytes(2)

                # Get KeyName
                $KeyName = Read-NullTerminatedString $br
                $null = $br.ReadBytes(2) # semicolon delimiter

                # Get ValueName
                $ValueName = Read-NullTerminatedString $br
                $null = $br.ReadBytes(2) # semicolon delimiter

                # Get ValueType
                $valueTypeValue = $br.ReadInt32()
                $valueType = [RegType]$valueTypeValue
                $null = $br.ReadBytes(2) # semicolon delimiter

                # Get ValueLength
                $valueLength = $br.ReadInt32()
                $null = $br.ReadBytes(2) # semicolon delimiter

                # Read value data based on type
                $valueData = switch ($valueType) {
                    ([RegType]::REG_DWORD) {
                        $br.ReadInt32()
                  
                    }
                    { $_ -in @([RegType]::REG_SZ, [RegType]::REG_EXPAND_SZ) } {
                        Read-NullTerminatedString $br
                    }
                    ([RegType]::REG_BINARY) {
                        $br.ReadBytes($valueLength)
                    }
                    ([RegType]::REG_MULTI_SZ) {
                        [System.Text.Encoding]::Unicode.GetString($br.ReadBytes($valueLength))
                    }
                    ([RegType]::REG_QWORD) {
                        $br.ReadInt64()
                    }
                }

                # Skip closing bracket ']' (2 bytes)
                $null = $br.ReadBytes(2)

                $Policy = [GPRegistryPolicy]::new($KeyName, $ValueName, $valueType, $valueLength, $valueData)
                $Policy
            }
        }
        catch {
            throw
        }
    }
    end {
        if ($br) { $br.Dispose() }
        if ($fs) { $fs.Dispose() }
    }
}
