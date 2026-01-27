 
function Read-AdmxFile {
    <#
    .SYNOPSIS
        Reads an ADMX file and returns an object containing all policies, categories, and metadata.
    
    .DESCRIPTION
        This function parses an ADMX file (Group Policy Administrative Template) and extracts:
        - Policy definitions with their configurations
        - Categories and their hierarchy
        - Supported on information
        - Registry keys and values
        - Namespaces and prefixes
    
    .PARAMETER FilePath
        Path to the ADMX file to read
    
    .PARAMETER IncludeAdmlPath
        Optional path to corresponding ADML file for localized strings
    
    .EXAMPLE
        $policies = Read-AdmxFile -FilePath "C:\Windows\PolicyDefinitions\System.admx"
        
    .EXAMPLE
        $policies = Read-AdmxFile -FilePath "System.admx" -IncludeAdmlPath "en-US\System.adml"
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    begin {
        function Resolve-LocalizedText {
            param(
                [string]$Raw
            )
            if ([string]::IsNullOrWhiteSpace($Raw)) { return $Raw }

            # Replace multiple tokens if present
            $pattern = '\$\((?<scope>string|policy)\.(?<id>[^)]+)\)'
            $result = [System.Text.RegularExpressions.Regex]::Replace($Raw, $pattern, {
                    param($m)
                    $id = $m.Groups['id'].Value
                    return $id
                })
            return $result
        }
        function Get-FullCategoryPath {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)][array] $Categories,
                [Parameter(Mandatory)][string] $Name,
                [string] $Separator = ' / '
            )

            # Build lookup by Name for fast parent resolution
            $lookup = @{}
            foreach ($c in $Categories) {
                if ($null -ne $c.Name) { $lookup[$c.Name] = $c }
            }

            $current = $Name
            $segments = [System.Collections.Generic.List[string]]::new()
            $seen = @{}

            while ($current -and $current -ne '') {
                if ($seen.ContainsKey($current)) {
                    throw "Cycle detected in parentref chain at '$current'."
                }
                $seen[$current] = $true

                if ($lookup.ContainsKey($current)) {
                    $item = $lookup[$current]
                    $display = $null
                    if ($item.PSObject.Properties.Match('displayname')) { $display = $item.displayname }
                    elseif ($item.PSObject.Properties.Match('displayName')) { $display = $item.displayName }
                    else { $display = $item.Name }

                    $segments.Add($display)
                    $current = $item.parentref
                }
                else {
                    # If parent not found in collection, include raw current and stop
                    $segments.Add($current)
                    break
                }
            }

            # segments collected from leaf -> root; reverse to get root -> leaf
            $arr = $segments.ToArray()
            [array]::Reverse($arr)
            return ($arr -join $Separator)
        }


        # Initialize result object
        $result = [PSCustomObject]@{
            Namespace        = @()
            Prefix           = @()
            Categories       = @()
            Policies         = @()
            SupportedOn      = @()
            Metadata         = @{}
            LocalizedStrings = @{}
        }

        # Load all ADML files in the same folder as the ADMX file
        if (Test-Path $path) {
            $admlFiles = Get-ChildItem -Path $path -Filter "*.adml" -File -Recurse 
            
            foreach ($admlFile in ($admlFiles)) {
               
                Write-Verbose "Loading ADML file: $($admlFile.FullName)"
                try {
                    [xml]$admlContent = Get-Content -Path $admlFile.FullName -Encoding UTF8
                    if ($admlContent.policyDefinitionResources.resources.stringTable.string) {
                        $strings = $admlContent.policyDefinitionResources.resources.stringTable.string
                        foreach ($string in $strings) {
                            $stringID = "$($admlfile.BaseName)_$($string.id)"
                            $result.LocalizedStrings[$stringID] = $string.'#text'
                        }
                    }
                }
                catch {
                    Write-Warning "Failed to load ADML file: $($admlFile.FullName) - $($_.Exception.Message)"
                }
            }
            #        $result.LocalizedStrings.keys | Sort-Object | Out-File '/home/gaspaq/Downloads/abc/a.txt'

        }

 
        #### GET CATEGORY
       
        $admxFiles = Get-ChildItem -Path $Path -Filter "*.admx" -File -Recurse  #| Select -first 30

        # flat list of PSCustomObjects


        foreach ($admxFile in ($admxFiles)) {
            Write-Verbose "Reading ADMX: $($admxFile.FullName)"

            #$admxfile = get-item '/home/gaspaq/Downloads/abc/appv.admx'
            
            try {
                [xml]$admx = Get-Content -Path $admxFile.FullName -Encoding UTF8
            }
            catch {
                Write-Warning "Failed to load $($admxFile.FullName): $($_.Exception.Message)"
                continue
            }

            $policyDefs = $admx.policyDefinitions
            if (-not $policyDefs) { continue }

            $cats = $policyDefs.categories.category
            if (-not $cats) { continue }

      
            foreach ($c in $cats) {
                # Normalize parent ref: if a parentCategory exists and contains ':', replace with '_'
                # $c = $cats[0]
                $string2 = $string1 = $parentRef = $null
                $Categorydisplayname = (Resolve-LocalizedText $c.DisplayName)
                $c.displayName = $result.LocalizedStrings[($Categorydisplayname.insert(0, "$($admxFile.BaseName)_"))]
                if ($c.parentCategory -ne $null) {
                    $parentRef = $c.parentCategory.ref

                    if ($parentRef -like '*:*') { 
                        $c.parentCategory.ref = $parentRef -replace ':', '_' 
                    }
                    ELSE {
                        $c.parentCategory.ref = $parentRef.insert(0, "$($admxFile.BaseName)_")
                    }
                }

                $item = [PSCustomObject]@{
                    ID          = $c.Name.insert(0, "$($admxFile.BaseName)_")
                    DisplayName = $c.displayName 
                    ParentRef   = $c.parentCategory.ref 

                }

                $result.Categories += $item
        
            }
        }

        #  $result.Categories | Sort-Object Name | Out-String | Out-File '/home/gaspaq/Downloads/abc/b.txt'


        Write-Verbose "Found $($admxFiles.Count) ADMX files" 
       
    }

       

    process {
        # 
        foreach ($admxFile in ($admxFiles)) {
            # Load XML content
            Write-Verbose "Loading ADMX file: $admxFile"
    
            # $admxFile = get-item '/home/gaspaq/Downloads/abc/AllowBuildPreview.admx'
            [xml]$admxContent = Get-Content -Path $admxFile -Encoding UTF8
            # Extract namespace information
            $policyDefinitions = $admxContent.policyDefinitions

            # Extract Policies
            if ($policyDefinitions.policies.policy) {
                $policies = $policyDefinitions.policies.policy



                foreach ($policy in $policies) {
                    $string1 = '{0}_{1}' -f $admxfile.BaseName, (Resolve-LocalizedText $policy.DisplayName)
                    $string2 = '{0}_{1}' -f $admxfile.BaseName, (Resolve-LocalizedText $policy.explainText)
                    IF ($policy.parentCategory.ref -match ':') {
                        $category = $policy.parentCategory.ref -replace ':', '_' 
                    }
                    ELSE {
                        $category = '{0}_{1}' -f $admxfile.BaseName, $policy.parentCategory.ref 
                    }
                    
                    $displayname = $result.LocalizedStrings[$string1]   
                    $explainText = $result.LocalizedStrings[$string2] 
                    $policyObj = [PSCustomObject]@{
                        Name        = $policy.name
                        File        = $admxfile.BaseName
                        DisplayName = $displayname
                        ExplainText = $explainText 
                        Class       = $policy.class ?? 'Machine'
                        Key         = $policy.key
                        ValueName   = $policy.valueName
                        Category    = Get-FullCategoryPath -Categories $result.Categories -Name $category
                        SupportedOn = $result.LocalizedStrings[($policy.supportedOn.ref -replace ':', '_' )]
                        Elements    = @()
                    }

                      
                    # Extract policy elements (text boxes, dropdowns, etc.)
                    $elements = @()

                    # Extract enabled/disabled values
                    if ($policy.enabledValue -or $policy.disabledValue) {

                        $elements += @{
                            Type        = 'decimal'
                            ValueName   = $policy.valueName
                            Description = 'TrueValue = Enabled, FalseValue = Disabled'
                            TrueValue   = $policy.enabledValue.decimal.value
                            FalseValue  = $policy.disabledValue.decimal.value
                        }
                    } 
                    IF (-not $policy.elements -and -not $policy.enabledValue -and -not $policy.disabledValue) {
                        $elements += @{
                            Type        = 'decimal'
                            ValueName   = $policy.valueName
                            Description = 'TrueValue = Enabled, FalseValue = Disabled'
                            TrueValue   = '1'
                            FalseValue  = '0'
                        }
                    }


                    if ($policy.elements) {
                        foreach ($element in $policy.elements.ChildNodes) {
                            switch ($element.Name) {
                                'decimal' {
                                    $elements += @{
                                        Type      = 'Decimal'
                                        #    Id        = $element.id
                                        ValueName = $element.valueName
                                        MinValue  = $element.minValue
                                        MaxValue  = $element.maxValue
                                        Default   = $element.default
                                        Required  = $element.required -eq 'true'
                                    }
                                }
                                'boolean' {
                                    $trueValue = "1"
                                    $falseValue = "0"
                                
                                    if ($element.trueValue.decimal) {
                                        $trueValue = $element.trueValue.decimal.value
                                    }
                                    elseif ($element.trueValue.string) {
                                        $trueValue = $element.trueValue.string
                                    }
                                
                                    if ($element.falseValue.decimal) {
                                        $falseValue = $element.falseValue.decimal.value
                                    }
                                    elseif ($element.falseValue.string) {
                                        $falseValue = $element.falseValue.string
                                    }
                                
                                    $elements += @{
                                        Type       = 'Boolean'
                                        #    Id         = $element.id
                                        ValueName  = $element.valueName
                                        TrueValue  = $trueValue
                                        FalseValue = $falseValue
                                    }
                                }
                                'enum' {
                                    $items = @()
                                    if ($element.item) {
                                        foreach ($item in $element.item) {
                                            $itemtext = '{0}_{1}' -f $admxfile.BaseName, (Resolve-LocalizedText $item.displayName)
                                            $displayName = $result.LocalizedStrings[$itemtext]
                                            $value = $null
                                        
                                            if ($item.value.decimal) {
                                                $value = $item.value.decimal.value
                                            }
                                            elseif ($item.value.string) {
                                                $value = $item.value.string
                                            }
                                        
                                            $items += @{
                                                DisplayName = $displayName
                                                Value       = $value
                                            }
                                        }
                                    }
                                    $elements += @{
                                        Type      = 'Enum'
                                        #    Id        = $element.id
                                        ValueName = $element.valueName
                                        Items     = $items
                                        Required  = $element.required -eq 'true'
                                    }
                                }
                                'text' {
                                    $elements += @{
                                        Type      = 'Text'
                                        #    Id        = $element.id
                                        ValueName = $element.valueName
                                        MaxLength = $element.maxLength
                                        Default   = $element.default
                                        Required  = $element.required -eq 'true'
                                    }
                                }
                                'multiText' {
                                    $elements += @{
                                        Type       = 'MultiText'
                                        #    Id         = $element.id
                                        ValueName  = $element.valueName
                                        MaxLength  = $element.maxLength
                                        MaxStrings = $element.maxStrings
                                        Required   = $element.required -eq 'true'
                                    }
                                }
                                'list' {
                                    $elements += @{
                                        Type           = 'List'
                                        #    Id             = $element.id
                                        Key            = $element.key
                                        ValuePrefix    = $element.valuePrefix
                                        Additive       = $element.additive -eq 'true'
                                        ExpandableText = $element.expandableText -eq 'true'
                                        ExplicitValue  = $element.explicitValue -eq 'true'
                                    }
                                }
                                default {
                                    # Handle any other element types
                                    $elements += @{
                                        Type = $element.Name
                                        #    Id   = $element.id
                                        Raw  = $element
                                    }
                                }
                            }
                        }
                    }
                 
                    # Assign elements to policy object
                    $policyObj.Elements = $elements
                
                    # Add policy to results
                    $result.Policies += $policyObj
                    
                }
    
            }
        
        } # process



    }
    end {
        # Add metadata
        $result.Metadata = @{
            TotalPolicies          = $result.Policies.Count
            TotalCategories        = $result.Categories.Count
            SupportedOnDefinitions = '' #$result.Policies.SupportedOn | Sort-Object -Unique
            UserPolicies           = ($result.Policies | Where-Object { $_.Class -eq 'User' }).Count
            MachinePolicies        = ($result.Policies | Where-Object { $_.Class -eq 'Machine' }).Count
            BothPolicies           = ($result.Policies | Where-Object { $_.Class -eq 'Both' }).Count
        }
        
        Write-Verbose "Successfully parsed ADMX file with $($result.Metadata.TotalPolicies) policies and $($result.Metadata.TotalCategories) categories"
        
        $result
    }
}
