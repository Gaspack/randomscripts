function Invoke-AllowDenyFilter {
    <#
    .SYNOPSIS
    Filters policy objects based on allow/deny groups and variables.
    
    .DESCRIPTION
    Evaluates policy objects against specified AD groups and variables to determine
    which policies should be applied. A policy is included if:
    - No allow criteria specified, OR all specified allow criteria are met
    - AND none of the deny criteria are met
    
    .PARAMETER PolicyObjects
    Array of policy objects with allow_group, deny_group, allow_vars, deny_vars properties.
    
    .PARAMETER Groups
    Array of groups to check against allow_group and deny_group properties.
    
    .PARAMETER Variables
    Array of variables to check against allow_vars and deny_vars properties.
    
    .OUTPUTS
    Filtered policy objects that match the criteria.
    
    .EXAMPLE
    $filtered = Invoke-AllowDenyFilter -PolicyObjects $policies -Groups $groups -Variables $vars
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object[]]$PolicyObjects,
        
        [Parameter(Mandatory = $true)]
        [string[]]$Groups,
        
        [Parameter(Mandatory = $true)]
        [string[]]$Variables
    )
    
    process {
        # Create case-insensitive HashSets for efficient lookups
        $ADGroupSet = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $ADGroupSet.UnionWith([string[]]$Groups)
        
        $ADVarSet = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $ADVarSet.UnionWith([string[]]$Variables)
        
        # Filter policies
        $PolicyObjects | Where-Object {
            $allowGroup = @($_.allow_group)
            $allowVars = @($_.allow_vars)
            $denyGroup = @($_.deny_group)
            $denyVars = @($_.deny_vars)
            
            $hasAllowGroup = $allowGroup.Count -gt 0
            $hasAllowVars = $allowVars.Count -gt 0
            $allowedGroups = $allowGroup | Where-Object { $ADGroupSet.Contains($_) }
            $allowedVars = $allowVars | Where-Object { $ADVarSet.Contains($_) }
            $denyGroupMatch = $denyGroup | Where-Object { $ADGroupSet.Contains($_) }
            $denyVarsMatch = $denyVars | Where-Object { $ADVarSet.Contains($_) }
            
            $allowGroupMatch = $hasAllowGroup -and $allowedGroups
            $allowVarsMatch = $hasAllowVars -and $allowedVars
            
            $allowDecision =
            # nothing specified -> include
            (-not $hasAllowGroup -and -not $hasAllowVars) -or
            # if allow_group is specified, it must match
            # if allow_vars is specified, it must match
            # both must be satisfied if both are specified
            ((-not $hasAllowGroup -or $allowGroupMatch) -and 
            (-not $hasAllowVars -or $allowVarsMatch))
            
            $allowDecision -and -not ($denyGroupMatch -or $denyVarsMatch)
        }
    }
}


# ============================================
# PESTER TESTS FOR Invoke-AllowDenyFilter
# ============================================

Describe "Invoke-AllowDenyFilter" {
    
    BeforeAll {
        $Groups = @('Group1', 'Group2', 'Group3')
        $Variables = @('Var1', 'Var2', 'Var3')
    }
    
    Context "Allow/Deny Criteria" {
        
        It "Should include policy with no allow/deny criteria" {
            $policy = [PSCustomObject]@{
                id          = "Test1-1"
                allow_group = @()
                deny_group  = @()
                allow_vars  = @()
                deny_vars   = @()
                description = "No criteria specified"
            }
            $result = $policy | Invoke-AllowDenyFilter -Groups $Groups -Variables $Variables
            $result | Should -Not -BeNullOrEmpty
            $result.id | Should -Be "Test1-1"
        }
        
        It "Should include policy with matching allow_group" {
            $policy = [PSCustomObject]@{
                id          = "Test2-1"
                allow_group = @('Group2')
                deny_group  = @()
                allow_vars  = @()
                deny_vars   = @()
            }
            $result = $policy | Invoke-AllowDenyFilter -Groups $Groups -Variables $Variables
            $result | Should -Not -BeNullOrEmpty
            $result.id | Should -Be "Test2-1"
        }
        
        It "Should exclude policy with non-matching allow_group" {
            $policy = [PSCustomObject]@{
                id          = "Test3-1"
                allow_group = @('NonExistentGroup')
                deny_group  = @()
                allow_vars  = @()
                deny_vars   = @()
            }
            $result = $policy | Invoke-AllowDenyFilter -Groups $Groups -Variables $Variables
            $result | Should -BeNullOrEmpty
        }
        
        It "Should include policy with matching allow_vars" {
            $policy = [PSCustomObject]@{
                id          = "Test4-1"
                allow_group = @()
                deny_group  = @()
                allow_vars  = @('Var2')
                deny_vars   = @()
            }
            $result = $policy | Invoke-AllowDenyFilter -Groups $Groups -Variables $Variables
            $result | Should -Not -BeNullOrEmpty
            $result.id | Should -Be "Test4-1"
        }
        
        It "Should exclude policy with non-matching allow_vars" {
            $policy = [PSCustomObject]@{
                id          = "Test5-1"
                allow_group = @()
                deny_group  = @()
                allow_vars  = @('NonExistentVar')
                deny_vars   = @()
            }
            $result = $policy | Invoke-AllowDenyFilter -Groups $Groups -Variables $Variables
            $result | Should -BeNullOrEmpty
        }
    }
    
    Context "Combined Allow Criteria" {
        
        It "Should include policy when both allow_group AND allow_vars match" {
            $policy = [PSCustomObject]@{
                id          = "Test6-1"
                allow_group = @('Group3')
                deny_group  = @()
                allow_vars  = @('Var1')
                deny_vars   = @()
            }
            $result = $policy | Invoke-AllowDenyFilter -Groups $Groups -Variables $Variables
            $result | Should -Not -BeNullOrEmpty
            $result.id | Should -Be "Test6-1"
        }
        
        It "Should exclude policy when both criteria specified but only allow_group matches" {
            $policy = [PSCustomObject]@{
                id          = "Test7-1"
                allow_group = @('Group2')
                deny_group  = @()
                allow_vars  = @('NonExistentVar')
                deny_vars   = @()
            }
            $result = $policy | Invoke-AllowDenyFilter -Groups $Groups -Variables $Variables
            $result | Should -BeNullOrEmpty
        }
        
        It "Should exclude policy when both criteria specified but only allow_vars matches" {
            $policy = [PSCustomObject]@{
                id          = "Test8-1"
                allow_group = @('NonExistentGroup')
                deny_group  = @()
                allow_vars  = @('Var3')
                deny_vars   = @()
            }
            $result = $policy | Invoke-AllowDenyFilter -Groups $Groups -Variables $Variables
            $result | Should -BeNullOrEmpty
        }
    }
    
    Context "Deny Criteria" {
        
        It "Should exclude policy when deny_group matches" {
            $policy = [PSCustomObject]@{
                id          = "Test9-1"
                allow_group = @()
                deny_group  = @('Group1')
                allow_vars  = @()
                deny_vars   = @()
            }
            $result = $policy | Invoke-AllowDenyFilter -Groups $Groups -Variables $Variables
            $result | Should -BeNullOrEmpty
        }
        
        It "Should exclude policy when deny_vars matches" {
            $policy = [PSCustomObject]@{
                id          = "Test10-1"
                allow_group = @()
                deny_group  = @()
                allow_vars  = @()
                deny_vars   = @('Var2')
            }
            $result = $policy | Invoke-AllowDenyFilter -Groups $Groups -Variables $Variables
            $result | Should -BeNullOrEmpty
        }
        
        It "Should exclude policy when allow matches but deny_group also matches" {
            $policy = [PSCustomObject]@{
                id          = "Test11-1"
                allow_group = @('Group2')
                deny_group  = @('Group1')
                allow_vars  = @()
                deny_vars   = @()
            }
            $result = $policy | Invoke-AllowDenyFilter -Groups $Groups -Variables $Variables
            $result | Should -BeNullOrEmpty
        }
        
        It "Should exclude policy when allow matches but deny_vars also matches" {
            $policy = [PSCustomObject]@{
                id          = "Test12-1"
                allow_group = @()
                deny_group  = @()
                allow_vars  = @('Var1')
                deny_vars   = @('Var3')
            }
            $result = $policy | Invoke-AllowDenyFilter -Groups $Groups -Variables $Variables
            $result | Should -BeNullOrEmpty
        }
    }
    
    Context "Multiple Values" {
        
        It "Should include policy with multiple allow_groups where at least one matches" {
            $policy = [PSCustomObject]@{
                id          = "Test13-1"
                allow_group = @('NonExistent1', 'Group3', 'NonExistent2')
                deny_group  = @()
                allow_vars  = @()
                deny_vars   = @()
            }
            $result = $policy | Invoke-AllowDenyFilter -Groups $Groups -Variables $Variables
            $result | Should -Not -BeNullOrEmpty
            $result.id | Should -Be "Test13-1"
        }
        
        It "Should exclude policy with multiple deny_groups where at least one matches" {
            $policy = [PSCustomObject]@{
                id          = "Test14-1"
                allow_group = @()
                deny_group  = @('NonExistent1', 'Group2', 'NonExistent2')
                allow_vars  = @()
                deny_vars   = @()
            }
            $result = $policy | Invoke-AllowDenyFilter -Groups $Groups -Variables $Variables
            $result | Should -BeNullOrEmpty
        }
    }
    
    Context "Case Insensitivity" {
        
        It "Should match groups and vars case-insensitively" {
            $policy = [PSCustomObject]@{
                id          = "Test15-1"
                allow_group = @('group2', 'group3')
                deny_group  = @()
                allow_vars  = @('var1', 'var3')
                deny_vars   = @()
            }
            $result = $policy | Invoke-AllowDenyFilter -Groups $Groups -Variables $Variables
            $result | Should -Not -BeNullOrEmpty
            $result.id | Should -Be "Test15-1"
        }
    }
    
    Context "Complex Scenarios" {
        
        It "Should include policy with multiple allow values and no deny matches" {
            $policy = [PSCustomObject]@{
                id          = "Test16-1"
                allow_group = @('Group2', 'Group3')
                deny_group  = @('GuestGroup')
                allow_vars  = @('Var1')
                deny_vars   = @()
            }
            $result = $policy | Invoke-AllowDenyFilter -Groups $Groups -Variables $Variables
            $result | Should -Not -BeNullOrEmpty
            $result.id | Should -Be "Test16-1"
        }
        
        It "Should exclude policy when allow matches but deny_group matches" {
            $policy = [PSCustomObject]@{
                id          = "Test16-2"
                allow_group = @('Group2')
                deny_group  = @('Group1')
                allow_vars  = @('Var2')
                deny_vars   = @()
            }
            $result = $policy | Invoke-AllowDenyFilter -Groups $Groups -Variables $Variables
            $result | Should -BeNullOrEmpty
        }
        
        It "Should exclude policy when allow matches but deny_vars matches" {
            $policy = [PSCustomObject]@{
                id          = "Test16-3"
                allow_group = @('Group2')
                deny_group  = @()
                allow_vars  = @('Var1')
                deny_vars   = @('Var3')
            }
            $result = $policy | Invoke-AllowDenyFilter -Groups $Groups -Variables $Variables
            $result | Should -BeNullOrEmpty
        }
    }
    
    Context "Batch Processing" {
        
        It "Should filter multiple policies correctly" {
            $policies = @(
                [PSCustomObject]@{
                    id          = "Batch-1"
                    allow_group = @('Group2')
                    deny_group  = @()
                    allow_vars  = @()
                    deny_vars   = @()
                },
                [PSCustomObject]@{
                    id          = "Batch-2"
                    allow_group = @('NonExistent')
                    deny_group  = @()
                    allow_vars  = @()
                    deny_vars   = @()
                },
                [PSCustomObject]@{
                    id          = "Batch-3"
                    allow_group = @()
                    deny_group  = @()
                    allow_vars  = @('Var1')
                    deny_vars   = @()
                }
            )
            $result = $policies | Invoke-AllowDenyFilter -Groups $Groups -Variables $Variables
            $result | Should -HaveCount 2
            $result.id | Should -Contain "Batch-1"
            $result.id | Should -Contain "Batch-3"
            $result.id | Should -Not -Contain "Batch-2"
        }
    }
}

# Invoke-Pester "/home/rslsync/Resilio Sync/Powershell/Modules/1_File/test.ps1" -Output Detailed