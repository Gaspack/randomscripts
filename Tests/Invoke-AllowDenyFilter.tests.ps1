
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