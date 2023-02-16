#####################################################
# HelloID-SA-Sync-ADGroups-To-Products
#
# Version: 1.0.0
#####################################################
$VerbosePreference = 'SilentlyContinue'
$InformationPreference = 'Continue'

# Configuration

    # Mandatory parameters
    $ProductCategory           = ''
    $OUPath                    = ''
    $Filter                    = ''
    $DefaultResourceOwnerGroup = ''

    # Optional parameters
    $NamePrefix                = ''
    $DescriptionPrefix         = ''
    $FaIcon                    = ''
    $ApprovalWorkflow          = ''
    $RemoveProduct             = ''
    ReturnOnUserDisable        = ''
    RequestCommentOption       = ''

#region HelloID functions
function Get-HIDDefaultAgentPool {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003036494-GET-Get-agent-pools
    #>
    [CmdletBinding()]
    param ()

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'GET'
            Uri    = 'agentpools'
        }
        $result = Invoke-HIDRestMethod @splatParams
        Write-Output $result | Where-Object { $_.options -eq '1' }
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-HIDSelfServiceCategory {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003036194-GET-Get-self-service-categories
    #>
    [CmdletBinding()]
    param ()

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'GET'
            Uri    = 'selfservice/categories'
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function New-HIDSelfServiceCategory {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003024773-POST-Create-self-service-category
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Name,

        [bool]
        $IsEnabled,

        [bool]
        $IsAutoDeny = $true,

        [bool]
        $IsAutoApprove = $false,

        [int]
        $AutomaticallyHandleAfterDays = 0
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $category = [ordered]@{
            'name'                         = $Name
            'isEnabled'                    = $IsEnabled
            'autoDeny'                     = $IsAutoDeny
            'autoApprove'                  = $IsAutoApprove
            'AutomaticallyHandleAfterDays' = $AutomaticallyHandleAfterDays
        } | ConvertTo-Json

        $splatParams = @{
            Method = 'POST'
            Uri    = 'selfservice/categories'
            Body   = $category
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-HIDSelfServiceProduct {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003027353-GET-Get-products
    #>
    [CmdletBinding()]
    param ()

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method   = 'GET'
            Uri      = 'selfservice/products'
            PageSize = 50
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function New-HIDSelfServiceProduct {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003024773-POST-Create-self-service-category
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Name,

        [string]
        $Description,

        [string]
        $ManagedByGroupGUID,

        [string]
        $Category,

        [string]
        $ApprovalWorkFlowName,

        [string]
        $AgentPoolGUID,

        [string]
        $Icon,

        [string]
        $FaIcon,

        [bool]
        $UseFaIcon,

        [int]
        $MultipleRequestOption,

        [bool]
        $IsEnabled,

        [bool]
        $IsAutoDeny,

        [bool]
        $IsAutoApprove,

        [bool]
        $IsCommentable,

        [bool]
        $HasTimeLimit,

        [string]
        $LimitType,

        [bool]
        $ManagerCanOverrideDuration,

        [int]
        $ReminderTimeOut,

        [int]
        $OwnerShipMaxDuration,

        [bool]
        $CreateDefaultEmailActions
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $product = @{
            'name'                       = $Name
            'description'                = $Description
            'managedByGroupGUID'         = $ManagedByGroupGUID
            'category'                   = $Category
            'approvalWorkflowName'       = $ApprovalWorkFlowName
            'agentPoolGUID'              = $AgentPoolGUID
            'icon'                       = $Icon
            'faIcon'                     = "fa-$FaIcon"
            'useFaIcon'                  = $UseFaIcon
            'multipleRequestOption'      = $MultipleRequestOption
            'isEnabled'                  = $IsEnabled
            'isAutoApprove'              = $IsAutoApprove
            'isAutoDeny'                 = $IsAutoDeny
            'isCommentable'              = $IsCommentable
            'hasTimeLimit'               = $HasTimeLimit
            'limitType'                  = $LimitType
            'managerCanOverrideDuration' = $ManagerCanOverrideDuration
            'reminderTimeout'            = $ReminderTimeOut
            'ownershipMaxDuration'       = $OwnerShipMaxDuration
            'createDefaultEmailActions'  = $CreateDefaultEmailActions
        } | ConvertTo-Json

        $splatParams = @{
            Method = 'POST'
            Uri    = 'selfservice/products'
            Body   = $product
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Remove-HIDProduct {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003038654-DELETE-Delete-product
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $ProductGUID
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        if ($resourceGroup) {
            $GroupName = "$GroupName Resource Owners"
        }
        $splatParams = @{
            Method = 'DELETE'
            Uri    = "selfservice/products/$ProductGUID"
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-HIDGroup {
    <#
    .DESCRIPTION
       https://docs.helloid.com/hc/en-us/articles/115002981813-GET-Get-specific-group
    #>
    [Cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $GroupName,

        [switch]
        $resourceGroup
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        if ($resourceGroup) {
            $GroupName = "$GroupName Resource Owners"
        }
        $splatParams = @{
            Method = 'GET'
            Uri    = "groups/$groupname"
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        if ($_.ErrorDetails.Message -match 'Group not found') {
            return $null
        }
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function New-HIDGroup {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115002956413-POST-Create-a-group
    #>
    [Cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $Name,

        [string[]]
        $UserNames,

        [bool]
        $IsEnabled
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $group = @{
            name      = $Name
            isEnabled = $IsEnabled
            userNames = @($UserNames)
        } | ConvertTo-Json

        $splatParams = @{
            Method = 'POST'
            Uri    = 'groups'
            Body   = $group
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function New-HIDGroupMemberAction {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $GroupName,

        [Parameter(Mandatory)]
        [string]
        $GroupSID,

        [Parameter(Mandatory)]
        [string]
        $Type,

        [Parameter(Mandatory)]
        [string]
        $SelfServiceGuid
    )

    try {
        switch ($Type){
            'Add-ADGroupMember' {
                $body = @{
                    executeOnState = 3
                    variables = @(
                        @{
                            'name'           = 'groupName'
                            'value'          = $GroupName
                            'typeConstraint' = 'string'
                            'secure'         = $false
                        },
                        @{
                            'name'           = 'groupSid'
                            'value'          = $GroupSID
                            'typeConstraint' = 'string'
                            'secure'         = $false
                        },
                        @{
                            'name'           = 'domain'
                            'value'          = '{{company.defaultAdDomain}}'
                            'typeConstraint' = 'string'
                            'secure'         = $false
                        },
                        @{
                            'name'           = 'addMembership'
                            'value'          = $true
                            'typeConstraint' = 'boolean'
                            'secure'         = $false
                        },
                        @{
                            'name'           = 'userSid'
                            'value'          = '{{requester.immutableId}}'
                            'typeConstraint' = 'string'
                            'secure'         = $false
                        }
                    )
                }
            }
            'Remove-ADGroupMember' {
                $body = @{
                    executeOnState = 11
                    variables = @(
                        @{
                            'name'           = 'groupName'
                            'value'          = $GroupName
                            'typeConstraint' = 'string'
                            'secure'         = $false
                        },
                        @{
                            'name'           = 'groupSid'
                            'value'          = $GroupSID
                            'typeConstraint' = 'string'
                            'secure'         = $false
                        },
                        @{
                            'name'           = 'domain'
                            'value'          = '{{company.defaultAdDomain}}'
                            'typeConstraint' = 'string'
                            'secure'         = $false
                        },
                        @{
                            'name'           = 'addMembership'
                            'value'          = $false
                            'typeConstraint' = 'boolean'
                            'secure'         = $false
                        },
                        @{
                            'name'           = 'userSid'
                            'value'          = '{{requester.immutableId}}'
                            'typeConstraint' = 'string'
                            'secure'         = $false
                        }
                    )
                }
            }
        }

        $splatParams = @{
            Method = 'POST'
            Uri    = "products/$SelfServiceGuid/adgroupmemberaction"
            Body   = $body | ConvertTo-Json
        }
        $null = Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Add-HIDGroupToUser {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115002954493-POST-Link-group-to-member
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $GroupName,

        [Parameter(Mandatory)]
        $UserName
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $group = @{
            name = $GroupName
        } | ConvertTo-Json

        $splatParams = @{
            Method = 'POST'
            Uri    = "users/$UserName/groups"
            Body   = $group
        }
        $null = Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Add-HIDGroupToGroup {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115002954493-POST-Link-group-to-member
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $GroupName,

        [Parameter(Mandatory)]
        $ResourceOwnerGroup
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $group = @{
            groupGUID = $($ResourceOwnerGroup.groupGuid)
        } | ConvertTo-Json

        $splatParams = @{
            Method = 'POST'
            Uri    = "groups/$GroupName/membergroups"
            Body   = $group
        }
        $null = Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Invoke-HIDRestMethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Method,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Uri,

        [Parameter()]
        [object]
        $Body,

        [Parameter()]
        [string]
        $ContentType = 'application/json',

        [Parameter()]
        [int]
        $PageSize
    )

    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

        $apiKeySecret = "$($portalApiKey):$($portalApiSecret)"
        $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($apiKeySecret))
        $headers = [System.Collections.Generic.Dictionary[[String],[String]]]::new()
        $headers.Add('Authorization', "Basic $base64")
        $headers.Add('Content-Type', $ContentType)

        $splatParams = @{
            Uri     = "$portalBaseUrl/api/v1/$Uri"
            Headers = $headers
            Method  = $Method
        }

        if ($Body) {
            $splatParams['Body'] = $Body
        }

        if ($PageSize){
            $objectList = [System.Collections.Generic.List[object]]::new()
            $take = $PageSize
            $skip = 0

            $splatParams['Uri'] = "$portalBaseUrl/api/v1/$Uri" + "?skip=$skip&take=$take"
            $splatParams['Method'] = 'GET'
            $responseObject = Invoke-RestMethod @splatParams
            $objectList.Add($responseObject)
            $skip += $take
            while($responseObject.Count -eq $take){
                $splatParams['Uri'] = "$portalBaseUrl/api/v1/$Uri" + "?skip=$skip&take=$take"
                $responseObject = Invoke-RestMethod @splatParams
                $skip += $take
                $objectList.AddRange($responseObject)
            }
            $results = $objectList
        } else {
            $results = Invoke-RestMethod @splatParams
        }

        Write-Output $results
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
#endregion HelloID functions

#region Helper functions
function Disable-HIDProduct {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]
        $Product
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"

        $Product.isEnabled = $false
        $body = ConvertTo-Json ($product | Select-Object -Property * -ExcludeProperty Code)
        $splatParams = @{
            Method = 'POST'
            Uri    = 'selfservice/products'
            Body   = ([System.Text.Encoding]::UTF8.GetBytes($body))
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Confirm-HIDGroup {
    <#
        Verifies if the group exists and creates it if it does not
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $GroupName
    )

    $group = Get-HIDGroup -GroupName $groupName
    if ($null -eq $group){
        HID-Write-Status -Message "Creating new group: [$groupName]" -Event Information
        $splatParams = @{
            name      = $groupName
            isEnabled = $true
        }
        New-HIDGroup @splatParams
        HID-Write-Status -Message "Finished creating group: [$groupName]" -Event Information
    }
}

function Invoke-GetADGroup {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]
        $SearchBase,

        [Parameter()]
        [string]
        $Filter
    )

    try{
        if($SearchBase -and $Filter){
            $groups = Get-ADGroup -Filter {name -like $Filter} -SearchBase $SearchBase -Properties isCriticalSystemObject,managedby
        } elseif($SearchBase -and !$Filter){
            $groups = Get-ADGroup -Filter * -SearchBase $SearchBase -Properties isCriticalSystemObject,managedby
        } elseif(!$SearchBase -and $Filter){
            $groups = Get-ADGroup -Filter {name -like $Filter} -Properties isCriticalSystemObject,managedby
        }

        $results = [System.Collections.Generic.List[object]]@()
        foreach($group in $groups){
            if(!$($group.managedBy)){
                $manager = ''
            } else {
                $manager = Get-ADUser -Identity "$($group.managedBy)" -Properties * | Select-Object UserPrincipalName
            }

            $object = [ordered]@{
                Name    = $($group.Name)
                DN      = $($group.DistinguishedName)
                Sid     = $($group.sid)
                Manager = $($manager.UserPrincipalName)
                Members = $($group.members)
            }
            $results.Add($object)
        }

        Write-Output $results
    } catch {
        throw "Could not retrieve Active Directory groups. Error: $($_.Exception.Message)"
    }
}
#endregion Helper functions

#region script
try {
    [int]$successCount = 0
    [int]$failedCount = 0

    HID-Write-Status -Message 'Importing the PowerShell Active Directory module' -Event 'Information'
    Import-Module -Name ActiveDirectory -ErrorAction Stop

    HID-Write-Status -Message 'Retrieving HelloID default agent pool' -Event 'Information'
    $defaultAgentPool = Get-HIDDefaultAgentPool
    if (!$defaultAgentPool) {
        throw 'No agent pool has been marked as default. Please make sure to set the default agent pool in the HelloID portal'
    }

    HID-Write-Status -Message 'Retrieving SelfService categories' -Event 'Information'
    $selfServiceCategories = Get-HIDSelfServiceCategory
    $activeCategory = $selfServiceCategories | Where-Object { $_.isEnabled -eq $true -and $_.name -eq $ProductCategory }
    if ($activeCategory){
        HID-Write-Status -Message "Creating products for SelfService category: [$($activeCategory.name)]" -Event 'Information'
    } elseif (-not($activeCategory)){
        HID-Write-Status -Message "No SelfService categories have been found. Creating: [$ProductCategory]" -Event 'Information'
        $splatCreateCategoryParams = @{
            'Name'                         = $ProductCategory
            'IsEnabled'                    = $true
            'AutoDeny'                     = $true
            'AutoApprove'                  = $false
            'AutomaticallyHandleAfterDays' = 0
        }
        New-HIDSelfServiceCategory @splatCreateCategoryParams
    } else {
        $ProductCategory = $($activeCategory.name)
    }

    HID-Write-Status -Message 'Retrieving SelfService products' -Event Information
    $collProducts = Get-HIDSelfServiceProduct
    if ($collProducts.Count -eq 0) {
        HID-Write-Status -Message 'No SelfService products have been found' -Event Information
    } else {
        $products = $collProducts
        HID-Write-Status -Message "Found: [$($products.Count)] SelfService product(s)" -Event Information
    }

    HID-Write-Status -Message 'Retrieving Active Directory groups' -Event 'Information'
    $activeDirectoryGroups = Invoke-GetADGroup -SearchBase $OUPath -Filter $Filter
    foreach ($adGroup in $activeDirectoryGroups){
        $groupManager = $($adGroup.manager)
        $groupSID = $($adGroup.Sid)
        $groupName = $($adGroup.name)

        if (-not($groupManager)) {
            $groupManager = $defaultResourceOwnerGroup
            HID-Write-Status -Message "Group manager for AD group: [$groupName] is not specified. Switching to the default manager: [$DefaultManager]" -Event Information
        }

        $productName = ("$NamePrefix $groupName").trim(' ')
        $product = $products | Where-Object { $_.name -eq $productName }
        if (!$product) {
            try {
                $resourceOwnerGroup = Confirm-HIDGroup -GroupName $groupManager
            } catch {
                $failedCount++
                throw "Could not create resource owner group for new HelloID Product: [$productName]. Error: $($_.Exception.Message)"
            }

            try {
                HID-Write-Status -Message "Creating new product: [$productName]" -Event Information
                $newProductParams = @{
                    Name                        = $productName
                    Description                 = ("$DescriptionPrefix $groupName").trim(' ')
                    ManagedByGroupGUID          = $($resourceOwnerGroup.groupGuid)
                    Category                    = $ProductCategory
                    ApprovalWorkflowName        = $ApprovalWorkflow
                    AgentPoolGUID               = ''
                    Icon                        = $null
                    FaIcon                      = $FaIcon
                    UseFaIcon                   = $true
                    MultipleRequestOption       = 1
                    IsEnabled                   = $true
                    IsAutoApprove               = $false
                    IsAutoDeny                  = $false
                    IsCommentable               = $true
                    HasTimeLimit                = $false
                    LimitType                   = 'Fixed'
                    ManagerCanOverrideDuration  = $true
                    ReminderTimeout             = 30
                    OwnershipMaxDuration        = 90
                    CreateDefaultEmailActions   = $true
                    ReturnOnUserDisable         = $ReturnOnUserDisable
                    RequestCommentOption        = $RequestCommentOption
                }
                $newSelfServiceProduct = New-HIDSelfServiceProduct @newProductParams
                $selfServiceGuid = $newSelfServiceProduct.selfserviceproductguid

                try {
                    HID-Write-Status -Message "Adding action: [Add-ADGroupMember] to: [$productName]" -Event Information
                    $splatCreateADGroupMemberActions = @{
                        Name            = $groupName
                        GroupSID        = $groupSID
                        Type            = 'Add-ADGroupMember'
                        SelfServiceGuid = $selfServiceGuid
                    }
                    New-HIDGroupMemberAction @splatCreateADGroupMemberActions
                    HID-Write-Status -Message "Added action: [Add-ADGroupMember] to: [$productName]" -Event Information
                } catch {
                    $ex = $_
                    $statusCode = [int]$_.Exception.Response.StatusCode
                    if ({$statusCode -eq 400} -or {$statusCode -eq 404}){
                        HID-Write-Status -Message "Could not add product action: [Add-ADGroupMember] to: [$productName], error: $($_.Exception.Message)" -Event Error
                        throw "Could not add product action: [Add-ADGroupMember] to: [$productName], error: $($_.Exception.Message)"
                    }
                    HID-Write-Status -Message "Could not add product action: [Add-ADGroupMember] to: [$productName], error: $($_.Exception.Message)" -Event Error
                }

                try {
                    HID-Write-Status -Message "Adding action: [Remove-ADGroupMember] to: [$productName]" -Event Information
                    $splatCreateADGroupMemberActions = @{
                        Name            = $groupName
                        GroupSID        = $groupSID
                        Type            = 'Remove-ADGroupMember'
                        SelfServiceGuid = $selfServiceGuid
                    }
                    New-HIDGroupMemberAction @splatCreateADGroupMemberActions
                    HID-Write-Status -Message "Added action: [Remove-ADGroupMember] to: [$productName]" -Event Information
                } catch {
                    $ex = $_
                    $statusCode = [int]$_.Exception.Response.StatusCode
                    if ({$statusCode -eq 400} -or {$statusCode -eq 404}){
                        HID-Write-Status -Message "Could not add product action: [Remove-ADGroupMember] to: [$productName], error: $($_.Exception.Message)" -Event Error
                        throw "Could not add product action: [Remove-ADGroupMember] to: [$productName], error: $($_.Exception.Message)"
                    }
                    HID-Write-Status -Message "Could not add product action: [Remove-ADGroupMember] to: [$productName], error: $($_.Exception.Message)" -Event Error
                }
            } catch {
                $failedCount++
                $ex = $_
                $statusCode = [int]$_.Exception.Response.StatusCode
                if ({$statusCode -eq 400} -or {$statusCode -eq 404}){
                    HID-Write-Status -Message "HelloID portal: [$portalBaseUri] returned code: [$statusCode]. This may be caused by an incorrect parameter or URI, please check the values you have specified" -Event Error
                    throw "Could not create HelloID Product: [$productName]. Error: $($_.Exception.Message)"
                }
                HID-Write-Status -Message "Could not create HelloID Product: [$productName]. Error: $($_.Exception.Message)" -Event Error
            }
            HID-Write-Status -Message "Successfully created product: [$productName] with the actions: [Add-ADGroupMember -state Approved] and: [Remove-ADGroup -state Returned]" -Event Success
            HID-Write-Summary -Message "Successfully created product: [$productName]" -Event Success
            $successCount++
        } else {
            try {
                $resourceOwnerGroupExisting = Confirm-HIDGroup -GroupName $defaultResourceOwnerGroup
                if ($($product.managedByGroupGUID) -eq $resourceOwnerGroupExisting.groupGuid) {
                    HID-Write-Status -Message "Resource owner group: [$($resourceOwnerGroupExisting.name)] already set as manager of product: '[$productName]" -Event Information
                } elseif(-not [string]::IsNullOrEmpty($($product.managedByGroupGUID))){
                    Add-HIDGroupToGroup -GroupName $($product.managedByGroupGUID) -ResourceOwnerGroup $resourceOwnerGroupExisting
                }
            } catch {
                $failedCount++
                throw "Could not add manager: [$groupManager] as member to resource owner group for: [$productName], error: $($_.Exception.Message)"
            }
            $successCount++
        }
    }

    if([string]::IsNullOrEmpty($NamePrefix)){
        HID-Write-Status -Message 'Skipping the removal or disable process of SelfService products. The variable: [NamePrefix] is not specified' -Event Warning
    } else {
        $availableProducts = $products | Where-Object{ $_.Name -match "$($NamePrefix) *"}
        $noADGroupOfSSPs = $availableProducts | Where-Object{($_.Name  -Replace "$($NamePrefix) " , "") -notin $activeDirectoryGroups.name -and $_.isEnabled -eq $true}

        $removeCounter = 0
        $disableCounter = 0
        foreach($item in $noADGroupOfSSPs){
            if($RemoveProduct){
                try{
                    HID-Write-Status -Message "Removing selfservice product $($item.name)" -Event Information
                    $null = Remove-HIDProduct -ProductGUID $($item.selfserviceProductGuid)
                    $removeCounter++
                } catch {
                    throw "Could not remove SelfService product: [$($item.name)], error: $($_.Exception.Message)"
                }
            } else {
                try{
                    HID-Write-Status -Message "Disabling SelfService product $($item.name)" -Event Information
                    $null = Disable-HIDProduct -Product $item
                    $disableCounter++
                } catch {
                    throw "Could not disable SelfService product: [$($item.name)], error: $($_.Exception.Message)"
                }
            }
        }
    }
    if($removeCounter -gt 0){
        HID-Write-Status -Message "Removed $($removeCounter) selfservice products of Active Directory groups which does not exists" -Event Information
    } elseif ($disableCounter -gt 0){
        HID-Write-Status -Message "Disabled $($disableCounter) selfservice products of Active Directory groups which does not exists" -Event Information
    }

    if($successCount -eq 0 -and $failedCount -ge 1){
        throw 'No Active Directory groups been synchronized to HelloID products'
    } elseif($successCount -eq 0 -and $failedCount -ge 0){
        HID-Write-Status -Message 'Successfully synchronized Active Directory groups to HelloID products' -Event Success
        HID-Write-Summary -Message 'Successfully synchronized Active Directory groups to HelloID products, no new products were created and no changes were made to existing products' -Event Success
    } else {
        HID-Write-Status -Message 'Successfully synchronized Active Directory groups to HelloID products' -Event Success
        HID-Write-Summary -Message "Successfully synchronized: [$successCount] Active Directory groups to HelloID products. [$failedCount] groups have not been synrhronized" -Event Success
    }
} catch {
    $ex = $_
    HID-Write-Status -Message "Could not synchronize Active Directory to HelloID products. Error: $($ex.Exception.Message)" -Event 'Failed'
    HID-Write-Summary -Message "Could not synchronize Active Directory to HelloID products. Error: $($ex.Exception.Message)" -Event 'Failed'
}
#endregion script
