# HelloID-Conn-SA-Sync-ActiveDirectory-Groups-To-SelfService-Products

| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.       |

## Table of Contents
- [HelloID-Conn-SA-Sync-ActiveDirectory-Groups-To-SelfService-Products](#helloid-conn-sa-sync-activedirectory-groups-to-selfservice-products)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Getting started](#getting-started)
    - [Prerequisites](#prerequisites)
      - [Create an API key and secret](#create-an-api-key-and-secret)
    - [Synchronization settings](#synchronization-settings)
  - [Remarks](#remarks)
  - [Getting help](#getting-help)
  - [HelloID Docs](#helloid-docs)

## Introduction

By using this connector, you will have the ability to create and remove HelloID SelfService Products based on groups in your local Active Directory.

The products will be create for each group in scope. This way you won't have to manually create a product for each group.

And vice versa for the removing of the products. The products will be removed (or disabled, based on your preference) when a group is nog longer in scope. This way no products will remain that "should no longer exist".

This is intended for scenarios where there are (lots of) groups that we want to be requestable as a product. This group sync is desinged to work in combination with the [ActiveDirectory Groupmembersips to Productassignments Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groupmemberships-To-SelfService-Productassignments).

## Getting started

### Prerequisites

- [ ] Make sure you have Windows PowerShell 5.1 installed on the server where the HelloID agent and Service Automation agent are running.

- [ ] Make sure you have installed the PowerShell [ActiveDirectory](https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps) module.

- [ ] Make sure the sychronization is configured to meet your requirements.


#### Create an API key and secret

1. Go to the `Manage portal > Security > API` section.
2. Click on the `Add Api key` button to create a new API key.
3. Optionally, you can add a note that will describe the purpose of this API key
4. Optionally, you can restrict the IP addresses from which this API key can be used.
5. Click on the `Save` button to save the API key.
6. Go to the `Manage portal > Automation > Variable library` section and confim that the auto variables specified in the [connection settings](#connection-settings) are available.

### Synchronization settings

| Variable name | Description   | Notes |
| ------------- | -----------   | ----- |
| $portalBaseUrl    | String value of HelloID Base Url  | (Default Global Variable) |
| $portalApiKey | String value of HelloID Api Key   | (Default Global Variable) |
| $portalApiSecret  | String value of HelloID Api Secret    | (Default Global Variable) |
| $ADGroupsFilter   | String value of filter of which AD groups to include   | Optional, when no filter is provided ($ADGroupsFilter = "*"), all groups will be queried  |
| $ADGroupsOUs  | Array of string values of which AD OUs to include in search for groups | Optional, when no OUs are provided ($ADGroupsOUs = @()), all ous will be queried  |
| $ProductAccessGroup  | String value of which HelloID group will have access to the products | Optional, if not found, the product is created without Access Group  |
| $ProductCategory  | String value of which HelloID category will be used for the products | Required, must be an existing category if not found, the task will fail  |
| $useADManagedByGroupAsResourceOwner  | Boolean value of whether to use the AD "ManagedBy" as resource owner for the products | Optional, can only be used when the "ManagedBy" is a group, does not work for user  |
| $SAProductResourceOwner  | String value of which HelloID group to use as resource owner for the products | Optional, if empty the groupname will be: "Resource owners [target-systeem] - [Product_Naam]")  |
| $SAProductWorkflow  | String value of which HelloID Approval Workflow to use for the products | Optional, if empty. The Default HelloID Workflow is used. If specified Workflow does not exist the task will fail  |
| $FaIcon  | String value of which Font Awesome icon to use for the products | For more valid icon names, see the Font Awesome cheat sheet [here](https://fontawesome.com/v5/cheatsheet)  |
| $productVisibility  | String value of which Visbility to use for the products | Supported values: All, Resource Owner And Manager, Resource Owner, Disabled. For more information, see the HelloID Docs [here](https://docs.helloid.com/en/service-automation/products/product-settings-reference.html)  |
| $productRequestCommentOption  | String value of which Comment Option to use for the products | Supported values: Optional, Hidden, Required. For more information, see the HelloID Docs [here](https://docs.helloid.com/en/service-automation/products/product-settings-reference.html)  |
| $returnProductOnUserDisable  | Boolean value of whether to set the option Return Product On User Disable for the products | For more information, see the HelloID Docs [here](https://docs.helloid.com/en/service-automation/products/product-settings-reference.html)  |
| $createDefaultEmailActions  | Boolean value of whether to set the option Create Default Email Action for the products | For more information, see the HelloID Docs [here](https://docs.helloid.com/en/service-automation/products/product-settings-reference.html)  |
| $multipleRequestOption  | Integer value of which option of Multiple Requests to use for the products | Supported values: 1, 2.For more information, see the HelloID Docs [here](https://docs.helloid.com/en/service-automation/products/product-settings-reference.html)  |
| $removeProduct  | Boolean value of whether to remove the products when they are no longer in scope | If set to $false, obsolete products will be disabled  |
| $overwriteExistingProduct  | Boolean value of whether to overwrite existing products in scope with the specified properties of this task | **Only meant for when you changed something in the product properties (e.g. the description, approval worklow or icon) and need to update this for all products in scope, should not be set to true when running daily!**  |
| $overwriteExistingProductAction  | Boolean value of whether to overwrite existing actions of products in scope with the specified actions of this task | **Only meant for when you changed something in the product actions and need to update this for all products in scope, should not be set to true when running daily!**  |
| $addMissingProductAction  | Boolean value of whether to add the missing specified actions of this task to existing products in scope | **Only meant when you **Only meant for when you changed the product actions and need to add this to all products in scope, should not be set to true when running daily!**  |
| $ProductSkuPrefix | String value of prefix that will be used in the Code for the products | Optional, but recommended, when no SkuPrefix is provided the products won't be recognizable as created by this task |
| $adGroupUniqueProperty   | String value of name of the property that is unique for the AD groups and will be used in the Code for the products | The default value ("objectGUID") is set be as unique as possible   |

## Remarks
- The Products are created and removed by default. Make sure your configuration is correct to avoid unwanted removals (and change this to disable)
- This group sync is desinged to work in combination with the [ActiveDirectory Groupmembersips to Productassignments Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groupmemberships-To-SelfService-Productassignments).

## Getting help
> _For more information on how to configure a HelloID PowerShell scheduled task, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/115003253294-Create-Custom-Scheduled-Tasks) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/