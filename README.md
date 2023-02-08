# HelloID-Conn-SA-Sync-ActiveDirectory-Groups-To-SelfService-Products

| :warning: Warning |
|:---------------------------|
| Note that this HelloID connector has not been tested in a production environment! |

## Table of Contents
- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
- [Getting started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Connection settings](#connection-settings)
    - [Create an API key and secret](#create-an-api-key-and-secret)
  - [Synchronization settings](#synchronization-settings)
- [Remarks](#remarks)
  - [Large JSON](#large-json)
- [Getting help](#getting-help)
- [HelloID Docs](#helloid-docs)

## Introduction

By using this connector, you will have the ability to create HelloId SelfService Products based on groups in your local Active Directory.

The sync task creates one self-service product per Active Directory group in the specified `Organizational Unit`. Each created product contains a `Change AD group membership` task which grants membership to the respective AD group on product approval, and another one which revokes membership on product return.

## Getting started

### Prerequisites

- [ ] Make sure you have Windows PowerShell 5.1 installed on the server where the HelloID agent and Service Automation agent are running.

- [ ] Make sure the sychronization is configured to meet your requirements.

- [ ] Make sure you have installed the PowerShell [ActiveDirectory](https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps) module.

### Connection settings

The connection settings are defined as automation variables within your HelloID portal. See also: https://docs.helloid.com/hc/en-us/articles/360001925134

| Variable name  	| Description	|
|---	|---	|
| portalBaseUrl| The URL to your HelloID portal|
| portalApiKey|  The portal API key 	|
| portalApiSecret| THe portal API secret|

#### Create an API key and secret

1. Go to the `Manage portal > Security > API` section.
2. Click on the `Add Api key` button to create a new API key.
3. Optionally, you can add a note that will describe the purpose of this API key
4. Optionally, you can restrict the IP addresses from which this API key can be used.
5. Click on the `Save` button to save the API key.
6. Go to the `Manage portal > Automation > Variable library` section and confim that the auto variables specified in the [connection settings](#connection-settings) are available.

### Synchronization settings

Task Settings | Name | Description | Example | Comment
--- | --- | --- | --- | ---
Prefix of product name | This string will be added at the beginning of each new product's name. | AD Sync Group | For example, if you have a group called "Accounting", and you provide a prefix of "AD Sync Group", the new product name would be "AD Sync Group Accounting". If a prefix is specified, this task will overwrite products with the same name. If no prefix is specified, this task will not overwrite products with the same name.
Prefix of product description | This string will be added at the beginning of each new product's description | AD Sync Group Description | This value must be set for consistent operation.
FA-Icon name | The name of the Font Awesome icon that will be associated with the new product. | group | For more valid icon names, see the Font Awesome cheat sheet [here](https://fontawesome.com/v5/cheatsheet).
HelloID product category | The name of the category to which the product will be associated. If no category of this name exists, a new one will be created. | General | Learn more about product categories here.
HelloID Approval Workflow | The name of the workflow that will be launched when a user requests the product. | Auto Approve | Learn more about approval workflows here.
Resource owner group | The name of the HelloID group whose members will be owners of this product, if the AD group does not have a manager. | Admins |
The Active Directory OU path | The base OU path in which HelloID should search for groups, specified as the distinguished name. | OU=groups,DC=enyoi,DC=local |
The Active Directory search filter | You may filter the resulting groups by their name. (Optional) | *HelloID* | Use an asterisk as a wildcard character in your filter. In the example of "*HelloID*", the filter will match any group that contains the string "HelloID".
Remove product if group does not exist | Every time this task runs, any products with the specified Prefix of product name will be deleted, if the corresponding group no longer exists in AD. |  |
Return on user disable | Whether the product will be returned when a user that it's assigned to gets disabled |  |
Request comment option | Whether a comment is optional, required or not possible when requesting |  |

## Remarks

### Large JSON

In rare cases you might encounter a problem when deserializing a large JSON and turn it into a PowerShell object. In these rare cases you will receive an error like: ``

```powershell
Exception calling "DeserializeObject" with "1" argument(s): "Error during serialization or deserialization using the JSON JavaScriptSerializer. The length of the string exceeds the value set on the maxJsonLength property. Parameter name: input"
```

This can be solved by using the `System.Web.Script.Serialization.JavaScriptSerializer` class to deserialize the JSON.

```powershell
# Create a new instance of the JavaScriptSerializer class
$serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer

# Deserialize the JSON string into a custom object
$deserializedObject = $serializer.DeserializeObject($json)
```

## Getting help
> _For more information on how to configure a HelloID PowerShell scheduled task, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/115003253294-Create-Custom-Scheduled-Tasks) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
