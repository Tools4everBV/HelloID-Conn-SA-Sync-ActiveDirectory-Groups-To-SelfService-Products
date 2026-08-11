# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [3.0.1] - 2026-08-11

### Fixed

- **Action Preservation**: Fixed critical bug where product actions were incorrectly removed when updating product properties only (without action updates configured). Actions are now correctly preserved when `$updateReasons` does not contain "Actions", preventing accidental deletion of onApprove, onReturn, and other lifecycle actions during property-only updates.
- **Documentation Consistency**: Corrected outdated references from "Exchange Online Shared Mailboxes" to "Active Directory Groups" in comments and logging messages throughout the script (copy-paste errors from template)

### Changed

- Added `resourceOwnerGroup` to the example properties in `$productPropertiesToUpdate` configuration comment for better clarity on available options

## [3.0.0] - 2026-08-06

### Added

- **Test Run Mode**: Added test run settings to limit operations per type (creates, updates, deletes) for safer testing
- **Safety Thresholds with Smart Update Detection**: Configurable thresholds for create, update, and remove operations to prevent accidental mass changes. Update threshold intelligently applies only to products that actually have detected changes (properties, actions, or access groups), not all existing products. This significantly reduces unnecessary API calls and improves performance while maintaining safety controls.
- **Intelligent Change Detection and Comparison**: Complete comparison logic that identifies exactly what needs updating before making changes:
  - Property comparison: Detects which specific properties have changed between source and HelloID, with verbose logging showing old and new values
  - Action comparison: Smart detection of action differences to only update when configured actions differ from existing ones
  - Access group comparison: Calculates which groups need to be added or removed based on update behavior setting
  - Only products with actual detected changes are counted toward update threshold and processed for updates
- **Configurable Remove Behavior**: Added three options for handling products no longer in source system:
  - `None`: Keep products (requires manual cleanup)
  - `Disable`: Disable products (reversible, recommended)
  - `Remove`: Permanently delete products (irreversible)
- **Resource Owner Group Cleanup**: Option to automatically remove resource owner groups when products are removed
- **Product Configuration Function**: New `New-HelloIDProductConfiguration` function with comprehensive inline documentation for all product properties
- **Granular Property Updates**: Added ability to specify exactly which product properties to update on existing products
- **Access Group Update Behavior**: Three modes for updating access groups (None, Add, Replace)
- **AD Group Property Selection**: Configurable list of AD group properties to retrieve from Active Directory
- **Category Auto-Creation**: Option to automatically create product categories if they don't exist
- **Product Lifecycle Actions**: Expanded support for all lifecycle actions (onRequest, onApprove, onDeny, onReturn, onWithdrawn)
- **Action Management**: Granular control over updating, adding, and removing product actions
- **Update Resource Owner on Name Change**: Option to rename resource owner groups when source object names change
- **Flexible AD Filtering**: Support for custom AD group filters and specific OU targeting
- **DisplayName Property Mapping**: Automatic mapping of AD `name` property to `displayName` for consistent product configuration

### Changed

- **BREAKING**: Complete restructuring of configuration with organized sections:
  - Connection Configuration
  - Script Behavior
  - Product Lifecycle
  - Source Data Selection
  - Product Identification
  - Product Configuration Function
  - Resource Owner Configuration
  - Update Behavior
- **BREAKING**: Renamed configuration variables for clarity and consistency:
  - `$ProductSkuPrefix` → `$productIdentifierPrefix`
  - `$adGroupUniqueProperty` → `$sourceObjectUniqueProperty`
  - `$productResourseOwner` → `$productResourceOwner`
  - `$calculateProductResourceOwnerPrefixSuffix` → `$resourceOwnerMode` (now "Fixed" or "Calculated")
  - `$overwriteAccessGroup` → `$accessGroupUpdateBehavior`
  - `$removeProduct` → `$removeProductBehavior` (now "None", "Disable", or "Remove")
  - `$ADGroupsFilter` → `$adGroupsFilter`
  - `$ADGroupsOUs` → `$adGroupsOUs`
- **BREAKING**: Product configuration now uses a function-based approach instead of inline variables
- **BREAKING**: Action scripts now referenced by variable name to keep configuration clean
- Enhanced inline documentation with detailed explanations for every configuration option
- Improved resource owner mode configuration with clearer "Fixed" vs "Calculated" terminology
- Better organization of update behavior settings with clear warnings
- Standardized variable naming conventions throughout the script (camelCase)
- AD query logic improved with better filter and OU handling

### Improved

- Comprehensive inline documentation for all configuration sections with detailed explanations for every configuration option
- Access groups documentation clarified to show they can be from any source configured in HelloID (not limited to specific sources)
- Update behavior documentation improved to focus on performance impact and continuous sync scenarios, making it clear that `$overwriteExistingProduct` can be permanently enabled for continuous synchronization
- Clear warnings and recommendations for potentially dangerous operations
- Better structured sections with clear separation of concerns
- More intuitive configuration with examples and best practices
- Enhanced safety with multiple threshold options and test run mode
- Better error handling for AD property mapping
- Optimized AD group retrieval with configurable property selection

### Fixed

- Configuration consistency issues with resource owner group management
- Unclear update behavior options now clearly documented
- AD groups missing `displayName` property now handled correctly with automatic mapping

## [2.2.4] - 08-01-2026

### Fixed

- `managerCanOverrideDuration` default value changed to `false` to prevent unintended behavior

## [2.2.3] - 22-10-2025

### Fixed

- Various fixes identified during implementation and testing

## [2.2.2] - 18-09-2024

### Fixed

- Fixed typo in variable name that could cause script failures

### Changed

- Set default value of `$overwriteExistingProduct` to `false` for safer operation (added 08-09-2025)

## [2.2.1] - 19-03-2024

### Fixed

- Fixed use of wrong variable in product configuration logic

## [2.2.0] - 08-11-2023

### Changed

- Updated to use new HelloID Product API endpoints
- Added compare logic before updating products to prevent unnecessary API calls

## [2.1.0] - 13-09-2023

### Added

- Enhanced product configuration options
- Improved synchronization logic

### Changed

- Updated product handling logic
- Improved error handling

## [2.0.0] - 26-06-2023

### Added

- Complete rewrite of synchronization logic
- Support for resource owner groups
- Configurable product properties
- Support for product categories
- Product approval workflow integration
- Product visibility settings
- Access group configuration

### Changed

- Improved performance and reliability
- Better error handling and logging
- Restructured configuration approach

## [1.0.0] - 08-02-2023

This is the first official release of HelloID-Conn-SA-Sync-ActiveDirectory-Groups-To-SelfService-Products.

### Added

- Initial synchronization of Active Directory groups to HelloID Self Service products
- Basic product configuration
- Automatic product creation and removal
- Support for AD group filtering by OU
- Integration with HelloID portal API
- Product action configuration for group membership management
