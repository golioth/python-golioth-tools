<!-- Copyright (c) 2024 Golioth, Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.6.5] - 2024-12-20

### Added

- Cohorts
- Packages
- Deployments

### Changed

- Project now has base_url_with_organization

## [v0.6.4] - 2024-09-11

### Fixed

- Fix device stream.get() function

### Removed

- Mark broken device stream.set() as todo
- Remove deprecated device stream.delete()

## [v0.6.1] - 2024-03-07

### Fixed
- Added metadata property to Device class
- Fixed a bug that prevented calling RPCs with no arguments

## [v0.6.0] - 2024-02-27

### Fixed

- Fixed a bug that prevented setting Boolean settings

### Added

- Device class now has a `refresh()` method for updating with the latest metadata
- Can request a Device by its DeviceId
- New CLI option for the pytest plugin to choose the API gateway URL
- New tests for tags and blueprints

## [v0.5.1] - 2024-01-20

### Fixed

- Fix Release.rollout_set() function so tags are not overwritten

## [v0.5.0] - 2024-01-11

### Breaking Changes

- Differentiate Release Tags from Device Tags by changing the parameter name
    - Release Tags property changed to `Release.release_tags`
    - CLI: `releases create` command flag `--tag` changed to `--release-tag`
    - CLI: `releases delete` command flag `--by-tag` changed to `--by-release-tag`
    - CLI: `releases rollback` command flag `--by-tag` changed to `--by-release-tag`

### Added

- Device Tags support for Releases
    - Added `device_tags` property to Release class.
    - Added optional `device_tags` parameter to `Releases.create()` function. This parameter accepts
      a list of Device tag IDs.
- Blueprint support in Artifacts
    - New Artifact class property `blueprint`
    - `ProjectArtifacts.upload()` now accepts an optional `blueprint_id` parameter
    - CLI: `artifacts upload` now includes an optional `--blueprint` flag

### Changed

- `Releases.create()` now only requires an Artifact ID. Both release tags and device tags are
  optional parameters.

### Fixed
