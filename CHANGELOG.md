# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

## [1.0.0] - 2026-02-24

This is the first official release of _HelloID-Conn-SA-Full-Microsoft-EntraID-AccountEnable_. This release includes functionality to enable Entra ID user accounts through HelloID Service Automation delegated forms.

### Added

- PowerShell data source to search for active Entra ID users with wildcard support across DisplayName, Mail, UserPrincipalName
- Task to enable Entra ID user accounts using the Microsoft Graph API (`PATCH /users/{id}` with `accountEnabled: true`)
- Certificate-based authentication for secure API access
- Audit logging for all account disable operations
- All-in-one setup script for HelloID form deployment

### Changed

### Deprecated

### Removed

### Fixed
