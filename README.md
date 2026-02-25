# HelloID-Conn-SA-Full-EntraID-AccountEnable

| :information_source: Information |
| :------------------------------- |
| This repository contains the connector and configuration code only. The implementer is responsible for acquiring the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements. |

## Description

HelloID-Conn-SA-Full-Microsoft-EntraID-AccountEnable is a delegated form designed for use with HelloID Service Automation (SA). It can be imported into HelloID and customized according to your requirements.

By using this delegated form, you can enable user accounts in Microsoft Entra ID. The following options are available:

1. Search and select an Entra ID user (wildcard search by display name, UserPrincipalName, or mail)
2. Enable the selected user account in Microsoft Entra ID

## Getting started
### Requirements

#### App Registration & Certificate Setup

Before implementing this connector, make sure to configure a Microsoft Entra ID App Registration. During the setup process, you'll create a new App Registration in the Entra portal, assign the necessary API permissions, and generate and assign a certificate.

Follow the official Microsoft documentation for creating an App Registration and setting up certificate-based authentication:

- [App-only authentication with certificate](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps#set-up-app-only-authentication)

#### HelloID-specific configuration

Once you have completed the Microsoft setup and followed their best practices, configure the following HelloID-specific requirements.

- **API Permissions** (Application permissions):
  - `User.Read.All` - To search and read user information
  - `User.ReadWrite.All` - To enable user accounts
- **Certificate Base64 encoded string:**
  - Base64 encoded string of the certificate assigned to the app registration. For instructions on creating the certificate and obtaining the base64 string, refer to our forum post: [Setting up a certificate for Microsoft Graph API in HelloID connectors](https://forum.helloid.com/forum/helloid-provisioning/5338-instruction-setting-up-a-certificate-for-microsoft-graph-api-in-helloid-connectors#post5338)

### Connection settings

The following global variables must be configured in HelloID when importing and configuring the delegated form.

| Setting | Description | Mandatory |
| --- | --- | --- |
| EntraIdTenantId | The unique identifier (ID) of the tenant in Microsoft Entra ID | Yes |
| EntraIdAppId | The unique identifier (ID) of the App Registration in Microsoft Entra ID | Yes |
| EntraIdCertificateBase64String | The Base64-encoded string representation of the app certificate | Yes |
| EntraIdCertificatePassword | The password associated with the app certificate | Yes |

## Remarks

### User Lookup by ID

- Uses the Entra ID user `id` for correlation and updates to ensure consistency across user object changes such as userPrincipalName changes.

### Wildcard Search

- Users can search for accounts using a wildcard (`*`) to return all disabled users, or by entering partial text to search across display name, UserPrincipalName, and mail fields.

### Account Status Filtering

- The data source only returns users with `accountEnabled = false`, meaning search results show only inactive user accounts available for enabling.

### Certificate-Based Authentication

- The connector uses certificate-based authentication to generate JSON Web Tokens (JWT) for secure communication with Microsoft Graph API.

## Development resources

### API endpoints

The following Microsoft Graph API endpoints are used by the connector:

| Endpoint | Description |
| --- | --- |
| /v1.0/users | Search and retrieve disabled users |
| /v1.0/users/{id} | Update a specific user |

### API documentation

- [List users](https://learn.microsoft.com/en-us/graph/api/user-list)
- [Update user](https://learn.microsoft.com/en-us/graph/api/user-update)

## Getting help

> :bulb: **Tip:**  
> For more information on Delegated Forms, please refer to our [documentation](https://docs.helloid.com/en/service-automation/delegated-forms.html) pages.

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/
