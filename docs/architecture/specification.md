## PhylaxBox — Product & Technical Specification

DRAFT v0.1 · November 2026

&#x20;Your data is under your control.

# PhylaxBox — Your Data Is Under Your Control

## 1. Overview

PhylaxBox is a privacy-first, cross-platform password manager that gives users complete control over their credentials and sensitive information.

Unlike traditional cloud-based password managers, PhylaxBox does not depend on a centralized backend to store or manage user vaults.

Instead, passwords are stored in a strongly encrypted file that users can keep locally, synchronize through a supported cloud provider, or back up using their preferred storage solution.

PhylaxBox combines modern cryptography, native desktop integration, browser extensions, and mobile autofill capabilities into a secure and convenient password management experience.

**Core principle:** The user owns the data, controls the encryption keys, and decides where the encrypted vault is stored.

### 1.1 Product Goals

- Provide a secure, easy-to-use password manager without requiring a proprietary cloud backend.
- Keep passwords and sensitive information encrypted at rest.
- Support offline-first operation.
- Allow optional synchronization between devices through user-controlled cloud accounts.
- Provide seamless browser and desktop integration.
- Support Windows, macOS, Linux, and eventually Android.
- Maintain a portable, versioned vault format independent of the user interface or operating system.
- Minimize unnecessary dependencies, network services, and attack surfaces.

### 1.2 Non-Goals

At least for the initial release, PhylaxBox will not:

- Operate a centralized password storage service.
- Require account registration with PhylaxBox.
- Store or recover users' master passwords.
- Require an internet connection for local vault operations.
- Support enterprise administration or centralized user management.
- Provide multi-user collaborative vaults.

---

## 2. PhylaxBox Philosophy

PhylaxBox is built around four fundamental principles.

### 2.1 No Centralized Data Storage

PhylaxBox does not maintain centralized servers containing users' credentials.

All sensitive information is encrypted locally before being written to disk or uploaded to a cloud provider.

Cloud services act only as storage and synchronization providers.

### 2.2 Your Data Belongs to You

Users retain ownership and control over their password vaults.

They can:

- Store vaults on local devices.
- Choose a supported cloud synchronization provider.
- Export encrypted backups.
- Move vault files between compatible devices.
- Stop using cloud synchronization without losing access to local data.

The vault format should be documented and designed for long-term portability.

### 2.3 Cryptography Protects Your Data

PhylaxBox uses modern, authenticated cryptography to protect credentials against unauthorized access and tampering.

Encryption and decryption occur locally on the user's device.

The master password and unencrypted vault contents are never transmitted to cloud storage providers.

### 2.4 Privacy by Design

PhylaxBox should collect as little information as possible.

The application should not require telemetry, analytics, advertising identifiers, or proprietary cloud accounts.

Any optional diagnostic reporting must be explicitly enabled and must never contain passwords, encryption keys, authentication tokens, or decrypted vault contents.

---

## 3. Supported Platforms

### 3.1 Desktop

The initial desktop application should support:

- Windows 10/11.
- macOS.
- Linux distributions compatible with the selected WebView backend.

Platform-specific packaging, operating system permissions, and native integrations must be handled separately.

### 3.2 Web Browsers

The initial browser extension should prioritize:

- Google Chrome.
- Microsoft Edge.
- Mozilla Firefox.

Other Chromium-based browsers may be supported after compatibility testing.

### 3.3 Android

An Android application is planned and may be developed in parallel with the desktop implementation.

The Android application must use the same vault format, cryptographic algorithms, and synchronization rules as the desktop application.

---

## 4. Password Vault

### 4.1 Vault Storage Format

PhylaxBox stores user credentials in a portable, encrypted binary file with the proposed extension:

`*.phylaxbox`

The logical vault content is represented as JSON.

Before encryption, the serialized JSON may be compressed to reduce storage size.

The storage pipeline is:

1. Serialize the vault data into JSON.
2. Validate the JSON structure.
3. Compress the serialized data using the configured compression algorithm.
4. Encrypt the compressed payload using authenticated encryption.
5. Write the encrypted payload and required metadata to the vault file.

The reverse process is performed when opening the vault.

Compression must never occur after encryption.

The implementation must enforce maximum input sizes and decompression limits to prevent resource exhaustion.

### 4.2 Cryptographic Design

The proposed cryptographic stack is:

| Component                     | Technology                                  |
| ----------------------------- | ------------------------------------------- |
| Cryptographic library         | libsodium                                   |
| Password-based key derivation | Argon2id                                    |
| Authenticated encryption      | XChaCha20-Poly1305                          |
| Random number generation      | libsodium CSPRNG                            |
| Sensitive memory handling     | sodium_malloc, sodium_mlock, sodium_memzero |
| Compression                   | zlib or Zstandard                           |
| Vault serialization           | JSON                                        |

A random salt is generated when creating a vault and stored in the unencrypted file header.

The same salt and Argon2id parameters must be used to reproduce the same password-derived key.

Encryption nonces must be generated securely and must not be reused with the same encryption key.

The vault must include authentication of its encrypted contents and security-relevant header metadata.

### 4.3 Encryption Key Architecture

PhylaxBox should use envelope encryption rather than encrypting the entire vault directly with a key derived from the master password.

The proposed design uses two separate keys:

**Master Key Encryption Key (KEK)**

Derived from the user's master password using Argon2id and a vault-specific random salt.

**Vault Data Encryption Key (DEK)**

A randomly generated encryption key used to encrypt the actual vault contents.

The DEK is encrypted using the KEK and stored inside the vault header.

This design enables:

- Changing the master password without re-encrypting the entire vault.
- Supporting multiple authorized unlocking methods.
- Implementing recovery keys.
- Separating password authentication from data encryption.

The recovery mechanism must never expose the DEK in plaintext outside a trusted, temporary memory context.

### 4.4 Vault File Structure

The proposed binary format contains:

**Unencrypted header**

- Magic identifier.
- Vault format version.
- Cryptographic algorithm identifiers.
- Argon2id salt and parameters.
- Encryption nonce information.
- Encrypted DEK and authentication metadata.
- Compression algorithm identifier.

**Encrypted payload**

- Vault identifier.
- Credential entries.
- Entry metadata.
- Categories and tags.
- Deletion records.
- Synchronization metadata.
- Vault preferences that may contain sensitive information.

Only the metadata required to open and interpret the vault should remain unencrypted.

### 4.5 Vault Data Model

Each credential entry should support:

| Field       | Description                                                      |
| ----------- | ---------------------------------------------------------------- |
| id          | Stable, globally unique entry identifier                         |
| title       | Human-readable credential name                                   |
| username    | Login identifier                                                 |
| password    | Encrypted-at-rest password                                       |
| urls        | Associated website URLs                                          |
| application | Optional desktop application identifier                          |
| notes       | Optional secure notes                                            |
| tags        | User-defined organization tags                                   |
| favorite    | Favorite status                                                  |
| createdAt   | Creation timestamp                                               |
| updatedAt   | Last modification timestamp                                      |
| deletedAt   | Optional deletion timestamp                                      |
| revision    | Entry revision information                                       |
| deviceId    | Identifier of the device responsible for the latest modification |

Additional metadata may be introduced as required.

All timestamps should use UTC.

Stable identifiers and explicit revisions are required for synchronization.

### 4.6 Master Password

The master password is the primary secret protecting a vault.

Requirements:

- Never store the master password in plaintext.
- Never transmit it to cloud providers.
- Never log or include it in diagnostic reports.
- Support long passphrases and Unicode input.
- Use a configurable, versioned Argon2id policy.
- Clear sensitive buffers when they are no longer needed, where technically possible.

PhylaxBox must clearly explain that losing the master password without a valid recovery method may result in permanent loss of access to the vault.

---

## 5. Recovery and Backup

### 5.1 Recovery Key

PhylaxBox should optionally generate a high-entropy recovery key when creating a vault.

The recovery key provides an alternative method to decrypt or unwrap the vault's Data Encryption Key.

It must be generated using a cryptographically secure random number generator.

The recovery key must not be derived from easily guessed security questions.

### 5.2 Recovery File

Users may export an optional recovery file.

The recovery file should contain the information necessary to recover access using the recovery key, without exposing the DEK in plaintext.

The recovery file must be protected against tampering and must be versioned.

Users should be encouraged to store it separately from the vault.

Recovery files must never be automatically uploaded to the same cloud location as the vault without explicit user consent.

### 5.3 Recovery Procedure

The recovery workflow should allow the user to:

1. Select an existing encrypted vault.
2. Choose the recovery option.
3. Provide the recovery key and any required recovery file.
4. Unlock the vault.
5. Configure a new master password.
6. Generate new recovery material if necessary.

### 5.4 Backup Strategy

PhylaxBox should support:

- Manual encrypted backups.
- Automatic local versioned backups.
- Backup retention policies.
- Restoration of previous vault versions.
- Integrity verification before restoration.

Backups must remain encrypted.

The application must never overwrite the only known valid vault copy before a replacement has been successfully written and verified.

---

## 6. Cloud Storage and Synchronization

### 6.1 Supported Providers

The first version will support:

- Dropbox.
- Google Drive.

Additional providers, including Nextcloud, may be considered in future releases.

### 6.2 Offline-First Architecture

Local storage is the primary source of data during normal application operation.

Cloud synchronization is optional.

The application must remain fully functional when the device is offline.

Changes made offline are synchronized when connectivity becomes available.

### 6.3 Cloud Authentication

Cloud integrations must use OAuth 2.0 Authorization Code Flow with PKCE whenever supported.

Requirements:

- Authentication through the user's default system browser.
- No embedded client secrets.
- Short-lived access tokens.
- Secure storage of refresh tokens using operating system credential facilities.
- Minimum required OAuth permissions.
- Support for disconnecting and revoking cloud access.

Cloud authentication tokens must be managed separately from the vault's encryption keys.

### 6.4 Cloud Storage Permissions

The application should request the minimum permissions required to manage its encrypted vault files.

For Dropbox, the preferred integration is an application-specific folder.

For Google Drive, the implementation should evaluate application-specific storage and file-scoped access according to the desired user experience.

The application must not request unrestricted access to the user's entire cloud account unless strictly necessary.

### 6.5 Synchronization Workflow

The synchronization process should:

1. Detect local vault modifications.
2. Persist the updated encrypted vault locally.
3. Retrieve remote file metadata.
4. Determine whether the remote vault has changed.
5. Download and validate remote changes when necessary.
6. Merge compatible changes.
7. Request user intervention for unresolved conflicts.
8. Encrypt and save the merged vault.
9. Upload the resulting encrypted file using provider-supported revision controls.
10. Update synchronization metadata only after successful confirmation.

Automatic synchronization may be triggered after modifications, with debouncing to avoid excessive uploads.

### 6.6 Conflict Resolution

Each credential entry must have a stable identifier and modification metadata.

However, timestamps alone must not be considered sufficient to resolve synchronization conflicts.

PhylaxBox should use a three-way merge strategy based on:

- Last synchronized common state.
- Current local state.
- Current remote state.

Changes to different entries should merge automatically.

Concurrent changes to the same entry require field-level conflict analysis or explicit user intervention.

Deletion records must be retained long enough to prevent deleted credentials from reappearing during synchronization.

Conflicting passwords must never be silently overwritten.

### 6.7 Cloud Synchronization Security

Only encrypted vault files may be uploaded.

The application must:

- Validate downloaded vault integrity.
- Detect unexpected remote revisions.
- Avoid blind overwrites.
- Preserve recoverable local copies.
- Use TLS for cloud API communication.
- Never include secrets in cloud synchronization logs.
- Detect synchronization failures and notify the user.

---

## 7. Desktop Application

### 7.1 Technology Stack

The desktop application will be implemented in modern C++.

The user interface will use HTML, CSS, and JavaScript rendered through a native WebView.

The WebView library is webview/webview (decided in [ADR 0002](adr/0002-webview-cpp20-tombstones.md); Saucer was the initial preference).

Proposed technologies:

| Component             | Technology                          |
| --------------------- | ----------------------------------- |
| Core application      | C++20                               |
| Build system          | CMake                               |
| Dependency management | vcpkg                               |
| Desktop WebView       | webview/webview (ADR 0002)          |
| Frontend              | HTML, CSS, JavaScript or TypeScript |
| Cryptography          | libsodium                           |
| JSON serialization    | nlohmann/json or equivalent         |
| Compression           | zlib or Zstandard                   |
| HTTP client           | cpp-httplib or equivalent           |
| Automated testing     | Catch2 or GoogleTest                |

The final dependency list should be validated for cross-platform compatibility.

### 7.2 Desktop UI Architecture

The WebView allows JavaScript code to invoke explicitly bound C++ functions.

The application should use this capability instead of running an HTTP server for the desktop UI.

The frontend must never access arbitrary native methods.

Only explicitly registered, validated operations should be available through the JavaScript-to-C++ bridge.

The native backend is responsible for:

- Vault encryption and decryption.
- Credential management.
- Cloud synchronization.
- Session management.
- Operating system integration.
- Secure storage.
- Browser extension communication.

The frontend is responsible for:

- Rendering the interface.
- Displaying credential lists.
- Handling user interactions.
- Requesting authorized backend operations.
- Displaying synchronization and security status.

### 7.3 Interface Design

The interface should be modern, minimal, intuitive, and focused on everyday usability.

The visual direction should prioritize:

- Clean layouts.
- Clear typography.
- Simple navigation.
- Dark and light themes.
- Fast credential search.
- Consistent security indicators.
- Minimal unnecessary dialogs.
- Accessibility and keyboard navigation.

The interface may follow established password manager usability conventions while maintaining an independent PhylaxBox visual identity.

### 7.4 Main Screens

**Vault Unlock**

- Master password input.
- Optional biometric unlock.
- Recovery option.
- Vault selection.

**Password Vault**

- Searchable credential list.
- Favorites.
- Categories and tags.
- Credential details.
- Copy username and password.
- Add, edit, and delete credentials.

**Password Generator**

- Configurable password length.
- Character categories.
- Secure random generation.
- Copy generated password.
- Optional passphrase generation.

**Cloud Synchronization**

- Provider selection.
- Account authorization.
- Connection status.
- Last synchronization time.
- Manual synchronization.
- Conflict resolution.

**Settings**

- Security settings.
- Automatic lock timeout.
- Clipboard clearing timeout.
- Theme and language.
- Backup and recovery.
- Cloud provider configuration.
- Browser extension integration.

### 7.5 Session Management

The application should support:

- Automatic vault locking after inactivity.
- Immediate manual locking.
- Locking when the operating system session is locked.
- Optional locking when the application is minimized.
- Reauthentication for sensitive operations.
- Secure release of sensitive memory when locking the vault.

The default inactivity timeout is proposed as five minutes, configurable by the user.

Biometric unlocking may be implemented through operating system security APIs, provided the underlying key management remains secure.

### 7.6 Desktop Autofill

PhylaxBox should support credential filling in native desktop applications where technically feasible.

The preferred approach is to use supported operating system accessibility or automation APIs.

The application must validate the target application before releasing credentials.

Clipboard-based filling may be offered as a fallback with explicit user consent.

The application must not claim protection against keyloggers or malware already running with sufficient privileges on the user's device.

---

## 8. Browser Extension

### 8.1 Overview

The browser extension is a mandatory feature of the first release.

It allows users to access and autofill credentials stored in their local PhylaxBox vault.

The extension depends on the desktop application and does not independently decrypt or persist the complete vault.

### 8.2 Main Features

- Detect login forms.
- Suggest matching credentials.
- Autofill usernames and passwords.
- Search credentials.
- Generate strong passwords.
- Save new login credentials.
- Update existing credentials.
- Display vault lock status.
- Request vault unlocking when necessary.

### 8.3 Browser Communication Architecture

The preferred architecture uses the browser's Native Messaging API.

The browser launches a registered native messaging host that communicates through standard input and output.

The native host forwards authorized requests to the running PhylaxBox desktop process through a local interprocess communication channel.

The architecture should avoid exposing an HTTP or HTTPS service for routine extension communication.

### 8.4 Authentication and Authorization

The extension must not receive unrestricted access to vault contents.

Security requirements:

- Restrict native messaging access to approved extension identifiers.
- Validate all incoming messages.
- Authenticate the native host to the desktop process.
- Use operating system access controls for local IPC.
- Require an unlocked vault or explicit user authorization.
- Limit requests to the minimum necessary credentials.
- Apply session expiration and authorization checks.
- Never expose the master password or encryption keys to the extension.

The extension should be treated as a separate security boundary, not as fully trusted code.

### 8.5 Credential Matching

Credentials should be matched using the current website's origin and associated domain information.

The extension must:

- Validate the current page origin.
- Avoid matching credentials solely by page title.
- Warn users about suspicious domain mismatches.
- Prevent automatic submission unless explicitly configured.
- Avoid automatically filling credentials into untrusted frames.
- Require user interaction when multiple credentials match.

Phishing-resistant behavior is a primary requirement.

### 8.6 Autofill Security

The extension should fill form fields through supported browser APIs and content scripts rather than simulating keyboard input.

Credentials must only be delivered to the authorized tab and frame.

The extension must minimize how long decrypted credentials remain in JavaScript memory.

The application must recognize that a malicious website or compromised browser can potentially observe values entered into its own form fields.

---

## 9. Native Messaging Host

### 9.1 Purpose

The Native Messaging Host acts as a controlled bridge between the browser extension and the PhylaxBox desktop application.

It must be implemented as a separate, lightweight executable.

### 9.2 Responsibilities

- Receive framed JSON messages from the browser.
- Validate message structure and size.
- Verify the requesting extension context where supported.
- Establish an authenticated IPC connection to the desktop application.
- Forward authorized requests.
- Return structured responses.
- Handle communication failures safely.

### 9.3 Local IPC

Possible transport mechanisms include:

- Windows Named Pipes.
- Unix Domain Sockets on Linux and macOS.
- Equivalent platform-specific IPC facilities.

Shared memory should not be the default transport because it introduces additional synchronization, lifecycle, and access-control complexity.

The IPC protocol must be versioned.

### 9.4 Security Constraints

The host must:

- Never independently store the master password.
- Never independently decrypt the vault.
- Never expose an unrestricted command execution interface.
- Never accept arbitrary file paths from browser messages.
- Enforce request size limits.
- Validate message types and parameters.
- Avoid logging sensitive payloads.
- Fail closed when the desktop application is unavailable or unauthorized.

---

## 10. Android Application

### 10.1 Overview

The Android application will provide access to the same encrypted vault format used by the desktop application.

It should operate independently after obtaining a local vault copy.

### 10.2 Main Features

- Open and unlock encrypted vaults.
- Search and manage credentials.
- Generate passwords.
- Copy credentials with clipboard protections.
- Synchronize through supported cloud providers.
- Support biometric authentication.
- Autofill credentials in compatible Android applications and browsers.
- Work offline.

### 10.3 Android Autofill Integration

The application should implement Android's Autofill Framework to provide password suggestions and fill credentials into compatible applications.

The design should also account for Android Credential Manager integration where applicable.

The user must explicitly enable PhylaxBox as an autofill provider.

### 10.4 Shared Cryptographic Core

The Android implementation should reuse the same vault format specification and cryptographic test vectors.

Where practical, the C++ cryptographic core may be shared through the Android NDK.

Platform-specific functionality should be implemented using native Android APIs.

---

## 11. Future Passkey Support

Passkeys are planned for a future release.

PhylaxBox should eventually support:

- Creating passkeys.
- Storing passkey credentials securely.
- Using passkeys for authentication.
- Synchronizing passkeys between authorized devices.
- Managing passkey lifecycle and deletion.
- Integrating with browser and operating system credential APIs.

Passkey support requires additional design work involving WebAuthn, FIDO2, credential providers, and secure private-key handling.

The initial vault format should support future schema extensions without requiring a complete redesign.

---

## 12. Security Requirements

### 12.1 Threat Model

PhylaxBox should explicitly address threats including:

- Theft of encrypted vault files.
- Offline master password guessing.
- Unauthorized cloud account access.
- Malicious browser extensions.
- Phishing websites.
- Local IPC abuse.
- Clipboard monitoring.
- Accidental credential disclosure.
- Synchronization conflicts and rollback attacks.
- Corrupted or malicious vault files.
- Memory disclosure.

A fully compromised operating system is outside the application's complete protection guarantees.

### 12.2 Secure Memory

Sensitive keys and plaintext credentials should be kept in memory only as long as necessary.

The implementation should use libsodium secure memory facilities where appropriate.

Copies of secrets should be minimized, and sensitive buffers should be cleared when no longer required.

### 12.3 Clipboard Protection

When copying passwords:

- Clear the clipboard after a configurable timeout when possible.
- Avoid clearing clipboard content that has subsequently been replaced by the user.
- Warn users that other applications may read clipboard contents.
- Prefer direct autofill when available.

### 12.4 File Integrity

The vault format must provide authenticated encryption and reject modified or corrupted encrypted content.

File writes must be performed using a safe replacement strategy.

The application must avoid partially written vault files.

### 12.5 Logging

Sensitive information must never be written to application logs.

Logs may contain operational information such as synchronization failures, vault format errors, and application lifecycle events.

---

## 13. Software Architecture

### 13.1 Architectural Principles

The implementation should follow these principles:

- Separation of concerns.
- Platform-independent business logic.
- Explicit security boundaries.
- Dependency inversion.
- Testable core components.
- Minimal exposed interfaces.
- Versioned protocols and file formats.

### 13.2 Proposed Components

**PhylaxBox Core**

Shared C++ library containing:

- Vault domain model.
- Credential management.
- Cryptographic operations.
- Serialization.
- Compression.
- Vault persistence.
- Synchronization and conflict resolution logic.

**PhylaxBox Desktop**

Native desktop application containing:

- WebView integration.
- JavaScript bridge.
- Session management.
- Native IPC server.
- Platform-specific integrations.

**PhylaxBox Native Host**

Standalone executable containing:

- Browser Native Messaging protocol.
- Request validation.
- Local IPC client.
- Structured request and response handling.

**PhylaxBox Browser Extension**

Browser extension containing:

- Popup interface.
- Content scripts.
- Credential matching.
- Native Messaging client.
- Autofill behavior.

**PhylaxBox Android**

Mobile application containing:

- Android user interface.
- Vault management.
- Autofill service.
- Cloud synchronization.
- Android-specific secure storage integration.

### 13.3 Proposed Repository Structure

```
phylaxbox/
├── CMakeLists.txt
├── CMakePresets.json
├── vcpkg.json
├── docs/
│   ├── architecture/
│   ├── security/
│   └── vault-format/
├── core/
│   ├── crypto/
│   ├── vault/
│   ├── storage/
│   ├── sync/
│   └── models/
├── desktop/
│   ├── src/
│   └── frontend/
├── native-host/
│   └── src/
├── browser-extension/
│   ├── src/
│   └── manifests/
├── android/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── crypto/
│   └── security/
└── packaging/
    ├── windows/
    ├── linux/
    └── macos/
```

The repository may use a monorepo structure while keeping components independently buildable and testable.

---

## 14. Non-Functional Requirements

### 14.1 Performance

- Fast application startup.
- Responsive credential search.
- Efficient handling of vaults containing at least 10,000 credential entries.
- Minimal background CPU usage.
- Avoid unnecessary cryptographic or serialization operations.
- Asynchronous cloud synchronization.

### 14.2 Reliability

- No data loss during interrupted writes.
- Safe recovery from application crashes.
- Atomic local vault replacement where supported.
- Explicit handling of synchronization failures.
- Backward-compatible vault format migration where feasible.

### 14.3 Portability

- Common encrypted vault format across platforms.
- Consistent cryptographic behavior.
- Cross-platform C++ core.
- Platform-specific integrations isolated behind interfaces.

### 14.4 Maintainability

- Automated unit and integration tests.
- Static analysis.
- Dependency vulnerability monitoring.
- Reproducible builds where practical.
- Documented security decisions.
- Versioned public interfaces and protocols.

### 14.5 Accessibility

The interface should support keyboard navigation, accessible labels, sufficient color contrast, and compatibility with supported operating system accessibility tools.

---

## 15. Testing Strategy

### 15.1 Cryptographic Tests

- Key derivation test vectors.
- Encryption/decryption round trips.
- Invalid password handling.
- Authentication failure handling.
- Corrupted header and payload detection.
- Recovery key validation.
- Cross-platform vault compatibility.

### 15.2 Synchronization Tests

- Offline modifications.
- Concurrent changes on multiple devices.
- Conflicting password updates.
- Deleted entry propagation.
- Interrupted uploads and downloads.
- Remote revision conflicts.
- Backup and restoration.

### 15.3 Security Tests

- Malformed Native Messaging messages.
- Unauthorized IPC requests.
- Browser origin validation.
- Malicious or oversized vault files.
- Decompression resource limits.
- Sensitive data leakage through logs.
- Session expiration.
- Clipboard behavior.

### 15.4 Integration Tests

- Desktop and browser extension communication.
- Dropbox synchronization.
- Google Drive synchronization.
- Windows, macOS, and Linux compatibility.
- Android vault interoperability when implemented.

---

## 16. Development Roadmap

### Phase 1 — Core Foundation

- Establish CMake and vcpkg project structure.
- Implement the shared C++ core.
- Define the versioned vault file format.
- Implement Argon2id and authenticated encryption.
- Implement JSON serialization and compression.
- Implement secure local persistence.
- Add cryptographic and storage tests.

### Phase 2 — Desktop MVP

- Integrate the WebView.
- Implement vault creation and unlocking.
- Implement credential CRUD operations.
- Implement credential search.
- Implement password generation.
- Implement session management.
- Implement backup and recovery workflows.

### Phase 3 — Browser Integration

- Implement the Native Messaging Host.
- Implement local IPC.
- Implement extension authentication and authorization.
- Build the browser extension.
- Implement domain matching and autofill.
- Validate browser compatibility.

### Phase 4 — Cloud Synchronization

- Implement Dropbox OAuth and synchronization.
- Implement Google Drive OAuth and synchronization.
- Implement revision tracking.
- Implement three-way merge.
- Implement conflict resolution.
- Test offline and multi-device scenarios.

### Phase 5 — Hardening and Release

- Conduct security review.
- Implement installers and packaging.
- Validate cross-platform behavior.
- Improve accessibility and performance.
- Prepare user documentation.
- Release the first stable desktop version.

### Phase 6 — Mobile and Advanced Features

- Implement Android application.
- Integrate Android Autofill.
- Extend cloud synchronization to mobile.
- Research and implement passkey support.
- Evaluate additional storage providers.

---

## 17. Open Architectural Decisions

The following decisions require further evaluation before the specification is finalized.

| Decision              | Current Proposal                          |
| --------------------- | ----------------------------------------- |
| Vault encryption      | XChaCha20-Poly1305                        |
| Key derivation        | Argon2id                                  |
| Key hierarchy         | KEK + randomly generated DEK              |
| Compression           | Zstandard or zlib                         |
| Vault serialization   | JSON                                      |
| Desktop frontend      | webview/webview + HTML/CSS/TypeScript (ADR 0002) |
| Browser communication | Native Messaging + pairing (ADR 0003)      |
| Desktop IPC           | Named Pipes / Unix Domain Sockets (ADR 0003) |
| Cloud authentication  | OAuth 2.0 + PKCE                          |
| Synchronization       | Three-way merge + revision control        |
| Recovery              | High-entropy recovery key                 |
| Android core          | Shared C++ library where practical        |
| Passkeys              | Future release                            |
| Desktop autofill      | Platform-specific, subject to feasibility |

These decisions should be documented as Architecture Decision Records (ADRs) as implementation progresses.

---

## 18. Product Vision

PhylaxBox aims to provide the convenience of modern password managers without requiring users to surrender control of their credentials to a centralized service.

Security, privacy, portability, and usability should reinforce each other rather than compete.

The long-term vision is a password manager where users can securely access their credentials across devices while remaining independent of any single storage provider or proprietary backend.

**PhylaxBox — Your data is under your control.**

## Architectural notes and research

A few findings are particularly relevant before we turn this specification into implementation tasks.

Native Messaging is the preferred browser integration.

Chrome officially supports native hosts using framed JSON messages over stdin/stdout. However, Chromium explicitly warns that Native Messaging is not itself a secure authenticated channel. PhylaxBox should add authentication and authorization at the IPC layer.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://developer.chrome.com\&sz=32)

Chrome for Developers+1



OAuth with PKCE is the correct choice for desktop clients.

Dropbox explicitly recommends PKCE for desktop applications that cannot securely store a client secret. The public App Key can be embedded in the application; the App Secret must not be.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://docs.dropboxapi.com\&sz=32)

Dropbox API Documentation+1



Google Drive offers two useful storage approaches.

The `appDataFolder` is hidden and application-specific, while `drive.file` supports access to files created or opened by the application. For your philosophy of user-controlled storage, the latter deserves consideration.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://developers.google.com\&sz=32)

Google for Developers+1



Android autofill is feasible through official APIs.

Android provides an Autofill Framework for password managers, and Credential Manager supports passwords and passkeys. These provide the foundations for the mobile integration.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://developer.android.com\&sz=32)

Android Developers+1



Saucer aligns well with the proposed desktop architecture.

Its native WebView integration and JavaScript/C++ interoperability support a desktop interface without requiring a local HTTP server for frontend communication.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://github.com\&sz=32)

GitHub+1



## One architecture detail I would prioritize

Proposed PhylaxBox communication architecture

Conceptual architecture. The native host never directly decrypts the vault.

The other important decision is the KEK + DEK key hierarchy. It is especially valuable for PhylaxBox because you want both master-password changes and an optional recovery mechanism.

Before implementing this architecture, I would also correct and replace the earlier cryptography examples from our conversation. They were useful for illustrating the concept, but they are not production-ready, particularly regarding key derivation, salt handling, and secure memory management.

My suggested next step: formalize the encrypted `.phylaxbox` file format as a versioned technical contract. Once that is stable, the desktop application, browser integration, and Android client can evolve independently without risking incompatible vault implementations.
