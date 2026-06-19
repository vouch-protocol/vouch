# Browser Extension Examples

This directory contains examples for the Vouch Chrome Extension integration.

## Overview

The refactored Chrome Extension uses a "Hybrid Bridge" architecture:

1. **Bridge Mode (Primary)**: When the Vouch Daemon is running, the extension acts as a proxy
2. **Local Mode (Fallback)**: When offline, uses IndexedDB + WebCrypto for secure local signing

## Files

### Core Components

- `background-usage.ts` - How the background script handles signing requests
- `content-script-example.ts` - Content script integration patterns
- `popup-integration.ts` - Popup UI integration

### Secure Key Manager

- `secure-key-manager-usage.ts` - Using the SecureKeyManager class

### Migration

- `migration-example.ts` - How legacy keys are migrated
