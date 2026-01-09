---
description: Set up Google OAuth for Chrome Extension and publish to Web Store
---

# Chrome Extension OAuth & Publishing Setup

## Prerequisites

- Google Workspace account with `extensions@vouch-protocol.com` email
- Extension code in `browser-extension/` folder
- $5 for Chrome Web Store developer registration

---

## Part 1: Load Extension Locally (Testing)

1. Open Chrome → Navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle in top-right corner)
3. Click **Load unpacked**
4. Select the `browser-extension/` folder
5. Extension will appear with an **Extension ID** (32 character string)

### Finding Your Extension ID

After loading the extension, look for a string like:
```
ID: abcdefghijklmnopqrstuvwxyz123456
```
This ID is shown directly below the extension name on the `chrome://extensions/` page.

**Copy this ID** – you'll need it for OAuth setup.

---

## Part 2: Create Google Cloud OAuth Client

### Step 1: Create Google Cloud Project

1. Go to https://console.cloud.google.com/
2. Sign in with `extensions@vouch-protocol.com`
3. Click project dropdown → **New Project**
4. Name: `Vouch Protocol Extension`
5. Click **Create**

### Step 2: Configure OAuth Consent Screen

1. Go to **APIs & Services** → **OAuth consent screen**
2. Select **External** → Click **Create**
3. Fill in App Information:
   - App name: `Vouch Protocol`
   - User support email: `support@vouch-protocol.com`
   - App logo: Upload extension icon
   - Developer contact: `extensions@vouch-protocol.com`
4. Click **Save and Continue**
5. Add Scopes:
   - Click **Add or Remove Scopes**
   - Search and select: `userinfo.email`
   - Click **Update** then **Save and Continue**
6. Test Users (optional for testing)
7. Summary → **Back to Dashboard**

### Step 3: Create OAuth Client ID

1. Go to **APIs & Services** → **Credentials**
2. Click **+ CREATE CREDENTIALS** → **OAuth client ID**
3. Application type: **Chrome Extension**
4. Name: `Vouch Browser Extension`
5. **Application ID**: Paste your Extension ID from Step 1
6. Click **Create**
7. **Copy the Client ID** (looks like: `123456789-xxxxx.apps.googleusercontent.com`)

### Step 4: Update manifest.json

// turbo
```bash
# Replace YOUR_CLIENT_ID with the actual client ID
sed -i 's/YOUR_GOOGLE_CLIENT_ID/ACTUAL_CLIENT_ID_HERE/' browser-extension/manifest.json
```

Or manually edit `browser-extension/manifest.json`:
```json
"oauth2": {
  "client_id": "YOUR_ACTUAL_CLIENT_ID.apps.googleusercontent.com",
  "scopes": ["https://www.googleapis.com/auth/userinfo.email"]
}
```

### Step 5: Reload Extension

1. Go to `chrome://extensions/`
2. Click the refresh icon on the Vouch extension
3. Test signing – it should now get your email!

---

## Part 3: Publish to Chrome Web Store

### Step 1: Register as Developer

1. Go to https://chrome.google.com/webstore/devconsole
2. Sign in with `extensions@vouch-protocol.com`
3. Pay $5 one-time registration fee
4. Accept Developer Agreement

### Step 2: Prepare Assets

Required assets:
- 128x128 icon (PNG)
- At least 1 screenshot (1280x800 or 640x400)
- Promotional tile 440x280 (optional but recommended)
- Privacy policy URL

### Step 3: Create ZIP Package

// turbo
```bash
cd /home/rampy/vouch-protocol
zip -r vouch-extension.zip browser-extension/ -x "*.git*"
```

### Step 4: Upload to Web Store

1. Click **New Item** in Developer Console
2. Upload `vouch-extension.zip`
3. Fill in listing details:
   - Description (detailed)
   - Category: Productivity or Security
   - Language
   - Screenshots
   - Privacy policy URL
4. Click **Submit for Review**

### Step 5: Wait for Review

- Review takes 1-3 business days
- You'll get email notification when approved/rejected
- If rejected, fix issues and resubmit

---

## Troubleshooting

### OAuth Error: "Not a valid origin"
- Make sure the Extension ID in Google Cloud matches your actual extension ID
- Extension ID changes when you reload unpacked extensions

### "User not in test users" Error
- In OAuth consent screen, add your email to Test Users
- Or publish the OAuth consent screen (requires verification for production)

### Identity API not working
- Check manifest.json has correct permissions: `"identity"`, `"identity.email"`
- Reload extension after manifest changes

---

## Email Structure Recommendation

| Email | Purpose |
|-------|---------|
| `extensions@vouch-protocol.com` | Chrome Web Store + OAuth (alias to hello@) |
| `support@vouch-protocol.com` | User support shown in OAuth consent |
| `hello@vouch-protocol.com` | General contact |
