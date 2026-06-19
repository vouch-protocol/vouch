# Publishing the Vouch VS Code extension

The extension lives under `vscode-vouch/` and ships to the Visual Studio
Marketplace under the publisher id `vouch-protocol`.

## One-time setup

1. **Microsoft / Azure DevOps account.** The Marketplace authenticates via
   Azure DevOps Personal Access Tokens. Sign in at
   <https://dev.azure.com/> with the Microsoft account that should own the
   publisher. Create an organization if you do not already have one.

2. **Create the publisher.** Go to
   <https://marketplace.visualstudio.com/manage> and create publisher id
   `vouch-protocol` (must match the `publisher` field in
   `vscode-vouch/package.json`).

3. **Generate a Personal Access Token (PAT).** In Azure DevOps:
   `User Settings -> Personal access tokens -> New Token`.
   Set:
   - **Organization**: *All accessible organizations*.
   - **Scopes**: *Custom defined* -> **Marketplace -> Manage**.
   - **Expiration**: pick something sensible (PATs max out at 1 year).
   Copy the token immediately; it is only shown once.

4. **Store the PAT.** Save it to your local secret manager (1Password,
   macOS Keychain, etc.). Do NOT commit it. The repo never sees the PAT;
   only the publish shell sees it via env var or stdin.

## Per-release flow

From `vscode-vouch/`:

```bash
# 1. Install dev deps (first time only).
npm install

# 2. Bump the version in package.json + add a CHANGELOG entry.

# 3. Compile and lint.
npm run compile

# 4. Build the .vsix locally (sanity check).
npx vsce package
# -> vouch-vscode-0.1.0.vsix in the current directory

# 5. (Optional) Install the .vsix into your local VS Code to smoke-test:
#    Extensions panel -> ... menu -> Install from VSIX...

# 6. Publish to the Marketplace.
#    Option A (interactive): vsce will prompt for the PAT.
npx vsce publish

#    Option B (CI / scripted): pass PAT via env var.
VSCE_PAT="<your PAT>" npx vsce publish
```

The listing usually becomes searchable on
<https://marketplace.visualstudio.com/vscode> within a few minutes of
`vsce publish` returning success. Direct install URL is
<https://marketplace.visualstudio.com/items?itemName=vouch-protocol.vouch-vscode>.

## Verification after publish

1. `code --install-extension vouch-protocol.vouch-vscode` works.
2. Command palette shows `Vouch: Insert local-first quickstart at cursor`.
3. The status-bar item appears (right side, `● Vouch`).
4. `Vouch: Ask the assistant` opens `vouch-protocol.com/ask` in the browser.

## Rolling back

Marketplace listings cannot be deleted in the UI for individual versions;
you can unpublish the whole extension with `vsce unpublish
vouch-protocol.vouch-vscode`, but prefer publishing a fixed `0.x.y+1`
release instead.
