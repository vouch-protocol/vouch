# Vouch Protocol Custom GPT

Everything needed to create the "Vouch Protocol Assistant" Custom GPT
in ChatGPT. The Custom GPT helps developers understand and integrate
Vouch; the optional Actions integration lets it sign credentials on
the developer's behalf via the hosted Vouch agent.

## Files

- `name.txt`: display name to paste into the builder
- `description.txt`: short description (under 300 chars)
- `instructions.md`: the system prompt
- `conversation-starters.md`: four starters for the builder
- `actions.yaml`: OpenAPI schema for ChatGPT Actions (optional)
- `actions-auth.md`: auth setup for Actions
- `knowledge/`: files to upload as the GPT's Knowledge

## Creating the GPT

1. Open https://chatgpt.com/gpts/editor
2. Click "Configure"
3. **Name**: paste from `name.txt`
4. **Description**: paste from `description.txt`
5. **Instructions**: paste from `instructions.md`
6. **Conversation starters**: paste each line from `conversation-starters.md`
7. **Knowledge**: upload all files from `knowledge/`
8. **Capabilities**: enable "Web Browsing" and "Code Interpreter"; leave
   "DALL-E" off
9. **Actions** (optional): paste `actions.yaml`, configure auth per
   `actions-auth.md`
10. Save & publish (Anyone with the link / Only me / Public)

## Updating

Whenever the protocol changes:

1. Refresh `knowledge/` with current docs (the same content as the
   Claude skill's `reference/` folder).
2. Re-upload to the GPT (the builder replaces files by name).
3. Bump the version note in `instructions.md` so users can tell.

## Not included

- A logo (provide a 512x512 PNG matching the Vouch website's icon set)
- Actions hosting (point the GPT at https://agent.vouch-protocol.com)
- Analytics (ChatGPT does not expose per-GPT analytics outside the
  builder's "Usage" tab)
