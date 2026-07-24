# Vouch Protocol Gemini Gem

Everything needed to create the "Vouch Protocol Helper" Gem in Google
Gemini. Gems are Google's equivalent of Custom GPTs: a named persona
with custom instructions and an optional knowledge corpus, available to
both Gemini consumer plans and Google Workspace.

## Files

- `name.txt`: display name to paste into the Gem builder
- `description.txt`: short description shown in the Gem picker
- `instructions.md`: the system prompt (Gemini calls this "Instructions")
- `examples.md`: example prompts (Gemini calls these "Examples")
- `knowledge/`: files to attach as the Gem's knowledge

## Creating the Gem

1. Open https://gemini.google.com/gems/create
   (Gemini Advanced / Google AI Pro tier required for full Gem features.)
2. Click "New Gem"
3. **Name**: paste from `name.txt`
4. **Description**: paste from `description.txt`
5. **Instructions**: paste the full contents of `instructions.md`
6. **Files (knowledge)**: upload everything from `knowledge/` (Gemini
   accepts up to 10 files per Gem; the corpus is 10 files exactly).
7. Click "Preview" and run one of the prompts from `examples.md` to
   verify it loads the knowledge correctly.
8. Save & share (Private / People with the link / Workspace org)

## Tool use in the Gem

Gemini Gems run inside the Gemini surface, so they automatically have
access to Google Search and Google Workspace tools (Docs, Sheets, Gmail,
Calendar). Use this in the instructions: the Gem can pull current GitHub
state via Search, draft an email, or stub a Doc with a quickstart.

The Gem does NOT have programmatic Actions like an OpenAI Custom GPT.
If you need the Gem to sign Vouch credentials, instruct the user to
run the Python or TypeScript SDK locally; the Gem provides the code.

## Updating

When the protocol or SDKs change:

1. Refresh `knowledge/` from the canonical reference set.
2. Remove all files in the Gem and re-upload (Gemini's UI deduplicates
   by filename).
3. Bump the version note in `instructions.md`.

## Tier compatibility

- **Gemini Free tier**: Gems work but cannot pin to a long-context model.
  Limit knowledge to four files; the Gem will summarize on the fly.
- **Gemini Advanced / Google AI Pro**: full ten-file corpus, Gemini 2.x
  long context.
- **Workspace**: Gems can be shared to the org; admins can install for
  all users.
