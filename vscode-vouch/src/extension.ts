/**
 * Vouch Protocol VS Code extension - v0.1.0.
 *
 * The extension is deliberately small and local-first. It does NOT phone home,
 * does NOT require an internet connection to function, and does NOT scan the
 * user's source for "vouch readiness" without consent. Three things it does:
 *
 *   1. Insert language-aware local-first quickstart snippets at the cursor
 *      (Python, TypeScript, Go). Same code as the vouch-protocol.com Guides,
 *      so a developer can ctrl-shift-P -> "Vouch: Insert" and have a working
 *      sign+verify loop without leaving VS Code.
 *
 *   2. Open an integrated terminal and run `vouch init` for the user, after
 *      asking for a domain (default "localhost" for dev work). Friendly nudge
 *      toward did:web:localhost first, then graduate to a real domain.
 *
 *   3. Open the Vouch Assistant chat in the user's default browser, so they
 *      can ask Vouch-specific questions without copy-pasting docs.
 *
 * A status-bar item (right side) gives a single click into the Vouch command
 * group. Configurable in settings (vouch.statusBar.enabled).
 */

import * as vscode from 'vscode';

const QUICKSTART_PYTHON = `from vouch.keys import generate_identity
from vouch.signer import Signer
from vouch.verifier import Verifier

# Generate an in-memory identity. The "domain" string is a label inside the
# DID; nothing is published anywhere yet. Replace with your real domain when
# you graduate to production.
identity = generate_identity(domain="localhost")

signer = Signer(
    private_key=identity.private_key_jwk,
    did=identity.did,
)

token = signer.sign({
    "action": "submit_claim",
    "target": "claim:HC-001",
    "resource": "https://insurance.example.com/claims/HC-001",
})

# trusted_roots is the local-dev escape hatch. In production drop both
# arguments and let the verifier resolve did:web over HTTPS.
verifier = Verifier(
    trusted_roots={identity.did: identity.public_key_jwk},
    allow_did_resolution=False,
)
ok, passport = verifier.check_vouch(token)
assert ok, "verification failed"
print("verified:", passport.payload)
`;

const QUICKSTART_TYPESCRIPT = `import {
  Signer,
  Verifier,
  generateIdentity,
  buildVouchCredential,
} from '@vouch-protocol/core';

async function main() {
  // Generate an in-memory identity. "localhost" is a placeholder label;
  // nothing is published anywhere yet.
  const identity = await generateIdentity('localhost');

  const signer = new Signer({
    privateKey: identity.privateKeyJwk,
    did: identity.did!,
  });

  const credential = buildVouchCredential({
    subjectDid: identity.did!,
    intent: {
      action: 'submit_claim',
      target: 'claim:HC-001',
      resource: 'https://insurance.example.com/claims/HC-001',
    },
    validSeconds: 300,
  });

  const signed = await signer.signCredential(credential);
  console.log('signed proof value:', signed.proof.proofValue);

  // trustedRoots is the local-dev escape hatch. In production drop both
  // arguments and let the verifier resolve did:web over HTTPS.
  const verifier = new Verifier({
    trustedRoots: { [identity.did!]: identity.publicKeyJwk },
    allowDidResolution: false,
  });
  const result = await verifier.verifyCredential(signed);
  console.log('valid:', result.valid, 'reasons:', result.reasons);
}

main().catch(console.error);
`;

const QUICKSTART_GO = `// Run the Vouch sidecar locally:
//   ./vouch-sidecar --did did:web:localhost --port 8877
//
// Then sign a credential by POSTing to localhost. Any language can call it.
package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

func main() {
	body := []byte(\`{
		"subjectDid": "did:web:localhost",
		"intent": {
			"action": "submit_claim",
			"target": "claim:HC-001",
			"resource": "https://insurance.example.com/claims/HC-001"
		},
		"validSeconds": 300
	}\`)

	resp, err := http.Post(
		"http://localhost:8877/sign",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	out, _ := io.ReadAll(resp.Body)
	fmt.Println(string(out))
}
`;

type QuickstartLang = 'python' | 'typescript' | 'go';

function quickstartFor(lang: QuickstartLang): string {
  switch (lang) {
    case 'python':
      return QUICKSTART_PYTHON;
    case 'typescript':
      return QUICKSTART_TYPESCRIPT;
    case 'go':
      return QUICKSTART_GO;
  }
}

function detectLanguageFor(editor: vscode.TextEditor | undefined): QuickstartLang {
  const id = editor?.document.languageId;
  if (id === 'python') return 'python';
  if (id === 'go') return 'go';
  return 'typescript';
}

async function insertLocalQuickstart(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  const detected = detectLanguageFor(editor);
  const choice = await vscode.window.showQuickPick(
    [
      { label: 'Python', value: 'python' as QuickstartLang, description: detected === 'python' ? '(matches current file)' : undefined },
      { label: 'TypeScript / JavaScript', value: 'typescript' as QuickstartLang, description: detected === 'typescript' ? '(matches current file)' : undefined },
      { label: 'Go', value: 'go' as QuickstartLang, description: detected === 'go' ? '(matches current file)' : undefined },
    ],
    {
      placeHolder: 'Pick a language for the local-first sign + verify quickstart',
    },
  );
  if (!choice) return;

  const snippet = quickstartFor(choice.value);

  if (!editor) {
    // No active editor — open a fresh untitled buffer in the chosen language.
    const langId = choice.value === 'typescript' ? 'typescript' : choice.value;
    const doc = await vscode.workspace.openTextDocument({
      content: snippet,
      language: langId,
    });
    await vscode.window.showTextDocument(doc);
    return;
  }

  await editor.edit((builder) => {
    builder.insert(editor.selection.active, snippet);
  });
}

async function runInit(): Promise<void> {
  const domain = await vscode.window.showInputBox({
    prompt: 'Domain for the new Vouch identity. Use "localhost" for dev-only.',
    placeHolder: 'localhost',
    value: 'localhost',
    validateInput: (v) => {
      if (!v || !v.trim()) return 'Domain is required.';
      if (/[\s'"`;|]/.test(v)) return 'Domain cannot contain whitespace or shell metacharacters.';
      return null;
    },
  });
  if (!domain) return;

  const term =
    vscode.window.terminals.find((t) => t.name === 'Vouch') ??
    vscode.window.createTerminal({ name: 'Vouch' });
  term.show(true);
  // Quote the domain defensively even though we validated it; belt + braces.
  term.sendText(`vouch init --domain ${JSON.stringify(domain)}`, true);
}

async function openAskAssistant(): Promise<void> {
  const url = vscode.workspace
    .getConfiguration('vouch')
    .get<string>('assistant.url', 'https://vouch-protocol.com/ask');
  await vscode.env.openExternal(vscode.Uri.parse(url));
}

function createStatusBarItem(context: vscode.ExtensionContext): void {
  const enabled = vscode.workspace.getConfiguration('vouch').get<boolean>('statusBar.enabled', true);
  if (!enabled) return;

  const item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 99);
  item.text = '$(shield) Vouch';
  item.tooltip = 'Vouch Protocol: insert quickstart, init identity, or open the assistant';
  // Use the workbench action to filter palette to "Vouch:".
  item.command = {
    title: 'Show Vouch commands',
    command: 'workbench.action.quickOpen',
    arguments: ['>Vouch: '],
  };
  item.show();
  context.subscriptions.push(item);
}

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.commands.registerCommand('vouch.insertLocalQuickstart', insertLocalQuickstart),
    vscode.commands.registerCommand('vouch.runInit', runInit),
    vscode.commands.registerCommand('vouch.openAskAssistant', openAskAssistant),
  );
  createStatusBarItem(context);
}

export function deactivate(): void {
  // No persistent resources to clean up.
}
