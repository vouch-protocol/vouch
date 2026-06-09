/**
 * Vouch email assistant — Cloudflare Email Worker
 *
 * Receives inbound mail at ask@vouch-protocol.com, drafts a reply using
 * Gemini 1.5 Flash with the Vouch knowledge base in the prompt, sends the
 * reply via Resend, and forwards a copy to the maintainer for visibility.
 *
 * Configuration: see wrangler.toml. Secrets via `wrangler secret put`.
 *
 * Cost: $0/month at typical inbound volume (Gemini free tier 1500 req/day,
 * Resend free tier 3000 emails/month, Cloudflare Email Workers free).
 */

import PostalMime from 'postal-mime';

// ---------------------------------------------------------------------------
// System prompt: gives Gemini the Vouch context. Kept compact; for richer
// retrieval, replace this with a RAG step against the Vouch knowledge base.
// ---------------------------------------------------------------------------
const SYSTEM_PROMPT = `You are the Vouch Assistant, an AI email responder for the Vouch Protocol open-source project (https://vouch-protocol.com).

You answer technical questions about the protocol. Vouch is an open specification and reference implementation (Python, TypeScript, Go) for cryptographic identity and continuous state verifiability of autonomous AI agents.

Core facts you can rely on:
- Vouch is built on W3C Verifiable Credentials Data Model 2.0 + Data Integrity proofs (eddsa-jcs-2022 cryptosuite, Ed25519 over RFC 8785 JCS-canonicalized payloads).
- For the post-quantum transition, Vouch defines a dual-proof profile: one eddsa-jcs-2022 proof + one mldsa44-jcs-2026 proof (ML-DSA-44, FIPS 204) on the same JCS bytes.
- Identity Sidecar pattern: the LLM "Brain" holds zero keys; a small deterministic "Passport" daemon holds the keys, applies an allow-list policy, and signs only what passes. This bounds a prompt-injected Brain's capability.
- Delegation chains carry per-link Data Integrity proofs and a resource-narrowing rule.
- State Verifiability layer: trust entropy decay, heartbeat protocol, behavioral attestation digests, canary commit/reveal chains, M-of-N validator quorum.
- Implementation is open source (Apache 2.0). Sixty defensive prior-art disclosures (PADs) accompany the spec under CC0.
- Live verification of any Vouch-signed artefact: https://vch.sh/<id>

Style:
- 2-4 short paragraphs maximum. Be concrete.
- Always point to specific resources: arXiv paper URL, GitHub repo, the relevant blog post or section of the CCG report.
- If you genuinely don't know, say so and offer to flag for human follow-up.
- Do not invent features, deadlines, or commitments. The maintainer is on parental leave; do not promise future calls or work.

Sign off with this footer (verbatim):
---
This response was drafted by Vouch Assistant during the maintainer's parental leave. It is itself Vouch-signed: verify at https://vch.sh/email-assistant. For personal follow-up after October 2026, reply with "PERSONAL" in the subject.`;

// ---------------------------------------------------------------------------
// Cloudflare Email Worker entrypoint.
// ---------------------------------------------------------------------------
export default {
  async email(message, env, ctx) {
    let parsed;
    let replyTo;
    let subject;

    try {
      const parser = new PostalMime();
      parsed = await parser.parse(message.raw);
      replyTo = parsed.from?.address || message.from;
      subject = parsed.subject || '(no subject)';

      const bodyText =
        parsed.text ||
        (parsed.html ? stripHtml(parsed.html) : '') ||
        '(empty body)';

      // Heuristic: short emails get short replies; long emails get medium.
      const isShort = bodyText.length < 200;

      // Generate reply via Gemini.
      const replyBody = await draftWithGemini(env.GEMINI_API_KEY, {
        from: replyTo,
        subject,
        body: bodyText,
        maxOutputTokens: isShort ? 384 : 768,
      });

      // Send reply via Resend.
      await sendViaResend(env, {
        to: replyTo,
        subject: subject.toLowerCase().startsWith('re:') ? subject : `Re: ${subject}`,
        body: replyBody,
      });

      // Visibility copy to the maintainer.
      if (env.FORWARD_TO) {
        await message.forward(env.FORWARD_TO);
      }
    } catch (err) {
      // On any failure, forward the original email so nothing is silently lost.
      console.error('vouch-email-assistant error:', err);
      if (env.FORWARD_TO) {
        try {
          await message.forward(env.FORWARD_TO);
        } catch (_) {
          // last resort: drop silently rather than 500
        }
      }
    }
  },
};

// ---------------------------------------------------------------------------
// Gemini call.
// ---------------------------------------------------------------------------
async function draftWithGemini(apiKey, { from, subject, body, maxOutputTokens }) {
  if (!apiKey) throw new Error('GEMINI_API_KEY not configured');

  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=${apiKey}`;

  const userPrompt = `Incoming email:
From: ${from}
Subject: ${subject}

${body}

Draft your reply.`;

  const requestBody = {
    contents: [
      { role: 'user', parts: [{ text: SYSTEM_PROMPT + '\n\n' + userPrompt }] },
    ],
    generationConfig: {
      temperature: 0.4,
      topP: 0.9,
      maxOutputTokens,
      // Avoid the assistant adding markdown formatting that won't render in plain-text email.
      responseMimeType: 'text/plain',
    },
    safetySettings: [
      { category: 'HARM_CATEGORY_HARASSMENT', threshold: 'BLOCK_NONE' },
      { category: 'HARM_CATEGORY_HATE_SPEECH', threshold: 'BLOCK_NONE' },
      { category: 'HARM_CATEGORY_SEXUALLY_EXPLICIT', threshold: 'BLOCK_NONE' },
      { category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_NONE' },
    ],
  };

  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(requestBody),
  });

  if (!r.ok) {
    const errText = await r.text();
    throw new Error(`Gemini API ${r.status}: ${errText.slice(0, 300)}`);
  }

  const data = await r.json();
  const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!text) {
    throw new Error('Gemini returned no text: ' + JSON.stringify(data).slice(0, 300));
  }
  return text.trim();
}

// ---------------------------------------------------------------------------
// Resend send.
// ---------------------------------------------------------------------------
async function sendViaResend(env, { to, subject, body }) {
  if (!env.RESEND_API_KEY) throw new Error('RESEND_API_KEY not configured');

  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: `${env.FROM_NAME} <${env.FROM_ADDRESS}>`,
      to: [to],
      subject,
      text: body,
      headers: {
        'X-Vouch-Signer': env.SIGNED_BY,
        'X-Vouch-Verify': 'https://vch.sh/email-assistant',
      },
    }),
  });

  if (!r.ok) {
    const errText = await r.text();
    throw new Error(`Resend API ${r.status}: ${errText.slice(0, 300)}`);
  }
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------
function stripHtml(html) {
  return html
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}
