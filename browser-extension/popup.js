/**
 * Vouch Protocol - Popup Script
 * 
 * Manages the extension popup UI:
 * - Display user's identity (email, public key)
 * - Show Address Book (contacts)
 * - Allow deleting contacts to reset trust
 */

// =============================================================================
// Tab Navigation
// =============================================================================

document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        // Update tab buttons
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');

        // Update tab panels
        const tabId = tab.dataset.tab;
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        document.getElementById(tabId).classList.add('active');

        // Load data for the tab
        if (tabId === 'me') {
            loadIdentity();
        } else if (tabId === 'contacts') {
            loadContacts();
        }
    });
});

// =============================================================================
// Identity Tab
// =============================================================================

async function loadIdentity() {
    const loading = document.getElementById('loading');
    const content = document.getElementById('identity-content');

    loading.style.display = 'block';
    content.style.display = 'none';

    try {
        const response = await chrome.runtime.sendMessage({ action: 'getMyIdentity' });

        if (response.success) {
            document.getElementById('my-email').textContent = response.data.email;
            document.getElementById('my-fingerprint').textContent = response.data.fingerprint;
            document.getElementById('my-pubkey').textContent = response.data.publicKey;

            // Load saved display name
            const settings = await chrome.storage.local.get(['vouch_display_name']);
            if (settings.vouch_display_name) {
                document.getElementById('display-name').value = settings.vouch_display_name;
            }

            loading.style.display = 'none';
            content.style.display = 'block';
        } else {
            loading.textContent = `Error: ${response.error}`;
        }
    } catch (error) {
        loading.textContent = `Error: ${error.message}`;
    }
}

// Save settings button
document.getElementById('save-settings').addEventListener('click', async () => {
    const displayName = document.getElementById('display-name').value.trim();

    await chrome.storage.local.set({
        vouch_display_name: displayName || null,
        vouch_is_pro: displayName ? true : false,  // Auto-enable pro if name is set
    });

    const btn = document.getElementById('save-settings');
    btn.textContent = '✅ Saved!';
    setTimeout(() => {
        btn.textContent = '💾 Save Settings';
    }, 2000);
});

// Copy public key button
document.getElementById('copy-key').addEventListener('click', async () => {
    const pubkey = document.getElementById('my-pubkey').textContent;
    try {
        await navigator.clipboard.writeText(pubkey);
        const btn = document.getElementById('copy-key');
        btn.textContent = '✅ Copied!';
        setTimeout(() => {
            btn.textContent = '📋 Copy Public Key';
        }, 2000);
    } catch (error) {
        alert('Failed to copy: ' + error.message);
    }
});

// =============================================================================
// Contacts Tab
// =============================================================================

async function loadContacts() {
    const container = document.getElementById('contacts-list');
    container.innerHTML = '<div class="loading">Loading contacts...</div>';

    try {
        const response = await chrome.runtime.sendMessage({ action: 'getAddressBook' });

        if (response.success) {
            const contacts = response.data;
            const emails = Object.keys(contacts);

            if (emails.length === 0) {
                container.innerHTML = `
          <div class="empty-state">
            <div class="empty-state-icon">📭</div>
            <div class="empty-state-text">
              No contacts yet.<br>
              Browse pages with Vouch signatures to add contacts.
            </div>
          </div>
        `;
                return;
            }

            container.innerHTML = '';

            for (const email of emails.sort()) {
                const contact = contacts[email];
                const item = document.createElement('div');
                item.className = 'contact-item';
                item.innerHTML = `
          <div class="contact-info">
            <div class="contact-email">${escapeHtml(email)}</div>
            <div class="contact-key">Key: ${contact.publicKey.substring(0, 20)}...</div>
          </div>
          <button class="contact-delete" data-email="${escapeHtml(email)}" title="Remove contact">🗑️</button>
        `;
                container.appendChild(item);
            }

            // Add delete handlers
            container.querySelectorAll('.contact-delete').forEach(btn => {
                btn.addEventListener('click', async () => {
                    const email = btn.dataset.email;
                    if (confirm(`Remove ${email} from contacts? This will reset trust and they will appear as "New Identity" again.`)) {
                        await chrome.runtime.sendMessage({ action: 'removeContact', email });
                        loadContacts(); // Reload
                    }
                });
            });
        } else {
            container.innerHTML = `<div class="loading">Error loading contacts</div>`;
        }
    } catch (error) {
        container.innerHTML = `<div class="loading">Error: ${error.message}</div>`;
    }
}

// =============================================================================
// Helpers
// =============================================================================

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// =============================================================================
// Initialize
// =============================================================================

document.addEventListener('DOMContentLoaded', loadIdentity);
