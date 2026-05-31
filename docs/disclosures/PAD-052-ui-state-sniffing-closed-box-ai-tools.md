# PAD-052: UI State Sniffing for Policy Extraction from Closed-Box AI Coding Applications

**Identifier:** PAD-052  
**Title:** Method for Extracting User-Declared Operational Policy from Closed-Source AI Coding Applications via Operating-System-Level Passive File-System Monitoring of Application State Caches Without Modification of the Target Application  
**Publication Date:** April 30, 2026  
**Prior Art Effective Date:** April 30, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** AI Safety / LLM Coding-Assistant Governance / Reverse-Compatibility / OS-Level Observation / Closed-Source Tool Augmentation  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-048 (Write-Only Asynchronous Context Ledger), PAD-049 (Decoupled Semantic Policy Extraction), PAD-051 (Parallel Intent Extraction via Local Shadow Models)  

---

## 1. Abstract

A method for extending in-session policy capture (per PAD-048) to closed-source AI coding applications, IDE extensions, and proprietary UI wrappers, where neither network interception (PAD-051) nor source-code monitoring (PAD-049) is feasible. The method uses operating-system-level passive file-system monitoring (`inotify` on Linux/WSL, `FSEvents` on macOS, `ReadDirectoryChangesW` on Windows) to observe the application's own session caches, SQLite databases, log files, and temporary state directories. When the target application persists user input (chat history, recent prompts, telemetry buffers), the monitor reads the persisted state, locates rule tags such as `<r>...</r>` in the user's recent input, and emits them into the standard Amnesia ledger.

The keystone property is **non-invasive observation**. The system does not modify the closed-source application, does not inject code into its address space, does not hook its API or runtime, and does not require its consent. It reads what the application already writes to disk during normal operation, and treats that as a side-effect signal of user intent. This is sometimes described as reading the "exhaust fumes" of the application.

Key innovations:

- **Read-only observation across closed boundaries.** The technique adds policy capture to applications whose authors did not provide a plugin API or extension point.
- **Cross-platform abstraction.** A unified watcher abstraction maps the platform-specific filesystem-event APIs to a single rule-extraction pipeline, supporting any application that persists user input on any major OS.
- **Application-state probes.** A library of per-application probes (Cursor's SQLite cache, Continue.dev's session log, JetBrains AI Assistant's state directory, etc.) enables drop-in support for new applications by adding a small probe descriptor.
- **No degradation of the target application.** Because the watcher only reads, and only reads files the application has already closed, there is no risk of corrupting the application's state or affecting its performance.

---

## 2. Problem Statement

### 2.1 Closed-source AI coding tools cannot be intercepted at API or CLI

PAD-051 specifies a network proxy approach that works for assistant clients whose API endpoint is configurable. However, several widely-deployed AI coding tools either:

- Hardcode their API endpoints (no environment variable, no settings UI to override).
- Use proprietary signing or attestation that breaks when traffic is proxied.
- Run inside an Electron or VS-Code wrapper that does not honor system proxy settings consistently.
- Are entirely closed-source and provide no plugin or extension API for capturing user input.

Examples include the AI features in JetBrains IDEs prior to plugin support, certain enterprise IDE wrappers, and several commercial coding assistants that bundle their own runtime.

### 2.2 Plugin architectures, where they exist, are insufficient

Some AI coding tools provide a plugin API but constrain it to surface-level features (snippets, command palettes) without exposing the user-input stream. A plugin cannot capture chat input.

### 2.3 Network interception breaks under TLS pinning

Even when traffic is proxiable in principle, several commercial AI applications pin TLS certificates and refuse to communicate through any proxy whose certificate the application does not pre-trust. Adding a custom CA for the user's local proxy is invasive and tool-specific.

### 2.4 No prior system extracts user-declared policy from closed-source AI tool state via OS-level passive monitoring

The technique of reading another application's persisted state to add policy capture, with the explicit intent of extending the application's behavior without modifying it, has not been deployed in the LLM-coding-assistant domain.

---

## 3. Solution (The Invention)

### 3.1 Operating-system-level file-system watcher

A small native daemon registers watchers against the file system locations where the target AI application persists user-facing state. The daemon does not poll continuously; it is event-driven via the OS notification API:

| OS | Notification API |
|---|---|
| Linux, WSL | `inotify` |
| macOS | `FSEvents` |
| Windows | `ReadDirectoryChangesW` |
| BSDs | `kqueue` |

On each file-modification event matching a configured probe, the daemon reads the file, parses it according to the probe's schema, locates rule tags in the user's recent input, and emits ledger entries.

### 3.2 Per-application probe library

Each supported application has a probe descriptor specifying:

```yaml
- application: "Cursor"
  identifier: "com.todesktop.230313mzl4w4u92"
  paths:
    macos: "~/Library/Application Support/Cursor/User/History/**/*"
    linux: "~/.config/Cursor/User/History/**/*"
    windows: "%APPDATA%/Cursor/User/History/**/*"
  storage_format: "sqlite-wal"
  user_input_query: |
    SELECT content FROM messages
    WHERE role='user' AND created_at > ?
  rule_extraction: "tag-r-grammar"

- application: "Continue.dev"
  identifier: "continue.continue"
  paths:
    macos: "~/.continue/sessions/*.json"
    linux: "~/.continue/sessions/*.json"
    windows: "%USERPROFILE%/.continue/sessions/*.json"
  storage_format: "json-array"
  user_input_query: "$..[?(@.role=='user')].content"
  rule_extraction: "tag-r-grammar"

- application: "JetBrains AI Assistant"
  identifier: "com.intellij.ml.llm"
  paths:
    macos: "~/Library/Logs/JetBrains/<product>/llm-assistant.log"
    linux: "~/.config/JetBrains/<product>/log/llm-assistant.log"
    windows: "%APPDATA%/JetBrains/<product>/log/llm-assistant.log"
  storage_format: "newline-delimited-json"
  user_input_query: "$.userMessage"
  rule_extraction: "tag-r-grammar"
```

Adding support for a new application is a configuration change, not a code change.

### 3.3 SQLite WAL polling

Many modern desktop applications persist user input via SQLite databases with Write-Ahead Logging (WAL). The watcher detects WAL file changes (`-wal` and `-shm` siblings of the main database file), opens the database in read-only mode (so as not to take a write lock), and queries for new user input rows since the last poll.

The read-only open is important: it ensures the watcher cannot corrupt the application's database, and it does not require the watcher to coordinate locks with the running application.

### 3.4 Log file tail monitoring

Applications that write user input to log files (JSON-lines or plain text) are watched via standard tail-on-rotation logic. The watcher:

1. Opens the log file for read.
2. Seeks to the previously-recorded offset.
3. Reads new bytes, parses each new record, extracts user-input fields, and applies rule extraction.
4. Records the new offset.
5. Handles log rotation by detecting inode changes.

### 3.5 Cache directory polling

For applications that store user input as discrete files (e.g., one chat session per JSON file under a cache directory), the watcher uses the OS notification API to detect new files and modifications, parses the files, and applies rule extraction.

### 3.6 Strict read-only stance

The watcher never writes to any of the target application's data directories. It does not modify, lock, or signal the application. If an application changes its storage format in an update, the relevant probe stops producing results until the probe descriptor is updated; the application itself is unaffected.

---

## 4. Prior Art Differentiation

| System | Reads other apps' state? | Read-only? | LLM-coding-assistant domain? | Multiple applications via probe library? |
|---|---|---|---|---|
| `lsof`, `ss`, `inotifywatch` (introspection tools) | Yes | Yes | No | N/A |
| Endpoint DLP agents (Forcepoint, Symantec, Microsoft Purview) | Yes | Yes | No (generic data) | Yes (signature library) |
| Forensic acquisition tools (FTK, EnCase) | Yes | Yes | No | Yes |
| Antivirus file-system filters | Yes | Mostly read-only | No | Yes |
| Application-specific AI plugins (Cursor extensions, Continue.dev plugins) | No (in-process) | N/A | Yes | No (one app per plugin) |
| **This disclosure** | **Yes** | **Yes** | **Yes** | **Yes** |

Differentiating claims:

1. The application of OS-level passive read-only file-system monitoring to closed-source AI coding tools, for the explicit purpose of extracting user-declared operational policy without modifying the target application, is novel.
2. The probe-library architecture, which converts adding support for a new closed-source AI tool from a code change into a configuration change, is a deployable engineering pattern not present in prior systems.
3. The combination of SQLite WAL read-only observation, log-file tail monitoring, and cache-directory polling, unified under a single rule-extraction pipeline targeting LLM coding assistants, is novel.
4. The technique fills a gap that PAD-051 (network proxy) cannot address (TLS-pinned and proxy-incompatible applications) and that PAD-049 (source comments) cannot address (chat input that never reaches source files).

---

## 5. Technical Implementation

### 5.1 Cross-platform abstraction layer

A small abstraction layer hides the OS-specific notification APIs behind a uniform `Watcher.subscribe(path_pattern, callback)` interface. Implementations:

```
watcher/
  linux.go    (uses fsnotify, which wraps inotify)
  macos.go    (uses fsevents)
  windows.go  (uses ReadDirectoryChangesW via fsnotify)
```

### 5.2 Application identification

When multiple AI coding applications are running, the watcher uses the bundle identifier (macOS), package name (Linux .desktop file), or app GUID (Windows registry) to associate each watched path with its source application. This metadata is included in the ledger entry's `source` field for auditability.

### 5.3 Privacy and consent

The watcher reads only data the user has already produced and the application has already persisted. It does not read messages from the LLM provider's response stream (those are the LLM's outputs, not the user's). It does not capture system prompts injected by the application, telemetry payloads, or any other content the user did not author.

A clear consent dialog at first run explains which directories the watcher will observe and which probes are active. The user can disable any probe at any time.

### 5.4 Reliability under application updates

When a target application updates and changes its storage format, the existing probe may produce no matches (graceful degradation) or, in rare cases, produce malformed output (which is rejected by ledger schema validation). The system never produces incorrect rules from stale probes.

### 5.5 Integration with the unified ledger

Rules extracted via UI sniffing land in the same `.vouch/ledger/` as rules from PAD-048 (chat tags), PAD-049 (source comments), and PAD-051 (proxy-based extraction). The Compactor reduces them uniformly. The downstream enforcement (PAD-050) does not need to know which extraction path produced a given rule.

---

## 6. Claims Summary

The following aspects are disclosed as prior art:

1. A method for extracting user-declared operational policy from closed-source AI coding applications by registering operating-system-level file-system watchers against the application's session caches, SQLite databases, log files, or temporary state directories, and parsing the application's already-persisted state to locate rule tags.

2. A read-only observational stance in which the watcher never modifies, locks, or signals the target application, ensuring that the technique adds capability to the application without affecting its operation, performance, or data integrity.

3. A probe-library architecture in which support for a new closed-source AI application is added by writing a small declarative descriptor specifying the application's storage paths, format, and user-input query, rather than by modifying the watcher's code.

4. A SQLite WAL read-only polling technique in which the watcher detects WAL changes, opens the database without acquiring a write lock, queries for new user-input rows, and emits ledger entries, all without interfering with the running application.

5. The combination of (1) through (4) as a unified extension method for adding policy capture to AI coding applications that lack plugin or extension APIs, do not honor system proxy settings, or pin their TLS certificates against network interception.

---

## Prior Art Declaration

This document is published as a defensive prior art disclosure under the Apache 2.0 license. The methods and systems described herein are hereby placed into the public domain to prevent patent monopolization. Any party implementing similar functionality after the publication date of this document cannot claim novelty for patent purposes.

**Reference Implementation:** https://github.com/vouch-protocol/vouch
