# Diamy Mail — ANNEX A26: Multi-Account Client

**Document title:** Diamy Mail — ANNEX A26: Multi-Account Client
**Version:** 1.3
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 4th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.6 (A00)
**Sibling dependencies:** A03 (Vault Client v1.1), A04 (Native Sync API v1.2), A17 (IAM v1.2), A19 (Client SDK v1.1), A25 (Architecture Invariants v1.1)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: multi-account client model — several Diamy identities (principals, possibly across tenants) coexisting in one native client, with strict per-account isolation, per-account vault/keys/sessions, account switching, optional unified inbox as a client-side merged view (never a merged store), compose-account selection, per-account settings/entitlements, notifications, offboarding/removal, failure model, test scenarios, common AI errors. Scope is Diamy↔Diamy identities only (external non-Diamy accounts, e.g. Gmail/IMAP, are explicitly out of scope). |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass (no contradictions found — clean design): clarified that N accounts on one physical machine = N independent IAM device enrollments, not N physical devices (A26-ACCT-2b, consistent with A20-CRED-4b and the A00 multi-device model); noted the Bridge (A20) is per-account for a multi-account user — each account wanting third-party-client access enrolls its own Bridge device, preserving isolation (A26-ACCT-2b). Confirmed §12 keeps the A25 INV-3 plaintext-exception list unchanged. |
| 1.3     | Jul 4th 2026 | Cédric BORNECQUE | Final sweep: fixed one more unqualified epoch mention (A26-ISO-5) missed in v1.2's pass, referencing A17-TOK-2. |
| 1.2     | Jul 4th 2026 | Cédric BORNECQUE | Coherence fix following review of the Diamy IAM – Integration Specification v1.6: softened three unqualified "epoch bump" mentions (A26-ISO-3, test #2, AI error #8) to reference A17-TOK-2's flagged (unconfirmed) revocation mechanism, consistent with the corpus-wide correction applied across A03/A04/A17/A20/A25. |

------

# Table of contents

[toc]

------

# 1. Scope

This annex specifies how a single Diamy **native client** hosts **multiple Diamy accounts** — several IAM principals (e.g. `cedric@teqtel.fr` and `cedric@w3tel.fr`, possibly in different tenants) — so a user with more than one Diamy identity can use them from one application without logging in and out. It is a **client-side coordination layer** over the already per-principal foundations (A03/A04/A17); it adds no server capability and changes no server behavior.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 In scope / out of scope

- **In scope**: multiple **Diamy** accounts (IAM principals) in one client; their isolation, coexistence, switching, and an optional unified view.
- **Out of scope (explicitly)**: connecting a **non-Diamy external account** (Gmail, a third-party IMAP/Exchange mailbox) *into* the Diamy client. That would require the client to speak outbound IMAP/SMTP to a foreign provider and to store non-Diamy-encrypted mail, which breaks the zero-access model for that mail and is a separate product/security decision. It is NOT covered here and MUST NOT be inferred from this annex. (The inverse direction — third-party clients reaching a Diamy mailbox — is the Bridge, A20.)

## 1.2 Why this is a coordination layer, not a redesign

The corpus is already per-principal end to end: the server isolates principals (A04-EP-3 forbids cross-principal access; cursors, journals, key directories, and mail-plane tokens are per-principal, A04/A17); the vault (A03) and its keys are per-principal. Multi-account therefore does NOT change the server or the crypto — it specifies how the **client** runs several per-principal contexts side by side, keeps them isolated, and presents them coherently. Each account is a full, independent A03 vault + A17 session; A26 governs their coexistence.

------

# 2. Account Model

- **A26-ACCT-1**: An **account** in the client is one IAM principal with a mail entitlement (A17-ENT-1), identified by its canonical address (A24) and its IAM principal/tenant context. The client maintains a list of enrolled accounts, each a fully independent context (§3). A user MAY add, remove, and switch between accounts.
- **A26-ACCT-2** (independent enrollment): Adding an account is a full, independent enrollment/authentication against IAM (A17) for that principal — its own device enrollment (A17-DIR-3), its own device mail keys (A17-KEY-2), its own mail-plane token (A17-TOK). Adding account B does NOT reuse account A's device identity, keys, or session. Each account's device is a distinct IAM device (consistent with A25 INV-11).
- **A26-ACCT-2b** (device semantics & Bridge, clarification): "Device" here is the **IAM device** sense (a client instance with its own keys), not the physical machine. N accounts running on ONE physical machine means **N independent IAM device enrollments** on that machine — one per account — not one shared device and not N physical devices. This mirrors A20-CRED-4b (the Bridge is its own enrolled device even when co-located with the native app) and the A00 multi-device model. Consequence for the **Bridge** (A20): the Bridge is **per-account** — a multi-account user who wants third-party-client access to two accounts enrolls a Bridge device per account (each with its own app-scoped Bridge password, loopback listener, and revocation), preserving the strict per-account isolation (§3). One Bridge instance MUST NOT serve two accounts' mailboxes through a shared listener/credential (that would breach A26-ISO).
- **A26-ACCT-3** (cross-tenant): The accounts MAY belong to **different tenants**. Tenant-scoped policy (webmail allowed, Bridge allowed, retention, classification rules, etc.) applies **per account** according to that account's tenant — the client MUST NOT apply one account's tenant policy to another. A stricter tenant's rules bind its account regardless of a laxer tenant's account in the same client.

------

# 3. Strict Per-Account Isolation (Normative — security-critical)

This is the core security requirement of multi-account: co-location in one app MUST NOT weaken the isolation the server already enforces.

- **A26-ISO-1** (separate vaults): Each account has its **own vault** (A03): its own SQLCipher catalogue, its own blob store, its own `k_cat`, its own device mail key, its own `k_folder` and `k_bi_*`. These MUST be stored under per-account-scoped secure-store items and per-account-separated local storage. One account's catalogue/blobs MUST NOT be readable with another account's keys.
- **A26-ISO-2** (no cross-account decryption): An account's keys MUST decrypt ONLY that account's data. The client MUST NOT provide any path by which account A's key material could be used against account B's ciphertext, even by a bug — key handles are bound to their account context (RECOMMENDED: encode the account identity in the key derivation/lookup, and in the type system per A18-TYPE / A19, so a cross-account key use is a compile or lookup error, not a silent leak).
- **A26-ISO-3** (separate sessions): Each account holds its own mail-plane token(s) and sync session (A17/A04), verified and revoked independently. A session revocation on account A (mechanism per A17-TOK-2 — confirmation pending) stops account A's sessions and MUST NOT affect account B. A revoked account is removed/locked without touching the others.
- **A26-ISO-4** (no metadata bleed): Search (A05), trust history (A06 on-device correspondent history), and classification training (A16 local) are **per-account** and MUST NOT cross accounts: account A's local search MUST NOT return account B's messages; A's correspondent history MUST NOT inform B's trust scores; A's classification corrections MUST NOT train B. The unified view (§5) is a **presentation** merge, not a data merge (§5).
- **A26-ISO-5** (offboarding one account): Removing an account (user action, or entitlement loss / session revocation on that account, mechanism per A17-TOK-2, A03-SEC-5) MUST dispose of THAT account's local vault per its tenant's policy (wipe or key-destruction, A03-SEC-5) and MUST leave the other accounts intact. Offboarding is per-account.

------

# 4. Account Lifecycle

- **A26-LIFE-1** (add): The user adds an account by authenticating that principal against IAM (A17); the client enrolls a new device for it, provisions its vault, and begins sync (A04). Adding an account MUST NOT require removing another.
- **A26-LIFE-2** (switch): The user switches the **active account** (the one whose folders/compose context are foregrounded). Switching is a UI/context change; it MUST NOT log out or desync background accounts — background accounts continue syncing (subject to resource policy, §7) so switching to them is instant and current.
- **A26-LIFE-3** (remove): The user removes an account; the client disposes of its local vault (A26-ISO-5) and its sessions, and drops it from the account list. Other accounts are unaffected.
- **A26-LIFE-4** (re-auth): An account whose session expires or is revoked (A17) enters a re-auth-required state **independently**; the other accounts keep working. The client surfaces which account needs attention without blocking the rest.
- **A26-LIFE-5** (per-account lock): App-lock (A03-SEC-1) locks the whole app (all accounts) by default. A tenant/user MAY additionally require per-account unlock for a stricter account (e.g. a high-security tenant's account needs its own biometric even after app unlock) — a per-account gate layered on the app lock.

------

# 5. Unified Inbox — a Presentation Merge, Never a Data Merge (Normative)

A user often wants "one inbox" across accounts. This is provided as a **client-side merged view**, with a hard rule that it never merges the underlying data or crosses the isolation boundary.

- **A26-UNI-1**: A unified inbox MAY present messages from multiple accounts in one chronological list. This is a **read-time presentation merge over separate per-account stores** (A26-ISO-1): the client queries each account's vault independently and interleaves the results for display. There is NO merged catalogue, NO merged blob store, NO shared key — the merge exists only in the rendered list.
- **A26-UNI-2** (account attribution): Every message in a unified view MUST be unambiguously attributed to its account (which identity received it), because the same sender may write to two of the user's addresses, and because acting on a message (reply, move, delete) happens in that message's account context. The UI MUST make the owning account clear and MUST route actions to the correct account's session (§6).
- **A26-UNI-3** (no cross-account operation): An operation on a unified-view message (flag, move, delete, reply) MUST execute in that message's **own account** (its vault, its session, its folders). The client MUST NOT, for example, move a message from account A into a folder of account B — folders are per-account (they are that account's encrypted `mail.folders`). "Move" in a unified view means "move within the owning account".
- **A26-UNI-4** (search in unified view): A unified search queries each account's local index (A05) separately and merges results, each attributed to its account (A26-UNI-2). It MUST NOT build a cross-account index (A26-ISO-4). Results from account A and account B coexist in the list but come from, and link back to, their own stores.
- **A26-UNI-5** (opt-in, and per-account exclusion): The unified view SHOULD be optional (a user may prefer separate per-account inboxes), and a user/tenant MAY exclude a specific account from the unified view (e.g. keep a sensitive tenant's mail in its own siloed inbox, never blended into the unified list) — an isolation-preserving option.

------

# 6. Compose & Send Account Selection

- **A26-SEND-1**: When composing, the client MUST have an unambiguous **sending account** (which identity the message is from). In a reply, it defaults to the account that owns the message being replied to (the address the original was sent to). In a new message, it defaults to the active account (§4) and MUST let the user pick among their accounts.
- **A26-SEND-2**: The send executes entirely in the chosen account's context: its outbound path (A04 `/submit` → A10), its DKIM/SPF/DMARC identity (A10/A11 for that account's domain), its Sent copy stored in that account's vault, its rate limits (A10-RL) against that account. The client MUST NOT send from account A using account B's session or identity — that would be From-spoofing across the user's own accounts and is forbidden (A10-AUTH-4 analogue).
- **A26-SEND-3** (no accidental cross-account leak): Auto-complete of recipients, signatures, and quoted history MUST be scoped to the sending account, so composing from account A does not surface account B's contacts or content. Cross-account contact bleed is a metadata-isolation violation (A26-ISO-4).

------

# 7. Resource & Sync Policy

- **A26-RES-1**: Background accounts sync per the same native sync rules (A04) and cache policy (A03-CACHE), but the client MUST bound aggregate resource use across accounts (total disk budget, connection count, background activity) so N accounts do not multiply resource consumption unboundedly. A per-account share within a client-wide budget is RECOMMENDED; the exact split is tunable.
- **A26-RES-2**: On a metered/constrained connection (mobile), the client MAY prioritize the active account's sync and defer background accounts' blob prefetch (metadata still syncs so unified/switch stays current). This is a performance policy; correctness (eventual full sync) MUST hold for all accounts.
- **A26-RES-3** (notifications): Push/notification wakeups (A04/A19 signal-only) are per-account; the client MUST attribute a notification to its account and MUST NOT reveal one account's content in another's context. A unified notification stream is a presentation merge (A26-UNI-1 discipline), not a data merge.

------

# 8. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| One account's session expires/revoked | That account enters re-auth-required independently; others keep working (A26-LIFE-4, A26-ISO-3) |
| One account's vault corrupt | Rebuild that account's vault from its server (A03 failure model); other accounts unaffected |
| Cross-account key use attempted (bug) | MUST be impossible by construction (A26-ISO-2); if detected, hard-fail that operation, never decrypt across accounts |
| Unified-view action on a message | Routed to the owning account's context; never executed cross-account (A26-UNI-3) |
| Send with ambiguous account | Block until the sending account is explicit (A26-SEND-1) |
| Account removed | That account's local data disposed per its tenant policy; others intact (A26-ISO-5, A26-LIFE-3) |
| Resource pressure (many accounts) | Bound aggregate use; prioritize active account; all accounts still reach eventual full sync (A26-RES-1/2) |
| One account's tenant forbids a feature (webmail/Bridge) | Applies to that account only; MUST NOT constrain or enable it for others (A26-ACCT-3) |

------

# 9. Observability Contract

Per A00 §11 (privacy-preserving):

- counters (client-side, aggregate): `accounts_enrolled` (count only), `account_switches_total`, `unified_view_queries_total`, `cross_account_operation_blocks_total` (should be ~0 — a non-zero rate indicates an isolation bug)
- **A26-OBS-1**: Telemetry MUST NOT reveal which accounts a user holds, their addresses, or any correlation between a user's accounts (that a person controls both `cedric@teqtel.fr` and `cedric@w3tel.fr` is sensitive). Only aggregate counts, never the identities or their linkage. This linkage MUST NOT be sent server-side at all (each account's server sees only that account; the *client* knows the linkage and MUST keep it local).
- **A26-OBS-2**: `cross_account_operation_blocks_total` is a security indicator (A22 candidate): any block means the client attempted a cross-account operation that isolation correctly refused — it should be zero, and a non-zero rate warrants investigation.

------

# 10. Test Scenarios (Normative)

1. **Isolation — separate vaults**: two accounts → two independent SQLCipher catalogues + blob stores + keys; assert account A's key cannot decrypt account B's catalogue/blobs (A26-ISO-1/2).
2. **Independent sessions**: revoke account A's session → A requires re-auth; B keeps syncing and working, untouched (A26-ISO-3, A26-LIFE-4).
3. **No metadata bleed**: local search in account A returns only A's messages; A's correspondent history does not affect B's trust scores; A's classification corrections do not train B (A26-ISO-4).
4. **Unified view is presentation-only**: unified inbox interleaves A and B messages, each attributed to its account; assert no merged catalogue/index/key exists — the merge is only in the rendered list (A26-UNI-1/2).
5. **Unified action routing**: flag/move/delete/reply on a unified-view message executes in that message's owning account; a move stays within the owning account's folders; never cross-account (A26-UNI-3).
6. **Compose account selection**: reply defaults to the account the original was addressed to; new message lets the user pick; send uses that account's identity/DKIM/Sent-copy/rate-limits; cannot send from A using B (A26-SEND-1/2).
7. **Contact scoping**: composing from A auto-completes only A's recipients; B's contacts not surfaced (A26-SEND-3).
8. **Cross-tenant policy**: account A (tenant X, webmail forbidden) + account B (tenant Y, webmail allowed) → webmail available for B only; A's restriction not applied to B and vice versa (A26-ACCT-3).
9. **Per-account offboarding**: remove account A → A's local vault disposed per tenant X policy; B fully intact (A26-ISO-5, A26-LIFE-3).
10. **Per-account lock**: a high-security account requires its own biometric even after app unlock (A26-LIFE-5).
11. **Resource bound**: five accounts → aggregate disk/connection use bounded; active account prioritized on metered connection; all reach eventual full sync (A26-RES).
12. **Linkage privacy**: assert the fact that one user holds both accounts is never sent server-side; telemetry never reveals account identities or linkage (A26-OBS-1).

------

# 11. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Building a single merged catalogue/blob store/index across accounts instead of separate per-account vaults with a presentation-only merge (A26-ISO-1, A26-UNI-1) — the model-breaking multi-account error.
2. ❌ Any code path where one account's key could decrypt another's data (A26-ISO-2) — must be impossible by construction, not merely avoided.
3. ❌ Letting account A's local search / correspondent history / classification training see or affect account B (A26-ISO-4).
4. ❌ Executing a unified-view action (move/reply/delete) in the wrong account, or moving a message across accounts' folders (A26-UNI-3).
5. ❌ Sending from account A using account B's identity/session — cross-account From-spoofing (A26-SEND-2).
6. ❌ Auto-completing recipients or surfacing signatures/history from a different account than the sending one (A26-SEND-3).
7. ❌ Applying one account's tenant policy (webmail/Bridge/retention) to another account (A26-ACCT-3).
8. ❌ A session revocation on one account affecting the others' sessions (A26-ISO-3).
9. ❌ Removing one account wiping or disturbing another's local data (A26-ISO-5).
10. ❌ Reusing account A's device identity/keys when adding account B instead of an independent enrollment (A26-ACCT-2) — collapses isolation and IAM device semantics.
11. ❌ Sending the cross-account linkage (that one user holds both) server-side, or exposing it in telemetry (A26-OBS-1).
12. ❌ Unbounded resource multiplication with N accounts (no aggregate budget) (A26-RES-1).

------

# 12. Relationship to the Invariants (A25)

Multi-account is a direct application of several corpus invariants; it introduces no exception to them:

- **INV-11** (every device is an enrolled, independently-revocable IAM device): each account enrolls its own device (A26-ACCT-2).
- **INV-1/INV-2/INV-4** (server can't decrypt; content is ciphertext; keys in secure store): unchanged per account; multi-account adds strict *inter-account* isolation on top (A26-ISO).
- **INV-23** (declared exceptions are tenant-governable, per tenant): each account obeys its own tenant's policy (A26-ACCT-3).
- **INV-21** (telemetry carries no sensitive linkage): the cross-account linkage is sensitive and stays client-local (A26-OBS-1).

Multi-account weakens no invariant; it is additive client coordination over per-principal foundations. This annex adds NO new plaintext exception (the A25 INV-3 / A00 §3.2 list is unchanged).

------

# 13. Deferred Items

- **External (non-Diamy) accounts** (Gmail/IMAP/Exchange in the Diamy client) — explicitly out of scope (§1.1); a separate product/security decision that would relax zero-access for that foreign mail. Recorded here so it is a deliberate future decision, not an accidental extension of this annex.
- Shared/delegated mailboxes (multiple principals authorized on one mailbox, e.g. `support@`) — distinct from multi-account (multiple *personal* identities); depends on the IAM entitlement extension deferred in A17/A03.
- Unified calendar across accounts (the calendar analogue of the unified inbox) — the same presentation-merge / no-data-merge discipline would apply (A12–A15); deferred until multi-account mail ships.
- Per-account theming/visual distinction to reduce send-from-wrong-account mistakes — a UX enhancement over A26-SEND-1.
- Cross-account unified contacts with explicit user consent — currently forbidden (A26-SEND-3); could be a consented, client-local feature later, never server-side.

------

*End of document.*
