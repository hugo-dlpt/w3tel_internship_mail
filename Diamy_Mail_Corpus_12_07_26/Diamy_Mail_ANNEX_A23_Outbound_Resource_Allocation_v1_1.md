# Diamy Mail — ANNEX A23: Outbound Resource Allocation

**Document title:** Diamy Mail — ANNEX A23: Outbound Resource Allocation
**Version:** 1.1
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 4th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.2 (A00)
**Sibling dependencies:** A10 (Outbound Deliverability v1.1), A11 (Domain Onboarding v1.1), A17 (IAM Integration v1.2)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: sending resource inventory, sending pools, tenant→pool allocation (primary + fallback), assignment modes (shared/dedicated/hybrid), selection policy, health model, SPF-consistency coupling, administrative API (control-plane, SED-protected), reputation isolation, capacity model, failure model, observability, test scenarios, common AI errors. Implements A00 §10.6 OPS-SEND-*. |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: verified all nine OPS-SEND-* rules are implemented; made the hybrid split not hard-depend on A16 — it MAY use A16 message class when available, else falls back to designated-identity or sub-domain rules that need no classifier (A23-MODE-3); added a definition of "bulk sending identity" (a designated From address or sub-domain a tenant registers for bulk/marketing, A23-BULK-1) since A10-RL-5 and this annex both reference it; added AI error #11 |

------

# Table of contents

[toc]

------

# 1. Scope

This annex specifies the **outbound resource allocation** model that binds tenants (IAM) to concrete sending resources (sending servers / IP pools). It is the data model and administrative control plane behind the OPS-SEND-* rules (A00 §10.6): the sending inventory, the tenant→pool binding, assignment modes, the selection policy `diamy-submitd` uses at emission, and the health/SPF coupling. It answers "the platform has multiple sending servers; how does a tenant's outbound get routed to them, and how is reputation isolated?"

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 Boundaries

- Emission mechanics (DKIM, rate limits, retries) are A10; this annex provides the **allocation** A10 consumes at emission (A10 pipeline step 5).
- SPF publication/verification is A11; this annex owns the **pool egress IPs** that SPF must match (OPS-SEND-9), and triggers A11 re-verification on reassignment.
- The administrative API is control-plane and SED-protected (A17-SED-1); this annex owns its allocation-specific endpoints.

## 1.2 Out of scope

Physical MTA/IP provisioning and PTR setup (operational/A18). Reputation feed ingestion (A10 §5). IAM tenant lifecycle (A17).

------

# 2. Core Concepts

- **Sending server**: a physical/logical outbound MTA resource (`diamy-submitd` instance + one or more egress IPs), with a stable UUIDv7 ID, a capacity envelope, a health state, and pool membership (A00 §2 def).
- **Sending pool**: a named, ordered set of sending servers/IPs treated as **one reputation and capacity unit** (A00 §2 def). Pools are the unit at which reputation is observed (A10-REP-4) and to which tenants bind.
- **Outbound allocation**: the binding of a tenant to a primary pool (+ optional ordered fallbacks) with an assignment mode (§4).

------

# 3. Data Model (logical)

## 3.1 Sending resource inventory — `send.servers`

| Field | Status | Notes |
| ----- | ------ | ----- |
| `server_id` UUIDv7 | REQUIRED | stable ID (OPS-SEND-1) |
| `egress_ips[]` | REQUIRED | one or more outbound IPs |
| `pool_id` | REQUIRED | at most one pool at a time (OPS-SEND-2) |
| `capacity` | REQUIRED | max concurrent connections, max messages/interval (OPS-SEND-1) |
| `health_state` | REQUIRED | `healthy` / `degraded` / `unhealthy` / `draining` |
| `ptr_verified` | REQUIRED | forward-confirmed rDNS present (A10-BULK-2) |
| `notes` | OPTIONAL | operational metadata |

## 3.2 Sending pools — `send.pools`

| Field | Status | Notes |
| ----- | ------ | ----- |
| `pool_id` UUIDv7 | REQUIRED | |
| `name` | REQUIRED | human-readable |
| `kind` | REQUIRED | `shared` / `dedicated` / `hybrid-component` |
| `member_server_ids[]` | REQUIRED | servers in this pool |
| `reputation_state` | REQUIRED | derived from A10-REP monitoring per pool |
| `egress_ip_set` | DERIVED | union of member servers' egress IPs (the SPF-relevant set) |

## 3.3 Tenant allocation — `send.allocations`

| Field | Status | Notes |
| ----- | ------ | ----- |
| `tenant_id` UUIDv7 | REQUIRED | IAM tenant (OPS-SEND-3) |
| `primary_pool_id` | REQUIRED | exactly one (OPS-SEND-3) |
| `fallback_pool_ids[]` | OPTIONAL | ordered; used only when primary unavailable/saturated |
| `mode` | REQUIRED | `shared` / `dedicated` / `hybrid` (§4) |
| `hybrid_rules` | CONDITIONAL | present when mode=hybrid (§4.3) |
| `bulk_identity_pool_id` | OPTIONAL | designated bulk-sending pool (A10-RL-5) |
| `updated_by` / `updated_at` | REQUIRED | audit (OPS-SEND-3) |

- **A23-DM-1**: `send.allocations`, `send.pools`, `send.servers` are **control-plane data** (OPS-SEND-8): administrative store, NO message plaintext, exposed only via authenticated admin APIs (§7). Changes are audit-logged.

------

# 4. Assignment Modes

## 4.1 Shared

- **A23-MODE-1**: In `shared` mode, the tenant uses a multi-tenant pool. Cost-efficient; the tenant's reputation is co-mingled with other shared-pool tenants, so per-tenant rate limits (A10-RL) and complaint monitoring (A10-REP) are the protection against one tenant harming others. Shared is the default for small/low-volume tenants.

## 4.2 Dedicated

- **A23-MODE-2**: In `dedicated` mode, the tenant is the **sole occupant** of a pool / IP set. This is the mechanism that isolates a large tenant's behavior from others (OPS-SEND-4, satisfying OPS-DELIV-2): the tenant's reputation is entirely its own. Sellable as a premium feature (the conversation's point). A dedicated pool's `egress_ip_set` is exclusively that tenant's, which must be reflected in its SPF (§6).

## 4.3 Hybrid

- **A23-MODE-3**: In `hybrid` mode, the tenant splits traffic across pools by rule — typically **transactional on a dedicated/high-reputation pool, bulk/marketing on a separate pool** — so a marketing complaint spike does not damage the deliverability of critical transactional mail. `hybrid_rules` define the split. The split MAY key on the A16 message class **when the classifier is available**, but MUST NOT hard-depend on it: the baseline split rules are by **designated bulk sending identity** (A23-BULK-1) or by **sub-domain**, both of which need no classifier. If A16 is present it refines the split; if absent, identity/sub-domain rules suffice. Each branch resolves to a pool as in §5.
- **A23-BULK-1** (bulk sending identity — definition): A "bulk sending identity" is a **designated From address or sub-domain** (e.g. `news@example.fr` or `mkt.example.fr`) that a tenant registers for bulk/marketing traffic. It carries: a higher rate baseline (A10-RL-5), the bulk-sender compliance obligations (A10 §7: one-click unsubscribe, complaint-rate discipline), and an optional dedicated `bulk_identity_pool_id` (§3.3) so bulk traffic is pooled separately from transactional. Registering a bulk identity is a deliberate tenant/admin action; unregistered identities are treated as ordinary 1:1 mail (and MUST NOT be used to send bulk to evade the obligations, A10-BULK-3).

------

# 5. Selection Policy (emission-time)

Consumed by `diamy-submitd` at A10 pipeline step 5.

- **A23-SEL-1**: At emission, resolve: tenant → allocation → (mode/hybrid-rule) → target pool → a **healthy** sending server within that pool by a documented policy (RECOMMENDED capacity-weighted round-robin, skipping `unhealthy`/`draining` servers). Record the chosen `server_id` in delivery metadata (OPS-SEND-5) for observability/troubleshooting.
- **A23-SEL-2**: If the primary pool has no healthy server, try fallback pools in order (OPS-SEND-3). If none is healthy, **fail closed**: queue the message (do NOT emit via an arbitrary/unassigned resource), and raise a health/alert signal (OPS-SEND-6). A queued message retries as capacity/health returns.
- **A23-SEL-3**: Selection MUST respect capacity envelopes (OPS-SEND-1): a server at its concurrent-connection or rate ceiling is skipped (treated as temporarily unavailable), not overloaded. Capacity limits are independent of and additional to anti-abuse rate limits (OPS-SEND-7, A10-RL-4).
- **A23-SEL-4**: `draining` servers (being removed/maintained) accept no new selections but finish in-flight; `degraded` servers MAY be de-prioritized (lower selection weight) rather than fully skipped, per policy.

------

# 6. SPF Consistency Coupling (Normative)

- **A23-SPF-1**: A pool's `egress_ip_set` MUST be consistent with the SPF records of every tenant allocated to it (OPS-SEND-9, A10-AUTH-2): a tenant may only emit from IPs its published SPF authorizes. The `include:` target Diamy gives a tenant at onboarding (A11-SPF-1) MUST resolve to the egress IPs of the tenant's assigned pool(s).
- **A23-SPF-2** (reassignment): Moving a tenant to a pool with a **different** `egress_ip_set` MUST trigger an A11 SPF re-verification workflow, and the tenant MUST NOT emit from the new pool until SPF re-verifies (A11-SPF-4, A10-AUTH-2). A reassignment that silently changes egress IPs without SPF update would break the tenant's SPF alignment at recipients — a deliverability incident. The allocation change and the SPF-reverify gate are coupled and MUST be enforced together.
- **A23-SPF-3**: Adding/removing a server (hence IPs) to/from a pool changes the pool's `egress_ip_set` and therefore affects every allocated tenant's SPF. Such a change MUST propagate: either the `include:` target updates transparently (RECOMMENDED — the tenant's `include:spf.diamy.app` resolves to the new set, no tenant action needed) or, if a tenant hard-coded IPs, they MUST be re-verified. The include-based model (A11-SPF-1) is preferred precisely because it absorbs pool changes without tenant DNS edits.

------

# 7. Administrative API (control-plane, SED-protected)

All endpoints are control-plane, require Super-Admin scope (IAM), are SED-protected (A17-SED-1), and are audit-logged.

| Method | Path | Purpose |
| ------ | ---- | ------- |
| GET | `/admin/send/servers` | List sending inventory + health |
| POST | `/admin/send/servers` | Register/update a sending server |
| POST | `/admin/send/servers/{id}/drain` | Set draining (graceful removal) |
| GET | `/admin/send/pools` | List pools + reputation state |
| POST | `/admin/send/pools` | Create/update a pool, membership |
| GET | `/admin/send/allocations/{tenant_id}` | Get a tenant's allocation |
| POST | `/admin/send/allocations/{tenant_id}` | Set/change allocation (triggers §6 SPF check) |

- **A23-API-1**: `POST /admin/send/allocations/{tenant_id}` MUST, when the change alters the tenant's `egress_ip_set`, return the required SPF re-verification state and MUST NOT mark the new pool emittable until A11 re-verifies (A23-SPF-2). The API surfaces the coupling; it does not let an admin bypass it.
- **A23-API-2**: These endpoints are the "control-plane administrative APIs" referenced by A17-SED-1; they are NOT data-plane and MUST NOT be reachable with only a mail-plane token.
- **A23-API-3**: Every mutation is audit-logged with actor, before/after, and timestamp (OPS-SEND-3, OBS-3).

------

# 8. Reputation Isolation

- **A23-REP-1**: Because reputation is observed **per pool** (A10-REP-4), the allocation model is the lever for reputation isolation: dedicated pools isolate a tenant entirely; shared pools co-mingle (protected by rate limits + complaint monitoring); hybrid isolates transactional from bulk within a tenant.
- **A23-REP-2**: When a pool's `reputation_state` degrades (blocklist, complaint spike — A10-REP), the platform MAY: auto-route allocated tenants to a healthy fallback pool (if configured and SPF-consistent), tighten limits, and alert. Auto-routing MUST respect SPF consistency (§6) — never route a tenant to a pool whose IPs its SPF doesn't authorize.
- **A23-REP-3**: A dedicated-pool tenant that damages its own reputation affects only itself (the isolation guarantee, the conversation's premium-feature rationale). This MUST be preserved: a dedicated tenant's problem MUST NOT spill to shared pools.

------

# 9. Capacity Model

- **A23-CAP-1**: Each server declares a capacity envelope (OPS-SEND-1); each pool's capacity is the aggregate of its healthy members. The platform MUST monitor pool utilization and alert before saturation, so a pool nearing capacity gets more servers (or tenants get rebalanced) before fail-closed queueing (§5) becomes routine.
- **A23-CAP-2**: New IPs/servers added to a pool SHOULD undergo IP warming (gradual volume ramp — the conversation's point; scheduler deferred to A10 §13/ops) before carrying full load, and MAY be added as `degraded`/low-weight initially (A23-SEL-4) to ramp gently.

------

# 10. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| No healthy server in primary pool | Try fallbacks in order; none → fail-closed queue + alert (A23-SEL-2, OPS-SEND-6) |
| All pools unhealthy | Queue, alert CRITICAL; never emit via unassigned resource |
| Allocation change alters egress IPs | Gate new pool on A11 SPF re-verify; block emission from new pool until green (A23-SPF-2) |
| Server added/removed (IP set change) | Propagate via include target (no tenant action) or re-verify hard-coded SPF (A23-SPF-3) |
| Pool reputation degraded | Auto-route to SPF-consistent fallback if configured, tighten limits, alert (A23-REP-2) |
| Capacity saturation | Alert before saturation; add servers / rebalance; fail-closed queue as last resort (A23-CAP-1) |
| Admin API called with mail-plane token only | Reject — control plane requires Super-Admin + SED (A23-API-2) |

------

# 11. Observability Contract

Per A00 §11:

- counters: `emissions_by_pool_total{pool,result}`, `emissions_by_server_total{server,result}`, `selection_fallbacks_total`, `fail_closed_queue_events_total`, `allocation_changes_total`, `spf_reverify_gates_total{result}`, `auto_reroutes_total`
- gauges: pool utilization (% capacity), per-pool reputation state, healthy/degraded/unhealthy/draining server counts per pool, tenants per pool, oldest fail-closed-queued age
- health (OBS-1): per-pool health and reputation crossing WARNING/CRITICAL (A22 thresholds); a pool nearing capacity; a pool on a blocklist
- audit (OBS-3): all allocation/pool/server mutations, SPF-reverify gates, auto-reroutes, drains
- **A23-OBS-1**: Telemetry is infrastructure metadata (pools, servers, IPs, counts) — it contains NO message content or recipient data (that lives nowhere near the allocation plane).

------

# 12. Test Scenarios (Normative)

1. **Basic allocation**: tenant on a shared pool → emission selects a healthy server in that pool, records server_id; SPF include resolves to the pool's IPs (§6).
2. **Dedicated isolation**: dedicated-pool tenant spikes complaints → only its pool's reputation degrades; shared-pool tenants unaffected (A23-REP-3).
3. **Fallback**: primary pool all unhealthy → emission uses first healthy fallback (SPF-consistent); assert no emission from an unassigned IP.
4. **Fail-closed**: primary + all fallbacks unhealthy → message queued, CRITICAL alert; NOT emitted via arbitrary IP (A23-SEL-2).
5. **Reassignment SPF gate**: move tenant to a pool with different IPs → emission from new pool blocked until A11 SPF re-verifies; old pool still works until switch (A23-SPF-2).
6. **Include propagation**: add a server (new IPs) to a pool → tenants' `include:spf.diamy.app` resolves to the new set automatically, no tenant DNS change; alignment holds (A23-SPF-3).
7. **Capacity skip**: a server at its connection ceiling is skipped, not overloaded; another healthy server selected (A23-SEL-3).
8. **Hybrid split**: hybrid tenant → transactional mail on dedicated pool, marketing on bulk pool; a marketing complaint spike does not degrade transactional deliverability (A23-MODE-3).
9. **Admin auth**: call allocation API with only a mail-plane token → rejected; with Super-Admin + SED → succeeds, audit-logged (A23-API-2/3).
10. **Drain**: set a server draining → no new selections, in-flight completes, then removable (A23-SEL-4).

------

# 13. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Selecting an arbitrary/unassigned sending server at emission instead of resolving the tenant's allocation (OPS-SEND-5, A23-SEL-1).
2. ❌ Emitting via a fallback/any IP when the pool is unhealthy instead of fail-closed queueing (A23-SEL-2, OPS-SEND-6).
3. ❌ Reassigning a tenant to a pool with different egress IPs without gating on SPF re-verification, breaking SPF alignment at recipients (A23-SPF-2, A10-AUTH-2).
4. ❌ Letting allocation bypass anti-abuse rate limits or vice versa — independent controls, both apply (A23-SEL-3, OPS-SEND-7, A10-RL-4).
5. ❌ Overloading a server past its capacity envelope instead of skipping it (A23-SEL-3).
6. ❌ Placing a server in more than one pool at a time (OPS-SEND-2, §3.1).
7. ❌ Auto-routing a tenant to a pool whose IPs its SPF doesn't authorize during a reputation event (A23-REP-2 — must stay SPF-consistent).
8. ❌ Exposing the allocation admin API on the data plane / with a mail-plane token instead of control-plane Super-Admin + SED (A23-API-2, A17-SED-1).
9. ❌ Letting a dedicated tenant's reputation problem spill to shared pools (A23-REP-3) — defeats the isolation guarantee.
10. ❌ Storing any message content/recipient data in the allocation plane (A23-DM-1, A23-OBS-1) — it is pure control-plane infrastructure metadata.
11. ❌ Making the hybrid split hard-depend on the A16 classifier so hybrid mode breaks when A16 is unavailable, instead of falling back to designated-identity / sub-domain rules (A23-MODE-3).

------

# 14. Deferred Items

- Automated IP-warming scheduler (gradual ramp for new pool IPs) — the need is stated (A23-CAP-2, the conversation's IP-warming point); the scheduler implementation is operational (A10 §13 / A18).
- Cross-region pool selection (route by recipient geography or sender region) — a deliverability/latency optimization; deferred.
- Automated capacity autoscaling (add servers to a pool on utilization thresholds) — operational automation; the manual admin path is V1.
- Cost/reputation optimization engine (recommend shared vs dedicated per tenant based on observed behavior) — an analytics enhancement; deferred.

------

*End of document.*
