# Scope

## Purpose

A small, complete reference showing one way to govern an AI agent that can take real actions
in a regulated financial-services workflow, independent of which model or agent framework runs it.

It is a learning and discussion asset. It is not a product and not production code.

## Scenario

An **advisor-assist agent** at a fictional wealth-management firm. A licensed advisor asks it to
look up clients, change a mailing address, draft an email, or request a wire. Every name, account
and balance is invented.

| Tool | Risk tier | Scope | Baseline policy |
| --- | --- | --- | --- |
| `get_client_profile` | READ | `client:read` | allow |
| `get_positions` | READ | `positions:read` | allow |
| `draft_client_email` | LOW | `comms:draft` | allow; deny if it promises returns |
| `update_mailing_address` | MEDIUM | `profile:write` | allow; approval if changed in the last 30 days |
| `initiate_wire_transfer` | HIGH | `payments:initiate` | approval; deny over $50,000, to unapproved beneficiaries, or from another client's account |

## In scope

1. **Delegated identity** — short-lived JWT (RFC 9068 profile, EdDSA, `act` claim) bound to one run; rotation and revocation.
2. **Tool registry** — one catalogue with risk tiers, exported as MCP, Anthropic and Bedrock tool formats.
3. **Gateway** — the single enforcement point for every tool call (16 ordered checks, fail closed), runnable as its own HTTP service.
4. **Policy** — declarative YAML, deny by default, rules can only tighten.
5. **Human approval** — durable pending actions, four-eyes, expiry, and re-validation before execution.
6. **Cross-run limits and idempotency** — rolling velocity limits per client and principal; idempotency keys on every side effect.
7. **Guardrails** — PII redaction in logs; injection scan on tool results.
8. **Audit** — hash-chained, tamper-evident JSONL.
9. **Model-agnostic loop** — adapters for Claude (Messages API), Amazon Bedrock (Converse), Google ADK, and an offline scripted model.
10. **Evals** — control layer (gateway holds under adversarial behaviour), behavior layer (agent does the right thing), optional LLM-judge rubric; CI gate.
11. **Evidence pack** — ABOM, effective authority, traces, completeness checks, ready for an independent assessment (e.g. ASF).

## Not in scope

- Real core-banking, custody or payments integrations.
- Real client data or PII. Anything resembling a real person or institution is coincidental.
- A production approval queue, database, or policy engine such as OPA/Cedar. The interfaces are shaped so these can be swapped in. Keycloak runs locally with a demo realm (fictional users, password `demo`); it is not hardened for production.
- Investment advice. The agent is instructed not to give it.
- Code, data or designs from any client engagement.

## Milestones

| # | Milestone | Done when |
| --- | --- | --- |
| M1 | Scope and skeleton | Governance core runs offline; `govagent demo` shows allow, approve and deny paths |
| M2 | Claude adapter + eval harness | 28 cases (20 control, 8 behavior); control layer 100% offline; live run against Claude produces a report |
| M3 | ADK and Bedrock adapters | Same suite runs through ADK (offline scripted + live) and Bedrock |
| M4 | Production hardening (v0.2) | JWT delegation tokens with rotation and revocation; cross-run velocity; durable approvals with re-validation; idempotency; gateway as a service. 36 cases pass on scripted, ADK and remote |
| M5 | Standards refresh (v0.3) | Checked against Sept 2026 sources: MCP 2026-07-28 scope challenges and task-style polling; Transaction Tokens gateway→backend; AuthZEN 1.0 PDP; W3C trace context; OWASP 2026 and FINRA 2026 mappings |
| M6 | Live demo (v0.4) | One-command launcher; advisor chat, supervisor approval queue and audit viewer over the real gateway; 84 tests; [DEMO.md](DEMO.md) walkthrough |
| M7 | Real identity provider (v0.5) | Keycloak 26.7 realm; sign-in with code + PKCE; RFC 8693 exchange per agent run; gateway verifies via JWKS; `keycloak-check` self-test |
| M8 | Multi-agent, observability, scores (v0.6) | Orchestrator and specialists with chained token exchange and an agent registry; agent harness; OpenTelemetry traces (built-in view and Jaeger); token inspector; allowed-vs-denied view; scored evals (pass@1, pass^k, multi-agent) in the UI; 107 tests |

## Design principles

- **One enforcement point.** Adapters and frameworks never execute tools directly.
- **The model is untrusted.** Safety must hold even when the model is hijacked (see `ctl-injection-hijack`).
- **Deny by default, tighten only.** A bad rule cannot open a hole.
- **Facts from systems of record.** Policy compares arguments with looked-up facts, never with model claims.
- **Evidence by construction.** The audit trail and ABOM come from the running system, not from documents.
