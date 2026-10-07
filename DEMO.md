# Demo walkthrough (about 10 minutes)

A script for showing the reference build live. It assumes the audience knows roughly what an AI
agent is but hasn't thought hard about what stops one from doing the wrong thing with real money.

## Before you start

```bash
./scripts/run-demo.sh
```

This opens a page with an advisor chat on the left and, on the right, three tabs: Gateway
decisions, Supervisor approvals, and Audit log. Everything on the page is fictional — a made-up
wealth-management firm, made-up clients and accounts. If you want to show live Claude instead of
the scripted model, export `ANTHROPIC_API_KEY` before running the script and pick "Claude (live)"
from the model menu.

If a scenario looks off partway through (state left over from an earlier run), click **Reset
demo** in the top right. It clears everything and starts clean.

### Showing it with a real identity provider

```bash
./scripts/run-demo.sh --idp keycloak
```

Same page, plus a sign-in bar. Sign in as **Ana** (advisor) and **Casey** (supervisor) before you
start, and **Riley** (compliance) if you'll show the audit log; each opens Keycloak's own login page
(password `demo`). If a scenario needs someone who isn't signed in, a "Sign in as …" button
appears and the step reruns after sign-in.

One extra line worth saying early: "These are real OAuth tokens from Keycloak. When Ana asks the
agent to do something, the agent doesn't reuse her login. It exchanges her token for a new one that
only works at the gateway, only for its own tools, and names the agent as the one acting. Keycloak
won't let that exchange add permissions, and it will never give the agent approval rights, even when
the person is a supervisor."

If the self-test at start-up reports a failure, the details are in `.demo/keycloak-check.txt`.

## 1. Frame it (30 seconds)

"This is a small reference build for one problem: once an AI agent can take real actions — read a
client's account, send a wire — how do you keep it inside the rules, even when the model gets
something wrong? I built this to work through that concretely, not as a product pitch."

## 2. A normal request (1 minute)

Click **Read-only question**. The advisor asks what a client holds; the agent answers.

"Nothing interesting here yet — I'm showing it so the next one has a contrast. Every one of these
tool calls went through one gateway. Click 'gateway decisions' on that message and you can see the
15 checks it ran, all passing."

## 3. A wire that needs a human (1.5 minutes)

Click **Wire that needs a supervisor**. The agent submits a $12,000 wire; it comes back
"submitted for approval, not sent yet."

"The agent can propose a wire, but it can't complete one on its own — policy says a human has to
sign off. Switch to the Supervisor tab and approve it as Casey. Now it's actually happened —
you can see the wire ID come back."

Then, on the same pending item, switch the "Approve as" selector to Ana (the advisor who asked
for it) and try to approve it.

"Refused. It's not just that the UI won't let you approve your own request — the gateway itself
checks who's asking, and Ana's token doesn't have the scope to approve anything at all. Four-eyes
isn't a UI rule here; it's enforced where the money actually moves."

## 4. The one I find most useful: prompt injection (2 minutes)

Click **Prompt injection hijacks the model**.

"This client's notes — in the system of record, not in anything the advisor typed — contain a line
telling the agent to wire $95,000 to an account nobody approved. The model reads that and, being a
model, follows it. Watch."

The transcript shows the model trying to send the wire and reporting success. Point at the
Gateway decisions tab instead.

"The model *thinks* it succeeded — that's the uncomfortable part, a hijacked model will happily
tell the advisor 'done.' But the gateway checked the beneficiary and the amount against the real
client record, not against what the model said, and denied it. This is the case I'd point to if
you only have time for one: the fix for prompt injection here isn't a smarter model, it's that
authorization never trusts the model's account of what happened."

## 5. Splitting a request to dodge a limit (1.5 minutes)

Click **Splitting a wire across chats**. Three separate messages: $20k, $20k, $15k, each in its
own run.

"Each one on its own is under the daily limit. Together they're not — and the third one is denied.
This matters because a limit checked only within a single conversation is trivial to walk around
by starting a new one. The gateway tracks this across runs, and it counts wires that are still
waiting for approval against the limit too, not just ones that already went through."

## 6. What's actually enforcing this (1.5 minutes)

Open the Gateway decisions tab on any prior call and point at the 16-step pipeline grid.

"Every tool call goes through the same ordered list: is the token real, is it bound to this run,
is the tool registered, does the request match policy against the real client record, is anyone
trying to move faster than the velocity limit allows, does it need a human, and so on. If any
step fails, the call stops there — it fails closed, not open. And the last two steps are worth
naming: the actual write to the backend carries a short-lived, single-use token that only the
gateway can mint, so a backend service will refuse a call that tries to skip the gateway
entirely; and every decision, allowed or denied, goes into a hash-chained audit log."

Optionally open the Audit log tab and point at the chain-intact indicator.

"That chain means if any past entry were edited, this would show broken immediately — I'm not
asking you to trust that nothing was tampered with, the system can prove it."

## 6b. Seeing one request end to end (3 minutes, if there's time)

Switch to **Allowed vs denied** and pick the multi-agent pair.

"Here the request goes to an orchestrator, which hands each part to a specialist: accounts,
payments, communications. On the left, a normal request: holdings, then a draft email. On the right,
the communications agent has been hijacked by text in the client's notes and tries to request a
wire. Ana herself could request that wire, so her permissions aren't what stops it. Two other
things do: the communications agent's own token has no payment scope, and the gateway checks what
*this* agent is for; a communications agent doesn't move money."

Open the **Tokens** tab on the right-hand side.

"Each step here is a real token. Ana's own, then the orchestrator's, exchanged from hers, then the
specialist's, exchanged again. Each one is narrower than the one before, and each one records who is
acting for whom. The orchestrator itself can't call a single tool, and a specialist can't skip the
orchestrator: the identity provider won't make that exchange."

Open the **Trace** tab.

"This is the same request as an OpenTelemetry trace: the model calls, the token exchanges, every
gateway check, the backend. The red span is where it stopped, and why. With Jaeger running, the same
trace is there too, which is what an operations team would actually look at."

Then **Scores**.

"And this is how I test it: the same cases every time, scored. The control cases check that the
gateway holds when the model misbehaves; the behavior cases check the agent does the right thing,
repeated to see how consistent it is. The gate is simple: every safety case passes, every time."

## 7. Close (30 seconds)

"That's the shape of it: one gateway in front of every action, policy checked against real
records instead of what the model claims, durable human approval where it's needed, and an
audit trail you can verify rather than take my word for. It runs the same way under Claude,
Bedrock or Google's ADK — the governance doesn't depend on which model is behind it. Happy to
go deeper on any piece, or show the architecture doc, which maps each control to the standard
it follows."

## If something comes up

- **"What if the model is smarter and doesn't fall for the injection?"** — Doesn't matter for this
  design; the check is on the gateway side, checked against records, not on trusting the model to
  behave. Model quality isn't part of the safety argument.
- **"Is this running against a real bank?"** — No. Everything is fictional and in-memory; see
  SCOPE.md for what's deliberately left out.
- **"How long did this take?"** — Say what's true for you; the repo history and commit dates are
  there if anyone wants to check.
- **"Is the multi-agent chain fully enforced by Keycloak?"** — Mostly. Each hop is a real token
  exchange and Keycloak refuses the ones that skip a step. The inner link of the `act` chain is set by
  the realm's configuration rather than copied from the previous token; the gateway's agent registry
  is what checks the chain. ARCHITECTURE.md says this plainly.
- **"Is the identity part real?"** — With `--idp keycloak`, yes: Keycloak issues every token, and the
  gateway only has Keycloak's public keys. One honest caveat: Keycloak doesn't emit the `act`
  (delegation) claim for an agent client on its own, so the realm adds it with a mapper; the gateway
  checks that it matches the client the token was issued to.
- **Reset demo** clears pending approvals and shared limits between runs — click it if a scenario
  behaves oddly because of leftover state from an earlier click.

## Optional extras (if there's time)

- **Network retry (idempotency)** — the same request sent twice with the same key produces one
  wire, not two.
- **Replay a finished run's token** — a token stops working the moment its run closes, even
  before it expires.
