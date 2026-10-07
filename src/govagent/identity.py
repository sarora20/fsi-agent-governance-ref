"""Delegated identity: the agent acts on behalf of a human, never beyond that human's rights.

Token format: a JWT access token (RFC 7519) following the RFC 9068 profile:
  header  typ=at+jwt, alg=EdDSA, kid=<signing key id>
  iss     the identity provider                     (validated, RFC 8725 §3.8)
  aud     the gateway's resource identifier           (validated, RFC 8707 / RFC 8725 §3.9)
  sub     the human principal
  act     {"sub": <agent id>}  delegation, not impersonation (RFC 8693 §4.1)
  client_id  the agent runtime (OAuth client)
  scope   space-delimited scopes, a subset of the principal's role
  clients the principal's client book (custom claim)
  run     the single agent run this token is bound to (custom claim)
  iat/nbf/exp/jti

Why asymmetric keys: the gateway only holds public keys, so nothing on the resource side
(or the agent runtime) can mint tokens. Keys carry a `kid`, so the issuer can rotate: new
tokens use the new key, verifiers accept old public keys until they are retired.
Revocation: by token id (jti) or by subject (all tokens for a person issued before a time).

Two token profiles:
  DEV_PROFILE   tokens from TokenService below (offline tests, evals, the default demo).
  OIDC_PROFILE  tokens from a real authorization server (Keycloak 26.7 in the demo). The person comes
                from `preferred_username`, the agent from `act`/`azp` (they must agree), the run from the
                token id, and role plus client book from the directory, not from the token. Token scopes
                are intersected with the role's scopes, so a mis-configured IdP cannot widen access.
Both profiles get the same cryptographic checks: typ=at+jwt, pinned EdDSA, known kid (JWKS), iss, aud,
exp, revocation.

Still to add: sender-constrained tokens (DPoP, RFC 9449) so a stolen token is useless without the
holder's private key.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Iterable

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import dpop
from .state import StateStore

if TYPE_CHECKING:
    from .agents import AgentRegistry

MAX_TTL_SECONDS = 3600
ALGORITHM = "EdDSA"
TOKEN_TYPE = "at+jwt"
DEFAULT_ISSUER = "https://idp.govagent.example"
DEFAULT_AUDIENCE = "https://gateway.govagent.example"

ROLE_SCOPES: dict[str, frozenset[str]] = {
    "advisor": frozenset(
        {"client:read", "positions:read", "profile:write", "comms:draft", "payments:initiate"}
    ),
    "service_associate": frozenset({"client:read", "positions:read", "profile:write", "comms:draft"}),
    "analyst": frozenset({"client:read", "positions:read"}),
    # controls:admin (engage/release a kill switch) is never in AGENT_SCOPES, for the same reason
    # approvals:decide and audit:read never are: an emergency stop is a human-only action.
    "supervisor": frozenset({"client:read", "approvals:decide", "controls:admin"}),
    "compliance": frozenset({"audit:read"}),
}


# What the agent's tools can need. Approving and reading the audit log are never delegated to the agent,
# even when the person could do them: the agent's OAuth client is not allowed to request those scopes.
AGENT_SCOPES: frozenset[str] = frozenset(
    {"client:read", "positions:read", "profile:write", "comms:draft", "payments:initiate"})


class TokenError(Exception):
    """Raised when a delegation token cannot be issued or verified."""


@dataclass(frozen=True)
class Principal:
    user_id: str
    display_name: str
    role: str
    entitled_clients: frozenset[str]


class Directory:
    """The system of record for people, roles and client books (an HR/IAM directory in production).
    Re-validation at execution time reads this, not the (possibly hours-old) token."""

    def __init__(self, principals: Iterable[Principal]):
        self._by_id = {p.user_id: p for p in principals}

    def get(self, user_id: str) -> Principal | None:
        return self._by_id.get(user_id)

    def put(self, principal: Principal) -> None:
        self._by_id[principal.user_id] = principal

    def remove(self, user_id: str) -> None:
        self._by_id.pop(user_id, None)


@dataclass(frozen=True)
class DelegationGrant:
    token_id: str
    principal_id: str
    role: str
    agent_id: str
    scopes: frozenset[str]
    clients: frozenset[str]
    run_id: str
    audience: str
    issued_at: float
    expires_at: float
    delegated: bool = True  # carries an RFC 8693 `act` claim (an agent acting for the person)
    actor_chain: tuple[str, ...] = ()  # nested `act`, outermost first: (acting agent, its delegator, ...)


def actor_chain(act: object, limit: int = 8) -> tuple[str, ...]:
    """RFC 8693 §4.1: a nested `act` records a delegation chain; the outermost is the current actor."""
    chain: list[str] = []
    while act is not None:
        if not isinstance(act, dict) or not act.get("sub"):
            raise TokenError("malformed act claim (every link needs a sub)")
        if len(chain) >= limit:
            raise TokenError(f"delegation chain longer than {limit}")
        chain.append(str(act["sub"]))
        act = act.get("act")
    return tuple(chain)


class KeyRing:
    """Signing keys held by the issuer. Rotation adds a key; retiring removes it from verification."""

    def __init__(self) -> None:
        self._keys: dict[str, Ed25519PrivateKey] = {}
        self._retired: set[str] = set()
        self.active_kid = ""
        self.rotate()

    @classmethod
    def from_seed(cls, seed: bytes, kid: str = "dev-1") -> "KeyRing":
        """Deterministic key for local demos only (seed must be 32 bytes)."""
        ring = cls.__new__(cls)
        ring._keys = {kid: Ed25519PrivateKey.from_private_bytes(seed[:32].ljust(32, b"\0"))}
        ring._retired = set()
        ring.active_kid = kid
        return ring

    def rotate(self) -> str:
        kid = f"k-{uuid.uuid4().hex[:8]}"
        self._keys[kid] = Ed25519PrivateKey.generate()
        self.active_kid = kid
        return kid

    def retire(self, kid: str) -> None:
        if kid == self.active_kid:
            raise ValueError("cannot retire the active signing key")
        self._retired.add(kid)

    def signing_key(self) -> tuple[str, Ed25519PrivateKey]:
        return self.active_kid, self._keys[self.active_kid]

    def public_keys(self) -> dict[str, Ed25519PublicKey]:
        """What a verifier receives (a JWKS endpoint in production)."""
        return {kid: k.public_key() for kid, k in self._keys.items() if kid not in self._retired}

    def jwks(self) -> dict:
        import json

        from jwt.algorithms import OKPAlgorithm

        return {"keys": [{**json.loads(OKPAlgorithm.to_jwk(pub)), "kid": kid, "alg": ALGORITHM, "use": "sig"}
                         for kid, pub in self.public_keys().items()]}


def _mint_audience(base: str, agent_id: str, registry: "AgentRegistry | None") -> str | list[str]:
    """RFC 8707: a token's audience should name the resource(s) it is valid for. When an agent
    registry is configured and knows this agent, the audience also names the agent itself, so a
    token minted for one agent cannot be mistaken, by audience alone, for one minted for another --
    independent of whatever the gateway's agent-registry stage (4) separately enforces. An unknown
    agent id, or no registry at all, keeps the single base audience unchanged (this is also why a
    bare TokenService(), as used by the lower-level identity tests, is untouched by this)."""
    if registry is not None and registry.get(agent_id) is not None:
        return sorted({base, agent_id})
    return base


class TokenService:
    """Stand-in for the identity provider's token-exchange endpoint."""

    def __init__(self, keys: KeyRing, issuer: str = DEFAULT_ISSUER, clock: Callable[[], float] = time.time,
                agent_registry: "AgentRegistry | None" = None):
        self.keys = keys
        self.issuer = issuer
        self._clock = clock
        self.agent_registry = agent_registry

    def issue(
        self,
        principal: Principal,
        agent_id: str,
        scopes: Iterable[str] | None = None,
        ttl_seconds: int = 900,
        audience: str = DEFAULT_AUDIENCE,
        run_id: str | None = None,
        dpop_jkt: str | None = None,
    ) -> str:
        allowed = ROLE_SCOPES.get(principal.role)
        if allowed is None:
            raise TokenError(f"unknown role '{principal.role}'")
        requested = frozenset(scopes) if scopes is not None else allowed
        excess = requested - allowed
        if excess:
            raise TokenError(f"scopes exceed role '{principal.role}': {sorted(excess)}")
        if not 0 < ttl_seconds <= MAX_TTL_SECONDS:
            raise TokenError(f"ttl must be between 1 and {MAX_TTL_SECONDS} seconds")
        now = int(self._clock())
        claims = {
            "iss": self.issuer,
            "aud": _mint_audience(audience, agent_id, self.agent_registry),
            "sub": principal.user_id,
            "act": {"sub": agent_id},
            "client_id": agent_id,
            "scope": " ".join(sorted(requested)),
            "role": principal.role,
            "clients": sorted(principal.entitled_clients),
            "run": run_id or f"run-{uuid.uuid4().hex[:12]}",
            "iat": now,
            "nbf": now,
            "exp": now + ttl_seconds,
            "jti": uuid.uuid4().hex,
        }
        if dpop_jkt:  # RFC 9449 §6.1: binds this token to whoever holds the matching private key
            claims["cnf"] = {"jkt": dpop_jkt}
        kid, key = self.keys.signing_key()
        return jwt.encode(claims, key, algorithm=ALGORITHM, headers={"kid": kid, "typ": TOKEN_TYPE})

    def exchange(self, subject_token: str, actor: str, scopes: Iterable[str], ttl_seconds: int = 300,
                 audience: str = DEFAULT_AUDIENCE, dpop_jkt: str | None = None) -> str:
        """RFC 8693 token exchange for delegation (dev stand-in for the IdP's token endpoint).
        Scopes can only narrow; the new `act` nests the subject token's actor, recording the chain.
        `dpop_jkt` rebinds the exchanged token to a (possibly different) key -- RFC 9449 §8 allows
        this; nothing requires the delegate to hold the same key as whoever it was exchanged from."""
        now = int(self._clock())
        try:
            kid = jwt.get_unverified_header(subject_token).get("kid", "")
            # iat/nbf/exp are checked manually below, against self._clock() -- the same clock that
            # minted this token's iat/nbf in the first place. PyJWT's own exp/nbf/iat checks run
            # against the real wall clock, which is wrong whenever an injected clock differs from
            # it (every test using a controllable Clock, and any demo that advances one on
            # purpose) -- exactly the class of bug fixed in build_environment()'s token threading
            # during item 5.
            subject = jwt.decode(subject_token, self.keys.public_keys()[kid], algorithms=[ALGORITHM],
                                 options={"verify_aud": False, "verify_iat": False, "verify_nbf": False,
                                         "verify_exp": False})
        except (KeyError, jwt.PyJWTError):
            raise TokenError("invalid subject token") from None
        if now >= subject["exp"]:
            raise TokenError("invalid subject token: expired")
        requested = frozenset(scopes)
        extra = requested - frozenset(str(subject["scope"]).split())
        if extra:
            raise TokenError(f"invalid_scope: {sorted(extra)} not present in the subject token")
        # Carry the subject's own binding forward by default (one agent process, one key pair
        # across its whole delegation chain is the common case); an explicit dpop_jkt overrides it.
        jkt = dpop_jkt or (subject.get("cnf") or {}).get("jkt")
        claims = {**{k: subject[k] for k in ("iss", "sub", "role", "clients") if k in subject},
                  "aud": _mint_audience(audience, actor, self.agent_registry),
                  "act": {"sub": actor, **({"act": subject["act"]} if "act" in subject else {})},
                  "client_id": actor, "scope": " ".join(sorted(requested)),
                  "run": f"run-{uuid.uuid4().hex[:12]}", "iat": now, "nbf": now,
                  "exp": min(now + ttl_seconds, int(subject["exp"])), "jti": uuid.uuid4().hex}
        if jkt:
            claims["cnf"] = {"jkt": jkt}
        kid, key = self.keys.signing_key()
        return jwt.encode(claims, key, algorithm=ALGORITHM, headers={"kid": kid, "typ": TOKEN_TYPE})


def run_id_for(claims: dict) -> str:
    """The run a token is bound to. Our dev IdP writes a `run` claim. A standard IdP (Keycloak) has no
    such claim, but it issues one exchanged token per agent run, so the token id (jti) is the run."""
    if claims.get("run"):
        return str(claims["run"])
    jti = str(claims.get("jti", ""))
    return f"run-{hashlib.sha256(jti.encode()).hexdigest()[:12]}" if jti else ""


def peek_run_id(token: str) -> str:
    """Read the run binding without verifying (for the agent runtime's own bookkeeping only)."""
    try:
        return run_id_for(jwt.decode(token, options={"verify_signature": False}))
    except jwt.PyJWTError:
        return ""


def peek_agent_id(token: str) -> str:
    """Read the claimed acting agent without verifying -- used only to decide whether a kill switch
    applies, never as a trust decision: a stop can only add a restriction, never grant one, so acting
    on an unverified claim here is safe. A forged token still fails identity right after this; a
    genuine one's claimed agent cannot be changed without invalidating its signature."""
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return ""
    act = claims.get("act")
    return str(act.get("sub", "")) if isinstance(act, dict) else ""


@dataclass(frozen=True)
class TokenProfile:
    """What the gateway expects from a given issuer's tokens. The cryptographic checks (typ=at+jwt,
    pinned EdDSA, kid, iss, aud, exp, revocation) are the same for every profile."""

    name: str
    required: tuple[str, ...]
    principal_claim: str  # which claim names the human, as the directory knows them
    identity_from_directory: bool  # role and client book from the system of record, not the token
    require_act_claim: bool
    payload_typ: str | None = None  # Keycloak also marks access tokens with "typ": "Bearer"


DEV_PROFILE = TokenProfile(
    "dev", ("iss", "aud", "sub", "act", "client_id", "scope", "run", "iat", "nbf", "exp", "jti"),
    principal_claim="sub", identity_from_directory=False, require_act_claim=True)

# Tokens from a standard OAuth 2.0 authorization server (tested against Keycloak 26.7). The agent is
# the client the token was issued to (`azp`); if an `act` claim is present it must name that client.
OIDC_PROFILE = TokenProfile(
    "oidc", ("iss", "aud", "sub", "azp", "scope", "iat", "exp", "jti", "preferred_username"),
    principal_claim="preferred_username", identity_from_directory=True, require_act_claim=False,
    payload_typ="Bearer")


class JwksKeySource:
    """Public keys from the authorization server's JWKS endpoint, cached. An unknown `kid` triggers
    one refresh (rate-limited), which is how key rotation at the IdP reaches the gateway."""

    def __init__(self, url: str, min_refresh_seconds: float = 30.0, timeout: float = 5.0,
                 fetch: Callable[[str], dict] | None = None, clock: Callable[[], float] = time.time):
        self.url = url
        self.min_refresh_seconds = min_refresh_seconds
        self.timeout = timeout
        self._fetch = fetch or self._http_get
        self._clock = clock
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._fetched_at = float("-inf")

    def _http_get(self, url: str) -> dict:
        import json
        import urllib.request

        with urllib.request.urlopen(url, timeout=self.timeout) as resp:  # noqa: S310 (configured URL)
            return json.loads(resp.read().decode())

    def refresh(self) -> dict[str, Ed25519PublicKey]:
        if self._clock() - self._fetched_at < self.min_refresh_seconds:
            return self._keys
        self._fetched_at = self._clock()
        try:
            doc = self._fetch(self.url)
        except Exception:  # noqa: BLE001 - keep the last good keys; verification fails closed on unknown kid
            return self._keys
        keys: dict[str, Ed25519PublicKey] = {}
        for jwk in doc.get("keys", []):
            if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or jwk.get("use", "sig") != "sig":
                continue  # only the pinned algorithm's keys are ever used
            try:
                keys[jwk["kid"]] = jwt.PyJWK(jwk, algorithm=ALGORITHM).key
            except (jwt.PyJWKError, KeyError):
                continue
        self._keys = keys
        return keys

    def __call__(self) -> dict[str, Ed25519PublicKey]:
        return self._keys or self.refresh()


class TokenVerifier:
    """Runs on the gateway. Holds only public keys."""

    def __init__(
        self,
        public_keys: dict[str, Ed25519PublicKey] | Callable[[], dict[str, Ed25519PublicKey]],
        audience: str = DEFAULT_AUDIENCE,
        issuer: str = DEFAULT_ISSUER,
        store: StateStore | None = None,
        clock: Callable[[], float] = time.time,
        profile: TokenProfile = DEV_PROFILE,
        directory: "Directory | None" = None,
        agent_registry: "AgentRegistry | None" = None,
        dpop_max_age_seconds: int = dpop.DEFAULT_MAX_AGE_SECONDS,
    ):
        if profile.identity_from_directory and directory is None:
            raise ValueError(f"token profile '{profile.name}' needs a directory")
        self.public_keys = public_keys
        self.audience = audience
        self.issuer = issuer
        self.store = store
        self._clock = clock
        self.profile = profile
        self.dpop_max_age_seconds = dpop_max_age_seconds
        self.directory = directory
        # Dev profile only (see the "audience narrowed to actor" step in verify()): lets the
        # verifier confirm a token's own audience names its claimed actor, for agents the same
        # registry knows about. Under the OIDC profile this stays unused -- there, `azp` already
        # cryptographically binds the token to the client Keycloak issued it to, and Keycloak's own
        # realm config narrows audience by its own, different convention (see keycloak_check.py).
        self.agent_registry = agent_registry

    @property
    def REQUIRED(self) -> list[str]:  # noqa: N802 (kept for callers that read it)
        return list(self.profile.required)

    def _key_for(self, kid: str):
        keys = self.public_keys() if callable(self.public_keys) else self.public_keys
        key = keys.get(kid)
        if key is None and hasattr(self.public_keys, "refresh"):
            key = self.public_keys.refresh().get(kid)  # the IdP may have rotated its signing key
        return key

    def verify(self, token: str, explain: list[dict] | None = None, dpop_proof: str | None = None,
              http_method: str | None = None, http_url: str | None = None) -> DelegationGrant:
        """Validate a token. With `explain`, each check is appended as {check, ok, detail} (the token
        inspector shows this); the first failing check raises TokenError, exactly as without it.

        A token carrying `cnf.jkt` (RFC 9449) is DPoP-bound: it is then no longer a bearer
        credential, and `dpop_proof`/`http_method`/`http_url` -- the live request's own method and
        URL, never cached -- become required. Presenting such a token without a valid, matching
        proof is refused here exactly like a missing signature; a token with no `cnf` claim is
        unaffected and these three arguments are simply ignored for it."""

        def step(check: str, ok: bool, detail: str, error: str | None = None) -> None:
            if explain is not None:
                explain.append({"check": check, "ok": ok, "detail": detail if ok else (error or detail)})
            if not ok:
                raise TokenError(error or detail)

        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            step("format", False, "", "malformed token")
        step("format", True, "a signed JWT (JWS compact form)")
        step("header typ", header.get("typ") == TOKEN_TYPE, f"typ={header.get('typ')} (RFC 9068 access token)",
             "wrong token type")
        step("algorithm pinned", header.get("alg") == ALGORITHM, f"alg={header.get('alg')}; only {ALGORITHM} "
             "is accepted (RFC 8725 §3.1)", "unexpected algorithm")
        key = self._key_for(header.get("kid", ""))
        step("signing key", key is not None, f"kid={header.get('kid')} found in the issuer's keys",
             "unknown or retired signing key")
        try:
            claims = jwt.decode(
                token, key, algorithms=[ALGORITHM], audience=self.audience, issuer=self.issuer,
                options={"require": list(self.profile.required), "verify_exp": False, "verify_nbf": False,
                         "verify_iat": False},
            )
        except jwt.InvalidAudienceError:
            step("signature", True, "valid")
            step("issuer", True, self.issuer)
            step("audience", False, "", "token not issued for this gateway (audience)")
        except jwt.InvalidIssuerError:
            step("signature", True, "valid")
            step("issuer", False, "", "untrusted issuer")
        except jwt.MissingRequiredClaimError as exc:
            step("signature", True, "valid")
            step("required claims", False, "", f"missing claim: {exc.claim}")
        except jwt.PyJWTError:
            step("signature", False, "", "invalid signature")
        step("signature", True, "verified with the issuer's public key; the gateway holds no private key")
        step("issuer", True, f"iss={claims['iss']}")
        step("audience", True, f"aud includes {self.audience} (RFC 8707)")
        step("required claims", True, ", ".join(self.profile.required))
        if self.profile.payload_typ:
            step("payload typ", claims.get("typ") == self.profile.payload_typ,
                 f"typ={claims.get('typ')} (not an ID or refresh token)", "wrong token type")
        now = self._clock()
        step("expiry", now < claims["exp"], f"expires in {int(claims['exp'] - now)}s", "token expired")
        if "nbf" in claims:
            step("not before", now >= claims["nbf"], "valid now", "token not yet valid")
        principal_id = str(claims[self.profile.principal_claim])
        if self.store is not None:
            step("revocation", self.store.revoked_at("jti", claims["jti"]) is None,
                 f"jti {str(claims['jti'])[:18]}… not revoked", "token revoked")
            subject_cut = self.store.revoked_at("sub", principal_id)
            step("subject revocation", subject_cut is None or claims["iat"] > subject_cut,
                 f"no revocation for {principal_id}", "all tokens for this subject were revoked")

        jkt = (claims.get("cnf") or {}).get("jkt")
        if jkt:
            # RFC 9449: this token is not a bearer credential. A caller presenting it without a
            # proof that both matches this exact request and was signed by the bound key is
            # refused here -- before scope, policy or anything else runs, the same "a stop can
            # only deny, nothing here can widen access" posture as every other gate in this file.
            step("dpop proof present", dpop_proof is not None and http_method is not None and http_url is not None,
                 "", "dpop: token is DPoP-bound (cnf.jkt) but no proof/method/url was given for this request")
            try:
                proof_thumbprint, proof_claims = dpop.verify_proof(
                    dpop_proof, http_method, http_url, access_token=token,
                    max_age_seconds=self.dpop_max_age_seconds, clock=self._clock)
            except dpop.DPoPError as exc:
                step("dpop proof valid", False, "", f"dpop: {exc}")
            step("dpop proof valid", True, f"method={http_method}, url={http_url}, iat fresh")
            step("dpop key binding", proof_thumbprint == jkt,
                 "proof signed by the key this token is bound to",
                 "dpop: proof was signed by a different key than this token's cnf.jkt names "
                 "(a stolen token presented with the thief's own key)")
            if self.store is not None:
                step("dpop replay", not self.store.dpop_replay_check(proof_claims["jti"], now),
                     f"proof jti {proof_claims['jti'][:12]}… not seen before", "dpop: proof already used (replay)")

        client = claims.get("client_id") or claims.get("azp")
        act = claims.get("act")
        if act is not None:
            actor = act.get("sub") if isinstance(act, dict) else None
            step("actor", bool(actor), "", "missing actor")
            step("actor matches client", not client or actor == client,
                 f"act.sub={actor} = {'client_id' if claims.get('client_id') else 'azp'}={client}",
                 "actor does not match the client the token was issued to")
            if (not self.profile.identity_from_directory and self.agent_registry is not None
                    and self.agent_registry.get(actor) is not None):
                # Every dev-minted token otherwise shares one audience (the gateway itself), so
                # audience alone cannot tell one agent's token from another's. Checked here,
                # independent of the agent-registry stage at the gateway (stage 4), so a token
                # whose own audience does not name its claimed actor is refused at identity --
                # before run binding, registry lookup or that later stage even run.
                aud = claims.get("aud")
                aud_values = aud if isinstance(aud, list) else [aud]
                step("audience narrowed to actor", actor in aud_values, f"aud includes '{actor}'",
                     f"token audience {aud_values} does not name its own actor '{actor}'")
            chain = actor_chain(act)
            step("delegation chain", True, " <- ".join(chain) + " <- " + principal_id)
        elif self.profile.require_act_claim or not client:
            step("actor", False, "", "missing actor")
        else:
            actor, chain = client, (client,)
            step("actor", True, f"no act claim: the person's own token via {client} (valid for console "
                 "actions, not for tool calls)")

        scopes = frozenset(str(claims["scope"]).split())
        if self.profile.identity_from_directory:
            person = self.directory.get(principal_id)
            step("person in directory", person is not None,
                 f"{principal_id}: role {person.role if person else '?'}, "
                 f"{len(person.entitled_clients) if person else 0} clients (from the system of record)",
                 f"unknown principal '{principal_id}'")
            role, clients = person.role, person.entitled_clients
            allowed = ROLE_SCOPES.get(role, frozenset())
            dropped = scopes - allowed
            scopes &= allowed  # a mis-set IdP scope cannot widen the role
            step("scopes within role", True, " ".join(sorted(scopes)) +
                 (f" (ignored: {' '.join(sorted(dropped))})" if dropped else ""))
        else:
            role, clients = claims.get("role", ""), frozenset(claims.get("clients", []))
            step("scopes", True, " ".join(sorted(scopes)))
        return DelegationGrant(
            token_id=claims["jti"], principal_id=principal_id, role=role, agent_id=actor, scopes=scopes,
            clients=frozenset(clients), run_id=run_id_for(claims), audience=self.audience,
            issued_at=claims["iat"], expires_at=claims["exp"], delegated=act is not None,
            actor_chain=chain,
        )

    def explain(self, token: str) -> tuple[list[dict], DelegationGrant | None]:
        steps: list[dict] = []
        try:
            return steps, self.verify(token, explain=steps)
        except TokenError:
            return steps, None
