"""Real OAuth 2.0 / OpenID Connect for the demo, against an authorization server such as Keycloak.

Two OAuth clients, as a production deployment would have:

  advisor-console        the web app people sign in to (authorization code + PKCE, RFC 7636).
                         Its access token is the person's own token: the supervisor console uses it
                         for approvals and the compliance view uses it for the audit log.
  advisor-assist-agent   the agent runtime. For every agent run it exchanges the person's token for
                         a new one (RFC 8693 token exchange): audience = the gateway, scopes narrowed
                         to what the agent's tools need, `act` = the agent. It never sees a password.

Nothing here is trusted by the gateway: the gateway verifies every token itself against the
authorization server's JWKS.
"""

from __future__ import annotations

import base64
import hashlib
import html
import re
import secrets
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt

from .. import AGENT_ID, telemetry
from ..identity import AGENT_SCOPES, ALGORITHM, JwksKeySource

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
LOGIN_SCOPES = ("openid", "client:read", "positions:read", "profile:write", "comms:draft", "payments:initiate",
                "approvals:decide", "audit:read", "controls:admin")

DEFAULT_ISSUER = "http://localhost:8180/realms/fsi-demo"
CONSOLE_CLIENT = ("advisor-console", "console-dev-secret-not-for-production")
AGENT_CLIENT = (AGENT_ID, "agent-dev-secret-not-for-production")
# every agent is its own confidential OAuth client (demo secrets; a deployment would use workload identity)
AGENT_CLIENTS = {AGENT_ID: AGENT_CLIENT, **{a: (a, f"{a.split('-')[0]}-dev-secret-not-for-production")
                                          for a in ("orchestrator-agent", "accounts-agent", "payments-agent",
                                                    "comms-agent")}}


class OidcError(Exception):
    def __init__(self, error: str, description: str = "", status: int = 400):
        super().__init__(f"{error}: {description}" if description else error)
        self.error, self.description, self.status = error, description, status


class LoginRequired(Exception):
    def __init__(self, who: str):
        super().__init__(f"{who} is not signed in")
        self.who = who


@dataclass
class TokenSet:
    access_token: str
    refresh_token: str | None
    expires_at: float
    username: str
    scopes: frozenset[str]


@dataclass
class OidcConfig:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    end_session_endpoint: str | None = None
    console: tuple[str, str] = CONSOLE_CLIENT
    agent: tuple[str, str] = AGENT_CLIENT
    agents: dict[str, tuple[str, str]] = field(default_factory=lambda: dict(AGENT_CLIENTS))

    @classmethod
    def discover(cls, issuer: str, http: httpx.Client | None = None, **kw: Any) -> "OidcConfig":
        http = http or httpx.Client(timeout=5)
        meta = http.get(issuer.rstrip("/") + "/.well-known/openid-configuration").raise_for_status().json()
        if meta.get("issuer") != issuer:  # RFC 8414 §3.3
            raise OidcError("issuer_mismatch", f"configured {issuer}, discovery says {meta.get('issuer')}")
        return cls(issuer=issuer, authorization_endpoint=meta["authorization_endpoint"],
                   token_endpoint=meta["token_endpoint"], jwks_uri=meta["jwks_uri"],
                   end_session_endpoint=meta.get("end_session_endpoint"), **kw)


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def scopes_of(token: str) -> frozenset[str]:
    return frozenset(str(jwt.decode(token, options={"verify_signature": False}).get("scope", "")).split())


@dataclass
class _Pending:
    verifier: str
    nonce: str
    who: str
    redirect_uri: str
    created: float = field(default_factory=time.time)


class OidcIdentity:
    """Sessions for the people signed in to this demo console, plus the agent's token exchange."""

    mode = "keycloak"

    def __init__(self, config: OidcConfig, usernames: dict[str, str], http: httpx.Client | None = None):
        self.config = config
        self.usernames = usernames  # demo key -> username (e.g. "ana" -> "ana.ruiz")
        self.http = http or httpx.Client(timeout=10)
        self.keys = JwksKeySource(config.jwks_uri, fetch=lambda url: self.http.get(url).raise_for_status().json())
        self._sessions: dict[str, TokenSet] = {}
        self._pending: dict[str, _Pending] = {}
        self._lock = threading.Lock()
        self._refresh_lock = threading.Lock()  # refresh tokens are single-use (revokeRefreshToken)

    # ---------------------------------------------------------------- sign-in (authorization code + PKCE)

    def authorize_url(self, who: str, redirect_uri: str) -> str:
        verifier, challenge = _pkce()
        state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        with self._lock:
            now = time.time()
            self._pending = {k: v for k, v in self._pending.items() if now - v.created < 600}
            self._pending[state] = _Pending(verifier, nonce, who, redirect_uri)
        params = {"response_type": "code", "client_id": self.config.console[0], "redirect_uri": redirect_uri,
                  "scope": " ".join(LOGIN_SCOPES), "state": state, "nonce": nonce,
                  "code_challenge": challenge, "code_challenge_method": "S256",
                  "login_hint": self.usernames.get(who, ""), "prompt": "login"}
        return self.config.authorization_endpoint + "?" + urllib.parse.urlencode(params)

    def complete_login(self, state: str, code: str) -> str:
        """Redeem the code, verify what came back, and store the session. Returns the demo key."""
        with self._lock:
            pending = self._pending.pop(state, None)
        if pending is None:
            raise OidcError("invalid_state", "unknown or expired login attempt")
        data = self._token_request({"grant_type": "authorization_code", "code": code,
                                    "redirect_uri": pending.redirect_uri, "code_verifier": pending.verifier},
                                   self.config.console)
        claims = self._verify(data["access_token"])
        if data.get("id_token"):
            id_claims = self._verify(data["id_token"], audience=self.config.console[0], access=False)
            if id_claims.get("nonce") != pending.nonce:
                raise OidcError("invalid_nonce", "ID token nonce does not match this login")
        username = claims.get("preferred_username", "")
        who = next((k for k, u in self.usernames.items() if u == username), None)
        if who is None:
            raise OidcError("unknown_user", f"{username!r} is not a person in this demo's directory")
        self._store(who, data, claims)
        return who

    def sign_out(self, who: str) -> None:
        with self._lock:
            self._sessions.pop(who, None)

    def signed_in(self) -> list[str]:
        with self._lock:
            return [k for k, s in self._sessions.items() if s.refresh_token or s.expires_at > time.time()]

    # ---------------------------------------------------------------- tokens used against the gateway

    def console_token(self, who: str) -> str:
        """The person's own access token (supervisor approvals, compliance audit view)."""
        with self._lock:
            session = self._sessions.get(who)
        if session is None:
            raise LoginRequired(who)
        if session.expires_at - 30 > time.time():
            return session.access_token
        with self._refresh_lock:
            with self._lock:
                session = self._sessions.get(who)
            if session is None:
                raise LoginRequired(who)
            if session.expires_at - 30 > time.time():  # another request refreshed it meanwhile
                return session.access_token
            if not session.refresh_token:
                self.sign_out(who)
                raise LoginRequired(who)
            try:
                data = self._token_request({"grant_type": "refresh_token", "refresh_token": session.refresh_token},
                                           self.config.console)
            except OidcError:
                self.sign_out(who)
                raise LoginRequired(who) from None
            self._store(who, data, self._verify(data["access_token"]))
            return data["access_token"]

    def agent_token(self, who: str, scopes: frozenset[str] | None = None, agent: str = AGENT_ID) -> str:
        """RFC 8693: the agent's client exchanges the person's token for one bound to this run."""
        return self.exchange(self.console_token(who), agent, scopes if scopes is not None else AGENT_SCOPES)

    def exchange(self, subject_token: str, agent: str, scopes: frozenset[str]) -> str:
        """RFC 8693 token exchange by `agent`'s own client. Keycloak only lets it narrow scopes, and only
        if `agent` is in the subject token's audience (that is what fixes who may delegate to whom)."""
        wanted = scopes & scopes_of(subject_token)
        form = {"grant_type": TOKEN_EXCHANGE, "subject_token": subject_token,
                "subject_token_type": ACCESS_TOKEN_TYPE, "requested_token_type": ACCESS_TOKEN_TYPE}
        if wanted:
            form["scope"] = " ".join(sorted(wanted))
        return self._token_request(form, self.config.agents[agent])["access_token"]

    def exchange_raw(self, subject_token: str, scope: str | None) -> httpx.Response:
        """For the self-test: send an exchange exactly as given and return the raw response."""
        form = {"grant_type": TOKEN_EXCHANGE, "subject_token": subject_token, "subject_token_type": ACCESS_TOKEN_TYPE}
        if scope:
            form["scope"] = scope
        return self.http.post(self.config.token_endpoint, data=form, auth=self.config.agent)

    # ---------------------------------------------------------------- helpers

    def _store(self, who: str, data: dict[str, Any], claims: dict[str, Any]) -> None:
        ts = TokenSet(data["access_token"], data.get("refresh_token"), time.time() + int(data.get("expires_in", 300)),
                      claims.get("preferred_username", ""), frozenset(str(claims.get("scope", "")).split()))
        with self._lock:
            self._sessions[who] = ts

    def _token_request(self, form: dict[str, str], client: tuple[str, str]) -> dict[str, Any]:
        grant = form["grant_type"].rsplit(":", 1)[-1]
        with telemetry.span("govagent.idp", f"idp {grant}", "CLIENT", **{
                "server.address": self.config.token_endpoint, "oauth.grant_type": form["grant_type"],
                "oauth.client_id": client[0], "govagent.token.requested_scopes": form.get("scope")}) as sp:
            # traceparent lets Keycloak's own spans (with tracing enabled) join this trace in Jaeger
            resp = self.http.post(self.config.token_endpoint, data=form, auth=client,
                                  headers=telemetry.inject_headers())
            try:
                body = resp.json()
            except ValueError:
                body = {}
            telemetry.set_attrs(sp, **{"http.response.status_code": resp.status_code,
                                       "govagent.token.granted_scope": body.get("scope")})
            if resp.status_code != 200 or "access_token" not in body:
                telemetry.mark_error(sp, f"{body.get('error')}: {body.get('error_description', '')}")
                raise OidcError(body.get("error", f"http_{resp.status_code}"), body.get("error_description", ""),
                                resp.status_code)
            return body

    def _verify(self, token: str, audience: str | None = None, access: bool = True) -> dict[str, Any]:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != ALGORITHM:
            raise OidcError("unexpected_algorithm", str(header.get("alg")))
        key = self.keys().get(header.get("kid", "")) or self.keys.refresh().get(header.get("kid", ""))
        if key is None:
            raise OidcError("unknown_key", "token signed with a key not in the JWKS")
        options = {"verify_aud": audience is not None}
        claims = jwt.decode(token, key, algorithms=[ALGORITHM], issuer=self.config.issuer, audience=audience,
                            options=options, leeway=5)
        if access and claims.get("typ") != "Bearer":
            raise OidcError("wrong_token_type", str(claims.get("typ")))
        return claims


class KeycloakTokenBroker:
    """Token broker for the orchestrator and single agent, backed by Keycloak (see TokenBroker)."""

    def __init__(self, identity: OidcIdentity, ledger: Any = None):
        from ..orchestrator import TokenLedger

        self.identity = identity
        self.ledger = ledger or TokenLedger()

    def person_to_agent(self, who: str, agent_id: str) -> str:
        from ..orchestrator.runtime import token_id

        subject = self.identity.console_token(who)
        self.ledger.record("sign-in", subject, requester="advisor-console", agent=None,
                           note="the person's own token from Keycloak sign-in (authorization code + PKCE)")
        token = self.identity.exchange(subject, agent_id, AGENT_SCOPES)
        self.ledger.record("token-exchange", token, requester=agent_id, agent=agent_id, parent=token_id(subject),
                           requested_scopes=AGENT_SCOPES & scopes_of(subject))
        return token

    def delegate(self, parent_token: str, agent_id: str, scopes: frozenset[str]) -> str:
        from ..orchestrator.runtime import token_id

        token = self.identity.exchange(parent_token, agent_id, scopes)
        self.ledger.record("token-exchange", token, requester=agent_id, agent=agent_id,
                           parent=token_id(parent_token), requested_scopes=scopes & scopes_of(parent_token))
        return token


def password_login(config: OidcConfig, username: str, password: str, redirect_uri: str,
                   http: httpx.Client | None = None) -> dict[str, Any]:
    """Drive the real browser login (authorization code + PKCE) over plain HTTP, for the self-test.
    This is the same flow a person uses; it is not the password grant (which is disabled)."""
    http = http or httpx.Client(timeout=10)
    verifier, challenge = _pkce()
    state = secrets.token_urlsafe(16)
    page = http.get(config.authorization_endpoint, params={
        "response_type": "code", "client_id": config.console[0], "redirect_uri": redirect_uri,
        "scope": " ".join(LOGIN_SCOPES), "state": state, "nonce": secrets.token_urlsafe(16),
        "code_challenge": challenge, "code_challenge_method": "S256", "prompt": "login"})
    form = re.search(r'<form[^>]*id="kc-form-login"[^>]*>', page.text) or \
        re.search(r'<form[^>]*action="[^"]*login-actions/authenticate[^"]*"[^>]*>', page.text)
    action = re.search(r'action="([^"]+)"', form.group(0)) if form else None
    if not action:
        raise OidcError("login_form_not_found", f"HTTP {page.status_code} from the authorization endpoint")
    resp = http.post(html.unescape(action.group(1)), data={"username": username, "password": password,
                                                            "credentialId": ""}, follow_redirects=False)
    location = resp.headers.get("location", "")
    query = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
    if "code" not in query or query.get("state", [""])[0] != state:
        raise OidcError("login_failed", f"HTTP {resp.status_code}; no authorization code for {username}")
    token = http.post(config.token_endpoint, auth=config.console, data={
        "grant_type": "authorization_code", "code": query["code"][0], "redirect_uri": redirect_uri,
        "code_verifier": verifier})
    body = token.json()
    if token.status_code != 200:
        raise OidcError(body.get("error", "token_error"), body.get("error_description", ""), token.status_code)
    return body
