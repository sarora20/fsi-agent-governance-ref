"""A small stand-in for Keycloak, driven by keycloak/realm-fsi-demo.json, for offline tests.

It reproduces the Keycloak 26.7 behaviour this build depends on, as documented:
  - authorization code + PKCE (S256) through a login form; no password grant
  - client scopes with role scope mappings are issued only to users holding one of those roles
  - audience mappers; `at+jwt` header when access.token.header.type.rfc9068 is set; EdDSA signing
  - standard token exchange: confidential requester with standard.token.exchange.enabled, requester must
    be in the subject token's `aud`, scope param = requester's optional scopes, and the realm's
    downscope-assertion-grant-enforcer policy (requested scopes must already be in the subject token)
  - hardcoded-claim and user-property mappers on the client

It is a test double, not a reimplementation: the real server is checked by `govagent keycloak-check`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import uuid
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jwt.algorithms import OKPAlgorithm

REALM_FILE = Path(__file__).resolve().parents[1] / "keycloak" / "realm-fsi-demo.json"
EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"


def _err(error: str, desc: str = "", status: int = 400):
    return JSONResponse({"error": error, "error_description": desc}, status_code=status)


def create_fake_keycloak(base_url: str = "http://localhost:8180", realm_file: Path = REALM_FILE) -> FastAPI:
    realm = json.loads(realm_file.read_text())
    name = realm["realm"]
    issuer = f"{base_url}/realms/{name}"
    prefix = f"/realms/{name}"
    key, kid = Ed25519PrivateKey.generate(), "fake-eddsa-1"
    clients = {c["clientId"]: c for c in realm["clients"]}
    scopes = {s["name"]: s for s in realm["clientScopes"]}
    scope_roles = {m["clientScope"]: set(m["roles"]) for m in realm.get("scopeMappings", [])}
    users = {u["username"]: {**u, "id": str(uuid.uuid5(uuid.NAMESPACE_URL, u["username"]))} for u in realm["users"]}
    downscope_only = any(p.get("enabled") and any(c["condition"] == "grant-type" and EXCHANGE in
                                                  c["configuration"].get("grant_types", []) for c in p["conditions"])
                         for p in realm.get("clientPolicies", {}).get("policies", []))
    logins: dict[str, dict] = {}
    codes: dict[str, dict] = {}
    refresh: dict[str, dict] = {}
    app = FastAPI()
    app.state.issued = []  # every access token issued, for assertions

    def permitted(scope: str, user: dict) -> bool:
        roles = scope_roles.get(scope)
        return not roles or bool(roles & set(user["realmRoles"]))

    def client_auth(request: Request) -> dict | None:
        header = request.headers.get("authorization", "")
        if not header.startswith("Basic "):
            return None
        cid, _, secret = base64.b64decode(header[6:]).decode().partition(":")
        c = clients.get(cid)
        return c if c and not c.get("publicClient") and c.get("secret") == secret else None

    def mint(client: dict, user: dict, requested: set[str], nonce: str | None = None,
             restricted: set[str] | None = None) -> dict:
        used = [s for s in client["defaultClientScopes"]] + [s for s in client["optionalClientScopes"] if s in requested]
        used = [s for s in used if s in scopes and permitted(s, user) and (restricted is None or s in restricted)]
        now = int(time.time())
        life = int(client["attributes"].get("access.token.lifespan") or realm.get("accessTokenLifespan", 300))
        claims: dict = {"exp": now + life, "iat": now, "jti": f"onrtac:{uuid.uuid4()}", "iss": issuer, "typ": "Bearer",
                        "azp": client["clientId"], "sid": "s1"}
        aud: list[str] = []
        token_scope = ["openid"] if "openid" in requested else []
        # Keycloak treats the client itself as a pseudo-scope; with a restricted-scope list (downscope-only
        # exchange) it is filtered out, so client-level mappers do not run (DefaultClientSessionContext.isAllowed).
        client_mappers = client.get("protocolMappers", []) if restricted is None else []
        mappers = [m for s in used for m in scopes[s].get("protocolMappers", [])] + client_mappers
        for s in used:
            if scopes[s]["attributes"].get("include.in.token.scope") == "true":
                token_scope.append(s)
        for m in mappers:
            cfg = m["config"]
            if cfg.get("access.token.claim") != "true":
                continue
            if m["protocolMapper"] == "oidc-sub-mapper":
                claims["sub"] = user["id"]
            elif m["protocolMapper"] == "oidc-audience-mapper":
                aud.append(cfg.get("included.client.audience") or cfg["included.custom.audience"])
            elif m["protocolMapper"] == "oidc-usermodel-property-mapper":
                claims[cfg["claim.name"]] = user[cfg["user.attribute"]]
            elif m["protocolMapper"] == "oidc-hardcoded-claim-mapper":
                parts, target = cfg["claim.name"].split("."), claims
                for p in parts[:-1]:
                    target = target.setdefault(p, {})
                target[parts[-1]] = cfg["claim.value"]
        if aud:
            claims["aud"] = aud[0] if len(aud) == 1 else aud
        claims["scope"] = " ".join(token_scope)
        typ = "at+jwt" if client["attributes"].get("access.token.header.type.rfc9068") == "true" else "JWT"
        access = jwt.encode(claims, key, algorithm="EdDSA", headers={"kid": kid, "typ": typ})
        app.state.issued.append(claims)
        out = {"access_token": access, "expires_in": life, "token_type": "Bearer", "scope": claims["scope"]}
        if "openid" in requested:
            out["id_token"] = jwt.encode({"iss": issuer, "aud": client["clientId"], "sub": user["id"], "iat": now,
                                          "exp": now + life, "nonce": nonce, "typ": "ID",
                                          "preferred_username": user["username"]}, key, algorithm="EdDSA",
                                         headers={"kid": kid, "typ": "JWT"})
        return out

    @app.get(prefix + "/.well-known/openid-configuration")
    def discovery():
        oidc = f"{issuer}/protocol/openid-connect"
        return {"issuer": issuer, "authorization_endpoint": f"{oidc}/auth", "token_endpoint": f"{oidc}/token",
                "jwks_uri": f"{oidc}/certs", "end_session_endpoint": f"{oidc}/logout",
                "grant_types_supported": ["authorization_code", "refresh_token", EXCHANGE],
                "code_challenge_methods_supported": ["S256"]}

    @app.get(prefix + "/protocol/openid-connect/certs")
    def certs():
        okp = {**json.loads(OKPAlgorithm.to_jwk(key.public_key())), "kid": kid, "alg": "EdDSA", "use": "sig"}
        rsa_decoy = {"kty": "RSA", "kid": "rsa-1", "alg": "RS256", "use": "sig", "n": "AQAB", "e": "AQAB"}
        return {"keys": [rsa_decoy, okp]}

    @app.get(prefix + "/protocol/openid-connect/auth")
    def authorize(request: Request):
        q = request.query_params
        c = clients.get(q.get("client_id", ""))
        if c is None or not c.get("standardFlowEnabled") or q.get("redirect_uri") not in c["redirectUris"]:
            return HTMLResponse("invalid client or redirect_uri", status_code=400)
        if c["attributes"].get("pkce.code.challenge.method") == "S256" and q.get("code_challenge_method") != "S256":
            return HTMLResponse("PKCE required", status_code=400)
        sc = secrets.token_urlsafe(8)
        logins[sc] = dict(q)
        action = f"{issuer}/login-actions/authenticate?session_code={sc}&amp;execution=x&amp;client_id={c['clientId']}"
        return HTMLResponse(f'<html><body><form id="kc-form-login" class="pf-v5-c-form" onsubmit="return true;" '
                            f'action="{action}" method="post"><input name="username"><input name="password" '
                            f'type="password"><button type="submit" id="kc-login">Sign In</button></form></body></html>')

    @app.post(prefix + "/login-actions/authenticate")
    def authenticate(session_code: str, username: str = Form(...), password: str = Form(...)):
        q = logins.pop(session_code, None)
        user = users.get(username)
        if q is None or user is None or user["credentials"][0]["value"] != password:
            return HTMLResponse("Invalid username or password.", status_code=200)
        code = secrets.token_urlsafe(16)
        codes[code] = {**q, "username": username}
        return RedirectResponse(f"{q['redirect_uri']}?code={code}&state={q['state']}", status_code=302)

    @app.post(prefix + "/protocol/openid-connect/token")
    async def token(request: Request):
        form = dict(await request.form())
        client = client_auth(request)
        if client is None:
            return _err("unauthorized_client", "Invalid client or Invalid client credentials", 401)
        grant = form.get("grant_type")
        if grant == "password":
            return _err("unauthorized_client", "Client not allowed for direct access grants")
        if grant == "authorization_code":
            c = codes.pop(form.get("code", ""), None)
            if c is None or c["client_id"] != client["clientId"] or c["redirect_uri"] != form.get("redirect_uri"):
                return _err("invalid_grant", "Code not valid")
            challenge = base64.urlsafe_b64encode(hashlib.sha256(form.get("code_verifier", "").encode()).digest())
            if challenge.rstrip(b"=").decode() != c["code_challenge"]:
                return _err("invalid_grant", "PKCE verification failed")
            user = users[c["username"]]
            out = mint(client, user, set(c["scope"].split()), c.get("nonce"))
            rt = secrets.token_urlsafe(24)
            refresh[rt] = {"client": client["clientId"], "user": user["username"], "scope": c["scope"]}
            return {**out, "refresh_token": rt}
        if grant == "refresh_token":
            r = refresh.pop(form.get("refresh_token", ""), None)
            if r is None or r["client"] != client["clientId"]:
                return _err("invalid_grant", "Invalid refresh token")
            out = mint(client, users[r["user"]], set(r["scope"].split()))
            rt = secrets.token_urlsafe(24)
            refresh[rt] = r
            return {**out, "refresh_token": rt}
        if grant == EXCHANGE:
            if client["attributes"].get("standard.token.exchange.enabled") != "true":
                return _err("unauthorized_client", "Standard token exchange is not enabled for the requested client")
            if form.get("subject_token_type") != "urn:ietf:params:oauth:token-type:access_token":
                return _err("invalid_request", "Parameter 'subject_token' supports access tokens only")
            try:
                subj = jwt.decode(form.get("subject_token", ""), key.public_key(), algorithms=["EdDSA"],
                                  options={"verify_aud": False}, issuer=issuer)
            except jwt.PyJWTError:
                return _err("invalid_token", "Invalid token")
            auds = subj.get("aud", [])
            auds = [auds] if isinstance(auds, str) else auds
            if client["clientId"] not in auds and subj.get("azp") != client["clientId"]:
                return _err("access_denied", "Client is not within the token audience")
            requested = set(form.get("scope", "").split())
            subject_scopes = set(subj.get("scope", "").split())
            restricted = None
            if downscope_only:
                if requested - subject_scopes:
                    missing = requested - subject_scopes
                    return _err("invalid_scope", f"Scopes {sorted(missing)} not present in the initial access token")
                restricted = subject_scopes | {s for s in client["defaultClientScopes"]
                                               if scopes[s]["attributes"].get("include.in.token.scope") == "false"}
            user = next(u for u in users.values() if u["id"] == subj["sub"])
            return {**mint(client, user, requested, restricted=restricted),
                    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"}
        return _err("unsupported_grant_type")

    app.state.issuer = issuer
    return app
