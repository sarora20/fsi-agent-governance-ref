"""DPoP: sender-constrained access tokens (RFC 9449).

Without this, a stolen delegation token is usable by whoever holds it -- the bearer-token
weakness every other control in this gateway assumes away. DPoP binds a token to a key pair the
*client* holds (never the issuer, never the gateway): each request carries a short-lived proof
JWT, signed by that key, over the HTTP method, the URL, a fresh timestamp and a hash of the
access token itself. The access token itself carries only the key's public thumbprint
(`cnf.jkt`, RFC 7638) -- so a resource server can confirm "this caller holds the private key
this token was bound to" without ever seeing that key.

This module is the pure cryptographic half: building and parsing a DPoP keypair, minting a
proof, and verifying one's signature and claims against what a REAL request just carried
(method, URL, the token's own ath hash). Replay protection (a proof's `jti` used twice) needs
durable, run-spanning state, so it lives in identity.py's TokenVerifier (which already holds a
StateStore for the parallel jti/subject revocation checks) -- not here.

What this changes for an existing caller: nothing, until a token actually carries `cnf.jkt`.
Every caller that never requests a DPoP-bound token keeps working exactly as before; the
dev/Keycloak profiles, the harness, the demo console and every existing test are all
bearer-token callers today, and stay that way unless they opt in.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PROOF_TYPE = "dpop+jwt"
PROOF_ALGORITHM = "EdDSA"
DEFAULT_MAX_AGE_SECONDS = 60  # a stale iat is as much a replay risk as a reused jti


class DPoPError(Exception):
    """Raised when a DPoP proof is missing, malformed, mis-bound or does not match the request."""


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwk_for(public_key: Ed25519PublicKey) -> dict[str, str]:
    """An Ed25519 public key as a JWK (RFC 8037 OKP), the form DPoP proofs embed in their header
    and the form a thumbprint (below) is computed over."""
    raw = public_key.public_bytes_raw()
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}


def jwk_thumbprint(public_key: Ed25519PublicKey) -> str:
    """RFC 7638: SHA-256 over the canonical JSON of only the required members, lexicographic
    key order, no whitespace. This -- not the proof's signature -- is what binds a token to a
    key: `cnf.jkt` on the token must equal this computed from whatever key signs each proof."""
    jwk = jwk_for(public_key)
    canonical = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]},
                           sort_keys=True, separators=(",", ":"))
    return _b64url(hashlib.sha256(canonical.encode()).digest())


def access_token_hash(access_token: str) -> str:
    """The `ath` claim: SHA-256 of the access token's own bytes, base64url. Binds a proof to one
    specific token, not just to its holder's key -- a stolen bearer token still can't be replayed
    under a thief's own proof, since the thief does not hold the private key `cnf.jkt` names."""
    return _b64url(hashlib.sha256(access_token.encode()).digest())


@dataclass(frozen=True)
class DPoPKey:
    """A client-held DPoP key pair. Generated once per agent runtime (or per run, for maximum
    unlinkability) and never sent anywhere -- only its public thumbprint ever leaves, carried
    inside the access token the IdP issues after seeing this key's JWK at the token request."""

    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "DPoPKey":
        return cls(Ed25519PrivateKey.generate())

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    @property
    def thumbprint(self) -> str:
        return jwk_thumbprint(self.public_key)

    def proof(self, htm: str, htu: str, access_token: str | None = None,
             clock: Callable[[], float] = time.time) -> str:
        """Mint one proof JWT for exactly one request. `htu` is the request URL with no query or
        fragment (RFC 9449 §4.2); `htm` is the HTTP method. `access_token` is required whenever
        this proof accompanies a resource request (as opposed to a token request, which has none
        yet) -- it is what ties the proof to the specific bearer credential being presented."""
        claims = {"jti": uuid.uuid4().hex, "htm": htm.upper(), "htu": htu, "iat": int(clock())}
        if access_token is not None:
            claims["ath"] = access_token_hash(access_token)
        return jwt.encode(claims, self.private_key, algorithm=PROOF_ALGORITHM,
                          headers={"typ": PROOF_TYPE, "jwk": jwk_for(self.public_key)})


def verify_proof(proof: str, htm: str, htu: str, access_token: str | None = None,
                 max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
                 clock: Callable[[], float] = time.time) -> tuple[str, dict[str, Any]]:
    """Verifies a proof's signature (against the public key its OWN header carries -- DPoP proofs
    are self-certifying; what makes that safe is the separate `cnf.jkt` check the caller still
    must do against the access token) and every claim except replay (jti reuse), which needs
    durable state this pure function does not hold. Returns (thumbprint of the signing key,
    parsed claims) on success; raises DPoPError naming exactly what failed, otherwise.

    Deliberately strict on htu: compared as given, not re-normalised (no scheme/host case
    folding, no default-port stripping) -- callers must pass the same canonical form on both
    sides, which every call site in this codebase does."""
    try:
        header = jwt.get_unverified_header(proof)
    except jwt.PyJWTError as exc:
        raise DPoPError(f"malformed proof: {exc}") from None
    if header.get("typ") != PROOF_TYPE:
        raise DPoPError(f"proof typ must be '{PROOF_TYPE}'")
    if header.get("alg") != PROOF_ALGORITHM:
        raise DPoPError(f"unexpected proof algorithm {header.get('alg')!r}")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "x" not in jwk:
        raise DPoPError("proof header is missing a usable Ed25519 jwk")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(_b64url_decode(jwk["x"]))
    except (ValueError, KeyError) as exc:
        raise DPoPError(f"malformed proof jwk: {exc}") from None
    try:
        claims = jwt.decode(proof, public_key, algorithms=[PROOF_ALGORITHM],
                            options={"require": ["jti", "htm", "htu", "iat"],
                                     "verify_exp": False, "verify_iat": False})  # freshness checked below,
                                                                                # against the given clock
    except jwt.PyJWTError as exc:
        raise DPoPError(f"invalid proof signature or claims: {exc}") from None
    if claims["htm"].upper() != htm.upper():
        raise DPoPError(f"proof is for method {claims['htm']!r}, this request is {htm!r}")
    if claims["htu"] != htu:
        raise DPoPError(f"proof is for a different URL ({claims['htu']!r} != {htu!r})")
    age = clock() - claims["iat"]
    if age < -5 or age > max_age_seconds:  # a few seconds of clock skew is tolerated, not more
        raise DPoPError(f"proof is {age:.0f}s old (max {max_age_seconds}s): mint one per request")
    if access_token is not None:
        if "ath" not in claims:
            raise DPoPError("proof has no ath claim, but this is a resource request")
        if claims["ath"] != access_token_hash(access_token):
            raise DPoPError("proof's ath does not match the access token actually presented")
    return jwk_thumbprint(public_key), claims
