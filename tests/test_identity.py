"""Delegation tokens: RFC 9068 JWT profile, RFC 8693 actor, RFC 8725 hardening, rotation, revocation."""

import jwt
import pytest
from conftest import Clock

from govagent.app import PRINCIPALS
from govagent.identity import (DEFAULT_AUDIENCE, KeyRing, TokenError, TokenService, TokenVerifier,
                               peek_run_id)
from govagent.state import StateStore


def setup(clock=None):
    keys, store = KeyRing(), StateStore()
    clock = clock or Clock()
    return keys, store, TokenService(keys, clock=clock), TokenVerifier(keys.public_keys, store=store, clock=clock)


def test_roundtrip_claims():
    _, _, issuer, verifier = setup()
    token = issuer.issue(PRINCIPALS["ana"], "agent-x", run_id="run-1")
    header = jwt.get_unverified_header(token)
    assert header["typ"] == "at+jwt" and header["alg"] == "EdDSA" and header["kid"]
    grant = verifier.verify(token)
    assert grant.principal_id == "ana.ruiz" and grant.agent_id == "agent-x" and grant.run_id == "run-1"
    assert "payments:initiate" in grant.scopes and grant.clients == {"C-1001", "C-1002"}
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["act"] == {"sub": "agent-x"} and claims["aud"] == DEFAULT_AUDIENCE and claims["client_id"]
    assert peek_run_id(token) == "run-1"


def test_scopes_cannot_exceed_role_and_ttl_is_bounded():
    _, _, issuer, _ = setup()
    with pytest.raises(TokenError, match="exceed role"):
        issuer.issue(PRINCIPALS["sam"], "a", scopes=["payments:initiate"])
    with pytest.raises(TokenError):
        issuer.issue(PRINCIPALS["ana"], "a", ttl_seconds=7200)


def test_expiry():
    clock = Clock()
    _, _, issuer, verifier = setup(clock)
    token = issuer.issue(PRINCIPALS["ana"], "a", ttl_seconds=60)
    clock.now += 61
    with pytest.raises(TokenError, match="expired"):
        verifier.verify(token)


def test_audience_and_issuer_are_enforced():
    keys, store, issuer, verifier = setup()
    with pytest.raises(TokenError, match="audience"):
        verifier.verify(issuer.issue(PRINCIPALS["ana"], "a", audience="https://other.example"))
    rogue = TokenService(keys, issuer="https://evil.example")
    with pytest.raises(TokenError, match="issuer"):
        verifier.verify(rogue.issue(PRINCIPALS["ana"], "a"))


def test_signature_type_and_algorithm_attacks():
    keys, _, issuer, verifier = setup()
    token = issuer.issue(PRINCIPALS["lee"], "a")
    other = TokenService(KeyRing())  # a different key with an unknown kid
    with pytest.raises(TokenError, match="unknown"):
        verifier.verify(other.issue(PRINCIPALS["lee"], "a"))
    claims = jwt.decode(token, options={"verify_signature": False})
    kid, key = keys.signing_key()
    with pytest.raises(TokenError, match="type"):  # an ID token or other JWT is not an access token
        verifier.verify(jwt.encode(claims, key, algorithm="EdDSA", headers={"kid": kid, "typ": "JWT"}))
    unsigned = jwt.encode(claims, None, algorithm="none", headers={"kid": kid, "typ": "at+jwt"})
    with pytest.raises(TokenError, match="algorithm"):  # RFC 8725 §3.1
        verifier.verify(unsigned)
    body = token.split(".")
    tampered = ".".join([body[0], body[1][:-2] + ("A" if body[1][-2] != "A" else "B") + body[1][-1], body[2]])
    with pytest.raises(TokenError):
        verifier.verify(tampered)


def test_key_rotation():
    keys, _, issuer, verifier = setup()
    old_token = issuer.issue(PRINCIPALS["ana"], "a")
    old_kid = keys.active_kid
    keys.rotate()
    new_token = issuer.issue(PRINCIPALS["ana"], "a")
    assert jwt.get_unverified_header(new_token)["kid"] != old_kid
    verifier.verify(old_token)  # still valid during the overlap
    verifier.verify(new_token)
    keys.retire(old_kid)
    with pytest.raises(TokenError, match="retired"):
        verifier.verify(old_token)
    verifier.verify(new_token)


def test_revocation_by_token_and_by_subject():
    clock = Clock()
    _, store, issuer, verifier = setup(clock)
    t1 = issuer.issue(PRINCIPALS["ana"], "a")
    store.revoke("jti", jwt.decode(t1, options={"verify_signature": False})["jti"], clock())
    with pytest.raises(TokenError, match="revoked"):
        verifier.verify(t1)
    t2 = issuer.issue(PRINCIPALS["ana"], "a")
    clock.now += 1
    store.revoke("sub", "ana.ruiz", clock())
    with pytest.raises(TokenError, match="subject"):
        verifier.verify(t2)
    clock.now += 1
    verifier.verify(issuer.issue(PRINCIPALS["ana"], "a"))  # tokens issued after the cut are fine


# ---------------------------------------------------------------- DPoP (RFC 9449, item 7)

def test_dpop_bound_token_requires_a_matching_proof():
    import govagent.dpop as dpop

    clock = Clock()
    _, _, issuer, verifier = setup(clock)
    key = dpop.DPoPKey.generate()
    token = issuer.issue(PRINCIPALS["ana"], "a", dpop_jkt=key.thumbprint)
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["cnf"] == {"jkt": key.thumbprint}

    url = "https://gateway.govagent.example/v1/tools/get_positions/invoke"
    proof = key.proof("POST", url, access_token=token, clock=clock)
    grant = verifier.verify(token, dpop_proof=proof, http_method="POST", http_url=url)
    assert grant.agent_id == "a"

    with pytest.raises(TokenError, match="no proof/method/url"):
        verifier.verify(token)  # a bound token presented bare


def test_dpop_bound_token_refuses_a_different_keys_proof():
    """The stolen-token scenario item 7 exists for: holding the bearer string is not enough."""
    import govagent.dpop as dpop

    clock = Clock()
    _, _, issuer, verifier = setup(clock)
    key, thief = dpop.DPoPKey.generate(), dpop.DPoPKey.generate()
    token = issuer.issue(PRINCIPALS["ana"], "a", dpop_jkt=key.thumbprint)
    url = "https://gateway.govagent.example/x"
    stolen_proof = thief.proof("POST", url, access_token=token, clock=clock)
    with pytest.raises(TokenError, match="different key"):
        verifier.verify(token, dpop_proof=stolen_proof, http_method="POST", http_url=url)


def test_dpop_proof_jti_cannot_be_replayed():
    import govagent.dpop as dpop

    clock = Clock()
    _, _, issuer, verifier = setup(clock)
    key = dpop.DPoPKey.generate()
    token = issuer.issue(PRINCIPALS["ana"], "a", dpop_jkt=key.thumbprint)
    url = "https://gateway.govagent.example/x"
    proof = key.proof("POST", url, access_token=token, clock=clock)
    verifier.verify(token, dpop_proof=proof, http_method="POST", http_url=url)
    with pytest.raises(TokenError, match="replay"):
        verifier.verify(token, dpop_proof=proof, http_method="POST", http_url=url)


def test_dpop_proof_must_match_the_actual_method_and_url():
    import govagent.dpop as dpop

    _, _, issuer, verifier = setup()
    key = dpop.DPoPKey.generate()
    token = issuer.issue(PRINCIPALS["ana"], "a", dpop_jkt=key.thumbprint)
    url = "https://gateway.govagent.example/v1/tools/initiate_wire_transfer/invoke"
    proof = key.proof("POST", url, access_token=token)
    with pytest.raises(TokenError, match="different URL"):
        verifier.verify(token, dpop_proof=proof, http_method="POST",
                        http_url="https://gateway.govagent.example/v1/tools/get_positions/invoke")


def test_a_non_bound_token_is_unaffected_by_dpop():
    _, _, issuer, verifier = setup()
    token = issuer.issue(PRINCIPALS["ana"], "a")  # no dpop_jkt
    grant = verifier.verify(token)  # no proof, no method, no url -- still fine
    assert grant.agent_id == "a"


def test_exchange_carries_the_subjects_dpop_binding_forward_by_default():
    import govagent.dpop as dpop

    clock = Clock()
    _, _, issuer, verifier = setup(clock)
    key = dpop.DPoPKey.generate()
    orch = issuer.issue(PRINCIPALS["ana"], "orchestrator-agent", dpop_jkt=key.thumbprint)
    pay = issuer.exchange(orch, "payments-agent", {"payments:initiate"})
    claims = jwt.decode(pay, options={"verify_signature": False})
    assert claims["cnf"] == {"jkt": key.thumbprint}  # same key, not re-stated by the caller

    url = "https://gateway.govagent.example/x"
    proof = key.proof("POST", url, access_token=pay, clock=clock)
    verifier.verify(pay, dpop_proof=proof, http_method="POST", http_url=url)  # does not raise
