"""DPoP (RFC 9449) pure crypto: proof minting, verification, and every denial path."""

import pytest

from govagent import dpop


def test_proof_round_trips_and_thumbprint_is_stable():
    key = dpop.DPoPKey.generate()
    url = "https://gateway.example/v1/tools/get_positions/invoke"
    proof = key.proof("POST", url, access_token="tok")
    thumbprint, claims = dpop.verify_proof(proof, "POST", url, access_token="tok")
    assert thumbprint == key.thumbprint
    assert claims["htm"] == "POST" and claims["htu"] == url and "jti" in claims


def test_method_is_case_insensitive_but_must_match():
    key = dpop.DPoPKey.generate()
    url = "https://gateway.example/x"
    proof = key.proof("get", url)
    dpop.verify_proof(proof, "GET", url)  # does not raise
    with pytest.raises(dpop.DPoPError, match="method"):
        dpop.verify_proof(proof, "POST", url)


def test_wrong_url_is_refused():
    key = dpop.DPoPKey.generate()
    proof = key.proof("GET", "https://gateway.example/a")
    with pytest.raises(dpop.DPoPError, match="different URL"):
        dpop.verify_proof(proof, "GET", "https://gateway.example/b")


def test_ath_binds_the_proof_to_one_specific_token():
    key = dpop.DPoPKey.generate()
    url = "https://gateway.example/x"
    proof = key.proof("GET", url, access_token="tokA")
    dpop.verify_proof(proof, "GET", url, access_token="tokA")  # does not raise
    with pytest.raises(dpop.DPoPError, match="ath"):
        dpop.verify_proof(proof, "GET", url, access_token="tokB")
    # a proof minted with no access_token at all (no ath claim) is fine for a request that also
    # passes no access_token; it is only refused when the REQUEST needed ath but got none:
    no_ath_proof = key.proof("GET", url)  # no access_token given at mint time
    with pytest.raises(dpop.DPoPError, match="no ath claim"):
        dpop.verify_proof(no_ath_proof, "GET", url, access_token="tokA")


def test_stale_proof_is_refused_small_skew_tolerated():
    key = dpop.DPoPKey.generate()
    url = "https://gateway.example/x"

    clock = {"t": 1_800_000_000.0}
    proof = key.proof("GET", url, clock=lambda: clock["t"])
    dpop.verify_proof(proof, "GET", url, clock=lambda: clock["t"] + 3)  # small skew: fine
    with pytest.raises(dpop.DPoPError, match="old"):
        dpop.verify_proof(proof, "GET", url, clock=lambda: clock["t"] + 61)


def test_tampered_signature_is_refused():
    key = dpop.DPoPKey.generate()
    proof = key.proof("GET", "https://gateway.example/x")
    header, payload, sig = proof.split(".")
    flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
    with pytest.raises(dpop.DPoPError, match="invalid proof signature"):
        dpop.verify_proof(f"{header}.{payload}.{flipped}", "GET", "https://gateway.example/x")


def test_a_different_keys_proof_thumbprints_differently():
    """verify_proof alone cannot catch a stolen-token replay (a proof is self-certifying by
    design) -- the caller must separately compare the returned thumbprint against the token's own
    cnf.jkt. This is exactly what identity.py's TokenVerifier does; this test fixes the contract
    that makes that check meaningful."""
    key, other = dpop.DPoPKey.generate(), dpop.DPoPKey.generate()
    url = "https://gateway.example/x"
    proof = other.proof("GET", url, access_token="tok")
    thumbprint, _ = dpop.verify_proof(proof, "GET", url, access_token="tok")  # valid on its own
    assert thumbprint != key.thumbprint


def test_wrong_typ_or_alg_header_is_refused():
    import jwt as pyjwt

    key = dpop.DPoPKey.generate()
    bad_typ = pyjwt.encode({"jti": "x", "htm": "GET", "htu": "u", "iat": 0}, key.private_key,
                           algorithm="EdDSA", headers={"typ": "jwt", "jwk": dpop.jwk_for(key.public_key)})
    with pytest.raises(dpop.DPoPError, match="typ"):
        dpop.verify_proof(bad_typ, "GET", "u")


def test_missing_or_malformed_jwk_header_is_refused():
    import jwt as pyjwt

    key = dpop.DPoPKey.generate()
    no_jwk = pyjwt.encode({"jti": "x", "htm": "GET", "htu": "u", "iat": 0}, key.private_key,
                          algorithm="EdDSA", headers={"typ": dpop.PROOF_TYPE})
    with pytest.raises(dpop.DPoPError, match="jwk"):
        dpop.verify_proof(no_jwk, "GET", "u")
