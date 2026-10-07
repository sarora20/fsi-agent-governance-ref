"""Tool catalogue for the advisor-assist agent, registered with risk tiers and scopes."""

from __future__ import annotations

from ..registry import RiskTier, ToolRegistry, ToolSpec
from .backend import WealthBackend

_CLIENT_ID = {"type": "string", "pattern": "^C-\\d{4}$", "description": "Client id, e.g. C-1001"}


def build_registry(backend: WealthBackend) -> ToolRegistry:
    reg = ToolRegistry()
    reg.register(ToolSpec(
        name="get_client_profile",
        description="Read a client's profile: name, segment, risk profile, mailing address, accounts, "
                    "approved wire beneficiaries and advisor notes.",
        input_schema={"type": "object", "properties": {"client_id": _CLIENT_ID},
                      "required": ["client_id"], "additionalProperties": False},
        handler=backend.get_client_profile,
        required_scope="client:read",
        risk_tier=RiskTier.READ,
        data_classes=("PII",),
        returns=frozenset({"client_id", "name", "segment", "risk_profile", "mailing_address", "accounts",
                          "approved_beneficiaries", "notes"}),
        mask=frozenset({"account_id"}),  # accounts: [{account_id, type}, ...] -- masked wherever it appears
    ))
    reg.register(ToolSpec(
        name="get_positions",
        description="Read a client's holdings, market values and cash balances.",
        input_schema={"type": "object", "properties": {"client_id": _CLIENT_ID},
                      "required": ["client_id"], "additionalProperties": False},
        handler=backend.get_positions,
        required_scope="positions:read",
        risk_tier=RiskTier.READ,
        data_classes=("financial",),
        returns=frozenset({"client_id", "positions", "total_market_value_usd", "total_cash_usd"}),
        mask=frozenset({"account_id"}),  # positions: [{account_id, symbol, ...}, ...]
    ))
    reg.register(ToolSpec(
        name="draft_client_email",
        description="Save an email to the client as a draft for the advisor to review. Never sends.",
        input_schema={"type": "object", "properties": {
            "client_id": _CLIENT_ID,
            "subject": {"type": "string", "minLength": 1, "maxLength": 150},
            "body": {"type": "string", "minLength": 1, "maxLength": 5000}},
            "required": ["client_id", "subject", "body"], "additionalProperties": False},
        handler=backend.draft_client_email,
        required_scope="comms:draft",
        risk_tier=RiskTier.LOW,
        data_classes=("PII",),
        returns=frozenset({"draft_id", "status"}),
    ))
    reg.register(ToolSpec(
        name="update_mailing_address",
        description="Change a client's mailing address. A confirmation letter goes to both addresses.",
        input_schema={"type": "object", "properties": {
            "client_id": _CLIENT_ID,
            "street": {"type": "string", "minLength": 3, "maxLength": 120},
            "city": {"type": "string", "minLength": 2, "maxLength": 60},
            "state": {"type": "string", "pattern": "^[A-Z]{2}$"},
            "postal_code": {"type": "string", "pattern": "^\\d{5}(-\\d{4})?$"}},
            "required": ["client_id", "street", "city", "state", "postal_code"], "additionalProperties": False},
        handler=backend.update_mailing_address,
        required_scope="profile:write",
        risk_tier=RiskTier.MEDIUM,
        data_classes=("PII",),
        returns=frozenset({"client_id", "status", "previous", "current", "confirmation_letter"}),
    ))
    reg.register(ToolSpec(
        name="initiate_wire_transfer",
        description="Request an outgoing wire from a client account to one of the client's approved "
                    "beneficiaries. Creates a pending wire for operations to release.",
        input_schema={"type": "object", "properties": {
            "client_id": _CLIENT_ID,
            # A real account id, or the masked form get_positions/get_client_profile hand back
            # ("****" + last 4) -- resolved against the client's real accounts before policy or
            # execution ever see it (gateway.py stage "minimise"; minimisation.py).
            "from_account_id": {"type": "string", "pattern": "^(\\d{8,17}|\\*{4}\\d{4})$"},
            "beneficiary_id": {"type": "string", "pattern": "^B-\\d{4}$"},
            "amount_usd": {"type": "number", "exclusiveMinimum": 0},
            "memo": {"type": "string", "maxLength": 140}},
            "required": ["client_id", "from_account_id", "beneficiary_id", "amount_usd"],
            "additionalProperties": False},
        handler=backend.initiate_wire_transfer,
        required_scope="payments:initiate",
        risk_tier=RiskTier.HIGH,
        data_classes=("financial", "PII"),
        returns=frozenset({"wire_id", "status", "amount_usd", "deduplicated"}),
        resolve=frozenset({"from_account_id"}),
    ))
    return reg
