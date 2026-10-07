import time

import pytest

from govagent.app import build_environment
from govagent.approvals import InlineApprovals, QueueApprovals


@pytest.fixture
def make_env():
    def _make(queue: bool = False, agent_registry=None, clock=time.time, **approvals):
        return build_environment(approvals=QueueApprovals() if queue else InlineApprovals(approvals),
                                 agent_registry=agent_registry, clock=clock)
    return _make


WIRE_OK = {"client_id": "C-1001", "from_account_id": "40012345678", "beneficiary_id": "B-2001", "amount_usd": 12000}
ADDR = {"client_id": "C-1001", "street": "1 Main St", "city": "Clayton", "state": "MO", "postal_code": "63105"}


class Clock:
    """Controllable clock for expiry and window tests."""

    def __init__(self, start: float = 1_800_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now
