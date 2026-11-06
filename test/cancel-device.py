"""Exercise cooperative cancellation without hardware or synthetic approval."""
import sys
import types

sys.path.insert(0, "device")
from wedgie_actions import confirm_action

calls = []


class PhysicalKeys:
    def __init__(self, physical=False):
        assert physical, "approval must read physical keys only"

    def pressed(self):
        return []


class Chip:
    def sign(self, *args):
        calls.append(args)
        return 1, 2


def ask(*args, **kwargs):
    for _ in range(4):
        assert kwargs["keys"].pressed() == []
    raise AssertionError("cancellation did not stop the prompt")


ui = types.SimpleNamespace(ask=ask, progress=lambda *a, **k: None)
sys.modules["ui"] = ui
sys.modules["lcd"] = types.SimpleNamespace(Keys=PhysicalKeys)
sys.modules["optiga"] = types.SimpleNamespace(FACTORY_KEY=0xe0f0)
polls = 0


def cancelled():
    global polls
    polls += 1
    return polls >= 3


assert confirm_action(Chip(), None, "airlock/v1", "Open?", [], cancelled) is None
assert not calls, "a cancelled prompt must never sign"
# Even if cancellation arrives just after physical approval, no signature is made.
ui.ask = lambda *a, **k: True
assert confirm_action(Chip(), None, "airlock/v1", "Open?", [], lambda: True) is None
assert not calls
print("cooperative cancellation OK")
