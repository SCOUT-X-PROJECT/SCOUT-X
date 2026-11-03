import sys

import pytest

from simulation.security.enforcer import ResponseEnforcer


class WindowsConsoleStream:
    encoding = "cp1252"

    def write(self, text: str) -> int:
        text.encode(self.encoding)
        return len(text)

    def flush(self) -> None:
        pass


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ("FORCE_LAND", "LANDING"),
        ("ISOLATE_DRONE", "ISOLATED"),
        ("LIMIT_MOVEMENT", "RESTRICTED"),
        ("MONITOR", "MONITORING"),
    ],
)
def test_enforcer_output_does_not_break_windows_console(
    monkeypatch: pytest.MonkeyPatch,
    response: str,
    expected: str,
) -> None:
    monkeypatch.setattr(sys, "stdout", WindowsConsoleStream())

    result = ResponseEnforcer().enforce({"response": response})

    assert result["enforced"] == expected
