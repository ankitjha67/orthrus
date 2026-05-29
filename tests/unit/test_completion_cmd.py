"""`hydra completion <shell>`: emits a sourceable tab-completion script.

The script goes to stdout (so it can be redirected/eval'd); each shell has a
recognisable signature, and all of them must reference the same trigger env var
that Click's runtime handshake expects.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from hydra import main

# (shell, a substring the generated script must contain)
_SIGNATURES = [
    ("bash", "_hydra_completion"),
    ("zsh", "#compdef hydra"),
    ("fish", "function _hydra_completion"),
]


@pytest.mark.parametrize(("shell", "signature"), _SIGNATURES)
def test_completion_emits_script(shell: str, signature: str):
    result = CliRunner().invoke(main.cli, ["--no-banner", "completion", shell])
    assert result.exit_code == 0, result.output
    assert signature in result.output
    # The script and Click's runtime must agree on the completion trigger var.
    assert "_HYDRA_COMPLETE" in result.output
    # An install hint is prepended as a shell comment.
    assert result.output.lstrip().startswith("#")


def test_completion_rejects_unknown_shell():
    result = CliRunner().invoke(main.cli, ["--no-banner", "completion", "powershell"])
    assert result.exit_code != 0
    assert "powershell" in result.output.lower()
