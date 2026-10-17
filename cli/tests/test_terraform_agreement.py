"""The CLI's callback ports and cognito.tf's registered callback URLs must be
the same three. Cognito matches the port exactly, so a drift shows up only
as a Hosted UI error page on someone's first login."""

import re
from pathlib import Path

from cascadesec import auth

COGNITO_TF = Path(__file__).resolve().parents[2] / "terraform" / "cognito.tf"


def test_callback_ports_match_cognito_tf():
    text = COGNITO_TF.read_text(encoding="utf-8")
    match = re.search(r"cli_callback_ports\s*=\s*\[([^\]]*)\]", text)
    assert match, "cli_callback_ports not found in cognito.tf"
    ports = tuple(int(p) for p in re.findall(r"\d+", match.group(1)))
    assert ports == auth.CALLBACK_PORTS


def test_cognito_tf_registers_localhost_callbacks():
    text = COGNITO_TF.read_text(encoding="utf-8")
    assert f'"http://localhost:${{port}}{auth.CALLBACK_PATH}"' in text
