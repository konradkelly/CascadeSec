"""cascadesec_core on the path, where the deployed zip has it: Terraform
vendors core/cascadesec_core beside handler.py (terraform/
lambda_mapping_agent.tf), so `import handler` finds it the same way here."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "core"))
