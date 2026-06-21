from __future__ import annotations

import argparse
import json
from pathlib import Path

from dotenv import load_dotenv

from aurora.agents.orchestrator import run_full_audit
from aurora.models.prf_schema import ProjectRequestForm


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="aurora", description="AURORA PRF autonomous risk review")
    p.add_argument("--prf", required=True, help="Path to PRF JSON file")
    p.add_argument(
        "--execution-mode",
        default="dry_run",
        choices=["dry_run", "full_audit"],
        help="Run mode. full_audit requires --population-map.",
    )
    p.add_argument(
        "--population-map",
        default=None,
        help="Path to population_map JSON file (required for execution-mode=full_audit)",
    )
    return p.parse_args()


def main() -> None:
    load_dotenv()

    args = _parse_args()
    prf_path = Path(args.prf)
    payload = json.loads(prf_path.read_text(encoding="utf-8"))

    prf = ProjectRequestForm.model_validate(payload)

    population_map = None
    if args.population_map:
        population_payload = json.loads(Path(args.population_map).read_text(encoding="utf-8"))
        if not isinstance(population_payload, dict):
            raise ValueError("population_map must be a JSON object mapping control_id to population size")
        population_map = {str(k): int(v) for k, v in population_payload.items()}

    report = run_full_audit(prf, execution_mode=args.execution_mode, population_map=population_map)

    print(report.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
