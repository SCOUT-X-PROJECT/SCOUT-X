# Contributing

Thanks for contributing to SCOUT-X. This repository is a simulation and
research prototype; contributions must not present simulated behavior as real
flight-control capability or claim forensic cryptographic erasure.

## Before opening a change

1. Create a Python 3.11+ virtual environment and install development
   requirements:

   ```bash
   python -m pip install -r requirements-dev.txt
   ```

2. Keep changes focused. Preserve existing behavior unless a test demonstrates
   that the behavior is incorrect. Add or update tests for behavior changes.
3. Use type hints for public Python functions, follow existing naming and
   formatting, and keep configuration in `simulation/config.py` rather than
   adding policy literals.
4. Never commit secrets, local `.env`, generated logs, model binaries, or real
   personal/flight data.
5. Keep upstream SCOUT-X attribution. Do not add license terms or choose a new
   license without authorization from the relevant copyright holders.

## Validate locally

Run the narrow tests for your change, then the full checks before submitting:

```bash
python -m pytest
ruff check .
ruff format --check .
mypy --follow-imports=silent
```

The CI workflow runs Python 3.11 and 3.12, an 80% coverage floor, and a
runtime dependency audit. Install the configured hooks with
`pre-commit install`.

## Pull requests

Describe the user-visible change, the modules affected, and any assumptions.
Include test commands/results and document new configuration or API behavior.
For security-sensitive changes, describe the threat boundary and remaining
limitations without including secrets or exploit instructions for real
systems.

## License and attribution

The upstream repository currently has no published license file or GitHub
license metadata, and this fork does not add a license. Attribution alone does
not grant redistribution rights. Before contributing material that would be
redistributed, confirm the applicable rights with the upstream project owners.
See the attribution and license-status note in the root README.
