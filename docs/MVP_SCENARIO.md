# NightZero MVP: Issue to Tested Pull Request

NightZero's first demo supports one constrained incident class: a reproducible
regression reported as a GitHub issue against the included `demo_target`
service. It is not a production deployment system.

## Seeded incident

- **Trigger:** a GitHub issue reports that checkout totals are rounded down.
- **Service:** `demo_target/pricing.py`
- **Failure signal:** `python -m unittest demo_target.test_pricing`
- **Culprit commit:** `8f3c2a1` (`Use integer division for display totals`)
- **Root cause:** `format_total` uses floor division and drops cents.
- **Patch shape:** replace `cents // 100` with `cents / 100` and render two
  decimal places.

## Safe outcome

The workflow copies the target into a temporary sandbox, records the failing
test output, applies the proposed one-file patch there, and records the passing
test output. Approval creates a reviewable, simulated pull-request record; it
never changes the target service, a remote branch, or production.

## Deferred modes

The GCP Pub/Sub-to-Cloud-Run SRE workflow, multi-tenant SaaS operation, and
multi-repository maintenance remain future deployment modes described in the
PRD. They are outside this MVP's live path.