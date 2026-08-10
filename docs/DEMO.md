# Three-minute demo

1. Run `python -m nightzero` and open the incident card.
2. Select **Run incident workflow**. Point out the source commit, issue evidence, one-file diff, failing-before result, and passing-after result.
3. Enter a reviewer name and `nightzero-demo`; explain that approval creates only a simulated PR record. Show the audit events in the generated JSON artifact.

The MVP uses a local sandbox and a simulated GitHub approval. The `Dockerfile` can be deployed to Cloud Run with the command in `README.md`; no production credentials or deployment permissions are included.