# Frozen admission protocol test dependency

These five **unmodified real modules** come from the superproject commit recorded in `manifest.json`. They are test dependencies, not production runtime copies and not mocks. The service repository's standalone GitHub checkout does not contain the superproject `driver/` directory.

Tests always import these files. `verifyAdmissionProtocolSnapshot()` checks all five SHA-256 values; when the expected superproject directory exists locally, it also requires byte-for-byte agreement with upstream. An absent superproject never skips tests or changes the implementation under test. A present but changed/incomplete upstream fails closed.

To update intentionally, review the real upstream changes, choose a committed superproject revision, copy its exact `git show <commit>:driver/identity-dev-admission/<file>` bytes, and update the commit and all five hashes together. Keep imports limited to Node builtins and these five local files. Run the standalone snapshot tests and all 27 actual Nest/MySQL admission tests before committing. Do not download upstream code during CI, silently refresh this snapshot, weaken a checksum, or replace it with a mock to make tests pass.

The manifest proves which reviewed source bytes were used. It does not prove real deployment, ingress coverage, a drained source, valid production credentials, or a completed migration.
