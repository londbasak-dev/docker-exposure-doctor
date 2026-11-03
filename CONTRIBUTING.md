# Contributing

Use Python 3.10 or newer and a virtual environment. Install this local package
with `python -m pip install -e .` and run
`python -m unittest discover -s tests -v`.

Keep changes focused and include a regression test for behavior changes.
Tests and examples must use freshly invented synthetic data only. Do not add
real account names, logs, keys, tokens, personal paths, cookies, host details,
or copied production configuration. Never include raw input in diagnostics.

Document rule coverage, false positives, and important false negatives.
These tools must remain offline, read-only toward input, and explicit about
their limitations. Do not add telemetry or automatic uploads. Review changes
locally before opening a pull request. No contributor identity is preassigned.
