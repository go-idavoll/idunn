# e2eapp trust anchor

`test/e2e/run.sh` writes a freshly generated `root.json` here before it builds
`e2eapp`. The keys behind it exist for one CI job only. The file is gitignored
and must never be committed.
