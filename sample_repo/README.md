# SecurePatch Realistic Target Repository

This repository is an intentionally vulnerable multi-module Python backend used
as the target application for the SecurePatch project.

It contains realistic application layers:

- application entry point
- configuration
- domain models
- HTTP-style route/controller modules
- business services
- repositories
- file handling
- command execution
- authentication
- authorization middleware
- logging
- audit events
- regression tests

## Security findings intentionally planted

### B602
routes/admin.py
  -> AdminController.execute()
  -> CommandService.execute()
  -> subprocess.call(command, shell=True)

### B301
routes/documents.py
  -> DocumentController.import_legacy()
  -> FileService.load_legacy_data()
  -> pickle.load()

### B105
config.py and utils/database.py contain demo hardcoded credential values.

B403/B404 are also expected because the demo intentionally imports pickle
and subprocess.

## Why this repository exists

SecurePatch should not merely find a vulnerable line. It should trace the
vulnerability through multiple modules, identify related functions and tests,
retrieve repository context, generate a minimal patch, apply that patch in a
sandbox, run regression tests, re-run the security scanner, and produce a
verified or rejected verdict.

The repository is intentionally larger than the original two-file demo so
source-graph navigation and impact analysis have meaningful work to perform.
