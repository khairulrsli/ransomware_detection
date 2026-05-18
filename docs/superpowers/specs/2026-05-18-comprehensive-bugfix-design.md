# Comprehensive Bug Fix & Code Quality — Design Spec
Date: 2026-05-18

## Scope
Approach B: fix all runtime bugs + code quality issues. No architectural split.

## New File
`app/detection_config.py` — exports `WEIGHTS` dict and `APP_DETECTION_THRESHOLD`. Both `main.py` and `calibrate_threshold.py` import from here.

## Changes Per File

### app/behavior_logger.py
1. Fix streaming risk formula: remove double-add of `iteration_risk`
2. Replace CSV read inside poll loop (TIER 2/3 check) with in-memory counters (`rapid_write_counter`, `high_entropy_files`) — already tracked
3. Fix stdlib import order (time, csv, os, tempfile, math, hashlib before psutil)
4. Add `encoding="utf-8"` to all `open()` calls
5. Fix `subprocess.run` — add `check=False` (explicit, these are best-effort kills)

### app/main.py
1. Fix `raising-bad-type` bug (locate and fix raise of NoneType)
2. Fix stdlib import order
3. Add `encoding="utf-8"` to `open()` calls
4. Import `WEIGHTS` from `detection_config` instead of defining inline
5. Fix `subprocess.run` — add `check=False`
6. Update UI text: "VM analysis runner" → "Behavioral sandbox analysis"

### app/process_supervisor.py
1. Fix `subprocess.run` — add `check=False`

### app/early_detection.py
1. Fix stdlib import order (os, sys before numpy/sklearn)

### app/preprocessing.py
1. Fix stdlib import order (pickle, os, math, collections before pandas/numpy)

### scripts/calibrate_threshold.py
1. Import `WEIGHTS` from `detection_config` instead of defining inline
2. Remove unused imports (`tf`, `MAX_LEN`, `compute_event_statistics`)

## Non-Goals
- Split main.py into layers
- Thread synchronization primitives (globals are monotonic flags, race is benign)
- Dataset expansion
