# IOC Indicators, CVSS Score, and Network Scoring — Design Spec

**Date:** 2026-05-18
**Status:** Approved

## Overview

Three enhancements to the ransomware detection GUI and scoring engine, requested by supervisor:

1. **IOC indicators panel** — show detected Indicators of Compromise in the GUI
2. **CVSS score** — display threat severity on the standard 0–10 CVSS scale
3. **Network scoring** — include network connections as a weighted signal in the composite threat score

## Layout

Layout A (user-selected): CVSS inline with threat score line; IOC panel added below existing Behavioral Metrics panel.

## Feature 1: CVSS Score

### Calculation

```
cvss_score = round(composite * 10, 1)
```

### Severity mapping (CVSS v3.1 standard)

| CVSS range | Severity |
|---|---|
| 0.0 | None |
| 0.1–3.9 | Low |
| 4.0–6.9 | Medium |
| 7.0–8.9 | High |
| 9.0–10.0 | Critical |

### Display

Added inline on the threat score line in `metrics_text`:

```
Threat Score : 0.82 (HIGH)    CVSS: 8.2 (HIGH)
```

Both RANSOMWARE and BENIGN result paths updated.

## Feature 2: IOC Indicators Panel

### Content

New section appended to `metrics_text` after the existing behavioral metrics block. Only IOCs with count > 0 are listed. If no IOCs fired, the section shows `No indicators triggered`.

```
IOC INDICATORS
---------------
● RapidFileWrite   : 5 events
● HighEntropyFile  : 2 files
● CanaryViolation  : 1 hit
● ShadowCopyDelete : 0          <- omitted if 0
● NetworkConnect   : 3 outbound
● SuspiciousChild  : 0          <- omitted if 0
● BusyLoop         : 0          <- omitted if 0
```

### Source data

All counts already extracted from `df` in `compute_threat_score()` and returned in the `metrics` dict. No new computation needed — only display changes.

## Feature 3: Network Scoring

### Signal calculation

```python
network_signal = min(1.0, network_ops / 3.0)
```

3 or more outbound connections triggers full signal (1.0). Rationale: ransomware C2 communication typically involves multiple connections; a single connection is common in benign software.

### Weight adjustment

`combo_signal` (write+CPU density) removed — its signal is already captured by `rapid_signal` and `busy_loop` counts individually. Weight redistributed to `network`.

| Signal | Old weight | New weight |
|---|---|---|
| ml | 0.30 | 0.30 |
| early | 0.15 | 0.15 |
| rapid | 0.15 | 0.15 |
| entropy | 0.15 | 0.15 |
| canary | 0.10 | 0.10 |
| shadow | 0.05 | 0.05 |
| combo | 0.05 | **0.00** |
| child | 0.05 | 0.05 |
| network | 0.00 | **0.05** |
| **Total** | **1.00** | **1.00** |

## Files Changed

| File | Change |
|---|---|
| `app/main.py` | Add `cvss_score` helper, add network signal to `compute_threat_score`, update `metrics_text` population in both RANSOMWARE and BENIGN paths, add IOC panel |

## Out of Scope

- Database schema changes (network_ops already stored)
- Changes to `behavior_logger.py` (NetworkConnect already logged)
- Retrain model (scoring weights change is post-LSTM fusion, does not affect model)
