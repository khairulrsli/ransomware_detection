"""Shared detection weights and thresholds — imported by main.py and calibrate_threshold.py."""

APP_DETECTION_THRESHOLD = 0.25
ML_ALERT_THRESHOLD = 0.5

WEIGHTS = {
    'ml':      0.30,
    'early':   0.15,
    'rapid':   0.15,
    'entropy': 0.15,
    'canary':  0.10,
    'shadow':  0.05,
    'network': 0.05,
    'child':   0.05,
}
