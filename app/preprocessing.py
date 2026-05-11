import pandas as pd
import pickle
import numpy as np
import os
import math
from collections import Counter
from tensorflow.keras.preprocessing.sequence import pad_sequences

MAX_LEN = 200

# ── SINGLETON TOKENIZER CACHE ─────────────────────────────────────────────
# Avoids reloading the tokenizer from disk on every single prediction call.
_cached_tokenizer = None
_cached_tokenizer_path = None


def load_tokenizer():
    """Load the tokenizer saved during model training (cached in memory)."""
    global _cached_tokenizer, _cached_tokenizer_path

    app_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(app_dir)
    model_dir = os.path.join(parent_dir, "model")
    tokenizer_path = os.path.join(model_dir, "tokenizer.pkl")

    # Return cached tokenizer if path hasn't changed
    if _cached_tokenizer is not None and _cached_tokenizer_path == tokenizer_path:
        return _cached_tokenizer

    try:
        with open(tokenizer_path, "rb") as f:
            _cached_tokenizer = pickle.load(f)
            _cached_tokenizer_path = tokenizer_path
            return _cached_tokenizer
    except FileNotFoundError:
        raise Exception(f"Tokenizer not found at {tokenizer_path}! Train the model first.")


def read_events_from_log(log_file):
    """Read API-call events from a CSV log file."""
    try:
        df = pd.read_csv(log_file)
    except pd.errors.ParserError:
        try:
            df = pd.read_csv(log_file, on_bad_lines="skip", engine="python")
            if len(df) == 0:
                raise Exception("Log file is empty after removing malformed lines!")
        except Exception as parse_error:
            raise Exception(f"Failed to parse log file: {str(parse_error)}")
    except FileNotFoundError:
        raise Exception(f"Log file not found: {log_file}")
    except pd.errors.EmptyDataError:
        raise Exception("Log file is empty!")

    if "event" not in df.columns:
        raise Exception("'event' column not found in log file")

    if len(df) == 0:
        raise Exception("No events recorded in log file")

    return df["event"].astype(str).tolist()


def compute_event_statistics(events):
    """
    Extract statistical features from an event sequence.

    Returns a dict of derived behavioral metrics that augment the raw sequence:
      - event_entropy: Shannon entropy of event distribution (high = diverse behavior)
      - write_ratio: fraction of events that are write-related
      - enum_ratio: fraction of events that are enumeration-related
      - rapid_write_density: rapid writes per total events
      - busy_loop_density: busy loops per total events
      - write_burst_max: longest consecutive streak of write events
      - transition_diversity: number of unique event pair transitions
      - phase_ratio: ratio of enumeration-heavy first half to write-heavy second half
    """
    if not events:
        return {}

    total = len(events)
    counts = Counter(events)

    # Shannon entropy — higher means more diverse (benign tends to be more uniform)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)

    # Write-related events
    write_events = {'WriteFile', 'RapidFileWrite', 'DeleteFile'}
    write_count = sum(counts.get(e, 0) for e in write_events)

    # Enumeration events (reconnaissance phase)
    enum_events = {'FindFirstFile', 'FindNextFile', 'OpenFile'}
    enum_count = sum(counts.get(e, 0) for e in enum_events)

    # Longest consecutive write burst
    max_burst = 0
    current_burst = 0
    for e in events:
        if e in write_events:
            current_burst += 1
            max_burst = max(max_burst, current_burst)
        else:
            current_burst = 0

    # Transition diversity (bigram unique count)
    transitions = set()
    for i in range(len(events) - 1):
        transitions.add((events[i], events[i + 1]))

    # Phase analysis: compare first half vs second half behavior
    mid = total // 2
    first_half_enum = sum(1 for e in events[:mid] if e in enum_events)
    second_half_write = sum(1 for e in events[mid:] if e in write_events)
    # Ransomware pattern: enumerate first, encrypt second
    phase_ratio = 0.0
    if mid > 0:
        phase_ratio = (first_half_enum / max(mid, 1)) * (second_half_write / max(total - mid, 1))

    return {
        'event_entropy': entropy,
        'write_ratio': write_count / total,
        'enum_ratio': enum_count / total,
        'rapid_write_density': counts.get('RapidFileWrite', 0) / total,
        'busy_loop_density': counts.get('BusyLoop', 0) / total,
        'write_burst_max': max_burst,
        'transition_diversity': len(transitions),
        'phase_ratio': phase_ratio,
    }


def preprocess_events(events, max_events=None):
    """
    Convert an API-call event list into the padded model input.

    max_events enables early detection by keeping only the first N API calls.
    Example: max_events=20 predicts from the first 20 observed events only.
    """
    tokenizer = load_tokenizer()

    if max_events is not None:
        events = events[:max_events]

    if not events:
        return np.zeros((1, MAX_LEN), dtype=np.float32)

    event_string = " ".join(str(event) for event in events)
    seq = tokenizer.texts_to_sequences([event_string])

    if not seq or len(seq[0]) == 0:
        return np.zeros((1, MAX_LEN), dtype=np.float32)

    return pad_sequences([seq[0]], maxlen=MAX_LEN, padding="post")


def preprocess_log(log_file, max_events=None):
    """
    Preprocess a single log file for prediction using the saved tokenizer.

    max_events can be used for early detection. When omitted, the full log is used.
    """
    events = read_events_from_log(log_file)
    return preprocess_events(events, max_events=max_events)
