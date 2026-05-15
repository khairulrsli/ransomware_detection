import numpy as np
import pandas as pd
import os
import pickle
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau, ModelCheckpoint
from sklearn.model_selection import train_test_split
from sklearn.metrics import (precision_score, recall_score, f1_score,
                             confusion_matrix, classification_report)
from sklearn.utils.class_weight import compute_class_weight
from lstm_model import build_lstm

MAX_LEN = 200
EARLY_WINDOWS = (10, 20, 30, 50, 75, 100, 150)


def load_training_data(data_dir=None):
    """Load all training samples and tag each by provenance.

    Returns (sequences, labels, sources) where `sources[i]` is 'real' if the
    filename contains '_real_', otherwise 'synthetic'. This lets the evaluator
    report metrics for the two distributions separately.
    """
    sequences, labels, sources = [], [], []

    if data_dir is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        data_dir = os.path.join(os.path.dirname(script_dir), "data", "raw")

    print(f"[*] Loading training data from: {data_dir}")
    if not os.path.exists(data_dir):
        raise FileNotFoundError(f"Training data directory not found: {data_dir}")

    csv_files = []
    for root, _, files in os.walk(data_dir):
        for f in files:
            if f.endswith('.csv'):
                csv_files.append(os.path.join(root, f))
    if len(csv_files) == 0:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")
    print(f"[*] Found {len(csv_files)} CSV files")

    for filepath in csv_files:
        filename = os.path.basename(filepath)
        try:
            df = pd.read_csv(filepath)
            if 'event' not in df.columns:
                continue
            events = df['event'].astype(str).tolist()
            if len(events) == 0:
                continue
            sequences.append(events)
            parent_folder = os.path.basename(os.path.dirname(filepath)).lower()
            if filename.startswith('benign') or parent_folder == 'benign':
                labels.append(0)
            else:
                labels.append(1)
            sources.append('real' if '_real_' in filename else 'synthetic')
        except Exception as e:
            print(f"[!] Error loading {filename}: {e}")
            continue

    if not sequences:
        raise ValueError("No valid training samples loaded")

    n_real = sources.count('real')
    print(f"\n[+] Total samples: {len(sequences)}")
    print(f"    Benign     : {labels.count(0)}")
    print(f"    Malicious  : {labels.count(1)}")
    print(f"    Real       : {n_real}")
    print(f"    Synthetic  : {len(sequences) - n_real}")
    return sequences, labels, sources


def preprocess_sequences(sequences):
    """Build vocabulary from training sequences and encode them to padded ints."""
    if not sequences:
        raise ValueError("No sequences to preprocess")

    tokenizer = Tokenizer(oov_token="<OOV>", filters='', lower=True)
    tokenizer.fit_on_texts([" ".join(str(e) for e in seq) for seq in sequences])

    vocab_size = len(tokenizer.word_index)
    print(f"[+] Vocabulary size: {vocab_size}")
    if vocab_size < 5:
        raise ValueError(f"Vocabulary too small ({vocab_size}).")

    X = []
    for seq in sequences:
        encoded = tokenizer.texts_to_sequences([" ".join(str(e) for e in seq)])[0]
        if not encoded:
            encoded = [1]
        X.append(pad_sequences([encoded], maxlen=MAX_LEN, padding='post')[0])

    model_dir = os.path.dirname(os.path.abspath(__file__))
    tokenizer_path = os.path.join(model_dir, 'tokenizer.pkl')
    with open(tokenizer_path, 'wb') as f:
        pickle.dump(tokenizer, f)
    print(f"[+] Tokenizer saved to {tokenizer_path}")
    return np.array(X), tokenizer


def transform_sequences(sequences, tokenizer):
    """Encode sequences with an existing tokenizer."""
    return np.array([encode_sequence_with_tokenizer(seq, tokenizer) for seq in sequences])


def encode_sequence_with_tokenizer(sequence, tokenizer, max_events=None):
    """Encode a full or partial API-call sequence with the training tokenizer."""
    if max_events is not None:
        sequence = sequence[:max_events]
    encoded = tokenizer.texts_to_sequences([" ".join(str(e) for e in sequence)])[0]
    if not encoded:
        encoded = [1]
    return pad_sequences([encoded], maxlen=MAX_LEN, padding='post')[0]


def evaluate_block(name, model, X, y, threshold=0.5):
    """Run prediction and print a labelled evaluation block."""
    if len(X) == 0:
        print(f"\n[!] {name}: no samples in this slice, skipping.")
        return None
    y_prob = model.predict(X, verbose=0).flatten()
    y_pred = (y_prob >= threshold).astype(int)
    acc  = (y_pred == y).mean()
    prec = precision_score(y, y_pred, zero_division=0)
    rec  = recall_score(y, y_pred, zero_division=0)
    f1   = f1_score(y, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y, y_pred, labels=[0, 1]).ravel()
    print("\n" + "=" * 60)
    print(f"  EVALUATION — {name}  (n={len(y)})")
    print("=" * 60)
    print(f"  Accuracy  : {acc*100:.2f}%")
    print(f"  Precision : {prec*100:.2f}%")
    print(f"  Recall    : {rec*100:.2f}%")
    print(f"  F1-Score  : {f1*100:.2f}%")
    print(f"\n  Confusion: TN={tn} FP={fp} FN={fn} TP={tp}")
    print(classification_report(y, y_pred, target_names=["Benign", "Malicious"], zero_division=0))
    return {"name": name, "n": int(len(y)),
            "accuracy": float(acc), "precision": float(prec),
            "recall": float(rec), "f1": float(f1),
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}


def evaluate_early_detection(model, sequences, labels, tokenizer,
                             windows=EARLY_WINDOWS, threshold=0.5):
    """Evaluate model with only the first N API calls available."""
    results = {}
    for window in list(windows) + [None]:
        X_w, y_w = [], []
        for seq, lab in zip(sequences, labels):
            if window is not None and len(seq) < window:
                continue
            X_w.append(encode_sequence_with_tokenizer(seq, tokenizer, max_events=window))
            y_w.append(lab)
        if not X_w:
            continue
        X_w, y_w = np.array(X_w), np.array(y_w)
        y_prob = model.predict(X_w, verbose=0).flatten()
        y_pred = (y_prob >= threshold).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_w, y_pred, labels=[0, 1]).ravel()
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        key = f"First {window} calls" if window is not None else "Full log"
        results[key] = {
            "samples": len(y_w),
            "accuracy": (y_pred == y_w).mean(),
            "precision": precision_score(y_w, y_pred, zero_division=0),
            "recall": recall_score(y_w, y_pred, zero_division=0),
            "f1": f1_score(y_w, y_pred, zero_division=0),
            "false_positive_rate": fpr,
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        }
    return results


def format_early_results(results, title="EARLY DETECTION (real-only test set)"):
    lines = ["=" * 70, f"  {title}", "=" * 70,
             f"{'Window':18s} {'Samples':>7s} {'Acc':>8s} {'Prec':>8s} "
             f"{'Recall':>8s} {'F1':>8s} {'FPR':>8s}"]
    for window, m in results.items():
        lines.append(
            f"{window:18s} {m['samples']:7d} "
            f"{m['accuracy']*100:7.2f}% "
            f"{m['precision']*100:7.2f}% "
            f"{m['recall']*100:7.2f}% "
            f"{m['f1']*100:7.2f}% "
            f"{m['false_positive_rate']*100:7.2f}%"
        )
    lines.append("=" * 70)
    return "\n".join(lines)


def train_model():
    sequences, labels, sources = load_training_data()
    labels = np.array(labels)
    sources = np.array(sources)

    # Stratify on (label, source) so train and test both contain real+synth, benign+malicious
    strata = np.array([f"{l}_{s}" for l, s in zip(labels, sources)])
    idx = np.arange(len(sequences))
    idx_train, idx_test = train_test_split(idx, test_size=0.2, random_state=42, stratify=strata)

    seq_train = [sequences[i] for i in idx_train]
    seq_test  = [sequences[i] for i in idx_test]
    y_train, y_test     = labels[idx_train], labels[idx_test]
    src_train, src_test = sources[idx_train], sources[idx_test]

    print("\n[+] Train set composition:")
    print(f"    Real benign     : {int(np.sum((src_train=='real')      & (y_train==0)))}")
    print(f"    Real malicious  : {int(np.sum((src_train=='real')      & (y_train==1)))}")
    print(f"    Synth benign    : {int(np.sum((src_train=='synthetic') & (y_train==0)))}")
    print(f"    Synth malicious : {int(np.sum((src_train=='synthetic') & (y_train==1)))}")
    print("[+] Test set composition:")
    print(f"    Real benign     : {int(np.sum((src_test=='real')       & (y_test==0)))}")
    print(f"    Real malicious  : {int(np.sum((src_test=='real')       & (y_test==1)))}")
    print(f"    Synth benign    : {int(np.sum((src_test=='synthetic')  & (y_test==0)))}")
    print(f"    Synth malicious : {int(np.sum((src_test=='synthetic')  & (y_test==1)))}")

    X_train, tokenizer = preprocess_sequences(seq_train)
    X_test = transform_sequences(seq_test, tokenizer)

    class_weights = compute_class_weight('balanced', classes=np.unique(y_train), y=y_train)
    class_weight_dict = dict(zip(np.unique(y_train), class_weights))
    print(f"[+] Class weights: {class_weight_dict}")

    vocab_size = len(tokenizer.word_index) + 1
    model = build_lstm(vocab_size=vocab_size, max_length=MAX_LEN)

    # Focal loss reduces gradient contribution of easy examples — useful here
    # because the synthetic samples are trivially classified after a few epochs
    # and would otherwise dominate the loss.
    try:
        from tensorflow.keras.losses import BinaryFocalCrossentropy
        from tensorflow.keras.optimizers import Adam
        model.compile(optimizer=Adam(learning_rate=0.001),
                      loss=BinaryFocalCrossentropy(gamma=2.0),
                      metrics=['accuracy'])
        print("[+] Loss: BinaryFocalCrossentropy (gamma=2.0)")
    except ImportError:
        print("[!] Focal loss not available, falling back to BCE")

    model.summary()

    model_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(model_dir, 'trained_model.h5')

    callbacks = [
        EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True, min_delta=0.001, verbose=1),
        ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=3, min_lr=1e-6, verbose=1),
        ModelCheckpoint(model_path, monitor='val_loss', save_best_only=True, verbose=1),
    ]

    print("\n[*] Training...")
    history = model.fit(
        X_train, y_train,
        validation_data=(X_test, y_test),
        epochs=30, batch_size=16, shuffle=True,
        class_weight=class_weight_dict, callbacks=callbacks, verbose=1,
    )

    # ── Three-way evaluation ────────────────────────────────────────────
    mask_real  = (src_test == 'real')
    mask_synth = (src_test == 'synthetic')
    combined = evaluate_block("Combined test set",   model, X_test,            y_test)
    real_res = evaluate_block("Real-only test set",  model, X_test[mask_real],  y_test[mask_real])
    synth_res = evaluate_block("Synthetic-only set", model, X_test[mask_synth], y_test[mask_synth])

    # Early-detection on the real subset (the honest one)
    seq_test_real = [seq_test[i] for i in range(len(seq_test)) if src_test[i] == 'real']
    y_test_real   = [int(y_test[i]) for i in range(len(y_test))  if src_test[i] == 'real']
    early_results = evaluate_early_detection(model, seq_test_real, y_test_real, tokenizer)
    early_text = format_early_results(early_results)
    print("\n" + early_text)

    # Save
    results_path = os.path.join(model_dir, 'evaluation_results.txt')
    with open(results_path, 'w') as f:
        f.write("MODEL EVALUATION RESULTS — provenance-aware split\n")
        f.write("=" * 70 + "\n\n")
        f.write("The dataset contains two distributions: a small set of real\n")
        f.write("API-sequence captures (filenames containing '_real_') and a\n")
        f.write("larger synthetic corpus used to bootstrap the event vocabulary.\n")
        f.write("Real and synthetic samples are stratified across train/test, and\n")
        f.write("metrics are reported separately for each slice.\n\n")
        for res in (combined, real_res, synth_res):
            if res is None:
                continue
            f.write("-" * 70 + "\n")
            f.write(f"  {res['name']}  (n={res['n']})\n")
            f.write("-" * 70 + "\n")
            f.write(f"  Accuracy  : {res['accuracy']*100:.2f}%\n")
            f.write(f"  Precision : {res['precision']*100:.2f}%\n")
            f.write(f"  Recall    : {res['recall']*100:.2f}%\n")
            f.write(f"  F1-Score  : {res['f1']*100:.2f}%\n")
            f.write(f"  Confusion : TN={res['tn']} FP={res['fp']} "
                    f"FN={res['fn']} TP={res['tp']}\n\n")
        f.write(early_text + "\n")
    print(f"\n[OK] Results saved to {results_path}")

    # Epoch log
    epochs_path = os.path.join(model_dir, 'training_epochs.txt')
    with open(epochs_path, 'w') as f:
        f.write("TRAINING EPOCH HISTORY\n" + "=" * 80 + "\n")
        f.write(f"  Architecture : Attention-CNN-BiLSTM Hybrid\n")
        f.write(f"  Loss         : BinaryFocalCrossentropy (gamma=2.0)\n")
        f.write(f"  Vocabulary   : {vocab_size}\n")
        f.write(f"  Train / Test : {len(X_train)} / {len(X_test)}\n")
        f.write(f"  Class wts    : {class_weight_dict}\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"{'Epoch':>6}  {'Loss':>10}  {'Acc':>10}  "
                f"{'Val Loss':>10}  {'Val Acc':>10}\n" + "-" * 60 + "\n")
        for i in range(len(history.history['loss'])):
            f.write(f"{i+1:>6}  {history.history['loss'][i]:>10.4f}  "
                    f"{history.history['accuracy'][i]*100:>9.2f}%  "
                    f"{history.history['val_loss'][i]:>10.4f}  "
                    f"{history.history['val_accuracy'][i]*100:>9.2f}%\n")
        f.write(f"\nBest val acc : {max(history.history['val_accuracy'])*100:.2f}%\n")
    print(f"[OK] Epochs saved to {epochs_path}")
    print(f"[OK] Model saved to {model_path}")
    return model, history


if __name__ == "__main__":
    print("=" * 70)
    print("LSTM TRAINING — provenance-aware evaluation")
    print("=" * 70 + "\n")
    train_model()
    print("\n[DONE]")
