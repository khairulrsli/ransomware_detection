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
    """Load all training samples from subfolders (ransomware/ and benign/)"""
    sequences = []
    labels = []

    if data_dir is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        data_dir = os.path.join(os.path.dirname(script_dir), "data", "raw")

    print(f"[*] Loading training data from: {data_dir}")

    if not os.path.exists(data_dir):
        raise FileNotFoundError(f"Training data directory not found: {data_dir}")

    # Scan ALL subfolders recursively
    csv_files = []
    for root, dirs, files in os.walk(data_dir):
        for f in files:
            if f.endswith('.csv'):
                csv_files.append(os.path.join(root, f))

    if len(csv_files) == 0:
        raise FileNotFoundError(
            f"No CSV files found in {data_dir} or any subfolders.\n"
            f"Make sure your CSV files are inside:\n"
            f"  {data_dir}\\ransomware\\\n"
            f"  {data_dir}\\benign\\"
        )

    print(f"[*] Found {len(csv_files)} CSV files")

    for filepath in csv_files:
        filename = os.path.basename(filepath)
        try:
            df = pd.read_csv(filepath)

            if 'event' not in df.columns:
                print(f"[!] Skipping {filename}: 'event' column not found")
                continue

            events = df['event'].astype(str).tolist()

            if len(events) == 0:
                print(f"[!] Skipping {filename}: no events recorded")
                continue

            sequences.append(events)

            # Determine label from filename OR parent folder name
            parent_folder = os.path.basename(os.path.dirname(filepath)).lower()
            if filename.startswith('benign') or parent_folder == 'benign':
                labels.append(0)
            else:
                labels.append(1)

        except Exception as e:
            print(f"[!] Error loading {filename}: {e}")
            continue

    if len(sequences) == 0:
        raise ValueError("No valid training samples loaded")

    print(f"\n[+] Total samples loaded: {len(sequences)}")
    print(f"    Benign:    {labels.count(0)}")
    print(f"    Malicious: {labels.count(1)}")
    return sequences, labels


def preprocess_sequences(sequences):
    """Convert text sequences to numerical"""

    all_events = []
    for seq in sequences:
        all_events.extend([str(event) for event in seq])

    if len(all_events) == 0:
        raise ValueError("No events to create vocabulary")

    tokenizer = Tokenizer(oov_token="<OOV>")
    tokenizer.fit_on_texts([[event] for event in all_events])

    vocab_size = len(tokenizer.word_index)
    print(f"[+] Vocabulary size: {vocab_size}")

    if vocab_size < 5:
        raise ValueError(f"Vocabulary too small ({vocab_size}). Need more diverse training data.")

    X = []
    for seq in sequences:
        try:
            encoded = tokenizer.texts_to_sequences([[str(event) for event in seq]])[0]
            if len(encoded) == 0:
                encoded = [1]
            padded = pad_sequences([encoded], maxlen=MAX_LEN, padding='post')[0]
            X.append(padded)
        except Exception as e:
            print(f"[!] Error processing sequence: {e}")
            continue

    if len(X) == 0:
        raise ValueError("No sequences could be processed")

    model_dir = os.path.dirname(os.path.abspath(__file__))
    tokenizer_path = os.path.join(model_dir, 'tokenizer.pkl')
    with open(tokenizer_path, 'wb') as f:
        pickle.dump(tokenizer, f)
    print(f"[+] Tokenizer saved to {tokenizer_path}")

    return np.array(X), tokenizer


def transform_sequences(sequences, tokenizer):
    """Encode sequences with an existing tokenizer."""
    X = []
    for seq in sequences:
        try:
            X.append(encode_sequence_with_tokenizer(seq, tokenizer))
        except Exception as e:
            print(f"[!] Error processing sequence: {e}")
            continue

    if len(X) == 0:
        raise ValueError("No sequences could be processed")

    return np.array(X)


def encode_sequence_with_tokenizer(sequence, tokenizer, max_events=None):
    """Encode a full or partial API-call sequence with the training tokenizer."""
    if max_events is not None:
        sequence = sequence[:max_events]

    encoded = tokenizer.texts_to_sequences([[str(event) for event in sequence]])[0]
    if len(encoded) == 0:
        encoded = [1]
    return pad_sequences([encoded], maxlen=MAX_LEN, padding='post')[0]


def evaluate_early_detection(model, sequences, labels, tokenizer, windows=EARLY_WINDOWS, threshold=0.5):
    """Evaluate model performance when only the first N API calls are available."""
    results = {}

    for window in list(windows) + [None]:
        X_window = []
        y_window = []

        for seq, label in zip(sequences, labels):
            if window is not None and len(seq) < window:
                continue
            X_window.append(encode_sequence_with_tokenizer(seq, tokenizer, max_events=window))
            y_window.append(label)

        if not X_window:
            continue

        X_window = np.array(X_window)
        y_window = np.array(y_window)
        y_prob = model.predict(X_window, verbose=0).flatten()
        y_pred = (y_prob >= threshold).astype(int)

        cm = confusion_matrix(y_window, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        key = f"First {window} calls" if window is not None else "Full log"

        results[key] = {
            "samples": len(y_window),
            "accuracy": (y_pred == y_window).mean(),
            "precision": precision_score(y_window, y_pred, zero_division=0),
            "recall": recall_score(y_window, y_pred, zero_division=0),
            "f1": f1_score(y_window, y_pred, zero_division=0),
            "false_positive_rate": fpr,
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        }

    return results


def format_early_results(results):
    lines = []
    lines.append("="*60)
    lines.append("  EARLY DETECTION EVALUATION")
    lines.append("="*60)
    lines.append(f"{'Window':18s} {'Samples':>7s} {'Acc':>8s} {'Prec':>8s} {'Recall':>8s} {'F1':>8s} {'FPR':>8s}")
    for window, metrics in results.items():
        lines.append(
            f"{window:18s} {metrics['samples']:7d} "
            f"{metrics['accuracy']*100:7.2f}% "
            f"{metrics['precision']*100:7.2f}% "
            f"{metrics['recall']*100:7.2f}% "
            f"{metrics['f1']*100:7.2f}% "
            f"{metrics['false_positive_rate']*100:7.2f}%"
        )
    lines.append("="*60)
    return "\n".join(lines)


def train_model():
    """Main training function with advanced optimizations."""

    try:
        sequences, labels = load_training_data()

        unique, counts = np.unique(labels, return_counts=True)
        print(f"[+] Class distribution: {dict(zip(unique, counts))}")

        # ── Compute class weights for balanced training ──────────────────
        seq_train, seq_test, y_train, y_test = train_test_split(
            sequences, labels, test_size=0.2, random_state=42, stratify=labels
        )
        y_train = np.array(y_train)
        y_test = np.array(y_test)

        X_train, tokenizer = preprocess_sequences(seq_train)
        X_test = transform_sequences(seq_test, tokenizer)

        class_weights = compute_class_weight('balanced', classes=np.unique(y_train), y=y_train)
        class_weight_dict = dict(zip(np.unique(y_train), class_weights))
        print(f"[+] Class weights: {class_weight_dict}")

        print(f"\n[+] Training set: {len(X_train)} samples")
        print(f"[+] Test set:     {len(X_test)} samples")

        vocab_size = len(tokenizer.word_index) + 1
        model = build_lstm(vocab_size=vocab_size, max_length=MAX_LEN)

        # Print model summary
        model.summary()

        # ── Advanced training callbacks ──────────────────────────────────
        model_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(model_dir, 'trained_model.h5')

        callbacks = [
            # Stop training when validation loss stops improving
            EarlyStopping(
                monitor='val_loss',
                patience=5,
                restore_best_weights=True,
                verbose=1,
                min_delta=0.001
            ),
            # Reduce learning rate on plateau
            ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=3,
                min_lr=1e-6,
                verbose=1
            ),
            # Save best model checkpoint
            ModelCheckpoint(
                model_path,
                monitor='val_loss',
                save_best_only=True,
                verbose=1
            ),
        ]

        print("\n[*] Training model with advanced optimizations...")
        print(f"    Batch size: 16 | Max epochs: 30 | Class-weighted")
        print(f"    Callbacks: EarlyStopping, ReduceLROnPlateau, ModelCheckpoint")

        history = model.fit(
            X_train, y_train,
            validation_data=(X_test, y_test),
            epochs=30,
            batch_size=16,
            shuffle=True,
            class_weight=class_weight_dict,
            callbacks=callbacks,
            verbose=1
        )

        # Evaluation
        print("\n[*] Evaluating model...")
        loss, accuracy = model.evaluate(X_test, y_test, verbose=0)

        y_pred_prob = model.predict(X_test, verbose=0).flatten()
        y_pred = (y_pred_prob >= 0.5).astype(int)

        precision  = precision_score(y_test, y_pred, zero_division=0)
        recall     = recall_score(y_test, y_pred, zero_division=0)
        f1         = f1_score(y_test, y_pred, zero_division=0)
        cm         = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()

        print("\n" + "="*60)
        print("  MODEL EVALUATION RESULTS")
        print("="*60)
        print(f"  Accuracy  : {accuracy*100:.2f}%")
        print(f"  Loss      : {loss:.4f}")
        print(f"  Precision : {precision*100:.2f}%")
        print(f"  Recall    : {recall*100:.2f}%")
        print(f"  F1-Score  : {f1*100:.2f}%")
        print("="*60)
        print("\n  Confusion Matrix:")
        print(f"  {'':20s}  Predicted Benign  Predicted Malicious")
        print(f"  {'Actual Benign':20s}  {tn:^16}  {fp:^19}")
        print(f"  {'Actual Malicious':20s}  {fn:^16}  {tp:^19}")
        print("\n  Classification Report:")
        print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))
        print("="*60)

        # Early Detection Evaluation
        early_results = evaluate_early_detection(
            model, seq_test, y_test, tokenizer, windows=EARLY_WINDOWS, threshold=0.5
        )
        early_results_text = format_early_results(early_results)
        print("\n" + early_results_text)

        # ── Save evaluation results ──────────────────────────────────
        results_path = os.path.join(model_dir, 'evaluation_results.txt')
        with open(results_path, 'w') as f:
            f.write("   MODEL EVALUATION RESULTS\n")
            f.write("="*60 + "\n")
            f.write(f"  Accuracy  : {accuracy*100:.2f}%\n")
            f.write(f"  Loss      : {loss:.4f}\n")
            f.write(f"  Precision : {precision*100:.2f}%\n")
            f.write(f"  Recall    : {recall*100:.2f}%\n")
            f.write(f"  F1-Score  : {f1*100:.2f}%\n")
            f.write("="*60 + "\n\n")
            f.write("  Confusion Matrix:\n")
            f.write(f"  {'':20s}  Predicted Benign  Predicted Malicious\n")
            f.write(f"  {'Actual Benign':20s}  {tn:^16}  {fp:^19}\n")
            f.write(f"  {'Actual Malicious':20s}  {fn:^16}  {tp:^19}\n\n")
            f.write("  Classification Report:\n")
            f.write(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))
            f.write("\n")
            f.write(early_results_text)
            f.write("\n")
        print(f"\n[✓] Results saved to {results_path}")

        # ── Save epoch-by-epoch training history ─────────────────────
        epochs_path = os.path.join(model_dir, 'training_epochs.txt')
        with open(epochs_path, 'w') as f:
            f.write("   TRAINING EPOCH HISTORY\n")
            f.write("="*80 + "\n")
            f.write(f"  Architecture   : Attention-CNN-BiLSTM Hybrid\n")
            f.write(f"  Max Seq Length : {MAX_LEN}\n")
            f.write(f"  Vocabulary     : {vocab_size}\n")
            f.write(f"  Training Set   : {len(X_train)} samples\n")
            f.write(f"  Test Set       : {len(X_test)} samples\n")
            f.write(f"  Batch Size     : 16\n")
            f.write(f"  Class Weights  : {class_weight_dict}\n")
            f.write("="*80 + "\n\n")

            # Header
            f.write(f"{'Epoch':>6}  {'Loss':>10}  {'Accuracy':>10}  "
                    f"{'Val Loss':>10}  {'Val Acc':>10}  {'LR':>12}\n")
            f.write("-" * 70 + "\n")

            # Write each epoch's metrics
            num_epochs = len(history.history['loss'])
            for epoch in range(num_epochs):
                train_loss = history.history['loss'][epoch]
                train_acc  = history.history['accuracy'][epoch]
                val_loss   = history.history['val_loss'][epoch]
                val_acc    = history.history['val_accuracy'][epoch]
                lr = history.history.get('lr', [0.001] * num_epochs)[epoch]

                f.write(f"{epoch+1:>6}  {train_loss:>10.4f}  {train_acc*100:>9.2f}%  "
                        f"{val_loss:>10.4f}  {val_acc*100:>9.2f}%  {lr:>12.6f}\n")

            f.write("-" * 70 + "\n")
            f.write(f"\nTotal Epochs Run : {num_epochs}\n")
            f.write(f"Best Val Loss    : {min(history.history['val_loss']):.4f}\n")
            f.write(f"Best Val Accuracy: {max(history.history['val_accuracy'])*100:.2f}%\n")
        print(f"[✓] Epoch history saved to {epochs_path}")

        # Model is already saved by ModelCheckpoint callback
        print(f"[✓] Best model saved to {model_path}")

        return model, history

    except Exception as e:
        print(f"\n[!] Training failed: {e}")
        raise


if __name__ == "__main__":
    print("="*60)
    print("LSTM MODEL TRAINING - RANSOMWARE DETECTION")
    print("  Architecture: Attention-CNN-BiLSTM Hybrid")
    print("="*60 + "\n")

    model, history = train_model()

    print("\n" + "="*60)
    print("TRAINING COMPLETE!")
    print("="*60)
