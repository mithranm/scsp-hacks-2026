import os
import sys
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch.amp import autocast
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegressionCV
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import classification_report
from collections import Counter
from tqdm import tqdm

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from models.common import (Tee, device, USE_AMP, TrafficDataset, PacketCNNLSTM,
                            EarlyStopping, make_loader)

# --- CONFIGURATION ---
BATCH_SIZE = 48
MAX_LEN = 5000
CNN_CHANNELS = [32, 64]
LSTM_HIDDEN = 64
LSTM_LAYERS = 2
EPOCHS = 50
LEARNING_RATE = 0.001
EARLY_STOPPING_PATIENCE = 15
N_FOLDS = 5
NUM_WORKERS = 4


# --- TRAINING ---
def train_cnn_lstm(model, train_loader, val_loader, class_weights, fold):
    criterion = nn.CrossEntropyLoss(weight=class_weights, label_smoothing=0.1)
    optimizer = optim.AdamW(model.parameters(), lr=LEARNING_RATE, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', patience=3, factor=0.5)
    early_stopping = EarlyStopping(patience=EARLY_STOPPING_PATIENCE)

    for epoch in range(EPOCHS):
        model.train()
        train_loss, correct, total = 0.0, 0, 0
        for seq, feat, labels_batch in tqdm(train_loader, leave=False,
                                            desc=f"Fold {fold} Epoch {epoch+1}"):
            seq = seq.to(device, non_blocking=True)
            feat = feat.to(device, non_blocking=True)
            labels_batch = labels_batch.to(device, non_blocking=True)
            optimizer.zero_grad()

            with autocast(device_type=device.type, dtype=torch.bfloat16, enabled=USE_AMP):
                outputs = model(seq, feat)
                loss = criterion(outputs, labels_batch)

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()

            train_loss += loss.item()
            _, predicted = torch.max(outputs.detach(), 1)
            total += labels_batch.size(0)
            correct += (predicted == labels_batch).sum().item()

        avg_train_loss = train_loss / len(train_loader)
        train_acc = 100 * correct / total

        model.eval()
        val_loss, val_correct, val_total = 0.0, 0, 0
        with torch.no_grad():
            for seq, feat, labels_batch in val_loader:
                seq = seq.to(device, non_blocking=True)
                feat = feat.to(device, non_blocking=True)
                labels_batch = labels_batch.to(device, non_blocking=True)
                with autocast(device_type=device.type, dtype=torch.bfloat16, enabled=USE_AMP):
                    outputs = model(seq, feat)
                    val_loss += criterion(outputs, labels_batch).item()
                _, predicted = torch.max(outputs, 1)
                val_total += labels_batch.size(0)
                val_correct += (predicted == labels_batch).sum().item()

        avg_val_loss = val_loss / len(val_loader)
        val_acc = 100 * val_correct / val_total

        print(f"  Epoch [{epoch+1}/{EPOCHS}]  "
              f"Train Loss: {avg_train_loss:.4f}  Acc: {train_acc:.1f}%  |  "
              f"Val Loss: {avg_val_loss:.4f}  Acc: {val_acc:.1f}%  "
              f"LR: {optimizer.param_groups[0]['lr']:.5f}")

        scheduler.step(avg_val_loss)
        if early_stopping(avg_val_loss, model):
            print(f"  Early stopping at epoch {epoch+1}")
            break

    early_stopping.restore_best(model)


def get_cnn_lstm_probs(model, loader):
    model.eval()
    all_probs = []
    with torch.no_grad():
        for seq, feat, _ in loader:
            seq = seq.to(device, non_blocking=True)
            feat = feat.to(device, non_blocking=True)
            with autocast(device_type=device.type, dtype=torch.bfloat16, enabled=USE_AMP):
                logits = model(seq, feat)
            probs = F.softmax(logits.float(), dim=1)
            all_probs.append(probs.cpu().numpy())
    return np.vstack(all_probs)


def train_model():
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    features_csv = os.path.join(base_dir, 'data', 'processed', 'features.csv')
    sequences_dir = os.path.join(base_dir, 'data', 'processed', 'sequences')

    if not os.path.exists(sequences_dir):
        print("ERROR: sequences/ not found. Run: python preprocessing/feature_extraction.py")
        return

    full_dataset = TrafficDataset(features_csv, sequences_dir, max_len=MAX_LEN, use_features=True)
    if len(full_dataset) == 0:
        print("ERROR: No .npy files found.")
        return

    feat_dim = len(full_dataset.feat_cols)
    print(f"Handcrafted features: {feat_dim}")

    labels = [int(full_dataset.data.iloc[i]['is_genai']) for i in range(len(full_dataset))]
    indices = np.array(range(len(full_dataset)))

    counts = Counter(labels)
    n = len(labels)
    class_weights = torch.tensor(
        [n / (2 * counts[c]) for c in sorted(counts)], dtype=torch.float32
    ).to(device)
    print(f"Class weights — Non-GenAI: {class_weights[0]:.3f}  GenAI: {class_weights[1]:.3f}")

    kfold = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=42)
    fold_reports_cnn = []
    fold_reports_gb = []
    fold_reports_ensemble = []

    for fold, (train_val_idx, test_idx) in enumerate(kfold.split(indices, labels), start=1):
        print(f"\n{'='*50}\nFOLD {fold}/{N_FOLDS}  — Test size: {len(test_idx)}\n{'='*50}")

        train_val_labels = [labels[i] for i in train_val_idx]
        train_idx, val_idx = train_test_split(
            train_val_idx.tolist(),
            test_size=0.15, stratify=train_val_labels, random_state=42
        )
        print(f"Train: {len(train_idx)}  Val: {len(val_idx)}  Test: {len(test_idx)}")

        scaler = StandardScaler()
        scaler.fit(full_dataset.raw_features[train_idx])
        full_dataset.normalized_features = scaler.transform(full_dataset.raw_features).astype(np.float32)
        selected_feat_dim = full_dataset.normalized_features.shape[1]

        # --- CNN-LSTM ---
        print(f"\n--- CNN-LSTM ---")
        full_dataset.augment = True
        train_loader = make_loader(full_dataset, train_idx, True, BATCH_SIZE, NUM_WORKERS)
        full_dataset.augment = False
        val_loader  = make_loader(full_dataset, val_idx, False, BATCH_SIZE, NUM_WORKERS)
        test_loader = make_loader(full_dataset, test_idx.tolist(), False, BATCH_SIZE, NUM_WORKERS)

        cnn_model = PacketCNNLSTM(
            input_dim=3, cnn_channels=CNN_CHANNELS,
            lstm_hidden=LSTM_HIDDEN, lstm_layers=LSTM_LAYERS,
            feat_dim=selected_feat_dim
        ).to(device)

        train_cnn_lstm(cnn_model, train_loader, val_loader, class_weights, fold)

        # Get CNN-LSTM probabilities on val and test sets for stacking
        cnn_val_probs = get_cnn_lstm_probs(cnn_model, val_loader)
        cnn_test_probs = get_cnn_lstm_probs(cnn_model, test_loader)
        cnn_preds = np.argmax(cnn_test_probs, axis=1)

        # --- Gradient Boosting ---
        print(f"\n--- Gradient Boosting ---")
        X_train_gb = full_dataset.normalized_features[train_idx]
        X_val_gb   = full_dataset.normalized_features[val_idx]
        X_test_gb  = full_dataset.normalized_features[test_idx]
        y_train_gb = np.array([labels[i] for i in train_idx])
        y_val_gb   = np.array([labels[i] for i in val_idx])

        gb = GradientBoostingClassifier(
            n_estimators=200, max_depth=5, learning_rate=0.05,
            subsample=0.8, random_state=42
        )
        gb.fit(X_train_gb, y_train_gb)
        gb_val_probs = gb.predict_proba(X_val_gb)
        gb_test_probs = gb.predict_proba(X_test_gb)
        gb_preds = np.argmax(gb_test_probs, axis=1)

        # --- Learned Stacking with LogisticRegressionCV ---
        print(f"\n--- Learned Stacking (LogisticRegressionCV) ---")
        # Stack CNN-LSTM and GB probabilities as meta-features
        meta_val = np.hstack([cnn_val_probs, gb_val_probs])
        meta_test = np.hstack([cnn_test_probs, gb_test_probs])

        meta_learner = LogisticRegressionCV(
            Cs=10, cv=3, scoring='accuracy', max_iter=1000, random_state=42
        )
        meta_learner.fit(meta_val, y_val_gb)
        ensemble_preds = meta_learner.predict(meta_test)
        print(f"  Meta-learner coefficients: {meta_learner.coef_.ravel()}")

        all_labels = [labels[i] for i in test_idx]

        print(f"\nFold {fold} — CNN-LSTM:")
        r_cnn = classification_report(all_labels, cnn_preds,
                                      target_names=['Non-GenAI', 'GenAI'],
                                      zero_division=0, output_dict=True)
        fold_reports_cnn.append(r_cnn)
        print(classification_report(all_labels, cnn_preds,
                                    target_names=['Non-GenAI', 'GenAI'], zero_division=0))

        print(f"Fold {fold} — Gradient Boosting:")
        r_gb = classification_report(all_labels, gb_preds,
                                     target_names=['Non-GenAI', 'GenAI'],
                                     zero_division=0, output_dict=True)
        fold_reports_gb.append(r_gb)
        print(classification_report(all_labels, gb_preds,
                                    target_names=['Non-GenAI', 'GenAI'], zero_division=0))

        print(f"Fold {fold} — Ensemble (Learned Stacking):")
        r_ens = classification_report(all_labels, ensemble_preds,
                                      target_names=['Non-GenAI', 'GenAI'],
                                      zero_division=0, output_dict=True)
        fold_reports_ensemble.append(r_ens)
        print(classification_report(all_labels, ensemble_preds,
                                    target_names=['Non-GenAI', 'GenAI'], zero_division=0))

    print(f"\n{'='*50}\nCROSS-VALIDATION SUMMARY\n{'='*50}")
    for name, reports in [('CNN-LSTM', fold_reports_cnn),
                          ('Gradient Boosting', fold_reports_gb),
                          ('Ensemble (Learned Stacking)', fold_reports_ensemble)]:
        accs = [r['accuracy'] for r in reports]
        f1s  = [r['weighted avg']['f1-score'] for r in reports]
        print(f"\n{name}:")
        print(f"  Accuracy : {np.mean(accs):.3f} ± {np.std(accs):.3f}")
        print(f"  F1       : {np.mean(f1s):.3f} ± {np.std(f1s):.3f}")


if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    output_path = os.path.join(base_dir, 'results', 'ensemble_output.txt')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        sys.stdout = Tee(sys.__stdout__, f)
        try:
            train_model()
        finally:
            sys.stdout = sys.__stdout__
    print(f"\nOutput saved to {output_path}")
