import os
import sys
import math
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.amp import autocast
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
from collections import Counter
from tqdm import tqdm

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from models.common import (Tee, device, USE_AMP, TrafficDataset, EarlyStopping,
                            make_loader)

# --- CONFIGURATION ---
BATCH_SIZE = 32
MAX_LEN = 5000
D_MODEL = 64
NHEAD = 4
NUM_LAYERS = 2
EPOCHS = 50
LEARNING_RATE = 0.001
EARLY_STOPPING_PATIENCE = 7
N_FOLDS = 5
NUM_WORKERS = 4
DROPOUT = 0.3


# --- MODEL ---
class PositionalEncoding(nn.Module):
    """Batch-first positional encoding: input/output (batch, seq, d_model)."""
    def __init__(self, d_model, max_len=6000):
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        self.register_buffer('pe', pe.unsqueeze(0))  # (1, max_len, d_model)

    def forward(self, x):
        return x + self.pe[:, :x.size(1), :]


class PacketTransformer(nn.Module):
    def __init__(self, input_dim=3, d_model=64, nhead=4, num_layers=2,
                 num_classes=2, dropout=0.4, feat_dim=231):
        super().__init__()
        self.embedding = nn.Linear(input_dim, d_model)
        self.pos_encoder = PositionalEncoding(d_model)
        encoder_layers = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=nhead, batch_first=True, dropout=dropout
        )
        self.transformer_encoder = nn.TransformerEncoder(encoder_layers, num_layers=num_layers)

        self.feat_proj = nn.Sequential(
            nn.Linear(feat_dim, 64),
            nn.ReLU(),
            nn.Dropout(dropout)
        )

        self.classifier = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(d_model + 64, 32),
            nn.ReLU(),
            nn.Linear(32, num_classes)
        )

    def forward(self, src, feat):
        x = self.embedding(src)
        x = self.pos_encoder(x)
        x = self.transformer_encoder(x)
        context = x.mean(dim=1)
        feat_out = self.feat_proj(feat)
        combined = torch.cat([context, feat_out], dim=1)
        return self.classifier(combined)


# --- TRAINING ---
def run_fold(model, train_loader, val_loader, criterion, fold):
    optimizer = optim.AdamW(model.parameters(), lr=LEARNING_RATE, weight_decay=1e-3)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', patience=3, factor=0.5)
    early_stopping = EarlyStopping(patience=EARLY_STOPPING_PATIENCE)

    for epoch in range(EPOCHS):
        # --- Train ---
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

        # --- Validate ---
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


def train_model():
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    features_csv = os.path.join(base_dir, 'data', 'processed', 'features.csv')
    sequences_dir = os.path.join(base_dir, 'data', 'processed', 'sequences')

    if not os.path.exists(sequences_dir):
        print("ERROR: sequences/ not found. Run: python preprocessing/feature_extraction.py")
        return

    full_dataset = TrafficDataset(features_csv, sequences_dir, max_len=MAX_LEN, use_features=True)
    if len(full_dataset) == 0:
        print("ERROR: No .npy files found. Run: python preprocessing/feature_extraction.py")
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
    fold_reports = []

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

        full_dataset.augment = True
        train_loader = make_loader(full_dataset, train_idx, True, BATCH_SIZE, NUM_WORKERS)
        full_dataset.augment = False
        val_loader   = make_loader(full_dataset, val_idx, False, BATCH_SIZE, NUM_WORKERS)
        test_loader  = make_loader(full_dataset, test_idx.tolist(), False, BATCH_SIZE, NUM_WORKERS)

        model = PacketTransformer(input_dim=3, d_model=D_MODEL, nhead=NHEAD,
                                  num_layers=NUM_LAYERS, dropout=DROPOUT,
                                  feat_dim=selected_feat_dim).to(device)

        criterion = nn.CrossEntropyLoss(weight=class_weights, label_smoothing=0.1)
        run_fold(model, train_loader, val_loader, criterion, fold)

        model.eval()
        all_preds, all_labels = [], []
        with torch.no_grad():
            for seq, feat, labels_batch in test_loader:
                seq = seq.to(device, non_blocking=True)
                feat = feat.to(device, non_blocking=True)
                with autocast(device_type=device.type, dtype=torch.bfloat16, enabled=USE_AMP):
                    outputs = model(seq, feat)
                _, predicted = torch.max(outputs, 1)
                all_preds.extend(predicted.cpu().numpy())
                all_labels.extend(labels_batch.numpy())

        report = classification_report(all_labels, all_preds,
                                       target_names=['Non-GenAI', 'GenAI'],
                                       zero_division=0, output_dict=True)
        fold_reports.append(report)
        print(f"\nFold {fold} Results:")
        print(classification_report(all_labels, all_preds,
                                    target_names=['Non-GenAI', 'GenAI'], zero_division=0))

        model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  f'genai_transformer_fold{fold}.pth')
        torch.save(model.state_dict(), model_path)

    print(f"\n{'='*50}\nCROSS-VALIDATION SUMMARY\n{'='*50}")
    for metric in ['precision', 'recall', 'f1-score']:
        scores = [r['weighted avg'][metric] for r in fold_reports]
        print(f"Weighted {metric:10s}: {np.mean(scores):.3f} ± {np.std(scores):.3f}")
    accs = [r['accuracy'] for r in fold_reports]
    print(f"Accuracy          : {np.mean(accs):.3f} ± {np.std(accs):.3f}")


if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    output_path = os.path.join(base_dir, 'results', 'transformer_output.txt')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        sys.stdout = Tee(sys.__stdout__, f)
        try:
            train_model()
        finally:
            sys.stdout = sys.__stdout__
    print(f"\nOutput saved to {output_path}")
