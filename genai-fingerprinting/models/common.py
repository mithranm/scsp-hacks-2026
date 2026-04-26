import os
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader, Subset


# --- OUTPUT TEE ---
class Tee:
    def __init__(self, *files):
        self.files = files

    def write(self, obj):
        for f in self.files:
            f.write(obj)
            f.flush()

    def flush(self):
        for f in self.files:
            f.flush()


# --- DEVICE SETUP ---
torch.backends.cuda.matmul.allow_tf32 = True
torch.backends.cudnn.allow_tf32 = True
torch.backends.cudnn.benchmark = True

if torch.cuda.is_available():
    device = torch.device("cuda")
elif torch.backends.mps.is_available():
    device = torch.device("mps")
else:
    device = torch.device("cpu")

USE_AMP = device.type == "cuda"
print(f"Using device: {device}  |  AMP (mixed precision): {USE_AMP}")


# --- DATASET ---
_META_COLS = {'filename', 'category', 'subcategory', 'app', 'is_genai', 'npy_path'}


class TrafficDataset(Dataset):
    """
    Loads packet sequences from .npy files and optionally handcrafted features.

    When use_features=False (default), __getitem__ returns (seq, label).
    When use_features=True, __getitem__ returns (seq, feat, label) and
    augmentation / per-fold feature scaling via normalized_features are supported.
    """

    def __init__(self, csv_file, seq_dir, max_len=5000, use_features=False):
        import pandas as pd
        self.data = pd.read_csv(csv_file)
        self.seq_dir = seq_dir
        self.max_len = max_len
        self.use_features = use_features
        self.augment = False

        self.data['npy_path'] = self.data['filename'].apply(
            lambda x: os.path.join(seq_dir, os.path.splitext(x)[0] + '.npy')
        )
        self.data = self.data[self.data['npy_path'].apply(os.path.exists)].reset_index(drop=True)
        print(f"Found {len(self.data)} valid sequence files.")

        if use_features:
            self.feat_cols = [c for c in self.data.columns if c not in _META_COLS]
            self.raw_features = self.data[self.feat_cols].values.astype(np.float32)
            self.normalized_features = self.raw_features.copy()

    def __len__(self):
        return len(self.data)

    def _augment(self, seq):
        seq = seq.copy()
        # Random crop
        if len(seq) > 100:
            crop_len = int(len(seq) * np.random.uniform(0.7, 1.0))
            start = np.random.randint(0, len(seq) - crop_len + 1)
            seq = seq[start:start + crop_len]

        seq[:, 1] = seq[:, 1] + np.random.normal(0, 0.02 * seq[:, 1].std() + 1e-6, len(seq))
        seq[:, 1] = np.clip(seq[:, 1], 0, None)

        # Packet drop
        keep = np.random.rand(len(seq)) > 0.10
        if keep.sum() > 10:
            seq = seq[keep]

        return seq

    def __getitem__(self, idx):
        row = self.data.iloc[idx]
        label = int(row['is_genai'])
        seq = np.load(row['npy_path']).copy()

        if len(seq) > 0:
            if self.augment:
                seq = self._augment(seq)
            seq[:, 0] = np.log1p(seq[:, 0])
            max_ts = seq[:, 0].max()
            if max_ts > 0:
                seq[:, 0] = seq[:, 0] / max_ts
            seq[:, 1] = seq[:, 1] / 1500.0
            seq[:, 2] = (seq[:, 2] + 1) / 2.0

        seq_len = seq.shape[0]
        if seq_len >= self.max_len:
            seq = seq[:self.max_len, :]
        else:
            padding = np.zeros((self.max_len - seq_len, 3))
            seq = np.vstack((seq, padding)) if seq_len > 0 else padding

        seq_t = torch.tensor(seq, dtype=torch.float32)
        label_t = torch.tensor(label, dtype=torch.long)

        if self.use_features:
            feat_t = torch.tensor(self.normalized_features[idx], dtype=torch.float32)
            return seq_t, feat_t, label_t
        return seq_t, label_t


# --- SHARED MODEL COMPONENTS ---
class SelfAttention(nn.Module):
    def __init__(self, hidden_size):
        super().__init__()
        self.score = nn.Linear(hidden_size, 1)

    def forward(self, lstm_output):
        weights = F.softmax(self.score(lstm_output).squeeze(-1), dim=1)
        return torch.bmm(weights.unsqueeze(1), lstm_output).squeeze(1)


class PacketCNNLSTM(nn.Module):
    def __init__(self, input_dim=3, cnn_channels=None, lstm_hidden=64,
                 lstm_layers=2, num_classes=2, dropout=0.3, feat_dim=231):
        super().__init__()
        if cnn_channels is None:
            cnn_channels = [32, 64]

        self.conv1 = nn.Conv1d(input_dim, cnn_channels[0], kernel_size=5, padding=2)
        self.bn1 = nn.BatchNorm1d(cnn_channels[0])
        self.pool1 = nn.MaxPool1d(kernel_size=2)
        self.drop1 = nn.Dropout(0.2)

        self.conv2 = nn.Conv1d(cnn_channels[0], cnn_channels[1], kernel_size=3, padding=1)
        self.bn2 = nn.BatchNorm1d(cnn_channels[1])
        self.pool2 = nn.MaxPool1d(kernel_size=2)
        self.drop2 = nn.Dropout(0.2)

        self.lstm = nn.LSTM(
            input_size=cnn_channels[1],
            hidden_size=lstm_hidden,
            num_layers=lstm_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if lstm_layers > 1 else 0.0
        )

        self.attention = SelfAttention(lstm_hidden * 2)

        self.feat_proj = nn.Sequential(
            nn.Linear(feat_dim, 64),
            nn.ReLU(),
            nn.Dropout(dropout)
        )

        self.classifier = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(lstm_hidden * 2 + 64, 64),
            nn.ReLU(),
            nn.Linear(64, num_classes)
        )

    def forward(self, src, feat):
        x = src.transpose(1, 2)
        x = self.drop1(self.pool1(F.relu(self.bn1(self.conv1(x)))))
        x = self.drop2(self.pool2(F.relu(self.bn2(self.conv2(x)))))
        x = x.transpose(1, 2)
        lstm_out, _ = self.lstm(x)
        context = self.attention(lstm_out)
        feat_out = self.feat_proj(feat)
        combined = torch.cat([context, feat_out], dim=1)
        return self.classifier(combined)


# --- EARLY STOPPING ---
class EarlyStopping:
    def __init__(self, patience=7):
        self.patience = patience
        self.counter = 0
        self.best_val_loss = float('inf')
        self.best_model_state = None

    def __call__(self, val_loss, model):
        if val_loss < self.best_val_loss:
            self.best_val_loss = val_loss
            self.best_model_state = {k: v.clone() for k, v in model.state_dict().items()}
            self.counter = 0
            return False
        self.counter += 1
        return self.counter >= self.patience

    def restore_best(self, model):
        if self.best_model_state:
            model.load_state_dict(self.best_model_state)


# --- DATA LOADER ---
def make_loader(dataset, indices, shuffle, batch_size, num_workers):
    return DataLoader(
        Subset(dataset, indices),
        batch_size=batch_size,
        shuffle=shuffle,
        num_workers=num_workers,
        pin_memory=(device.type == "cuda"),
        persistent_workers=(num_workers > 0),
        prefetch_factor=2 if num_workers > 0 else None,
        drop_last=False,
    )
