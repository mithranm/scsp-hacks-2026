import os
import sys
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
from sklearn.feature_selection import VarianceThreshold, SelectKBest, mutual_info_classif
from sklearn.pipeline import Pipeline

try:
    from tabpfn import AutoTabPFNClassifier as _TabPFN
    _USE_AUTO = True
except ImportError:
    from tabpfn import TabPFNClassifier as _TabPFN
    _USE_AUTO = False

from models.common import Tee

MAX_FEATURES = 60  # TabPFN has internal feature limits; keep selection

# --- CONFIGURATION ---
N_FOLDS = 5
META_COLS = ['filename', 'category', 'subcategory', 'app', 'is_genai']


def train_model():
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    features_csv = os.path.join(base_dir, 'data', 'processed', 'features.csv')

    if not os.path.exists(features_csv):
        print("ERROR: features.csv not found. Run: python preprocessing/feature_extraction.py")
        return

    df = pd.read_csv(features_csv)
    feature_cols = [c for c in df.columns if c not in META_COLS]
    X = df[feature_cols].values
    y = df['is_genai'].values

    print(f"Dataset: {len(df)} samples, {len(feature_cols)} features")
    print(f"Class distribution: Non-GenAI={sum(y==0)}, GenAI={sum(y==1)}")

    kfold = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=42)
    fold_reports = []

    variant = "AutoTabPFN (max_time=30s)" if _USE_AUTO else "TabPFN"
    print(f"\n{'='*50}\n{variant}\n{'='*50}")

    for fold, (train_idx, test_idx) in enumerate(kfold.split(X, y), start=1):
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]

        scaler = StandardScaler()
        X_train = scaler.fit_transform(X_train)
        X_test = scaler.transform(X_test)

        k = min(MAX_FEATURES, X_train.shape[1])
        selector = Pipeline([
            ('variance', VarianceThreshold(threshold=0.0)),
            ('kbest', SelectKBest(mutual_info_classif, k=min(k, X_train.shape[1]))),
        ])
        X_train = selector.fit_transform(X_train, y_train)
        X_test = selector.transform(X_test)
        if fold == 1:
            print(f"  Feature selection: {len(feature_cols)} → {X_train.shape[1]} features")

        model = _TabPFN(max_time=30) if _USE_AUTO else _TabPFN()
        model.fit(X_train, y_train)
        preds = model.predict(X_test)

        report = classification_report(y_test, preds,
                                       target_names=['Non-GenAI', 'GenAI'],
                                       zero_division=0, output_dict=True)
        fold_reports.append(report)
        print(f"\nFold {fold} Results:")
        print(classification_report(y_test, preds,
                                    target_names=['Non-GenAI', 'GenAI'], zero_division=0))

    print(f"\n{'='*50}\nTabPFN — CROSS-VALIDATION SUMMARY\n{'='*50}")
    for metric in ['precision', 'recall', 'f1-score']:
        scores = [r['weighted avg'][metric] for r in fold_reports]
        print(f"Weighted {metric:10s}: {np.mean(scores):.3f} ± {np.std(scores):.3f}")
    accs = [r['accuracy'] for r in fold_reports]
    print(f"Accuracy          : {np.mean(accs):.3f} ± {np.std(accs):.3f}")


if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    output_path = os.path.join(base_dir, 'results', 'tabpfn_output.txt')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        sys.stdout = Tee(sys.__stdout__, f)
        try:
            train_model()
        finally:
            sys.stdout = sys.__stdout__
    print(f"\nOutput saved to {output_path}")
