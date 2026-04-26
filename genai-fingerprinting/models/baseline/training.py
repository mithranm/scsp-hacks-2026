import os
import sys
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import classification_report
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from models.common import Tee

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

    # Compute scale_pos_weight for imbalanced classes
    n_neg = sum(y == 0)
    n_pos = sum(y == 1)
    scale_pos = n_neg / n_pos if n_pos > 0 else 1.0

    models = {
        'Random Forest': RandomForestClassifier(
            n_estimators=200, max_depth=None, min_samples_leaf=2,
            class_weight='balanced', random_state=42, n_jobs=-1
        ),
        'Gradient Boosting': GradientBoostingClassifier(
            n_estimators=200, max_depth=5, learning_rate=0.05,
            subsample=0.8, random_state=42
        ),
        'XGBoost': XGBClassifier(
            n_estimators=200, max_depth=4, learning_rate=0.05,
            scale_pos_weight=scale_pos, eval_metric='logloss',
            random_state=42, n_jobs=-1, verbosity=0
        ),
        'LightGBM': LGBMClassifier(
            n_estimators=200, max_depth=4, learning_rate=0.05,
            scale_pos_weight=scale_pos,
            random_state=42, n_jobs=-1, verbose=-1
        ),
    }

    kfold = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=42)

    for model_name, model_template in models.items():
        print(f"\n{'='*50}\n{model_name}\n{'='*50}")
        fold_reports = []

        for fold, (train_idx, test_idx) in enumerate(kfold.split(X, y), start=1):
            X_train, X_test = X[train_idx], X[test_idx]
            y_train, y_test = y[train_idx], y[test_idx]

            scaler = StandardScaler()
            X_train = scaler.fit_transform(X_train)
            X_test = scaler.transform(X_test)

            model = model_template.__class__(**model_template.get_params())
            model.fit(X_train, y_train)
            preds = model.predict(X_test)

            report = classification_report(y_test, preds,
                                           target_names=['Non-GenAI', 'GenAI'],
                                           zero_division=0, output_dict=True)
            fold_reports.append(report)
            print(f"\nFold {fold} Results:")
            print(classification_report(y_test, preds,
                                        target_names=['Non-GenAI', 'GenAI'], zero_division=0))

            if hasattr(model, 'feature_importances_') and fold == 1:
                importances = model.feature_importances_
                top_idx = np.argsort(importances)[-10:][::-1]
                print("Top 10 features:")
                for i in top_idx:
                    print(f"  {feature_cols[i]:30s} {importances[i]:.4f}")

        print(f"\n{'='*50}\n{model_name} — CROSS-VALIDATION SUMMARY\n{'='*50}")
        for metric in ['precision', 'recall', 'f1-score']:
            scores = [r['weighted avg'][metric] for r in fold_reports]
            print(f"Weighted {metric:10s}: {np.mean(scores):.3f} ± {np.std(scores):.3f}")
        accs = [r['accuracy'] for r in fold_reports]
        print(f"Accuracy          : {np.mean(accs):.3f} ± {np.std(accs):.3f}")


if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    output_path = os.path.join(base_dir, 'results', 'baseline_output.txt')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        sys.stdout = Tee(sys.__stdout__, f)
        try:
            train_model()
        finally:
            sys.stdout = sys.__stdout__
    print(f"\nOutput saved to {output_path}")
