"""
Full training pipeline:
  1. Feature Extraction -> data/processed/features.csv
  2. Baseline models    -> results/baseline_output.txt   (RF, GB, XGBoost, LightGBM)
  3. TabPFN             -> results/tabpfn_output.txt
  4. BiLSTM             -> results/bilstm_output.txt
  5. Transformer        -> results/transformer_output.txt
  6. CNN-LSTM           -> results/cnn_lstm_output.txt
  7. Ensemble           -> results/ensemble_output.txt
"""

import os
import subprocess
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

STEPS = [
    ("Feature Extraction",         "preprocessing/feature_extraction.py"),
    ("Baseline (RF/GB/XGB/LGBM)", "models/baseline/training.py"),
    ("TabPFN",              "models/tabpfn/training.py"),
    ("BiLSTM",              "models/bilstm/training.py"),
    ("Transformer",         "models/transformer/training.py"),
    ("CNN-LSTM",            "models/cnn_lstm/training.py"),
    ("Ensemble",            "models/ensemble/training.py"),
]


def run_step(name, script_rel):
    script = os.path.join(BASE_DIR, script_rel)
    print(f"\n{'='*60}")
    print(f"  STARTING: {name}")
    print(f"  Script  : {script_rel}")
    print(f"{'='*60}\n")

    start = time.time()
    result = subprocess.run(
        [sys.executable, script],
        cwd=BASE_DIR,
    )
    elapsed = time.time() - start

    if result.returncode != 0:
        print(f"\n[ERROR] {name} failed with exit code {result.returncode}.")
        return False

    print(f"\n[DONE] {name} finished in {elapsed:.1f}s")
    return True


def main():
    os.makedirs(os.path.join(BASE_DIR, "results"), exist_ok=True)

    print("=" * 60)
    print("  GenAI Fingerprinting — Full Pipeline")
    print("=" * 60)

    for name, script in STEPS:
        ok = run_step(name, script)
        if not ok:
            print(f"\nPipeline aborted at step: {name}")
            sys.exit(1)

    print(f"\n{'='*60}")
    print("  ALL STEPS COMPLETE")
    print(f"  Results saved in: {os.path.join(BASE_DIR, 'results')}")
    print("=" * 60)


if __name__ == "__main__":
    main()
