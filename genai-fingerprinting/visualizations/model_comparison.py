import os
import numpy as np
import matplotlib.pyplot as plt

plt.rcParams.update({
    'font.size': 11,
    'axes.labelsize': 12,
    'axes.titlesize': 13,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 10,
    'figure.dpi': 150,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
})

# ── Results extracted from output files ──────────────────────────────────────

MODELS = [
    'Random\nForest',
    'Gradient\nBoosting',
    'XGBoost',
    'LightGBM',
    'TabPFN',
    'BiLSTM',
    'Transformer',
    'CNN-LSTM',
    'Ensemble\n(CNN-LSTM+GB)',
]

# Mean ± std from cross-validation summaries (5-fold, 179 samples, 233 features)
ACCURACY_MEAN = np.array([86.6, 88.8, 86.6, 88.2, 89.9, 86.0, 81.0, 85.5, 89.4])
ACCURACY_STD  = np.array([ 3.3,  6.6,  2.8,  5.5,  5.0,  3.0,  6.4,  1.1,  2.2])

PRECISION_MEAN = np.array([87.1, 89.1, 87.6, 88.7, 90.2, 87.4, 82.1, 86.5, 90.2])
RECALL_MEAN    = np.array([86.6, 88.8, 86.6, 88.2, 89.9, 86.0, 81.0, 85.5, 89.4])
F1_MEAN        = np.array([86.5, 88.7, 86.5, 88.2, 89.9, 85.9, 80.8, 85.4, 89.3])

# Per-fold accuracy (%) for each model
FOLD_ACCS = {
    'Random\nForest':          [89, 92, 86, 83, 83],
    'Gradient\nBoosting':      [89, 97, 92, 89, 77],
    'XGBoost':                 [86, 92, 86, 86, 83],
    'LightGBM':                [81, 92, 94, 92, 83],
    'TabPFN':                  [86, 92, 97, 92, 83],
    'BiLSTM':                  [83, 92, 86, 83, 86],
    'Transformer':             [81, 83, 86, 69, 83],
    'CNN-LSTM':                [86, 86, 86, 83, 86],
    'Ensemble\n(CNN-LSTM+GB)': [92, 89, 92, 89, 86],
}

# Colour palette: classical ML=blue/green, TabPFN=purple, deep learning=orange/red
COLORS = ['#2980b9', '#1abc9c', '#27ae60', '#16a085', '#8e44ad', '#e67e22', '#e74c3c', '#f39c12', '#c0392b']

# Sort order: highest to lowest mean accuracy
ORDER = np.argsort(ACCURACY_MEAN)[::-1]
MODELS_S       = [MODELS[i]       for i in ORDER]
ACC_MEAN_S     = ACCURACY_MEAN[ORDER]
ACC_STD_S      = ACCURACY_STD[ORDER]
PREC_MEAN_S    = PRECISION_MEAN[ORDER]
REC_MEAN_S     = RECALL_MEAN[ORDER]
F1_MEAN_S      = F1_MEAN[ORDER]
COLORS_S       = [COLORS[i]       for i in ORDER]
FOLD_ACCS_S    = [FOLD_ACCS[MODELS[i]] for i in ORDER]


if __name__ == '__main__':
    # ── Figure layout ─────────────────────────────────────────────────────────
    fig = plt.figure(figsize=(16, 12))
    fig.suptitle('GenAI Traffic Fingerprinting — Model Comparison\n(5-Fold Stratified Cross-Validation, 179 samples, 233 features)',
                 fontsize=14, fontweight='bold', y=0.98)

    gs = fig.add_gridspec(2, 2, hspace=0.38, wspace=0.32,
                          left=0.08, right=0.97, top=0.91, bottom=0.07)

    ax1 = fig.add_subplot(gs[0, :])   # top: accuracy bar chart (full width)
    ax2 = fig.add_subplot(gs[1, 0])   # bottom-left: per-fold line plot
    ax3 = fig.add_subplot(gs[1, 1])   # bottom-right: precision/recall/F1 grouped bars

    # ── Plot 1: Mean Accuracy ± Std ───────────────────────────────────────────
    x = np.arange(len(MODELS_S))
    bars = ax1.bar(x, ACC_MEAN_S, color=COLORS_S, edgecolor='white',
                   linewidth=1.2, zorder=3, width=0.55)
    ax1.errorbar(x, ACC_MEAN_S, yerr=ACC_STD_S,
                 fmt='none', color='#2c3e50', capsize=6, capthick=2,
                 linewidth=2, zorder=4)

    for bar, mean, std in zip(bars, ACC_MEAN_S, ACC_STD_S):
        ax1.text(bar.get_x() + bar.get_width() / 2,
                 mean + std + 0.8,
                 f'{mean:.1f}%\n±{std:.1f}',
                 ha='center', va='bottom', fontsize=9.5, fontweight='bold',
                 color='#2c3e50')

    ax1.set_xticks(x)
    ax1.set_xticklabels(MODELS_S, fontsize=10.5)
    ax1.set_ylabel('Accuracy (%)', fontsize=12)
    ax1.set_title('Mean Cross-Validation Accuracy ± Std Dev', fontweight='bold')
    ax1.set_ylim(50, 105)
    ax1.axhline(y=90, color='#2c3e50', linestyle='--', alpha=0.4, linewidth=1.2,
                label='90% reference')
    ax1.legend(loc='lower right', fontsize=9)
    ax1.spines['top'].set_visible(False)
    ax1.spines['right'].set_visible(False)
    ax1.yaxis.grid(True, alpha=0.3, zorder=0)
    ax1.set_axisbelow(True)

    # ── Plot 2: Per-Fold Accuracy ─────────────────────────────────────────────
    folds = [1, 2, 3, 4, 5]
    for i, (model, fold_acc) in enumerate(zip(MODELS_S, FOLD_ACCS_S)):
        ax2.plot(folds, fold_acc, marker='o', color=COLORS_S[i],
                 linewidth=1.8, markersize=6, label=model.replace('\n', ' '),
                 alpha=0.9)

    ax2.set_xlabel('Fold', fontsize=12)
    ax2.set_ylabel('Accuracy (%)', fontsize=12)
    ax2.set_title('Per-Fold Accuracy', fontweight='bold')
    ax2.set_xticks(folds)
    ax2.set_ylim(45, 105)
    ax2.axhline(y=90, color='#2c3e50', linestyle='--', alpha=0.35, linewidth=1.2)
    ax2.legend(loc='lower left', fontsize=8, ncol=1,
               framealpha=0.85, edgecolor='#cccccc')
    ax2.spines['top'].set_visible(False)
    ax2.spines['right'].set_visible(False)
    ax2.yaxis.grid(True, alpha=0.3)
    ax2.set_axisbelow(True)

    # ── Plot 3: Precision / Recall / F1 grouped bars ──────────────────────────
    n_models = len(MODELS_S)
    width = 0.25
    x3 = np.arange(n_models)

    ax3.bar(x3 - width, PREC_MEAN_S, width, label='Precision',
            color='#3498db', edgecolor='white', linewidth=0.8)
    ax3.bar(x3,          REC_MEAN_S,  width, label='Recall',
            color='#2ecc71', edgecolor='white', linewidth=0.8)
    ax3.bar(x3 + width,  F1_MEAN_S,   width, label='F1-Score',
            color='#e67e22', edgecolor='white', linewidth=0.8)

    ax3.set_xticks(x3)
    ax3.set_xticklabels(MODELS_S, fontsize=8.5)
    ax3.set_ylabel('Score (%)', fontsize=12)
    ax3.set_title('Precision / Recall / F1 (Weighted Avg)', fontweight='bold')
    ax3.set_ylim(50, 102)
    ax3.axhline(y=90, color='#2c3e50', linestyle='--', alpha=0.35, linewidth=1.2)
    ax3.legend(loc='lower right', fontsize=9)
    ax3.spines['top'].set_visible(False)
    ax3.spines['right'].set_visible(False)
    ax3.yaxis.grid(True, alpha=0.3)
    ax3.set_axisbelow(True)

    # ── Save ──────────────────────────────────────────────────────────────────
    output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'figures')
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, 'model_comparison.png')
    plt.savefig(output_path)
    plt.close()
    print(f"Saved to {output_path}")
