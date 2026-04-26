import os
import warnings
warnings.filterwarnings('ignore')

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
from scipy import stats

plt.rcParams.update({
    'font.size': 12,
    'axes.labelsize': 14,
    'axes.titlesize': 14,
    'xtick.labelsize': 11,
    'ytick.labelsize': 11,
    'legend.fontsize': 11,
    'figure.dpi': 150,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight'
})

COLORS = {'genai': '#2ecc71', 'non_genai': '#3498db', 'accent': '#e74c3c', 'neutral': '#95a5a6'}

SUBCAT_COLORS = {
    'audio': '#1abc9c', 'text': '#2ecc71', 'video': '#27ae60',
    'browsing': '#3498db', 'gaming': '#9b59b6', 'human_human_calling': '#e74c3c',
    'others': '#f39c12', 'live_streaming': '#e67e22', 'on_demand_streaming': '#d35400'
}


def plot_class_distribution(df, output_dir):
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    ax1 = axes[0]
    class_counts = df['is_genai'].value_counts()
    ax1.pie(class_counts.values, labels=['Non-GenAI', 'GenAI'], colors=[COLORS['non_genai'], COLORS['genai']],
            explode=(0, 0.05), autopct='%1.1f%%', startangle=90)
    ax1.set_title('Binary Class Distribution', fontweight='bold', pad=20)

    ax2 = axes[1]
    subcat_counts = df.groupby(['category', 'subcategory']).size().reset_index(name='count')
    subcat_counts['label'] = subcat_counts['subcategory'].str.replace('_', '\n')
    colors_list = [SUBCAT_COLORS.get(s, COLORS['neutral']) for s in subcat_counts['subcategory']]

    bars = ax2.bar(range(len(subcat_counts)), subcat_counts['count'], color=colors_list, edgecolor='white')
    ax2.set_xticks(range(len(subcat_counts)))
    ax2.set_xticklabels(subcat_counts['label'], rotation=45, ha='right')
    ax2.set_ylabel('Number of Samples')
    ax2.set_title('Distribution by Traffic Type', fontweight='bold')

    for bar, count in zip(bars, subcat_counts['count']):
        ax2.annotate(str(count), xy=(bar.get_x() + bar.get_width()/2, bar.get_height()), ha='center', va='bottom', fontsize=10)

    genai_end = len(df[df['category'] == 'genai']['subcategory'].unique()) - 1
    ax2.axvline(x=genai_end + 0.5, color='gray', linestyle='--', alpha=0.5)
    ax2.spines['top'].set_visible(False)
    ax2.spines['right'].set_visible(False)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig1_class_distribution.png'))
    plt.close()


def plot_rtp_and_protocol_analysis(df, output_dir):
    fig, axes = plt.subplots(2, 2, figsize=(12, 10))

    ax = axes[0, 0]
    subcats = df['subcategory'].unique()
    rtp_by_subcat = df.groupby('subcategory')['rtp_ratio'].mean().reindex(subcats)
    colors = [SUBCAT_COLORS.get(s, COLORS['neutral']) for s in subcats]
    bars = ax.bar(range(len(subcats)), rtp_by_subcat.values, color=colors)
    ax.set_xticks(range(len(subcats)))
    ax.set_xticklabels([s.replace('_', '\n') for s in subcats], rotation=45, ha='right')
    ax.set_ylabel('Mean RTP Ratio')
    ax.set_title('RTP Traffic Ratio by Category', fontweight='bold')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    ax = axes[0, 1]
    genai_udp = df[df['is_genai'] == 1]['udp_ratio'].mean()
    genai_tcp = df[df['is_genai'] == 1]['tcp_ratio'].mean()
    nongenai_udp = df[df['is_genai'] == 0]['udp_ratio'].mean()
    nongenai_tcp = df[df['is_genai'] == 0]['tcp_ratio'].mean()

    x = np.arange(2)
    width = 0.35
    ax.bar(x - width/2, [nongenai_tcp, nongenai_udp], width, label='Non-GenAI', color=COLORS['non_genai'])
    ax.bar(x + width/2, [genai_tcp, genai_udp], width, label='GenAI', color=COLORS['genai'])
    ax.set_xticks(x)
    ax.set_xticklabels(['TCP', 'UDP'])
    ax.set_ylabel('Mean Ratio')
    ax.set_title('Protocol Distribution', fontweight='bold')
    ax.legend()
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    ax = axes[1, 0]
    human_calls = df[df['subcategory'] == 'human_human_calling']['rtp_count'] if 'human_human_calling' in df['subcategory'].values else pd.Series([0])
    genai_audio = df[df['subcategory'] == 'audio']['rtp_count'] if 'audio' in df['subcategory'].values else pd.Series([0])
    genai_video = df[df['subcategory'] == 'video']['rtp_count'] if 'video' in df['subcategory'].values else pd.Series([0])

    data_to_plot = []
    labels = []
    if len(human_calls) > 0:
        data_to_plot.append(human_calls)
        labels.append('Human Calls')
    if len(genai_audio) > 0:
        data_to_plot.append(genai_audio)
        labels.append('GenAI Audio')
    if len(genai_video) > 0:
        data_to_plot.append(genai_video)
        labels.append('GenAI Video')

    if data_to_plot:
        bp = ax.boxplot(data_to_plot, labels=labels, patch_artist=True)
        colors_bp = [COLORS['non_genai'], COLORS['genai'], COLORS['genai']][:len(data_to_plot)]
        for patch, color in zip(bp['boxes'], colors_bp):
            patch.set_facecolor(color)
            patch.set_alpha(0.7)
    ax.set_ylabel('RTP Packet Count')
    ax.set_title('RTP Packets: Human vs GenAI Calls', fontweight='bold')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    ax = axes[1, 1]
    rtc_cats = ['human_human_calling', 'audio', 'video', 'live_streaming', 'on_demand_streaming']
    rtc_data = df[df['subcategory'].isin(rtc_cats)]
    if len(rtc_data) > 0:
        for subcat in rtc_cats:
            subcat_data = rtc_data[rtc_data['subcategory'] == subcat]
            if len(subcat_data) > 0:
                color = SUBCAT_COLORS.get(subcat, COLORS['neutral'])
                ax.scatter(subcat_data['bitrate_mean'], subcat_data['bitrate_cv'],
                          c=color, label=subcat.replace('_', ' ').title(), s=80, alpha=0.7)
    ax.set_xlabel('Mean Bitrate (bps)')
    ax.set_ylabel('Bitrate Coefficient of Variation')
    ax.set_title('Bitrate Patterns: Streaming vs Calls', fontweight='bold')
    ax.legend(loc='upper right')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig2_rtp_protocol_analysis.png'))
    plt.close()


def plot_connection_patterns(df, output_dir):
    fig, axes = plt.subplots(2, 2, figsize=(12, 10))

    ax = axes[0, 0]
    genai_ips = df[df['is_genai'] == 1]['unique_dst_ips']
    nongenai_ips = df[df['is_genai'] == 0]['unique_dst_ips']
    bp = ax.boxplot([nongenai_ips, genai_ips], labels=['Non-GenAI', 'GenAI'], patch_artist=True)
    bp['boxes'][0].set_facecolor(COLORS['non_genai'])
    bp['boxes'][1].set_facecolor(COLORS['genai'])
    for box in bp['boxes']:
        box.set_alpha(0.7)
    ax.set_ylabel('Unique Destination IPs')
    ax.set_title('Connection Diversity: GenAI vs Non-GenAI', fontweight='bold')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    try:
        stat, pval = stats.mannwhitneyu(genai_ips, nongenai_ips, alternative='two-sided')
        sig = '***' if pval < 0.001 else '**' if pval < 0.01 else '*' if pval < 0.05 else 'ns'
        ax.text(0.95, 0.95, f'p={pval:.2e}\n{sig}', transform=ax.transAxes, ha='right', va='top', fontsize=9,
                bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    except:
        pass

    ax = axes[0, 1]
    subcats = df['subcategory'].unique()
    conc_by_subcat = df.groupby('subcategory')['ip_concentration'].mean().reindex(subcats)
    colors = [SUBCAT_COLORS.get(s, COLORS['neutral']) for s in subcats]
    bars = ax.bar(range(len(subcats)), conc_by_subcat.values, color=colors)
    ax.set_xticks(range(len(subcats)))
    ax.set_xticklabels([s.replace('_', '\n') for s in subcats], rotation=45, ha='right')
    ax.set_ylabel('IP Concentration')
    ax.set_title('Traffic Concentration (1=Single Server)', fontweight='bold')
    ax.axhline(y=0.8, color='gray', linestyle='--', alpha=0.5, label='High concentration')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    ax = axes[1, 0]
    genai_flows = df[df['is_genai'] == 1]['num_flows']
    nongenai_flows = df[df['is_genai'] == 0]['num_flows']
    bp = ax.boxplot([nongenai_flows, genai_flows], labels=['Non-GenAI', 'GenAI'], patch_artist=True)
    bp['boxes'][0].set_facecolor(COLORS['non_genai'])
    bp['boxes'][1].set_facecolor(COLORS['genai'])
    for box in bp['boxes']:
        box.set_alpha(0.7)
    ax.set_ylabel('Number of Flows')
    ax.set_title('Flow Count: CDN-based vs Single Connection', fontweight='bold')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    ax = axes[1, 1]
    for is_genai in [0, 1]:
        mask = df['is_genai'] == is_genai
        label = 'GenAI' if is_genai == 1 else 'Non-GenAI'
        color = COLORS['genai'] if is_genai == 1 else COLORS['non_genai']
        ax.scatter(df[mask]['unique_dst_ips'], df[mask]['ip_entropy'],
                  c=color, label=label, s=80, alpha=0.7)
    ax.set_xlabel('Unique Destination IPs')
    ax.set_ylabel('IP Entropy')
    ax.set_title('Connection Pattern Analysis', fontweight='bold')
    ax.legend()
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig3_connection_patterns.png'))
    plt.close()


def plot_inference_patterns(df, output_dir):
    fig, axes = plt.subplots(2, 2, figsize=(12, 10))

    ax = axes[0, 0]
    text_genai = df[df['subcategory'] == 'text']['avg_inference_delay'] if 'text' in df['subcategory'].values else pd.Series([0])
    browsing = df[df['subcategory'] == 'browsing']['avg_inference_delay'] if 'browsing' in df['subcategory'].values else pd.Series([0])
    other = df[df['subcategory'] == 'others']['avg_inference_delay'] if 'others' in df['subcategory'].values else pd.Series([0])

    data_to_plot = []
    labels = []
    colors_bp = []
    if len(text_genai) > 0 and text_genai.sum() > 0:
        data_to_plot.append(text_genai)
        labels.append('GenAI Text')
        colors_bp.append(COLORS['genai'])
    if len(browsing) > 0:
        data_to_plot.append(browsing)
        labels.append('Browsing')
        colors_bp.append(COLORS['non_genai'])
    if len(other) > 0:
        data_to_plot.append(other)
        labels.append('Other')
        colors_bp.append(COLORS['neutral'])

    if data_to_plot:
        bp = ax.boxplot(data_to_plot, labels=labels, patch_artist=True)
        for patch, color in zip(bp['boxes'], colors_bp):
            patch.set_facecolor(color)
            patch.set_alpha(0.7)
    ax.set_ylabel('Average Inference Delay (s)')
    ax.set_title('LLM Inference Delay Detection', fontweight='bold')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    ax = axes[0, 1]
    genai_patterns = df[df['is_genai'] == 1]['req_resp_pattern_count']
    nongenai_patterns = df[df['is_genai'] == 0]['req_resp_pattern_count']
    bp = ax.boxplot([nongenai_patterns, genai_patterns], labels=['Non-GenAI', 'GenAI'], patch_artist=True)
    bp['boxes'][0].set_facecolor(COLORS['non_genai'])
    bp['boxes'][1].set_facecolor(COLORS['genai'])
    for box in bp['boxes']:
        box.set_alpha(0.7)
    ax.set_ylabel('Request-Response Pattern Count')
    ax.set_title('Detected LLM-style Patterns', fontweight='bold')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    ax = axes[1, 0]
    subcats = df['subcategory'].unique()
    ratio_by_subcat = df.groupby('subcategory')['req_resp_size_ratio'].mean().reindex(subcats)
    colors = [SUBCAT_COLORS.get(s, COLORS['neutral']) for s in subcats]
    bars = ax.bar(range(len(subcats)), ratio_by_subcat.values, color=colors)
    ax.set_xticks(range(len(subcats)))
    ax.set_xticklabels([s.replace('_', '\n') for s in subcats], rotation=45, ha='right')
    ax.set_ylabel('Request/Response Size Ratio')
    ax.set_title('Traffic Asymmetry (Low = Server Response Heavy)', fontweight='bold')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    ax = axes[1, 1]
    for subcat in ['text', 'browsing', 'on_demand_streaming']:
        if subcat in df['subcategory'].values:
            subcat_data = df[df['subcategory'] == subcat]
            color = SUBCAT_COLORS.get(subcat, COLORS['neutral'])
            ax.scatter(subcat_data['avg_inference_delay'], subcat_data['response_stream_duration'],
                      c=color, label=subcat.replace('_', ' ').title(), s=80, alpha=0.7)
    ax.set_xlabel('Avg Inference Delay (s)')
    ax.set_ylabel('Response Stream Duration (s)')
    ax.set_title('LLM Response Characteristics', fontweight='bold')
    ax.legend()
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig4_inference_patterns.png'))
    plt.close()


def plot_feature_importance(df, output_dir):
    meta_cols = ['filename', 'category', 'subcategory', 'app', 'is_genai']
    feature_cols = [c for c in df.columns if c not in meta_cols]

    correlations = {}
    for col in feature_cols:
        try:
            corr = df[col].corr(df['is_genai'])
            if not np.isnan(corr):
                correlations[col] = corr
        except:
            pass

    sorted_corr = sorted(correlations.items(), key=lambda x: abs(x[1]), reverse=True)[:25]

    fig, ax = plt.subplots(figsize=(10, 10))
    features = [x[0] for x in sorted_corr]
    values = [x[1] for x in sorted_corr]
    clean_features = [f.replace('_', ' ').title() for f in features]

    colors = [COLORS['genai'] if v > 0 else COLORS['non_genai'] for v in values]

    bars = ax.barh(range(len(features)), values, color=colors, edgecolor='white')
    ax.set_yticks(range(len(features)))
    ax.set_yticklabels(clean_features)
    ax.set_xlabel('Correlation with GenAI Label')
    ax.set_title('Top 25 Discriminative Features', fontweight='bold')
    ax.axvline(x=0, color='black', linewidth=0.5)
    ax.invert_yaxis()
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    for bar, val in zip(bars, values):
        offset = 0.02 if val > 0 else -0.02
        ha = 'left' if val > 0 else 'right'
        ax.text(val + offset, bar.get_y() + bar.get_height()/2, f'{val:.3f}', va='center', ha=ha, fontsize=8)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig5_feature_importance.png'))
    plt.close()


def plot_pca_tsne(df, output_dir):
    meta_cols = ['filename', 'category', 'subcategory', 'app', 'is_genai']
    feature_cols = [c for c in df.columns if c not in meta_cols]

    X = df[feature_cols].fillna(0).values
    y = df['is_genai'].values

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    X_scaled = np.nan_to_num(X_scaled, nan=0, posinf=0, neginf=0)

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))

    pca = PCA(n_components=2)
    X_pca = pca.fit_transform(X_scaled)

    for is_genai in [0, 1]:
        mask = y == is_genai
        label = 'GenAI' if is_genai == 1 else 'Non-GenAI'
        color = COLORS['genai'] if is_genai == 1 else COLORS['non_genai']
        axes[0].scatter(X_pca[mask, 0], X_pca[mask, 1], c=color, label=label, alpha=0.7, s=80, edgecolors='white')

    axes[0].set_xlabel(f'PC1 ({pca.explained_variance_ratio_[0]*100:.1f}%)')
    axes[0].set_ylabel(f'PC2 ({pca.explained_variance_ratio_[1]*100:.1f}%)')
    axes[0].set_title('PCA Projection', fontweight='bold')
    axes[0].legend()
    axes[0].spines['top'].set_visible(False)
    axes[0].spines['right'].set_visible(False)

    tsne = TSNE(n_components=2, random_state=42, perplexity=min(30, len(df)-1))
    X_tsne = tsne.fit_transform(X_scaled)

    for is_genai in [0, 1]:
        mask = y == is_genai
        label = 'GenAI' if is_genai == 1 else 'Non-GenAI'
        color = COLORS['genai'] if is_genai == 1 else COLORS['non_genai']
        axes[1].scatter(X_tsne[mask, 0], X_tsne[mask, 1], c=color, label=label, alpha=0.7, s=80, edgecolors='white')

    axes[1].set_xlabel('t-SNE 1')
    axes[1].set_ylabel('t-SNE 2')
    axes[1].set_title('t-SNE Projection', fontweight='bold')
    axes[1].legend()
    axes[1].spines['top'].set_visible(False)
    axes[1].spines['right'].set_visible(False)

    plt.suptitle('Feature Space Visualization (231 Features)', fontweight='bold', y=1.02)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig6_pca_tsne.png'))
    plt.close()


def plot_subcategory_tsne(df, output_dir):
    meta_cols = ['filename', 'category', 'subcategory', 'app', 'is_genai']
    feature_cols = [c for c in df.columns if c not in meta_cols]

    X = df[feature_cols].fillna(0).values
    subcats = df['subcategory'].values

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    X_scaled = np.nan_to_num(X_scaled, nan=0, posinf=0, neginf=0)

    tsne = TSNE(n_components=2, random_state=42, perplexity=min(30, len(df)-1))
    X_tsne = tsne.fit_transform(X_scaled)

    fig, ax = plt.subplots(figsize=(12, 8))

    for subcat in df['subcategory'].unique():
        mask = subcats == subcat
        color = SUBCAT_COLORS.get(subcat, COLORS['neutral'])
        is_genai = df[df['subcategory'] == subcat]['is_genai'].iloc[0]
        marker = 's' if is_genai == 1 else 'o'
        ax.scatter(X_tsne[mask, 0], X_tsne[mask, 1], c=color, label=subcat.replace('_', ' ').title(),
                   alpha=0.8, s=100, edgecolors='white', marker=marker)

    ax.set_xlabel('t-SNE 1')
    ax.set_ylabel('t-SNE 2')
    ax.set_title('Traffic Type Clustering (t-SNE)', fontweight='bold')
    ax.legend(loc='center left', bbox_to_anchor=(1, 0.5), title='Traffic Type\n(■=GenAI, ●=Non-GenAI)')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig7_subcategory_tsne.png'))
    plt.close()


def generate_figures(features_path, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    df = pd.read_csv(features_path)
    print(f"Loaded {len(df)} samples with {len(df.columns) - 5} features")

    plot_class_distribution(df, output_dir)
    plot_rtp_and_protocol_analysis(df, output_dir)
    plot_connection_patterns(df, output_dir)
    plot_inference_patterns(df, output_dir)
    plot_feature_importance(df, output_dir)
    plot_pca_tsne(df, output_dir)
    plot_subcategory_tsne(df, output_dir)

    print(f"Figures saved to {output_dir}")


if __name__ == '__main__':
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    features_path = os.path.join(base_dir, 'data', 'processed', 'features.csv')
    output_dir = os.path.join(base_dir, 'figures')
    generate_figures(features_path, output_dir)
