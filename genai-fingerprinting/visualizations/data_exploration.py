"""
Data Exploration & Trend Analysis for GenAI vs Non-GenAI Network Traffic
========================================================================
Reads raw pcap files and produces individual, presentation-quality charts
comparing GenAI and non-GenAI traffic characteristics.

Each chart is saved as its own file for easy use in presentations.

Usage:
    python visualizations/data_exploration.py
"""

import os
import sys
import warnings
from collections import defaultdict

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scipy import stats
from scapy.all import rdpcap, IP, TCP, UDP, Raw, conf

conf.verb = 0
warnings.filterwarnings('ignore')

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data', 'raw')
LABELS_CSV = os.path.join(DATA_DIR, 'labels.csv')
OUTPUT_DIR = os.path.join(BASE_DIR, 'figures', 'data_exploration')
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ─── Professional Style ──────────────────────────────────────────────────────
plt.rcParams.update({
    'figure.facecolor': '#ffffff',
    'axes.facecolor': '#ffffff',
    'axes.edgecolor': '#d1d5db',
    'axes.labelcolor': '#374151',
    'axes.titlesize': 13,
    'axes.titleweight': 'semibold',
    'axes.titlecolor': '#111827',
    'axes.grid': False,
    'xtick.color': '#6b7280',
    'ytick.color': '#6b7280',
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
    'font.size': 10,
    'figure.dpi': 150,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'savefig.facecolor': '#ffffff',
    'savefig.edgecolor': 'none',
    'legend.frameon': False,
    'legend.fontsize': 9,
})

# ─── Color Palette (Muted, Professional) ─────────────────────────────────────
C_GENAI = '#1e293b'
C_NON_GENAI = '#94a3b8'
C_ACCENT = '#dc2626'
C_UPLINK = '#475569'
C_DOWNLINK = '#d97706'

SUBCAT_ORDER = ['text', 'audio', 'video', 'browsing', 'human_human_calling',
                'gaming', 'live_streaming', 'on_demand_streaming', 'others']
GENAI_SUBCATS = {'text', 'audio', 'video'}

C_MODALITY = {'text': '#0f172a', 'audio': '#475569', 'video': '#94a3b8'}


# ─── Helper Functions ─────────────────────────────────────────────────────────

def _save(fig, name):
    fig.savefig(os.path.join(OUTPUT_DIR, name))
    plt.close(fig)
    print(f"  Saved: {name}")


def _clean(ax):
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#d1d5db')
    ax.spines['bottom'].set_color('#d1d5db')


def _subcat_color(s):
    return C_GENAI if s in GENAI_SUBCATS else C_NON_GENAI


def _bp_style():
    return dict(
        patch_artist=True,
        widths=0.45,
        boxprops=dict(linewidth=0.8),
        whiskerprops=dict(linewidth=0.8, color='#9ca3af'),
        capprops=dict(linewidth=0.8, color='#9ca3af'),
        medianprops=dict(linewidth=1.5, color='#0f172a'),
        flierprops=dict(marker='o', markersize=3,
                        markerfacecolor='#9ca3af', markeredgecolor='none'),
    )


def _color_bp(bp, colors):
    for patch, color in zip(bp['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.25)
        patch.set_edgecolor(color)


def _add_pvalue(ax, data1, data2):
    try:
        _, p = stats.mannwhitneyu(data1.dropna(), data2.dropna(),
                                  alternative='two-sided')
        color = C_ACCENT if p < 0.05 else '#9ca3af'
        ax.annotate(f'p = {p:.2e}', xy=(0.5, 0.97), xycoords='axes fraction',
                    ha='center', fontsize=9, color=color, style='italic')
    except Exception:
        pass


def _add_divider(ax, means_index):
    n = sum(1 for s in means_index if s in GENAI_SUBCATS)
    if 0 < n < len(means_index):
        ax.axvline(x=n - 0.5, color='#d1d5db', linestyle='--', linewidth=0.8)


def subcat_bar(df, metric, ylabel, title, filename, scale=1.0):
    """Standard subcategory bar chart."""
    sub_df = df[df['subcategory'].isin(SUBCAT_ORDER)]
    means = sub_df.groupby('subcategory')[metric].mean().reindex(SUBCAT_ORDER).dropna()

    fig, ax = plt.subplots(figsize=(9, 5))
    _clean(ax)
    colors = [_subcat_color(s) for s in means.index]
    ax.bar(range(len(means)), means.values * scale, color=colors,
           edgecolor='white', linewidth=0.5, width=0.7)
    ax.set_xticks(range(len(means)))
    ax.set_xticklabels([s.replace('_', '\n') for s in means.index],
                       fontsize=8, rotation=45, ha='right')
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    _add_divider(ax, means.index)
    plt.tight_layout()
    _save(fig, filename)


def binary_box(df, metric, ylabel, title, filename, scale=1.0):
    """GenAI vs Non-GenAI boxplot."""
    g = df[df['label'] == 'GenAI'][metric].dropna() * scale
    n = df[df['label'] == 'Non-GenAI'][metric].dropna() * scale

    fig, ax = plt.subplots(figsize=(5, 5.5))
    _clean(ax)
    bp = ax.boxplot([g, n], labels=['GenAI', 'Non-GenAI'], **_bp_style())
    _color_bp(bp, [C_GENAI, C_NON_GENAI])
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    _add_pvalue(ax, g, n)
    plt.tight_layout()
    _save(fig, filename)


def modality_box(df, metric, ylabel, title, filename, scale=1.0):
    """GenAI text vs audio vs video boxplot."""
    genai_df = df[df['is_genai'] == 1]
    mods = ['text', 'audio', 'video']

    fig, ax = plt.subplots(figsize=(5.5, 5.5))
    _clean(ax)

    data, labels, colors = [], [], []
    for mod in mods:
        vals = genai_df[genai_df['subcategory'] == mod][metric].dropna() * scale
        if len(vals) > 0:
            data.append(vals.values)
            labels.append(mod.capitalize())
            colors.append(C_MODALITY[mod])

    if not data:
        plt.close(fig)
        return

    bp = ax.boxplot(data, labels=labels, **_bp_style())
    _color_bp(bp, colors)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    plt.tight_layout()
    _save(fig, filename)


def app_box(df, metric, ylabel, title, filename, divide=1.0):
    """Per-application boxplot."""
    app_counts = df['app'].value_counts()
    top_apps = app_counts[app_counts >= 2].index.tolist()
    sub_df = df[df['app'].isin(top_apps)]

    genai_apps = sorted(sub_df[sub_df['is_genai'] == 1]['app'].unique())
    non_genai_apps = sorted(sub_df[sub_df['is_genai'] == 0]['app'].unique())
    app_order = genai_apps + non_genai_apps

    data, labels, colors = [], [], []
    for app in app_order:
        vals = sub_df[sub_df['app'] == app][metric].dropna() / divide
        if len(vals) == 0:
            continue
        data.append(vals.values)
        labels.append(app)
        colors.append(C_GENAI if app in genai_apps else C_NON_GENAI)

    if not data:
        return

    fig, ax = plt.subplots(figsize=(max(8, len(labels) * 0.8), 5.5))
    _clean(ax)
    style = _bp_style()
    style['widths'] = 0.55
    bp = ax.boxplot(data, labels=labels, **style)
    _color_bp(bp, colors)
    ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=8)
    ax.set_ylabel(ylabel)
    ax.set_title(title)

    n_g = len([a for a in labels if a in genai_apps])
    if 0 < n_g < len(labels):
        ax.axvline(x=n_g + 0.5, color='#d1d5db', linestyle='--', linewidth=0.8)

    plt.tight_layout()
    _save(fig, filename)


# ─── Data Extraction ──────────────────────────────────────────────────────────

def is_rtp_packet(pkt):
    if UDP not in pkt or Raw not in pkt:
        return False
    payload = bytes(pkt[Raw].load)
    if len(payload) < 12:
        return False
    version = (payload[0] >> 6) & 0x03
    pt = payload[1] & 0x7F
    return version == 2 and pt < 128


def resolve_pcap_path(filename, category, subcategory):
    if category == 'genai':
        for subdir in ['audio', 'text', 'video']:
            p = os.path.join(DATA_DIR, 'genai', subdir, filename)
            if os.path.exists(p):
                return p
    else:
        for subdir in ['browsing', 'gaming', 'human_human_calling',
                        'live_streaming', 'on_demand_streaming', 'others']:
            p = os.path.join(DATA_DIR, 'non_genai', subdir, filename)
            if os.path.exists(p):
                return p
    return None


def extract_trace_stats(filepath, max_packets=10000):
    try:
        packets = rdpcap(filepath, count=max_packets)
    except Exception as e:
        print(f"  [WARN] Could not read {os.path.basename(filepath)}: {e}")
        return None

    if len(packets) < 10:
        return None

    src_counts = defaultdict(int)
    for pkt in packets[:500]:
        if IP in pkt:
            src_counts[pkt[IP].src] += 1
    if not src_counts:
        return None
    client_ip = max(src_counts, key=src_counts.get)

    timestamps, sizes = [], []
    protocols = {'tcp': 0, 'udp': 0, 'rtp': 0, 'tls': 0, 'other': 0}
    fwd_sizes, bwd_sizes = [], []
    fwd_ts, bwd_ts = [], []
    all_dst_ips = set()
    flows = set()

    for pkt in packets:
        if IP not in pkt:
            continue
        ts = float(pkt.time)
        size = len(pkt)
        timestamps.append(ts)
        sizes.append(size)
        is_fwd = pkt[IP].src == client_ip

        if is_fwd:
            fwd_sizes.append(size)
            fwd_ts.append(ts)
            all_dst_ips.add(pkt[IP].dst)
        else:
            bwd_sizes.append(size)
            bwd_ts.append(ts)

        if TCP in pkt:
            protocols['tcp'] += 1
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            if sport == 443 or dport == 443:
                protocols['tls'] += 1
            flows.add((pkt[IP].src, pkt[IP].dst, sport, dport, 'TCP'))
        elif UDP in pkt:
            protocols['udp'] += 1
            if is_rtp_packet(pkt):
                protocols['rtp'] += 1
            flows.add((pkt[IP].src, pkt[IP].dst, pkt[UDP].sport, pkt[UDP].dport, 'UDP'))
        else:
            protocols['other'] += 1

    total_pkts = len(timestamps)
    if total_pkts == 0:
        return None

    timestamps = np.array(timestamps)
    sizes = np.array(sizes)
    duration = timestamps[-1] - timestamps[0]
    if duration <= 0:
        duration = 1.0

    all_iats = np.diff(np.sort(timestamps))
    fwd_iats = np.diff(np.sort(fwd_ts)) if len(fwd_ts) > 1 else np.array([])
    bwd_iats = np.diff(np.sort(bwd_ts)) if len(bwd_ts) > 1 else np.array([])

    t_start, t_end = timestamps[0], timestamps[-1]
    bins = np.arange(t_start, t_end + 1, 1.0)
    if len(bins) > 1:
        byte_per_bin, _ = np.histogram(timestamps, bins=bins, weights=sizes)
        bitrates = byte_per_bin * 8
    else:
        bitrates = np.array([np.sum(sizes) * 8])

    fwd_bytes = sum(fwd_sizes)
    bwd_bytes = sum(bwd_sizes)
    total_bytes = fwd_bytes + bwd_bytes
    asymmetry = bwd_bytes / fwd_bytes if fwd_bytes > 0 else 0

    return {
        'total_packets': total_pkts,
        'duration_s': duration,
        'total_bytes': total_bytes,
        'fwd_bytes': fwd_bytes,
        'bwd_bytes': bwd_bytes,
        'fwd_packets': len(fwd_sizes),
        'bwd_packets': len(bwd_sizes),
        'pkt_size_mean': float(np.mean(sizes)),
        'pkt_size_median': float(np.median(sizes)),
        'pkt_size_std': float(np.std(sizes)),
        'pkt_size_max': float(np.max(sizes)),
        'pkt_size_p95': float(np.percentile(sizes, 95)),
        'fwd_pkt_size_mean': float(np.mean(fwd_sizes)) if fwd_sizes else 0,
        'bwd_pkt_size_mean': float(np.mean(bwd_sizes)) if bwd_sizes else 0,
        'iat_mean': float(np.mean(all_iats)) if len(all_iats) > 0 else 0,
        'iat_median': float(np.median(all_iats)) if len(all_iats) > 0 else 0,
        'iat_std': float(np.std(all_iats)) if len(all_iats) > 0 else 0,
        'iat_p95': float(np.percentile(all_iats, 95)) if len(all_iats) > 0 else 0,
        'iat_cv': float(np.std(all_iats) / np.mean(all_iats)) if len(all_iats) > 0 and np.mean(all_iats) > 0 else 0,
        'fwd_iat_mean': float(np.mean(fwd_iats)) if len(fwd_iats) > 0 else 0,
        'bwd_iat_mean': float(np.mean(bwd_iats)) if len(bwd_iats) > 0 else 0,
        'bwd_iat_std': float(np.std(bwd_iats)) if len(bwd_iats) > 0 else 0,
        'bwd_iat_cv': float(np.std(bwd_iats) / np.mean(bwd_iats)) if len(bwd_iats) > 0 and np.mean(bwd_iats) > 0 else 0,
        'tcp_ratio': protocols['tcp'] / total_pkts,
        'udp_ratio': protocols['udp'] / total_pkts,
        'rtp_ratio': protocols['rtp'] / total_pkts,
        'tls_ratio': protocols['tls'] / total_pkts,
        'unique_dst_ips': len(all_dst_ips),
        'num_flows': len(flows),
        'mean_bitrate_bps': float(np.mean(bitrates)),
        'bitrate_cv': float(np.std(bitrates) / np.mean(bitrates)) if np.mean(bitrates) > 0 else 0,
        'max_bitrate_bps': float(np.max(bitrates)),
        'byte_asymmetry': asymmetry,
        'fwd_bwd_pkt_ratio': len(fwd_sizes) / len(bwd_sizes) if bwd_sizes else 0,
        'fwd_byte_fraction': fwd_bytes / total_bytes if total_bytes > 0 else 0.5,
        'pps': total_pkts / duration,
    }


def load_dataset():
    labels = pd.read_csv(LABELS_CSV)
    print(f"Labels file: {len(labels)} entries")

    records = []
    for _, row in labels.iterrows():
        filepath = resolve_pcap_path(row['filename'], row['category'],
                                     row['subcategory'])
        if filepath is None:
            print(f"  [SKIP] File not found: {row['filename']}")
            continue

        print(f"  Processing: {row['filename'][:60]}...")
        result = extract_trace_stats(filepath)
        if result is None:
            continue

        result['filename'] = row['filename']
        result['category'] = row['category']
        result['subcategory'] = row['subcategory']
        result['app'] = row['app']
        result['is_genai'] = row['is_genai']
        result['label'] = 'GenAI' if row['is_genai'] == 1 else 'Non-GenAI'
        records.append(result)

    df = pd.DataFrame(records)
    print(f"\nDataset: {len(df)} traces loaded "
          f"({df['is_genai'].sum()} GenAI, "
          f"{(~df['is_genai'].astype(bool)).sum()} Non-GenAI)")
    return df


# ─── Chart Generation Functions ───────────────────────────────────────────────

def generate_protocol_charts(df):
    subcat_bar(df, 'tcp_ratio', 'Mean TCP Ratio',
               'TCP Traffic Ratio by Category', '01_protocol_tcp.png')
    subcat_bar(df, 'udp_ratio', 'Mean UDP Ratio',
               'UDP Traffic Ratio by Category', '02_protocol_udp.png')
    subcat_bar(df, 'rtp_ratio', 'Mean RTP Ratio',
               'RTP Traffic Ratio by Category', '03_protocol_rtp.png')


def generate_packet_size_charts(df):
    # 04: Distribution histogram
    fig, ax = plt.subplots(figsize=(7, 5))
    _clean(ax)
    for label, color, a in [('GenAI', C_GENAI, 0.55),
                             ('Non-GenAI', C_NON_GENAI, 0.45)]:
        data = df[df['label'] == label]['pkt_size_mean']
        ax.hist(data, bins=25, alpha=a, color=color, label=label,
                edgecolor='white', linewidth=0.5)
    ax.set_xlabel('Mean Packet Size (bytes)')
    ax.set_ylabel('Count')
    ax.set_title('Mean Packet Size Distribution')
    ax.legend()
    plt.tight_layout()
    _save(fig, '04_pktsize_distribution.png')

    # 05: Directional by subcategory
    sub_df = df[df['subcategory'].isin(SUBCAT_ORDER)]
    fwd = sub_df.groupby('subcategory')['fwd_pkt_size_mean'].mean() \
                .reindex(SUBCAT_ORDER).dropna()
    bwd = sub_df.groupby('subcategory')['bwd_pkt_size_mean'].mean() \
                .reindex(SUBCAT_ORDER).dropna()

    fig, ax = plt.subplots(figsize=(9, 5))
    _clean(ax)
    x = np.arange(len(fwd))
    w = 0.35
    ax.bar(x - w / 2, fwd.values, w, label='Client \u2192 Server',
           color=C_GENAI, alpha=0.65, edgecolor='white', linewidth=0.5)
    ax.bar(x + w / 2, bwd.values, w, label='Server \u2192 Client',
           color=C_NON_GENAI, alpha=0.65, edgecolor='white', linewidth=0.5)
    ax.set_xticks(x)
    ax.set_xticklabels([s.replace('_', '\n') for s in fwd.index],
                       fontsize=8, rotation=45, ha='right')
    ax.set_ylabel('Mean Packet Size (bytes)')
    ax.set_title('Directional Packet Sizes by Category')
    ax.legend()
    _add_divider(ax, fwd.index)
    plt.tight_layout()
    _save(fig, '05_pktsize_directional.png')

    # 06: P95 boxplot
    binary_box(df, 'pkt_size_p95', 'P95 Packet Size (bytes)',
               'P95 Packet Size Comparison', '06_pktsize_p95.png')


def generate_iat_charts(df):
    subcat_bar(df, 'iat_mean', 'Mean IAT (ms)',
               'Mean Inter-Arrival Time by Category',
               '07_iat_mean.png', scale=1000)
    subcat_bar(df, 'iat_p95', 'P95 IAT (ms)',
               'P95 Inter-Arrival Time by Category',
               '08_iat_p95.png', scale=1000)
    binary_box(df, 'bwd_iat_cv', 'Backward IAT CV',
               'Server-Side IAT Regularity', '09_iat_server_regularity.png')

    # 10: IAT distribution overlay
    fig, ax = plt.subplots(figsize=(7, 5))
    _clean(ax)
    cats = [
        ('text', 'GenAI Text', C_MODALITY['text']),
        ('audio', 'GenAI Audio', C_MODALITY['audio']),
        ('browsing', 'Browsing', '#94a3b8'),
        ('on_demand_streaming', 'Streaming', '#b0b0b0'),
        ('human_human_calling', 'Human Calls', '#78716c'),
    ]
    for sub, label, color in cats:
        data = df[df['subcategory'] == sub]['iat_mean'] * 1000
        if len(data) > 2:
            ax.hist(data, bins=15, alpha=0.4, label=label, color=color,
                    edgecolor='white', linewidth=0.5)
    ax.set_xlabel('Mean IAT (ms)')
    ax.set_ylabel('Count')
    ax.set_title('IAT Distribution Comparison')
    ax.legend()
    plt.tight_layout()
    _save(fig, '10_iat_distribution.png')


def generate_connection_charts(df):
    binary_box(df, 'unique_dst_ips', 'Unique Destination IPs',
               'Connection Diversity', '11_connection_unique_ips.png')
    binary_box(df, 'num_flows', 'Number of Unique Flows',
               'Flow Count Comparison', '12_connection_flow_count.png')
    subcat_bar(df, 'unique_dst_ips', 'Mean Unique Destination IPs',
               'Connection Diversity by Category',
               '13_connection_by_category.png')


def generate_asymmetry_charts(df):
    # 14: Median byte asymmetry by subcategory
    sub_df = df[df['subcategory'].isin(SUBCAT_ORDER)]
    medians = sub_df.groupby('subcategory')['byte_asymmetry'].median() \
                    .reindex(SUBCAT_ORDER).dropna()

    fig, ax = plt.subplots(figsize=(9, 5))
    _clean(ax)
    colors = [_subcat_color(s) for s in medians.index]
    ax.bar(range(len(medians)), medians.values, color=colors,
           edgecolor='white', linewidth=0.5, width=0.7)
    ax.set_xticks(range(len(medians)))
    ax.set_xticklabels([s.replace('_', '\n') for s in medians.index],
                       fontsize=8, rotation=45, ha='right')
    ax.set_ylabel('Median Server / Client Byte Ratio')
    ax.set_title('Traffic Asymmetry by Category')
    ax.axhline(y=1.0, color=C_ACCENT, linestyle=':', alpha=0.3, linewidth=0.8)
    _add_divider(ax, medians.index)
    plt.tight_layout()
    _save(fig, '14_asymmetry_by_category.png')

    # 15: Upload fraction boxplot
    binary_box(df, 'fwd_byte_fraction', 'Client Upload Byte Fraction',
               'Upload vs Download Balance',
               '15_asymmetry_upload_fraction.png')

    # 16: Upload vs download scatter
    fig, ax = plt.subplots(figsize=(7, 5.5))
    _clean(ax)
    for label, color in [('GenAI', C_GENAI), ('Non-GenAI', C_NON_GENAI)]:
        sub = df[df['label'] == label]
        ax.scatter(sub['fwd_bytes'] / 1e6, sub['bwd_bytes'] / 1e6,
                   c=color, alpha=0.5, s=35, label=label,
                   edgecolors='white', linewidth=0.3)
    ax.set_xlabel('Upload (MB)')
    ax.set_ylabel('Download (MB)')
    ax.set_title('Upload vs Download Volume')
    ax.legend()
    lim = max(ax.get_xlim()[1], ax.get_ylim()[1])
    ax.plot([0, lim], [0, lim], color='#d1d5db', linestyle='--', linewidth=0.8)
    plt.tight_layout()
    _save(fig, '16_asymmetry_scatter.png')


def generate_bitrate_charts(df):
    subcat_bar(df, 'mean_bitrate_bps', 'Mean Bitrate (Mbps)',
               'Average Throughput by Category',
               '17_bitrate_by_category.png', scale=1 / 1e6)
    subcat_bar(df, 'bitrate_cv', 'Bitrate CV',
               'Throughput Variability by Category',
               '18_bitrate_variability.png')

    # 19: Bitrate landscape scatter
    fig, ax = plt.subplots(figsize=(7, 5.5))
    _clean(ax)
    for label, color in [('GenAI', C_GENAI), ('Non-GenAI', C_NON_GENAI)]:
        sub = df[df['label'] == label]
        ax.scatter(sub['mean_bitrate_bps'] / 1e6, sub['bitrate_cv'],
                   c=color, alpha=0.5, s=35, label=label,
                   edgecolors='white', linewidth=0.3)
    ax.set_xlabel('Mean Bitrate (Mbps)')
    ax.set_ylabel('Bitrate CV')
    ax.set_title('Throughput Landscape')
    ax.legend()
    plt.tight_layout()
    _save(fig, '19_bitrate_landscape.png')


def generate_correlation_chart(df):
    feature_cols = [
        'pkt_size_mean', 'pkt_size_std', 'pkt_size_p95',
        'iat_mean', 'iat_std', 'iat_p95', 'iat_cv',
        'bwd_iat_mean', 'bwd_iat_cv',
        'tcp_ratio', 'udp_ratio', 'rtp_ratio',
        'unique_dst_ips', 'num_flows',
        'mean_bitrate_bps', 'bitrate_cv',
        'byte_asymmetry', 'fwd_byte_fraction',
        'pps', 'fwd_bwd_pkt_ratio',
    ]
    available = [c for c in feature_cols if c in df.columns]
    corrs = df[available].corrwith(df['is_genai']).sort_values()

    fig, ax = plt.subplots(figsize=(8, 7))
    _clean(ax)
    colors = [C_ACCENT if v < 0 else C_GENAI for v in corrs.values]
    ax.barh(range(len(corrs)), corrs.values, color=colors,
            edgecolor='white', linewidth=0.3, height=0.7)
    for i, (val, _) in enumerate(zip(corrs.values, corrs.index)):
        ax.text(val + 0.01 * np.sign(val), i, f'{val:.3f}',
                va='center', fontsize=8, color='#374151')
    ax.set_yticks(range(len(corrs)))
    ax.set_yticklabels([c.replace('_', ' ').title() for c in corrs.index],
                       fontsize=9)
    ax.set_xlabel('Correlation with GenAI Label')
    ax.set_title('Feature Correlation with GenAI Classification')
    ax.axvline(x=0, color='#374151', linewidth=0.5)
    ax.set_xlim(-0.6, 0.6)
    plt.tight_layout()
    _save(fig, '20_feature_correlations.png')


def generate_app_charts(df):
    app_box(df, 'iat_p95', 'P95 IAT (s)',
            'P95 Inter-Arrival Time by App', '21_app_iat_p95.png')
    app_box(df, 'unique_dst_ips', 'Count',
            'Unique Destination IPs by App', '22_app_unique_ips.png')
    app_box(df, 'pkt_size_mean', 'Bytes',
            'Mean Packet Size by App', '23_app_pkt_size.png')
    app_box(df, 'mean_bitrate_bps', 'Mbps',
            'Mean Bitrate by App', '24_app_bitrate.png', divide=1e6)


def generate_modality_charts(df):
    modality_box(df, 'tcp_ratio', 'TCP Ratio',
                 'GenAI: TCP Ratio by Modality', '25_modality_tcp.png')
    modality_box(df, 'udp_ratio', 'UDP Ratio',
                 'GenAI: UDP Ratio by Modality', '26_modality_udp.png')
    modality_box(df, 'rtp_ratio', 'RTP Ratio',
                 'GenAI: RTP Ratio by Modality', '27_modality_rtp.png')
    modality_box(df, 'iat_mean', 'Mean IAT (s)',
                 'GenAI: Mean IAT by Modality', '28_modality_iat.png')
    modality_box(df, 'pkt_size_mean', 'Mean Packet Size (bytes)',
                 'GenAI: Packet Size by Modality', '29_modality_pktsize.png')
    modality_box(df, 'mean_bitrate_bps', 'Mean Bitrate (bps)',
                 'GenAI: Bitrate by Modality', '30_modality_bitrate.png')


def generate_key_findings(df):
    binary_box(df, 'iat_p95', 'P95 IAT (ms)',
               'Inter-Arrival Time (P95)',
               '31_key_iat_p95.png', scale=1000)
    binary_box(df, 'unique_dst_ips', 'Unique Destination IPs',
               'Connection Diversity',
               '32_key_connection_diversity.png')

    # 33: RTP signature
    order = ['text', 'audio', 'video', 'browsing', 'human_human_calling',
             'gaming', 'live_streaming', 'on_demand_streaming']
    sub_df = df[df['subcategory'].isin(order)]
    means = sub_df.groupby('subcategory')['rtp_ratio'].mean() \
                  .reindex(order).dropna()

    fig, ax = plt.subplots(figsize=(9, 5))
    _clean(ax)
    colors = [_subcat_color(s) for s in means.index]
    ax.bar(range(len(means)), means.values, color=colors,
           edgecolor='white', linewidth=0.5, width=0.7)
    ax.set_xticks(range(len(means)))
    ax.set_xticklabels([s.replace('_', '\n') for s in means.index],
                       fontsize=8, rotation=45, ha='right')
    ax.set_ylabel('RTP Ratio')
    ax.set_title('RTP Protocol Signature')
    _add_divider(ax, means.index)
    plt.tight_layout()
    _save(fig, '33_key_rtp_signature.png')

    # 34: Throughput landscape
    fig, ax = plt.subplots(figsize=(7, 5.5))
    _clean(ax)
    for label, color in [('GenAI', C_GENAI), ('Non-GenAI', C_NON_GENAI)]:
        sub = df[df['label'] == label]
        ax.scatter(sub['mean_bitrate_bps'] / 1e6, sub['bitrate_cv'],
                   c=color, alpha=0.5, s=45, label=label,
                   edgecolors='white', linewidth=0.3)
    ax.set_xlabel('Mean Bitrate (Mbps)')
    ax.set_ylabel('Bitrate CV')
    ax.set_title('Throughput Landscape')
    ax.legend()
    plt.tight_layout()
    _save(fig, '34_key_throughput_landscape.png')


# ─── Time Series (Averaged Across All Traces) ────────────────────────────────

N_BINS = 100  # Number of normalized time bins for averaging


def _extract_raw_packets(filepath, max_packets=10000):
    """Read a pcap and return (client_ip, list of (timestamp, size, is_fwd))."""
    try:
        packets = rdpcap(filepath, count=max_packets)
    except Exception:
        return None, []

    src_counts = defaultdict(int)
    for pkt in packets[:500]:
        if IP in pkt:
            src_counts[pkt[IP].src] += 1
    if not src_counts:
        return None, []
    client_ip = max(src_counts, key=src_counts.get)

    records = []
    for pkt in packets:
        if IP not in pkt:
            continue
        records.append((float(pkt.time), len(pkt), pkt[IP].src == client_ip))

    return client_ip, records


def _normalize_throughput(records, n_bins=N_BINS, window=1.0):
    """From raw packet records, compute normalized throughput arrays.

    Returns (fwd_resampled, bwd_resampled) each of length n_bins,
    or (None, None) on failure. Time is normalized to [0, 1].
    """
    if len(records) < 10:
        return None, None

    timestamps = np.array([r[0] for r in records])
    sizes = np.array([r[1] for r in records])
    is_fwd = np.array([r[2] for r in records])

    t_start, t_end = timestamps.min(), timestamps.max()
    duration = t_end - t_start
    if duration <= 0:
        return None, None

    # Compute throughput in absolute 1-second windows first
    abs_bins = np.arange(t_start, t_end + window, window)
    if len(abs_bins) < 2:
        return None, None

    fwd_mask = is_fwd
    bwd_mask = ~is_fwd

    fwd_tp, _ = np.histogram(timestamps[fwd_mask], bins=abs_bins,
                              weights=sizes[fwd_mask])
    bwd_tp, _ = np.histogram(timestamps[bwd_mask], bins=abs_bins,
                              weights=sizes[bwd_mask])
    fwd_tp = fwd_tp * 8 / (window * 1000)  # Kbps
    bwd_tp = bwd_tp * 8 / (window * 1000)

    # Normalize time axis to [0, 1] and resample to n_bins
    abs_centers = (abs_bins[:-1] - t_start) / duration  # [0, ~1]
    norm_x = np.linspace(0, 1, n_bins)

    fwd_resampled = np.interp(norm_x, abs_centers, fwd_tp)
    bwd_resampled = np.interp(norm_x, abs_centers, bwd_tp)

    return fwd_resampled, bwd_resampled


def _normalize_pktsize(records, n_bins=N_BINS):
    """From raw packet records, compute normalized mean packet size arrays.

    Returns (fwd_resampled, bwd_resampled) each of length n_bins.
    """
    if len(records) < 10:
        return None, None

    timestamps = np.array([r[0] for r in records])
    sizes = np.array([r[1] for r in records])
    is_fwd = np.array([r[2] for r in records])

    t_start, t_end = timestamps.min(), timestamps.max()
    duration = t_end - t_start
    if duration <= 0:
        return None, None

    # Normalize timestamps to [0, 1]
    t_norm = (timestamps - t_start) / duration
    bin_edges = np.linspace(0, 1, n_bins + 1)
    bin_idx = np.clip(np.digitize(t_norm, bin_edges) - 1, 0, n_bins - 1)

    fwd_result = np.full(n_bins, np.nan)
    bwd_result = np.full(n_bins, np.nan)

    for b in range(n_bins):
        mask = bin_idx == b
        fwd_in_bin = sizes[mask & is_fwd]
        bwd_in_bin = sizes[mask & ~is_fwd]
        if len(fwd_in_bin) > 0:
            fwd_result[b] = np.mean(fwd_in_bin)
        if len(bwd_in_bin) > 0:
            bwd_result[b] = np.mean(bwd_in_bin)

    # Forward-fill NaNs for smoother averaging
    fwd_result = pd.Series(fwd_result).ffill().bfill().values
    bwd_result = pd.Series(bwd_result).ffill().bfill().values

    return fwd_result, bwd_result


def _normalize_iat(records, n_bins=N_BINS):
    """From raw packet records, compute normalized mean IAT array.

    Returns iat_resampled of length n_bins.
    """
    if len(records) < 20:
        return None

    timestamps = np.sort([r[0] for r in records])
    t_start, t_end = timestamps[0], timestamps[-1]
    duration = t_end - t_start
    if duration <= 0:
        return None

    iats = np.diff(timestamps) * 1000  # ms
    iat_times = timestamps[1:]

    t_norm = (iat_times - t_start) / duration
    bin_edges = np.linspace(0, 1, n_bins + 1)
    bin_idx = np.clip(np.digitize(t_norm, bin_edges) - 1, 0, n_bins - 1)

    result = np.full(n_bins, np.nan)
    for b in range(n_bins):
        vals = iats[bin_idx == b]
        if len(vals) > 0:
            result[b] = np.median(vals)

    result = pd.Series(result).ffill().bfill().values
    return result


def _collect_rows(df, subcategory, app_filter=None):
    """Get all rows matching a subcategory (and optional app filter)."""
    sub = df[df['subcategory'] == subcategory]
    if app_filter:
        sub = sub[sub['app'].str.contains(app_filter, case=False, na=False)]
    return sub


def _plot_averaged_throughput(df, subcategory, app_filter, title, filename):
    """Average throughput across all traces in a category and save."""
    rows = _collect_rows(df, subcategory, app_filter)
    if len(rows) == 0:
        return

    all_fwd, all_bwd = [], []
    for _, row in rows.iterrows():
        filepath = resolve_pcap_path(row['filename'], row['category'],
                                     row['subcategory'])
        if not filepath:
            continue
        _, records = _extract_raw_packets(filepath)
        fwd, bwd = _normalize_throughput(records)
        if fwd is not None:
            all_fwd.append(fwd)
            all_bwd.append(bwd)
            print(f"    [{len(all_fwd)}] {row['filename'][:50]}...")

    if len(all_fwd) < 1:
        return

    x = np.linspace(0, 100, N_BINS)
    fwd_mean = np.mean(all_fwd, axis=0)
    bwd_mean = np.mean(all_bwd, axis=0)
    n_traces = len(all_fwd)

    fig, ax = plt.subplots(figsize=(10, 4))
    _clean(ax)

    ax.plot(x, fwd_mean, color=C_UPLINK, linewidth=1.2, label='Uplink')
    ax.plot(x, bwd_mean, color=C_DOWNLINK, linewidth=1.2, label='Downlink')

    if n_traces > 1:
        fwd_std = np.std(all_fwd, axis=0)
        bwd_std = np.std(all_bwd, axis=0)
        ax.fill_between(x, fwd_mean - fwd_std, fwd_mean + fwd_std,
                        alpha=0.12, color=C_UPLINK)
        ax.fill_between(x, bwd_mean - bwd_std, bwd_mean + bwd_std,
                        alpha=0.12, color=C_DOWNLINK)

    ax.set_title(f'{title}  (n={n_traces})', fontsize=11)
    ax.set_xlabel('Session Progress (%)')
    ax.set_ylabel('Throughput (Kbps)')
    ax.legend(loc='upper right')
    ax.set_xlim(0, 100)
    ax.set_ylim(bottom=0)
    plt.tight_layout()
    _save(fig, filename)


def _plot_averaged_pktsize(df, subcategory, app_filter, title, filename):
    """Average packet size over normalized time across all traces."""
    rows = _collect_rows(df, subcategory, app_filter)
    if len(rows) == 0:
        return

    all_fwd, all_bwd = [], []
    for _, row in rows.iterrows():
        filepath = resolve_pcap_path(row['filename'], row['category'],
                                     row['subcategory'])
        if not filepath:
            continue
        _, records = _extract_raw_packets(filepath)
        fwd, bwd = _normalize_pktsize(records)
        if fwd is not None:
            all_fwd.append(fwd)
            all_bwd.append(bwd)

    if len(all_fwd) < 1:
        return

    x = np.linspace(0, 100, N_BINS)
    fwd_mean = np.mean(all_fwd, axis=0)
    bwd_mean = np.mean(all_bwd, axis=0)
    n_traces = len(all_fwd)

    fig, ax = plt.subplots(figsize=(10, 4))
    _clean(ax)

    ax.plot(x, fwd_mean, color=C_UPLINK, linewidth=1.2,
            label='Client \u2192 Server')
    ax.plot(x, bwd_mean, color=C_DOWNLINK, linewidth=1.2,
            label='Server \u2192 Client')

    if n_traces > 1:
        fwd_std = np.std(all_fwd, axis=0)
        bwd_std = np.std(all_bwd, axis=0)
        ax.fill_between(x, fwd_mean - fwd_std, fwd_mean + fwd_std,
                        alpha=0.12, color=C_UPLINK)
        ax.fill_between(x, bwd_mean - bwd_std, bwd_mean + bwd_std,
                        alpha=0.12, color=C_DOWNLINK)

    ax.set_title(f'{title}  (n={n_traces})', fontsize=11)
    ax.set_xlabel('Session Progress (%)')
    ax.set_ylabel('Mean Packet Size (bytes)')
    ax.legend(loc='upper right')
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 1600)
    plt.tight_layout()
    _save(fig, filename)


def _plot_averaged_iat(df, subcategory, app_filter, title, filename):
    """Average IAT over normalized time across all traces."""
    rows = _collect_rows(df, subcategory, app_filter)
    if len(rows) == 0:
        return

    all_iat = []
    for _, row in rows.iterrows():
        filepath = resolve_pcap_path(row['filename'], row['category'],
                                     row['subcategory'])
        if not filepath:
            continue
        _, records = _extract_raw_packets(filepath)
        iat = _normalize_iat(records)
        if iat is not None:
            all_iat.append(iat)

    if len(all_iat) < 1:
        return

    x = np.linspace(0, 100, N_BINS)
    iat_mean = np.mean(all_iat, axis=0)
    n_traces = len(all_iat)

    fig, ax = plt.subplots(figsize=(10, 4))
    _clean(ax)

    ax.plot(x, iat_mean, color=C_GENAI, linewidth=1.2, label='Mean IAT')

    if n_traces > 1:
        iat_std = np.std(all_iat, axis=0)
        ax.fill_between(x, iat_mean - iat_std, iat_mean + iat_std,
                        alpha=0.15, color=C_GENAI)

    ax.set_title(f'{title}  (n={n_traces})', fontsize=11)
    ax.set_xlabel('Session Progress (%)')
    ax.set_ylabel('Median IAT (ms)')
    ax.legend(loc='upper right')
    ax.set_xlim(0, 100)
    ax.set_ylim(bottom=0)
    plt.tight_layout()
    _save(fig, filename)


def generate_throughput_timeseries(df):
    print("  Averaging throughput across traces...")
    categories = [
        ('text', None, 'GenAI Text',
         'ts_throughput_genai_text.png'),
        ('audio', None, 'GenAI Audio',
         'ts_throughput_genai_audio.png'),
        ('video', None, 'GenAI Video',
         'ts_throughput_genai_video.png'),
        ('browsing', None, 'Web Browsing',
         'ts_throughput_browsing.png'),
        ('on_demand_streaming', None, 'Video Streaming',
         'ts_throughput_streaming.png'),
        ('human_human_calling', None, 'Human Call',
         'ts_throughput_calling.png'),
        ('live_streaming', None, 'Live Streaming',
         'ts_throughput_live_streaming.png'),
        ('gaming', None, 'Gaming',
         'ts_throughput_gaming.png'),
    ]
    for subcat, app, title, filename in categories:
        _plot_averaged_throughput(df, subcat, app, title, filename)


def _generate_platform_charts(df, plot_fn, metric_name, prefix):
    """Generate per-platform averaged charts for a given metric."""
    genai_df = df[df['is_genai'] == 1]
    platforms = ['chatgpt', 'gemini', 'grok', 'perplexity']
    modalities = ['text', 'audio']

    for platform in platforms:
        for modality in modalities:
            sub = genai_df[
                (genai_df['app'].str.contains(platform, case=False,
                                              na=False)) &
                (genai_df['subcategory'] == modality)
            ]
            if len(sub) == 0:
                continue
            title = f'{platform.capitalize()} \u2014 {modality.capitalize()}'
            fname = f'{prefix}_{platform}_{modality}.png'
            plot_fn(sub, modality, None, title, fname)


def generate_platform_timeseries(df):
    print("  Averaging by platform (throughput, pktsize, IAT)...")
    _generate_platform_charts(df, _plot_averaged_throughput,
                              'throughput', 'ts_platform_throughput')
    _generate_platform_charts(df, _plot_averaged_pktsize,
                              'pktsize', 'ts_platform_pktsize')
    _generate_platform_charts(df, _plot_averaged_iat,
                              'iat', 'ts_platform_iat')


# All subcategories for pktsize and IAT averaging
_TS_CATEGORIES = [
    ('text', None, 'GenAI Text', 'genai_text'),
    ('audio', None, 'GenAI Audio', 'genai_audio'),
    ('video', None, 'GenAI Video', 'genai_video'),
    ('browsing', None, 'Web Browsing', 'browsing'),
    ('on_demand_streaming', None, 'Video Streaming', 'streaming'),
    ('human_human_calling', None, 'Human Call', 'calling'),
    ('live_streaming', None, 'Live Streaming', 'live_streaming'),
    ('gaming', None, 'Gaming', 'gaming'),
]


def generate_pktsize_timeseries(df):
    print("  Averaging packet sizes across traces...")
    for subcat, app, title, slug in _TS_CATEGORIES:
        _plot_averaged_pktsize(df, subcat, app, title,
                               f'ts_pktsize_{slug}.png')


def generate_iat_timeseries(df):
    print("  Averaging IAT across traces...")
    for subcat, app, title, slug in _TS_CATEGORIES:
        _plot_averaged_iat(df, subcat, app, title,
                           f'ts_iat_{slug}.png')


# ─── Summary Stats ────────────────────────────────────────────────────────────

def print_summary_stats(df):
    print("\n" + "=" * 70)
    print("DATASET SUMMARY")
    print("=" * 70)
    print(f"Total traces: {len(df)}")
    print(f"  GenAI:     {df['is_genai'].sum()} "
          f"({df[df['is_genai']==1]['subcategory'].value_counts().to_dict()})")
    print(f"  Non-GenAI: {(~df['is_genai'].astype(bool)).sum()} "
          f"({df[df['is_genai']==0]['subcategory'].value_counts().to_dict()})")

    print(f"\nApplications covered:")
    for cat in ['genai', 'non_genai']:
        apps = df[df['category'] == cat]['app'].unique()
        print(f"  {cat}: {', '.join(sorted(apps))}")

    print(f"\n{'Feature':<25} {'GenAI (med)':<15} {'Non-GenAI (med)':<15} "
          f"{'p-value':<12}")
    print("-" * 70)
    for feat in ['iat_p95', 'iat_mean', 'unique_dst_ips', 'num_flows',
                 'pkt_size_mean', 'tcp_ratio', 'udp_ratio', 'rtp_ratio',
                 'mean_bitrate_bps', 'bitrate_cv', 'byte_asymmetry']:
        g = df[df['is_genai'] == 1][feat]
        n = df[df['is_genai'] == 0][feat]
        try:
            _, p = stats.mannwhitneyu(g.dropna(), n.dropna(),
                                      alternative='two-sided')
        except Exception:
            p = float('nan')
        sig = '***' if p < 0.001 else '**' if p < 0.01 else '*' if p < 0.05 else ''
        print(f"  {feat:<23} {g.median():>11.4f}   {n.median():>11.4f}   "
              f"{p:>8.2e} {sig}")

    print("\n" + "=" * 70)


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 70)
    print("GenAI Traffic Fingerprinting \u2014 Data Exploration")
    print("=" * 70)

    df = load_dataset()

    if len(df) < 5:
        print("ERROR: Too few traces loaded. Check data paths.")
        sys.exit(1)

    stats_path = os.path.join(OUTPUT_DIR, 'trace_stats.csv')
    df.to_csv(stats_path, index=False)
    print(f"\nTrace stats saved to: {stats_path}")

    print_summary_stats(df)

    print("\nGenerating individual charts...")
    generate_protocol_charts(df)
    generate_packet_size_charts(df)
    generate_iat_charts(df)
    generate_connection_charts(df)
    generate_asymmetry_charts(df)
    generate_bitrate_charts(df)
    generate_correlation_chart(df)
    generate_app_charts(df)
    generate_modality_charts(df)
    generate_key_findings(df)

    print("\nGenerating time series charts...")
    generate_throughput_timeseries(df)
    generate_platform_timeseries(df)
    generate_pktsize_timeseries(df)
    generate_iat_timeseries(df)

    print(f"\nAll charts saved to: {OUTPUT_DIR}")
    print("Done!")
