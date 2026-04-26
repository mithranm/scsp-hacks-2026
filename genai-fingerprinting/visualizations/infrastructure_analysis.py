"""
Infrastructure-Level Traffic Analysis
======================================
Per-platform, per-response analysis of transmission paradigms.
Segments conversations into turns, estimates TTFT, analyzes
intra-response streaming patterns, compares audio turn-taking,
and evaluates all patterns against non-GenAI traffic baselines
(browsing, streaming, gaming, human calls).

Usage:
    python visualizations/infrastructure_analysis.py
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
OUTPUT_DIR = os.path.join(BASE_DIR, 'figures', 'infrastructure')
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ─── Style ────────────────────────────────────────────────────────────────────
plt.rcParams.update({
    'figure.facecolor': '#ffffff',
    'axes.facecolor': '#ffffff',
    'axes.edgecolor': '#d1d5db',
    'axes.labelcolor': '#374151',
    'axes.titlesize': 12,
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

# Colors — distinct per traffic type
C_PLATFORM = {
    'chatgpt': '#0f172a',
    'gemini': '#475569',
    'grok': '#78716c',
    'perplexity': '#64748b',
    'human_call': '#b91c1c',
    'browsing': '#2563eb',
    'streaming': '#059669',
    'gaming': '#d97706',
    'social': '#7c3aed',
}


def _save(fig, name):
    fig.savefig(os.path.join(OUTPUT_DIR, name))
    plt.close(fig)
    print(f"  Saved: {name}")


def _clean(ax):
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#d1d5db')
    ax.spines['bottom'].set_color('#d1d5db')


def _bp_style():
    return dict(
        patch_artist=True, widths=0.5,
        boxprops=dict(linewidth=0.8),
        whiskerprops=dict(linewidth=0.8, color='#9ca3af'),
        capprops=dict(linewidth=0.8, color='#9ca3af'),
        medianprops=dict(linewidth=1.5, color='#0f172a'),
        flierprops=dict(marker='o', markersize=3,
                        markerfacecolor='#9ca3af', markeredgecolor='none'),
    )


# ─── Pcap Loading ─────────────────────────────────────────────────────────────

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


def extract_packets(filepath, max_packets=15000):
    """Extract packet records: list of (timestamp, size, is_fwd, proto)."""
    try:
        packets = rdpcap(filepath, count=max_packets)
    except Exception as e:
        print(f"    [WARN] {e}")
        return []

    src_counts = defaultdict(int)
    for pkt in packets[:500]:
        if IP in pkt:
            src_counts[pkt[IP].src] += 1
    if not src_counts:
        return []
    client_ip = max(src_counts, key=src_counts.get)

    records = []
    for pkt in packets:
        if IP not in pkt:
            continue
        is_fwd = pkt[IP].src == client_ip
        proto = 'tcp' if TCP in pkt else ('udp' if UDP in pkt else 'other')
        records.append((float(pkt.time), len(pkt), is_fwd, proto))

    return records


# ─── Turn Segmentation ────────────────────────────────────────────────────────

def segment_turns(records, gap_threshold=2.0):
    """Split a trace into conversation turns based on silence gaps.

    Works for any request-response traffic: GenAI text prompts,
    browsing page loads, etc.

    Returns list of dicts with per-turn metrics.
    """
    if len(records) < 20:
        return []

    timestamps = np.array([r[0] for r in records])
    gaps = np.diff(timestamps)

    # Split at silence gaps
    splits = [0]
    for i, g in enumerate(gaps):
        if g > gap_threshold:
            splits.append(i + 1)
    splits.append(len(records))

    turns = []
    for seg_start, seg_end in zip(splits[:-1], splits[1:]):
        seg = records[seg_start:seg_end]
        if len(seg) < 5:
            continue

        fwd_pkts = [(ts, sz) for ts, sz, is_fwd, _ in seg if is_fwd]
        bwd_pkts = [(ts, sz) for ts, sz, is_fwd, _ in seg if not is_fwd]

        if not fwd_pkts or not bwd_pkts:
            continue

        # TTFT: time from last uplink packet in the initial burst
        # to first downlink packet
        last_fwd_ts = None
        first_bwd_ts = None
        saw_fwd = False

        for ts, sz, is_fwd, _ in seg:
            if is_fwd:
                saw_fwd = True
                last_fwd_ts = ts
            elif saw_fwd and last_fwd_ts is not None:
                first_bwd_ts = ts
                break

        ttft = (first_bwd_ts - last_fwd_ts) if (last_fwd_ts and first_bwd_ts) else None

        # Response phase: all downlink packets after the transition
        response_pkts = []
        started = False
        for ts, sz, is_fwd, _ in seg:
            if not is_fwd and saw_fwd:
                started = True
            if started and not is_fwd:
                response_pkts.append((ts, sz))

        # Intra-response inter-packet times
        if len(response_pkts) > 1:
            resp_ts = np.array([r[0] for r in response_pkts])
            resp_sz = np.array([r[1] for r in response_pkts])
            resp_ipt = np.diff(resp_ts) * 1000  # ms

            turn = {
                'ttft_ms': ttft * 1000 if ttft and ttft > 0 else None,
                'response_duration_ms': (resp_ts[-1] - resp_ts[0]) * 1000,
                'response_pkt_count': len(response_pkts),
                'response_bytes': int(np.sum(resp_sz)),
                'response_pkt_size_mean': float(np.mean(resp_sz)),
                'response_pkt_size_std': float(np.std(resp_sz)),
                'response_ipt_mean_ms': float(np.mean(resp_ipt)),
                'response_ipt_median_ms': float(np.median(resp_ipt)),
                'response_ipt_std_ms': float(np.std(resp_ipt)),
                'response_ipt_cv': float(np.std(resp_ipt) / np.mean(resp_ipt))
                    if np.mean(resp_ipt) > 0 else 0,
                'response_ipt_p95_ms': float(np.percentile(resp_ipt, 95)),
                'delivery_rate_pps': len(response_pkts) / (resp_ts[-1] - resp_ts[0])
                    if resp_ts[-1] > resp_ts[0] else 0,
                'prompt_pkt_count': len(fwd_pkts),
                'prompt_bytes': sum(s for _, s in fwd_pkts),
                'total_duration_ms': (seg[-1][0] - seg[0][0]) * 1000,
                '_resp_ipts': resp_ipt,
                '_resp_sizes': resp_sz,
                '_resp_ts': resp_ts,
            }
            turns.append(turn)

    return turns


def extract_continuous_delivery(records, window_sec=1.0):
    """Analyze downlink delivery patterns for continuous traffic (streaming, gaming).

    Instead of segmenting turns, this analyzes the overall downlink packet
    delivery cadence across the whole trace. Returns per-window and aggregate stats.
    """
    if len(records) < 50:
        return None

    # Downlink packets only
    bwd = [(ts, sz) for ts, sz, is_fwd, _ in records if not is_fwd]
    if len(bwd) < 20:
        return None

    bwd_ts = np.array([r[0] for r in bwd])
    bwd_sz = np.array([r[1] for r in bwd])
    bwd_ipt = np.diff(bwd_ts) * 1000  # ms

    if len(bwd_ipt) < 10:
        return None

    # Per-window delivery stats (sliding windows for temporal analysis)
    t_start = bwd_ts[0]
    t_end = bwd_ts[-1]
    windows = np.arange(t_start, t_end, window_sec)
    window_rates = []
    window_bytes = []
    for w_start in windows:
        w_end = w_start + window_sec
        mask = (bwd_ts >= w_start) & (bwd_ts < w_end)
        n_pkts = np.sum(mask)
        total_bytes = np.sum(bwd_sz[mask]) if n_pkts > 0 else 0
        window_rates.append(n_pkts)
        window_bytes.append(total_bytes)

    window_rates = np.array(window_rates)
    window_bytes = np.array(window_bytes)

    # Compute delivery regularity: how consistent is the packet rate?
    active_windows = window_rates[window_rates > 0]
    rate_cv = (np.std(active_windows) / np.mean(active_windows)
               if len(active_windows) > 2 and np.mean(active_windows) > 0
               else 0)

    # Burst detection: windows with >2x mean rate
    mean_rate = np.mean(active_windows) if len(active_windows) > 0 else 0
    burst_pct = (np.sum(active_windows > 2 * mean_rate) / len(active_windows) * 100
                 if len(active_windows) > 0 else 0)

    # Idle detection: fraction of windows with zero packets
    idle_pct = np.sum(window_rates == 0) / len(window_rates) * 100

    return {
        'n_downlink_pkts': len(bwd),
        'pkt_size_mean': float(np.mean(bwd_sz)),
        'pkt_size_std': float(np.std(bwd_sz)),
        'pkt_size_median': float(np.median(bwd_sz)),
        'ipt_mean_ms': float(np.mean(bwd_ipt)),
        'ipt_median_ms': float(np.median(bwd_ipt)),
        'ipt_std_ms': float(np.std(bwd_ipt)),
        'ipt_cv': float(np.std(bwd_ipt) / np.mean(bwd_ipt))
            if np.mean(bwd_ipt) > 0 else 0,
        'ipt_p95_ms': float(np.percentile(bwd_ipt, 95)),
        'delivery_rate_cv': float(rate_cv),
        'burst_pct': float(burst_pct),
        'idle_pct': float(idle_pct),
        'mean_window_rate': float(mean_rate),
        '_bwd_ipts': bwd_ipt,
        '_bwd_sizes': bwd_sz,
        '_bwd_ts': bwd_ts,
        '_window_rates': window_rates,
    }


def segment_audio_turns(records, gap_threshold=0.3):
    """Detect turn-taking in audio traces."""
    if len(records) < 50:
        return None

    fwd = [(ts, sz) for ts, sz, is_fwd, _ in records if is_fwd]
    bwd = [(ts, sz) for ts, sz, is_fwd, _ in records if not is_fwd]

    if not fwd or not bwd:
        return None

    fwd_ts = np.array([r[0] for r in fwd])
    fwd_gaps = np.diff(fwd_ts)
    bwd_ts = np.array([r[0] for r in bwd])

    thinking_gaps = []
    for i, gap in enumerate(fwd_gaps):
        if gap > gap_threshold:
            gap_start = fwd_ts[i]
            gap_end = fwd_ts[i + 1]
            bwd_during = bwd_ts[(bwd_ts > gap_start) & (bwd_ts < gap_end)]

            if len(bwd_during) == 0:
                thinking_gaps.append(gap * 1000)
            elif len(bwd_during) > 0:
                first_bwd = bwd_during[0]
                latency = (first_bwd - gap_start) * 1000
                if latency > 50:
                    thinking_gaps.append(latency)

    total_duration = records[-1][0] - records[0][0]
    if total_duration <= 0:
        return None

    t_start = records[0][0]
    t_end = records[-1][0]
    bin_width = 0.1
    bins = np.arange(t_start, t_end, bin_width)
    if len(bins) < 2:
        return None

    fwd_activity, _ = np.histogram(fwd_ts, bins=bins)
    bwd_activity, _ = np.histogram(bwd_ts, bins=bins)

    fwd_dominant = np.sum(fwd_activity > bwd_activity)
    bwd_dominant = np.sum(bwd_activity > fwd_activity)
    both_active = np.sum((fwd_activity > 0) & (bwd_activity > 0))
    total_windows = len(fwd_activity)

    return {
        'thinking_gaps_ms': thinking_gaps,
        'mean_thinking_gap_ms': np.mean(thinking_gaps) if thinking_gaps else 0,
        'median_thinking_gap_ms': np.median(thinking_gaps) if thinking_gaps else 0,
        'fwd_dominant_pct': fwd_dominant / total_windows * 100,
        'bwd_dominant_pct': bwd_dominant / total_windows * 100,
        'both_active_pct': both_active / total_windows * 100,
        'turn_asymmetry': bwd_dominant / fwd_dominant if fwd_dominant > 0 else 0,
        'n_turn_transitions': len(thinking_gaps),
    }


# ─── Streaming Paradigm Classification ────────────────────────────────────────

def classify_paradigm(resp_ipts, resp_sizes):
    """Classify response delivery as token-streaming, chunked, or batch.

    Token-streaming (SSE): Many small packets at relatively regular intervals.
    Chunked: Bursts of packets separated by gaps.
    Batch: Few large packets delivered quickly.
    """
    if len(resp_ipts) < 3:
        return 'insufficient'

    n_pkts = len(resp_ipts) + 1
    mean_size = np.mean(resp_sizes)
    ipt_cv = np.std(resp_ipts) / np.mean(resp_ipts) if np.mean(resp_ipts) > 0 else 0

    if n_pkts < 10 and mean_size > 800:
        return 'batch'

    if len(resp_ipts) > 10:
        median_ipt = np.median(resp_ipts)
        above_2x_median = np.sum(resp_ipts > 2 * median_ipt) / len(resp_ipts)
        if above_2x_median > 0.15 and ipt_cv > 1.2:
            return 'chunked'

    if ipt_cv < 1.0 and mean_size < 700:
        return 'token_streaming'

    if ipt_cv > 1.5:
        return 'chunked'

    return 'mixed'


# ─── Main Analysis Pipeline ──────────────────────────────────────────────────

def run_analysis():
    labels = pd.read_csv(LABELS_CSV)
    print(f"Labels: {len(labels)} entries\n")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 1: GenAI Text — Turn Segmentation
    # ══════════════════════════════════════════════════════════════════════
    print("Phase 1: Turn segmentation (GenAI text traces)...")
    text_turns = []

    text_labels = labels[
        (labels['is_genai'] == 1) & (labels['subcategory'] == 'text')
    ]
    for _, row in text_labels.iterrows():
        filepath = resolve_pcap_path(row['filename'], row['category'],
                                     row['subcategory'])
        if not filepath:
            continue
        print(f"  {row['app']}: {row['filename'][:50]}...")
        records = extract_packets(filepath)
        turns = segment_turns(records, gap_threshold=2.0)
        platform = row['app'].split('_')[0].lower()
        for t in turns:
            t['platform'] = platform
            t['filename'] = row['filename']
            t['traffic_type'] = 'genai_text'
            text_turns.append(t)

    print(f"  Extracted {len(text_turns)} turns from "
          f"{len(text_labels)} text traces\n")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 2: Browsing — Turn Segmentation (same structure)
    # ══════════════════════════════════════════════════════════════════════
    print("Phase 2: Turn segmentation (browsing traces)...")
    browsing_turns = []

    browsing_labels = labels[labels['subcategory'] == 'browsing']
    for _, row in browsing_labels.iterrows():
        filepath = resolve_pcap_path(row['filename'], row['category'],
                                     row['subcategory'])
        if not filepath:
            continue
        print(f"  {row['app']}: {row['filename'][:50]}...")
        records = extract_packets(filepath)
        # Browsing has shorter inter-page gaps than GenAI conversation pauses,
        # but still has clear request→response structure
        turns = segment_turns(records, gap_threshold=1.0)
        for t in turns:
            t['platform'] = 'browsing'
            t['filename'] = row['filename']
            t['traffic_type'] = 'browsing'
            browsing_turns.append(t)

    print(f"  Extracted {len(browsing_turns)} turns from "
          f"{len(browsing_labels)} browsing traces\n")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 3: Streaming — Continuous Delivery Analysis
    # ══════════════════════════════════════════════════════════════════════
    print("Phase 3: Continuous delivery analysis (streaming)...")
    streaming_delivery = []

    streaming_labels = labels[
        labels['subcategory'].isin(['live_streaming', 'on_demand_streaming'])
    ]
    for _, row in streaming_labels.iterrows():
        filepath = resolve_pcap_path(row['filename'], row['category'],
                                     row['subcategory'])
        if not filepath:
            continue
        print(f"  {row['app']}: {row['filename'][:50]}...")
        records = extract_packets(filepath)
        result = extract_continuous_delivery(records)
        if result:
            result['platform'] = 'streaming'
            result['app'] = row['app']
            result['subcategory'] = row['subcategory']
            result['traffic_type'] = 'streaming'
            streaming_delivery.append(result)

    print(f"  Analyzed {len(streaming_delivery)} streaming traces\n")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 4: Gaming — Continuous Delivery Analysis
    # ══════════════════════════════════════════════════════════════════════
    print("Phase 4: Continuous delivery analysis (gaming)...")
    gaming_delivery = []

    gaming_labels = labels[labels['subcategory'] == 'gaming']
    for _, row in gaming_labels.iterrows():
        filepath = resolve_pcap_path(row['filename'], row['category'],
                                     row['subcategory'])
        if not filepath:
            continue
        print(f"  {row['app']}: {row['filename'][:50]}...")
        records = extract_packets(filepath)
        result = extract_continuous_delivery(records)
        if result:
            result['platform'] = 'gaming'
            result['app'] = row['app']
            result['traffic_type'] = 'gaming'
            gaming_delivery.append(result)

    print(f"  Analyzed {len(gaming_delivery)} gaming traces\n")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 5: GenAI Text — Continuous Delivery (for cross-type comparison)
    # ══════════════════════════════════════════════════════════════════════
    print("Phase 5: Continuous delivery analysis (GenAI text — for comparison)...")
    genai_text_delivery = []

    for _, row in text_labels.iterrows():
        filepath = resolve_pcap_path(row['filename'], row['category'],
                                     row['subcategory'])
        if not filepath:
            continue
        records = extract_packets(filepath)
        result = extract_continuous_delivery(records)
        if result:
            platform = row['app'].split('_')[0].lower()
            result['platform'] = platform
            result['app'] = row['app']
            result['traffic_type'] = 'genai_text'
            genai_text_delivery.append(result)

    print(f"  Analyzed {len(genai_text_delivery)} GenAI text traces\n")

    # Also extract continuous delivery for browsing
    print("  Continuous delivery analysis (browsing — for comparison)...")
    browsing_delivery = []
    for _, row in browsing_labels.iterrows():
        filepath = resolve_pcap_path(row['filename'], row['category'],
                                     row['subcategory'])
        if not filepath:
            continue
        records = extract_packets(filepath)
        result = extract_continuous_delivery(records)
        if result:
            result['platform'] = 'browsing'
            result['app'] = row['app']
            result['traffic_type'] = 'browsing'
            browsing_delivery.append(result)

    print(f"  Analyzed {len(browsing_delivery)} browsing traces\n")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 6: Audio Turn-Taking Analysis
    # ══════════════════════════════════════════════════════════════════════
    print("Phase 6: Audio turn-taking analysis...")
    audio_results = []

    audio_genai = labels[
        (labels['is_genai'] == 1) & (labels['subcategory'] == 'audio')
    ]
    for _, row in audio_genai.iterrows():
        filepath = resolve_pcap_path(row['filename'], row['category'],
                                     row['subcategory'])
        if not filepath:
            continue
        print(f"  GenAI audio: {row['app']} — {row['filename'][:40]}...")
        records = extract_packets(filepath)
        result = segment_audio_turns(records, gap_threshold=0.3)
        if result:
            platform = row['app'].split('_')[0].lower()
            result['platform'] = platform
            result['type'] = 'genai_audio'
            result['app'] = row['app']
            audio_results.append(result)

    human_calls = labels[labels['subcategory'] == 'human_human_calling']
    for _, row in human_calls.iterrows():
        filepath = resolve_pcap_path(row['filename'], row['category'],
                                     row['subcategory'])
        if not filepath:
            continue
        print(f"  Human call: {row['app']} — {row['filename'][:40]}...")
        records = extract_packets(filepath)
        result = segment_audio_turns(records, gap_threshold=0.3)
        if result:
            result['platform'] = row['app']
            result['type'] = 'human_call'
            result['app'] = row['app']
            audio_results.append(result)

    print(f"  Analyzed {len(audio_results)} audio traces\n")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 7: Paradigm Classification (all traffic types)
    # ══════════════════════════════════════════════════════════════════════
    print("Phase 7: Streaming paradigm classification...")

    # GenAI text — per platform
    paradigm_counts = defaultdict(lambda: defaultdict(int))
    for t in text_turns:
        if '_resp_ipts' in t and '_resp_sizes' in t:
            p = classify_paradigm(t['_resp_ipts'], t['_resp_sizes'])
            paradigm_counts[t['platform']][p] += 1

    # Browsing — treat as one group
    for t in browsing_turns:
        if '_resp_ipts' in t and '_resp_sizes' in t:
            p = classify_paradigm(t['_resp_ipts'], t['_resp_sizes'])
            paradigm_counts['browsing'][p] += 1

    # Streaming — classify downlink delivery pattern
    for d in streaming_delivery:
        if '_bwd_ipts' in d and '_bwd_sizes' in d:
            p = classify_paradigm(d['_bwd_ipts'], d['_bwd_sizes'])
            paradigm_counts['streaming'][p] += 1

    # Gaming
    for d in gaming_delivery:
        if '_bwd_ipts' in d and '_bwd_sizes' in d:
            p = classify_paradigm(d['_bwd_ipts'], d['_bwd_sizes'])
            paradigm_counts['gaming'][p] += 1

    for category, counts in paradigm_counts.items():
        total = sum(counts.values())
        print(f"  {category}: " + ", ".join(
            f"{k}={v} ({v/total*100:.0f}%)" for k, v in counts.items()))

    # ── Save turn-level CSV ──
    all_turns = text_turns + browsing_turns
    turn_df = pd.DataFrame([
        {k: v for k, v in t.items() if not k.startswith('_')}
        for t in all_turns
    ])
    turn_csv = os.path.join(OUTPUT_DIR, 'turn_analysis.csv')
    turn_df.to_csv(turn_csv, index=False)
    print(f"\nSaved turn data: {turn_csv} ({len(turn_df)} turns)")

    # ══════════════════════════════════════════════════════════════════════
    # FIGURES — Section A: Per-Platform GenAI Analysis (Figs 01-07)
    # ══════════════════════════════════════════════════════════════════════

    print("\nGenerating figures...")

    platforms = sorted(set(t['platform'] for t in text_turns))
    platform_colors = [C_PLATFORM.get(p, '#6b7280') for p in platforms]

    # ── Fig 01: TTFT by platform ──
    fig, ax = plt.subplots(figsize=(7, 5))
    _clean(ax)
    data, labels_list, colors = [], [], []
    for p in platforms:
        vals = [t['ttft_ms'] for t in text_turns
                if t['platform'] == p and t['ttft_ms'] is not None
                and 10 < t['ttft_ms'] < 30000]
        if vals:
            data.append(vals)
            labels_list.append(p.capitalize())
            colors.append(C_PLATFORM.get(p, '#6b7280'))

    if data:
        bp = ax.boxplot(data, labels=labels_list, **_bp_style())
        for patch, c in zip(bp['boxes'], colors):
            patch.set_facecolor(c)
            patch.set_alpha(0.25)
            patch.set_edgecolor(c)
        ax.set_ylabel('Time to First Token (ms)')
        ax.set_title('TTFT by Platform')
        plt.tight_layout()
        _save(fig, '01_ttft_by_platform.png')
    else:
        plt.close(fig)

    # ── Fig 02: Intra-response inter-packet time by platform ──
    fig, ax = plt.subplots(figsize=(7, 5))
    _clean(ax)
    data, labels_list, colors = [], [], []
    for p in platforms:
        vals = [t['response_ipt_median_ms'] for t in text_turns
                if t['platform'] == p and t.get('response_ipt_median_ms') is not None]
        if vals:
            data.append(vals)
            labels_list.append(p.capitalize())
            colors.append(C_PLATFORM.get(p, '#6b7280'))

    if data:
        bp = ax.boxplot(data, labels=labels_list, **_bp_style())
        for patch, c in zip(bp['boxes'], colors):
            patch.set_facecolor(c)
            patch.set_alpha(0.25)
            patch.set_edgecolor(c)
        ax.set_ylabel('Median Inter-Packet Time (ms)')
        ax.set_title('Intra-Response Delivery Cadence by Platform')
        plt.tight_layout()
        _save(fig, '02_response_cadence_by_platform.png')
    else:
        plt.close(fig)

    # ── Fig 03: Response packet size by platform ──
    fig, ax = plt.subplots(figsize=(7, 5))
    _clean(ax)
    data, labels_list, colors = [], [], []
    for p in platforms:
        vals = [t['response_pkt_size_mean'] for t in text_turns
                if t['platform'] == p]
        if vals:
            data.append(vals)
            labels_list.append(p.capitalize())
            colors.append(C_PLATFORM.get(p, '#6b7280'))

    if data:
        bp = ax.boxplot(data, labels=labels_list, **_bp_style())
        for patch, c in zip(bp['boxes'], colors):
            patch.set_facecolor(c)
            patch.set_alpha(0.25)
            patch.set_edgecolor(c)
        ax.set_ylabel('Mean Response Packet Size (bytes)')
        ax.set_title('Response Packet Size by Platform')
        plt.tight_layout()
        _save(fig, '03_response_pktsize_by_platform.png')
    else:
        plt.close(fig)

    # ── Fig 04: IPT CV by platform (streaming regularity) ──
    fig, ax = plt.subplots(figsize=(7, 5))
    _clean(ax)
    data, labels_list, colors = [], [], []
    for p in platforms:
        vals = [t['response_ipt_cv'] for t in text_turns
                if t['platform'] == p and t['response_ipt_cv'] < 10]
        if vals:
            data.append(vals)
            labels_list.append(p.capitalize())
            colors.append(C_PLATFORM.get(p, '#6b7280'))

    if data:
        bp = ax.boxplot(data, labels=labels_list, **_bp_style())
        for patch, c in zip(bp['boxes'], colors):
            patch.set_facecolor(c)
            patch.set_alpha(0.25)
            patch.set_edgecolor(c)
        ax.set_ylabel('Inter-Packet Time CV')
        ax.set_title('Delivery Regularity by Platform\n'
                      '(Low = steady streaming, High = chunked)')
        plt.tight_layout()
        _save(fig, '04_delivery_regularity_by_platform.png')
    else:
        plt.close(fig)

    # ── Fig 05: Streaming paradigm stacked bar (all traffic types) ──
    if paradigm_counts:
        # Include all traffic types, not just GenAI platforms
        all_types = platforms + ['browsing', 'streaming', 'gaming']
        # Only keep types with data
        all_types = [t for t in all_types if t in paradigm_counts]

        fig, ax = plt.subplots(figsize=(9, 5))
        _clean(ax)

        paradigms_all = ['token_streaming', 'chunked', 'batch', 'mixed',
                         'insufficient']
        p_colors = {'token_streaming': '#0f172a', 'chunked': '#475569',
                    'batch': '#94a3b8', 'mixed': '#d1d5db',
                    'insufficient': '#e5e7eb'}

        x = np.arange(len(all_types))
        bottoms = np.zeros(len(all_types))

        for paradigm in paradigms_all:
            vals = []
            for t in all_types:
                total = sum(paradigm_counts[t].values())
                count = paradigm_counts[t].get(paradigm, 0)
                vals.append(count / total * 100 if total > 0 else 0)
            vals = np.array(vals)
            if np.any(vals > 0):
                ax.bar(x, vals, bottom=bottoms, width=0.6,
                       color=p_colors.get(paradigm, '#999'),
                       edgecolor='white', linewidth=0.5,
                       label=paradigm.replace('_', ' ').title())
                bottoms += vals

        ax.set_xticks(x)
        ax.set_xticklabels([t.capitalize() for t in all_types], rotation=30,
                           ha='right')
        ax.set_ylabel('Percentage of Responses')
        ax.set_title('Delivery Paradigm: GenAI Platforms vs Non-GenAI Traffic')
        ax.legend(loc='upper right', fontsize=8)
        ax.set_ylim(0, 105)
        plt.tight_layout()
        _save(fig, '05_paradigm_all_traffic_types.png')

    # ── Fig 06: Cumulative response bytes (one example per platform) ──
    fig, ax = plt.subplots(figsize=(9, 5))
    _clean(ax)
    plotted = set()
    for t in text_turns:
        p = t['platform']
        if p in plotted:
            continue
        if '_resp_ts' in t and '_resp_sizes' in t and len(t['_resp_ts']) > 10:
            ts = t['_resp_ts'] - t['_resp_ts'][0]
            cum_bytes = np.cumsum(t['_resp_sizes'])
            ax.plot(ts * 1000, cum_bytes / 1000,
                    color=C_PLATFORM.get(p, '#6b7280'),
                    linewidth=1.2, label=p.capitalize(), alpha=0.8)
            plotted.add(p)

    if plotted:
        ax.set_xlabel('Time Within Response (ms)')
        ax.set_ylabel('Cumulative Response Data (KB)')
        ax.set_title('Response Delivery Shape\n'
                      '(Linear = constant-rate streaming, '
                      'Stepped = chunked delivery)')
        ax.legend()
        plt.tight_layout()
        _save(fig, '06_cumulative_response_bytes.png')
    else:
        plt.close(fig)

    # ── Fig 07: Delivery rate (pps) by platform ──
    fig, ax = plt.subplots(figsize=(7, 5))
    _clean(ax)
    data, labels_list, colors = [], [], []
    for p in platforms:
        vals = [t['delivery_rate_pps'] for t in text_turns
                if t['platform'] == p and t['delivery_rate_pps'] > 0]
        if vals:
            data.append(vals)
            labels_list.append(p.capitalize())
            colors.append(C_PLATFORM.get(p, '#6b7280'))

    if data:
        bp = ax.boxplot(data, labels=labels_list, **_bp_style())
        for patch, c in zip(bp['boxes'], colors):
            patch.set_facecolor(c)
            patch.set_alpha(0.25)
            patch.set_edgecolor(c)
        ax.set_ylabel('Packets Per Second')
        ax.set_title('Response Delivery Rate by Platform')
        plt.tight_layout()
        _save(fig, '07_delivery_rate_by_platform.png')
    else:
        plt.close(fig)

    # ══════════════════════════════════════════════════════════════════════
    # FIGURES — Section B: GenAI vs Non-GenAI Comparison (Figs 13-22)
    # ══════════════════════════════════════════════════════════════════════

    print("\n  --- Cross-traffic comparison figures ---")

    # ── Fig 13: Request-Response Latency: GenAI Text vs Browsing ──
    # Both have request→response structure. Compare the "TTFT" equivalent.
    fig, ax = plt.subplots(figsize=(7, 5))
    _clean(ax)
    data, labels_list, colors = [], [], []

    # GenAI text — aggregate across platforms
    genai_ttft = [t['ttft_ms'] for t in text_turns
                  if t['ttft_ms'] is not None and 10 < t['ttft_ms'] < 30000]
    browsing_ttft = [t['ttft_ms'] for t in browsing_turns
                     if t['ttft_ms'] is not None and 10 < t['ttft_ms'] < 30000]

    if genai_ttft:
        data.append(genai_ttft)
        labels_list.append('GenAI Text')
        colors.append('#0f172a')
    if browsing_ttft:
        data.append(browsing_ttft)
        labels_list.append('Browsing')
        colors.append(C_PLATFORM['browsing'])

    if len(data) >= 2:
        bp = ax.boxplot(data, labels=labels_list, **_bp_style())
        for patch, c in zip(bp['boxes'], colors):
            patch.set_facecolor(c)
            patch.set_alpha(0.25)
            patch.set_edgecolor(c)

        _, p_val = stats.mannwhitneyu(genai_ttft, browsing_ttft,
                                      alternative='two-sided')
        color = '#dc2626' if p_val < 0.05 else '#9ca3af'
        ax.annotate(f'p = {p_val:.2e}', xy=(0.5, 0.97),
                    xycoords='axes fraction', ha='center',
                    fontsize=9, color=color, style='italic')

        ax.set_ylabel('First Response Latency (ms)')
        ax.set_title('Request→Response Latency\n'
                      'GenAI Text (inference delay) vs Browsing (server response)')
        plt.tight_layout()
        _save(fig, '13_ttft_genai_vs_browsing.png')
    else:
        plt.close(fig)

    # ── Fig 14: Per-platform TTFT vs Browsing ──
    fig, ax = plt.subplots(figsize=(9, 5))
    _clean(ax)
    data, labels_list, colors = [], [], []

    for p in platforms:
        vals = [t['ttft_ms'] for t in text_turns
                if t['platform'] == p and t['ttft_ms'] is not None
                and 10 < t['ttft_ms'] < 30000]
        if vals:
            data.append(vals)
            labels_list.append(p.capitalize())
            colors.append(C_PLATFORM.get(p, '#6b7280'))

    if browsing_ttft:
        data.append(browsing_ttft)
        labels_list.append('Browsing')
        colors.append(C_PLATFORM['browsing'])

    if len(data) >= 2:
        bp = ax.boxplot(data, labels=labels_list, **_bp_style())
        for patch, c in zip(bp['boxes'], colors):
            patch.set_facecolor(c)
            patch.set_alpha(0.25)
            patch.set_edgecolor(c)
        ax.set_ylabel('First Response Latency (ms)')
        ax.set_title('Per-Platform TTFT vs Browsing Page-Load Latency')
        plt.tight_layout()
        _save(fig, '14_ttft_per_platform_vs_browsing.png')
    else:
        plt.close(fig)

    # ── Fig 15: Intra-Response Delivery Cadence — All Traffic Types ──
    # For turn-based: use per-turn median IPT
    # For continuous: use trace-level median IPT
    fig, ax = plt.subplots(figsize=(10, 5))
    _clean(ax)
    data, labels_list, colors = [], [], []

    for p in platforms:
        vals = [t['response_ipt_median_ms'] for t in text_turns
                if t['platform'] == p and t.get('response_ipt_median_ms') is not None]
        if vals:
            data.append(vals)
            labels_list.append(p.capitalize())
            colors.append(C_PLATFORM.get(p, '#6b7280'))

    browsing_cadence = [t['response_ipt_median_ms'] for t in browsing_turns
                        if t.get('response_ipt_median_ms') is not None]
    if browsing_cadence:
        data.append(browsing_cadence)
        labels_list.append('Browsing')
        colors.append(C_PLATFORM['browsing'])

    streaming_cadence = [d['ipt_median_ms'] for d in streaming_delivery]
    if streaming_cadence:
        data.append(streaming_cadence)
        labels_list.append('Streaming')
        colors.append(C_PLATFORM['streaming'])

    gaming_cadence = [d['ipt_median_ms'] for d in gaming_delivery]
    if gaming_cadence:
        data.append(gaming_cadence)
        labels_list.append('Gaming')
        colors.append(C_PLATFORM['gaming'])

    if len(data) >= 2:
        bp = ax.boxplot(data, labels=labels_list, **_bp_style())
        for patch, c in zip(bp['boxes'], colors):
            patch.set_facecolor(c)
            patch.set_alpha(0.25)
            patch.set_edgecolor(c)
        ax.set_ylabel('Median Downlink Inter-Packet Time (ms)')
        ax.set_title('Delivery Cadence: GenAI Platforms vs Non-GenAI Traffic')
        plt.xticks(rotation=30, ha='right')
        plt.tight_layout()
        _save(fig, '15_cadence_all_traffic_types.png')
    else:
        plt.close(fig)

    # ── Fig 16: Response Packet Size — All Traffic Types ──
    fig, ax = plt.subplots(figsize=(10, 5))
    _clean(ax)
    data, labels_list, colors = [], [], []

    for p in platforms:
        vals = [t['response_pkt_size_mean'] for t in text_turns
                if t['platform'] == p]
        if vals:
            data.append(vals)
            labels_list.append(p.capitalize())
            colors.append(C_PLATFORM.get(p, '#6b7280'))

    browsing_sizes = [t['response_pkt_size_mean'] for t in browsing_turns]
    if browsing_sizes:
        data.append(browsing_sizes)
        labels_list.append('Browsing')
        colors.append(C_PLATFORM['browsing'])

    streaming_sizes = [d['pkt_size_mean'] for d in streaming_delivery]
    if streaming_sizes:
        data.append(streaming_sizes)
        labels_list.append('Streaming')
        colors.append(C_PLATFORM['streaming'])

    gaming_sizes = [d['pkt_size_mean'] for d in gaming_delivery]
    if gaming_sizes:
        data.append(gaming_sizes)
        labels_list.append('Gaming')
        colors.append(C_PLATFORM['gaming'])

    if len(data) >= 2:
        bp = ax.boxplot(data, labels=labels_list, **_bp_style())
        for patch, c in zip(bp['boxes'], colors):
            patch.set_facecolor(c)
            patch.set_alpha(0.25)
            patch.set_edgecolor(c)
        ax.set_ylabel('Mean Downlink Packet Size (bytes)')
        ax.set_title('Response Packet Size: GenAI Platforms vs Non-GenAI Traffic')
        plt.xticks(rotation=30, ha='right')
        plt.tight_layout()
        _save(fig, '16_pktsize_all_traffic_types.png')
    else:
        plt.close(fig)

    # ── Fig 17: Delivery Regularity (IPT CV) — All Traffic Types ──
    fig, ax = plt.subplots(figsize=(10, 5))
    _clean(ax)
    data, labels_list, colors = [], [], []

    for p in platforms:
        vals = [t['response_ipt_cv'] for t in text_turns
                if t['platform'] == p and t['response_ipt_cv'] < 10]
        if vals:
            data.append(vals)
            labels_list.append(p.capitalize())
            colors.append(C_PLATFORM.get(p, '#6b7280'))

    browsing_cv = [t['response_ipt_cv'] for t in browsing_turns
                   if t['response_ipt_cv'] < 10]
    if browsing_cv:
        data.append(browsing_cv)
        labels_list.append('Browsing')
        colors.append(C_PLATFORM['browsing'])

    streaming_cv = [d['ipt_cv'] for d in streaming_delivery if d['ipt_cv'] < 10]
    if streaming_cv:
        data.append(streaming_cv)
        labels_list.append('Streaming')
        colors.append(C_PLATFORM['streaming'])

    gaming_cv = [d['ipt_cv'] for d in gaming_delivery if d['ipt_cv'] < 10]
    if gaming_cv:
        data.append(gaming_cv)
        labels_list.append('Gaming')
        colors.append(C_PLATFORM['gaming'])

    if len(data) >= 2:
        bp = ax.boxplot(data, labels=labels_list, **_bp_style())
        for patch, c in zip(bp['boxes'], colors):
            patch.set_facecolor(c)
            patch.set_alpha(0.25)
            patch.set_edgecolor(c)
        ax.set_ylabel('Inter-Packet Time CV')
        ax.set_title('Delivery Regularity: GenAI vs Non-GenAI\n'
                      '(Low = steady streaming, High = bursty/chunked)')
        plt.xticks(rotation=30, ha='right')
        plt.tight_layout()
        _save(fig, '17_regularity_all_traffic_types.png')
    else:
        plt.close(fig)

    # ── Fig 18: IPT Distribution Overlay — GenAI vs Browsing vs Streaming ──
    fig, ax = plt.subplots(figsize=(9, 5))
    _clean(ax)

    # GenAI text (pooled)
    genai_ipts = []
    for t in text_turns:
        if '_resp_ipts' in t:
            clipped = t['_resp_ipts'][t['_resp_ipts'] < 500]
            genai_ipts.extend(clipped)

    browsing_ipts = []
    for t in browsing_turns:
        if '_resp_ipts' in t:
            clipped = t['_resp_ipts'][t['_resp_ipts'] < 500]
            browsing_ipts.extend(clipped)

    streaming_ipts = []
    for d in streaming_delivery:
        if '_bwd_ipts' in d:
            clipped = d['_bwd_ipts'][d['_bwd_ipts'] < 500]
            streaming_ipts.extend(clipped)

    gaming_ipts = []
    for d in gaming_delivery:
        if '_bwd_ipts' in d:
            clipped = d['_bwd_ipts'][d['_bwd_ipts'] < 500]
            gaming_ipts.extend(clipped)

    plotted = False
    for label, ipts, c in [
        ('GenAI Text', genai_ipts, '#0f172a'),
        ('Browsing', browsing_ipts, C_PLATFORM['browsing']),
        ('Streaming', streaming_ipts, C_PLATFORM['streaming']),
        ('Gaming', gaming_ipts, C_PLATFORM['gaming']),
    ]:
        if len(ipts) > 20:
            ax.hist(ipts, bins=60, alpha=0.3, color=c,
                    label=f'{label} (n={len(ipts)})',
                    edgecolor='white', linewidth=0.3, density=True)
            plotted = True

    if plotted:
        ax.set_xlabel('Inter-Packet Time (ms)')
        ax.set_ylabel('Density')
        ax.set_title('Downlink IPT Distribution\n'
                      'GenAI Token Delivery vs Browsing Chunks vs '
                      'Streaming Frames')
        ax.legend()
        plt.tight_layout()
        _save(fig, '18_ipt_distribution_cross_traffic.png')
    else:
        plt.close(fig)

    # ── Fig 19: Delivery Rate — All Traffic Types ──
    fig, ax = plt.subplots(figsize=(10, 5))
    _clean(ax)
    data, labels_list, colors = [], [], []

    for p in platforms:
        vals = [t['delivery_rate_pps'] for t in text_turns
                if t['platform'] == p and t['delivery_rate_pps'] > 0]
        if vals:
            data.append(vals)
            labels_list.append(p.capitalize())
            colors.append(C_PLATFORM.get(p, '#6b7280'))

    browsing_rate = [t['delivery_rate_pps'] for t in browsing_turns
                     if t['delivery_rate_pps'] > 0]
    if browsing_rate:
        data.append(browsing_rate)
        labels_list.append('Browsing')
        colors.append(C_PLATFORM['browsing'])

    # For continuous traffic, use mean window rate as proxy
    streaming_rate = [d['mean_window_rate'] for d in streaming_delivery
                      if d['mean_window_rate'] > 0]
    if streaming_rate:
        data.append(streaming_rate)
        labels_list.append('Streaming')
        colors.append(C_PLATFORM['streaming'])

    gaming_rate = [d['mean_window_rate'] for d in gaming_delivery
                   if d['mean_window_rate'] > 0]
    if gaming_rate:
        data.append(gaming_rate)
        labels_list.append('Gaming')
        colors.append(C_PLATFORM['gaming'])

    if len(data) >= 2:
        bp = ax.boxplot(data, labels=labels_list, **_bp_style())
        for patch, c in zip(bp['boxes'], colors):
            patch.set_facecolor(c)
            patch.set_alpha(0.25)
            patch.set_edgecolor(c)
        ax.set_ylabel('Downlink Packets Per Second')
        ax.set_title('Delivery Rate: GenAI vs Non-GenAI')
        plt.xticks(rotation=30, ha='right')
        plt.tight_layout()
        _save(fig, '19_delivery_rate_all_traffic.png')
    else:
        plt.close(fig)

    # ── Fig 20: Idle Fraction — GenAI vs Streaming vs Browsing ──
    # GenAI text has idle periods between turns; streaming has near-zero idle
    fig, ax = plt.subplots(figsize=(8, 5))
    _clean(ax)
    data, labels_list, colors = [], [], []

    genai_idle = [d['idle_pct'] for d in genai_text_delivery]
    if genai_idle:
        data.append(genai_idle)
        labels_list.append('GenAI Text')
        colors.append('#0f172a')

    browsing_idle = [d['idle_pct'] for d in browsing_delivery]
    if browsing_idle:
        data.append(browsing_idle)
        labels_list.append('Browsing')
        colors.append(C_PLATFORM['browsing'])

    streaming_idle = [d['idle_pct'] for d in streaming_delivery]
    if streaming_idle:
        data.append(streaming_idle)
        labels_list.append('Streaming')
        colors.append(C_PLATFORM['streaming'])

    gaming_idle = [d['idle_pct'] for d in gaming_delivery]
    if gaming_idle:
        data.append(gaming_idle)
        labels_list.append('Gaming')
        colors.append(C_PLATFORM['gaming'])

    if len(data) >= 2:
        bp = ax.boxplot(data, labels=labels_list, **_bp_style())
        for patch, c in zip(bp['boxes'], colors):
            patch.set_facecolor(c)
            patch.set_alpha(0.25)
            patch.set_edgecolor(c)
        ax.set_ylabel('Idle Window Fraction (%)')
        ax.set_title('Idle Periods: GenAI Turn-Taking vs Continuous Traffic\n'
                      '(Higher = more silence gaps between activity)')
        plt.tight_layout()
        _save(fig, '20_idle_fraction_comparison.png')
    else:
        plt.close(fig)

    # ── Fig 21: Burst Fraction — GenAI vs Streaming vs Browsing ──
    fig, ax = plt.subplots(figsize=(8, 5))
    _clean(ax)
    data, labels_list, colors = [], [], []

    genai_burst = [d['burst_pct'] for d in genai_text_delivery]
    if genai_burst:
        data.append(genai_burst)
        labels_list.append('GenAI Text')
        colors.append('#0f172a')

    browsing_burst = [d['burst_pct'] for d in browsing_delivery]
    if browsing_burst:
        data.append(browsing_burst)
        labels_list.append('Browsing')
        colors.append(C_PLATFORM['browsing'])

    streaming_burst = [d['burst_pct'] for d in streaming_delivery]
    if streaming_burst:
        data.append(streaming_burst)
        labels_list.append('Streaming')
        colors.append(C_PLATFORM['streaming'])

    gaming_burst = [d['burst_pct'] for d in gaming_delivery]
    if gaming_burst:
        data.append(gaming_burst)
        labels_list.append('Gaming')
        colors.append(C_PLATFORM['gaming'])

    if len(data) >= 2:
        bp = ax.boxplot(data, labels=labels_list, **_bp_style())
        for patch, c in zip(bp['boxes'], colors):
            patch.set_facecolor(c)
            patch.set_alpha(0.25)
            patch.set_edgecolor(c)
        ax.set_ylabel('Burst Windows (% of active windows >2x mean rate)')
        ax.set_title('Burst Fraction: GenAI vs Non-GenAI\n'
                      '(Higher = more uneven delivery, spike-then-idle pattern)')
        plt.tight_layout()
        _save(fig, '21_burst_fraction_comparison.png')
    else:
        plt.close(fig)

    # ── Fig 22: Delivery Rate CV — All Traffic Types ──
    # How consistent is the packet delivery rate across 1s windows?
    fig, ax = plt.subplots(figsize=(8, 5))
    _clean(ax)
    data, labels_list, colors = [], [], []

    genai_rate_cv = [d['delivery_rate_cv'] for d in genai_text_delivery
                     if d['delivery_rate_cv'] < 10]
    if genai_rate_cv:
        data.append(genai_rate_cv)
        labels_list.append('GenAI Text')
        colors.append('#0f172a')

    browsing_rate_cv = [d['delivery_rate_cv'] for d in browsing_delivery
                        if d['delivery_rate_cv'] < 10]
    if browsing_rate_cv:
        data.append(browsing_rate_cv)
        labels_list.append('Browsing')
        colors.append(C_PLATFORM['browsing'])

    streaming_rate_cv = [d['delivery_rate_cv'] for d in streaming_delivery
                         if d['delivery_rate_cv'] < 10]
    if streaming_rate_cv:
        data.append(streaming_rate_cv)
        labels_list.append('Streaming')
        colors.append(C_PLATFORM['streaming'])

    gaming_rate_cv = [d['delivery_rate_cv'] for d in gaming_delivery
                      if d['delivery_rate_cv'] < 10]
    if gaming_rate_cv:
        data.append(gaming_rate_cv)
        labels_list.append('Gaming')
        colors.append(C_PLATFORM['gaming'])

    if len(data) >= 2:
        bp = ax.boxplot(data, labels=labels_list, **_bp_style())
        for patch, c in zip(bp['boxes'], colors):
            patch.set_facecolor(c)
            patch.set_alpha(0.25)
            patch.set_edgecolor(c)
        ax.set_ylabel('Delivery Rate CV (across 1s windows)')
        ax.set_title('Temporal Delivery Consistency\n'
                      '(Low = constant rate, High = variable/bursty)')
        plt.tight_layout()
        _save(fig, '22_delivery_rate_cv_comparison.png')
    else:
        plt.close(fig)

    # ── Fig 23: 2D Scatter — IPT CV vs Packet Size (all traffic types) ──
    fig, ax = plt.subplots(figsize=(9, 6))
    _clean(ax)

    # GenAI text per platform
    for p in platforms:
        cvs = [t['response_ipt_cv'] for t in text_turns
               if t['platform'] == p and t['response_ipt_cv'] < 10]
        sizes = [t['response_pkt_size_mean'] for t in text_turns
                 if t['platform'] == p and t['response_ipt_cv'] < 10]
        if cvs and sizes:
            ax.scatter(cvs, sizes, s=20, alpha=0.5,
                       color=C_PLATFORM.get(p, '#6b7280'),
                       edgecolors='white', linewidth=0.3,
                       label=p.capitalize())

    # Browsing
    b_cvs = [t['response_ipt_cv'] for t in browsing_turns
             if t['response_ipt_cv'] < 10]
    b_sizes = [t['response_pkt_size_mean'] for t in browsing_turns
               if t['response_ipt_cv'] < 10]
    if b_cvs:
        ax.scatter(b_cvs, b_sizes, s=20, alpha=0.5,
                   color=C_PLATFORM['browsing'], marker='s',
                   edgecolors='white', linewidth=0.3,
                   label='Browsing')

    # Streaming
    s_cvs = [d['ipt_cv'] for d in streaming_delivery if d['ipt_cv'] < 10]
    s_sizes = [d['pkt_size_mean'] for d in streaming_delivery if d['ipt_cv'] < 10]
    if s_cvs:
        ax.scatter(s_cvs, s_sizes, s=30, alpha=0.5,
                   color=C_PLATFORM['streaming'], marker='^',
                   edgecolors='white', linewidth=0.3,
                   label='Streaming')

    # Gaming
    g_cvs = [d['ipt_cv'] for d in gaming_delivery if d['ipt_cv'] < 10]
    g_sizes = [d['pkt_size_mean'] for d in gaming_delivery if d['ipt_cv'] < 10]
    if g_cvs:
        ax.scatter(g_cvs, g_sizes, s=30, alpha=0.5,
                   color=C_PLATFORM['gaming'], marker='D',
                   edgecolors='white', linewidth=0.3,
                   label='Gaming')

    ax.set_xlabel('Inter-Packet Time CV (delivery regularity)')
    ax.set_ylabel('Mean Packet Size (bytes)')
    ax.set_title('Delivery Fingerprint: IPT Regularity vs Packet Size\n'
                  '(Each point = one response/trace)')
    ax.legend(fontsize=8)
    plt.tight_layout()
    _save(fig, '23_fingerprint_scatter_all_traffic.png')

    # ══════════════════════════════════════════════════════════════════════
    # FIGURES — Section C: Audio Comparison (Figs 08-12)
    # ══════════════════════════════════════════════════════════════════════

    print("\n  --- Audio comparison figures ---")

    # ── Fig 08: Audio — thinking gap comparison ──
    if audio_results:
        genai_gaps = []
        human_gaps = []
        for r in audio_results:
            if r['type'] == 'genai_audio':
                genai_gaps.extend(r['thinking_gaps_ms'])
            else:
                human_gaps.extend(r['thinking_gaps_ms'])

        if genai_gaps and human_gaps:
            fig, ax = plt.subplots(figsize=(6, 5))
            _clean(ax)

            genai_clipped = [g for g in genai_gaps if g < 10000]
            human_clipped = [g for g in human_gaps if g < 10000]

            bp = ax.boxplot(
                [genai_clipped, human_clipped],
                labels=['GenAI Audio', 'Human Call'],
                **_bp_style()
            )
            bp['boxes'][0].set_facecolor('#0f172a')
            bp['boxes'][0].set_alpha(0.25)
            bp['boxes'][0].set_edgecolor('#0f172a')
            bp['boxes'][1].set_facecolor('#b91c1c')
            bp['boxes'][1].set_alpha(0.25)
            bp['boxes'][1].set_edgecolor('#b91c1c')

            try:
                _, p = stats.mannwhitneyu(genai_clipped, human_clipped,
                                          alternative='two-sided')
                color = '#dc2626' if p < 0.05 else '#9ca3af'
                ax.annotate(f'p = {p:.2e}', xy=(0.5, 0.97),
                            xycoords='axes fraction', ha='center',
                            fontsize=9, color=color, style='italic')
            except Exception:
                pass

            ax.set_ylabel('Thinking Gap Duration (ms)')
            ax.set_title('Response Latency: GenAI Audio vs Human Calls\n'
                          '(Gap between speaker stop and listener start)')
            plt.tight_layout()
            _save(fig, '08_audio_thinking_gap.png')

    # ── Fig 09: Audio — turn asymmetry ──
    if audio_results:
        fig, ax = plt.subplots(figsize=(8, 5))
        _clean(ax)

        genai_asym = [r['turn_asymmetry'] for r in audio_results
                      if r['type'] == 'genai_audio' and r['turn_asymmetry'] > 0]
        human_asym = [r['turn_asymmetry'] for r in audio_results
                      if r['type'] == 'human_call' and r['turn_asymmetry'] > 0]

        if genai_asym and human_asym:
            bp = ax.boxplot(
                [genai_asym, human_asym],
                labels=['GenAI Audio', 'Human Call'],
                **_bp_style()
            )
            bp['boxes'][0].set_facecolor('#0f172a')
            bp['boxes'][0].set_alpha(0.25)
            bp['boxes'][0].set_edgecolor('#0f172a')
            bp['boxes'][1].set_facecolor('#b91c1c')
            bp['boxes'][1].set_alpha(0.25)
            bp['boxes'][1].set_edgecolor('#b91c1c')

            ax.set_ylabel('Downlink / Uplink Dominance Ratio')
            ax.set_title('Turn Asymmetry: GenAI Audio vs Human Calls\n'
                          '(>1 = AI speaks more, ~1 = symmetric)')
            ax.axhline(y=1.0, color='#d1d5db', linestyle='--', linewidth=0.8)
            plt.tight_layout()
            _save(fig, '09_audio_turn_asymmetry.png')

    # ── Fig 10: Audio — per-platform thinking gap ──
    if audio_results:
        genai_audio_platforms = sorted(set(
            r['platform'] for r in audio_results if r['type'] == 'genai_audio'
        ))

        fig, ax = plt.subplots(figsize=(8, 5))
        _clean(ax)
        data, plot_labels, colors = [], [], []
        for p in genai_audio_platforms:
            gaps = []
            for r in audio_results:
                if r['type'] == 'genai_audio' and r['platform'] == p:
                    gaps.extend([g for g in r['thinking_gaps_ms'] if g < 10000])
            if gaps:
                data.append(gaps)
                plot_labels.append(p.capitalize())
                colors.append(C_PLATFORM.get(p, '#6b7280'))

        human_gaps_list = []
        for r in audio_results:
            if r['type'] == 'human_call':
                human_gaps_list.extend([g for g in r['thinking_gaps_ms']
                                        if g < 10000])
        if human_gaps_list:
            data.append(human_gaps_list)
            plot_labels.append('Human Call')
            colors.append('#b91c1c')

        if len(data) >= 2:
            bp = ax.boxplot(data, labels=plot_labels, **_bp_style())
            for patch, c in zip(bp['boxes'], colors):
                patch.set_facecolor(c)
                patch.set_alpha(0.25)
                patch.set_edgecolor(c)
            ax.set_ylabel('Response Latency (ms)')
            ax.set_title('Per-Platform Response Latency in Audio')
            plt.tight_layout()
            _save(fig, '10_audio_latency_by_platform.png')
        else:
            plt.close(fig)

    # ── Fig 11: Response size vs TTFT scatter (per platform) ──
    fig, ax = plt.subplots(figsize=(8, 5.5))
    _clean(ax)
    for p in platforms:
        ttfts = []
        resp_bytes = []
        for t in text_turns:
            if t['platform'] == p and t['ttft_ms'] and 10 < t['ttft_ms'] < 30000:
                ttfts.append(t['ttft_ms'])
                resp_bytes.append(t['response_bytes'] / 1000)
        if ttfts:
            ax.scatter(ttfts, resp_bytes, s=25, alpha=0.5,
                       color=C_PLATFORM.get(p, '#6b7280'),
                       edgecolors='white', linewidth=0.3,
                       label=p.capitalize())

    # Add browsing for comparison
    for t in browsing_turns:
        if t['ttft_ms'] and 10 < t['ttft_ms'] < 30000:
            ax.scatter(t['ttft_ms'], t['response_bytes'] / 1000,
                       s=15, alpha=0.3, color=C_PLATFORM['browsing'],
                       marker='s', edgecolors='white', linewidth=0.3)
    # Dummy point for legend
    if browsing_turns:
        ax.scatter([], [], s=15, color=C_PLATFORM['browsing'],
                   marker='s', label='Browsing')

    ax.set_xlabel('First Response Latency (ms)')
    ax.set_ylabel('Response Size (KB)')
    ax.set_title('Response Latency vs Size: GenAI Platforms vs Browsing')
    ax.legend(fontsize=8)
    plt.tight_layout()
    _save(fig, '11_ttft_vs_response_size.png')

    # ── Fig 12: IPT distribution overlay per GenAI platform ──
    fig, ax = plt.subplots(figsize=(8, 5))
    _clean(ax)
    for p in platforms:
        all_ipts = []
        for t in text_turns:
            if t['platform'] == p and '_resp_ipts' in t:
                clipped = t['_resp_ipts'][t['_resp_ipts'] < 500]
                all_ipts.extend(clipped)
        if len(all_ipts) > 20:
            ax.hist(all_ipts, bins=50, alpha=0.35,
                    color=C_PLATFORM.get(p, '#6b7280'),
                    label=f'{p.capitalize()} (n={len(all_ipts)})',
                    edgecolor='white', linewidth=0.3, density=True)
    ax.set_xlabel('Inter-Packet Time (ms)')
    ax.set_ylabel('Density')
    ax.set_title('Intra-Response IPT Distribution by GenAI Platform\n'
                  '(Reveals token delivery cadence)')
    ax.legend()
    plt.tight_layout()
    _save(fig, '12_ipt_distribution_by_platform.png')

    # ══════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════════════════════

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    # GenAI platform summaries
    for p in platforms:
        p_turns = [t for t in text_turns if t['platform'] == p]
        ttfts = [t['ttft_ms'] for t in p_turns
                 if t['ttft_ms'] and 10 < t['ttft_ms'] < 30000]
        cadences = [t['response_ipt_median_ms'] for t in p_turns
                    if t.get('response_ipt_median_ms')]
        cvs = [t['response_ipt_cv'] for t in p_turns
               if t.get('response_ipt_cv') and t['response_ipt_cv'] < 10]

        print(f"\n{p.upper()} ({len(p_turns)} turns)")
        if ttfts:
            print(f"  TTFT:             {np.median(ttfts):.0f} ms median "
                  f"({np.percentile(ttfts, 25):.0f}-"
                  f"{np.percentile(ttfts, 75):.0f} IQR)")
        if cadences:
            print(f"  Delivery cadence: {np.median(cadences):.1f} ms median IPT")
        if cvs:
            print(f"  Delivery CV:      {np.median(cvs):.2f} "
                  f"({'regular' if np.median(cvs) < 1 else 'bursty'})")
        counts = paradigm_counts.get(p, {})
        if counts:
            dominant = max(counts, key=counts.get)
            print(f"  Paradigm:         {dominant.replace('_', ' ')}")

    # Browsing summary
    if browsing_turns:
        b_ttfts = [t['ttft_ms'] for t in browsing_turns
                   if t['ttft_ms'] and 10 < t['ttft_ms'] < 30000]
        b_cadences = [t['response_ipt_median_ms'] for t in browsing_turns
                      if t.get('response_ipt_median_ms')]
        b_cvs = [t['response_ipt_cv'] for t in browsing_turns
                 if t.get('response_ipt_cv') and t['response_ipt_cv'] < 10]

        print(f"\nBROWSING ({len(browsing_turns)} turns)")
        if b_ttfts:
            print(f"  Response latency: {np.median(b_ttfts):.0f} ms median "
                  f"({np.percentile(b_ttfts, 25):.0f}-"
                  f"{np.percentile(b_ttfts, 75):.0f} IQR)")
        if b_cadences:
            print(f"  Delivery cadence: {np.median(b_cadences):.1f} ms median IPT")
        if b_cvs:
            print(f"  Delivery CV:      {np.median(b_cvs):.2f}")
        b_counts = paradigm_counts.get('browsing', {})
        if b_counts:
            dominant = max(b_counts, key=b_counts.get)
            print(f"  Paradigm:         {dominant.replace('_', ' ')}")

    # Streaming summary
    if streaming_delivery:
        s_cadences = [d['ipt_median_ms'] for d in streaming_delivery]
        s_cvs = [d['ipt_cv'] for d in streaming_delivery]
        print(f"\nSTREAMING ({len(streaming_delivery)} traces)")
        print(f"  Delivery cadence: {np.median(s_cadences):.1f} ms median IPT")
        print(f"  Delivery CV:      {np.median(s_cvs):.2f}")
        s_idle = [d['idle_pct'] for d in streaming_delivery]
        print(f"  Idle fraction:    {np.median(s_idle):.1f}%")

    # Gaming summary
    if gaming_delivery:
        g_cadences = [d['ipt_median_ms'] for d in gaming_delivery]
        g_cvs = [d['ipt_cv'] for d in gaming_delivery]
        print(f"\nGAMING ({len(gaming_delivery)} traces)")
        print(f"  Delivery cadence: {np.median(g_cadences):.1f} ms median IPT")
        print(f"  Delivery CV:      {np.median(g_cvs):.2f}")

    # Cross-type statistical tests
    print("\n--- STATISTICAL TESTS (GenAI text vs non-GenAI) ---")

    if genai_ttft and browsing_ttft:
        _, p = stats.mannwhitneyu(genai_ttft, browsing_ttft)
        print(f"  TTFT: GenAI vs Browsing  p = {p:.2e}  "
              f"(GenAI median={np.median(genai_ttft):.0f} ms, "
              f"Browsing median={np.median(browsing_ttft):.0f} ms)")

    genai_cadences = [t['response_ipt_median_ms'] for t in text_turns
                      if t.get('response_ipt_median_ms')]
    if genai_cadences and browsing_cadence:
        _, p = stats.mannwhitneyu(genai_cadences, browsing_cadence)
        print(f"  Cadence: GenAI vs Browsing  p = {p:.2e}  "
              f"(GenAI median={np.median(genai_cadences):.1f} ms, "
              f"Browsing median={np.median(browsing_cadence):.1f} ms)")

    if genai_cadences and streaming_cadence:
        _, p = stats.mannwhitneyu(genai_cadences, streaming_cadence)
        print(f"  Cadence: GenAI vs Streaming  p = {p:.2e}  "
              f"(GenAI median={np.median(genai_cadences):.1f} ms, "
              f"Streaming median={np.median(streaming_cadence):.1f} ms)")

    genai_cvs = [t['response_ipt_cv'] for t in text_turns
                 if t.get('response_ipt_cv') and t['response_ipt_cv'] < 10]
    if genai_cvs and browsing_cv:
        _, p = stats.mannwhitneyu(genai_cvs, browsing_cv)
        print(f"  IPT CV: GenAI vs Browsing  p = {p:.2e}  "
              f"(GenAI median={np.median(genai_cvs):.2f}, "
              f"Browsing median={np.median(browsing_cv):.2f})")

    if genai_cvs and streaming_cv:
        _, p = stats.mannwhitneyu(genai_cvs, streaming_cv)
        print(f"  IPT CV: GenAI vs Streaming  p = {p:.2e}  "
              f"(GenAI median={np.median(genai_cvs):.2f}, "
              f"Streaming median={np.median(streaming_cv):.2f})")

    if audio_results:
        print("\nAUDIO ANALYSIS")
        genai_gaps = [g for r in audio_results if r['type'] == 'genai_audio'
                      for g in r['thinking_gaps_ms'] if g < 10000]
        human_gaps = [g for r in audio_results if r['type'] == 'human_call'
                      for g in r['thinking_gaps_ms'] if g < 10000]
        if genai_gaps:
            print(f"  GenAI response latency:  "
                  f"{np.median(genai_gaps):.0f} ms median")
        if human_gaps:
            print(f"  Human response latency:  "
                  f"{np.median(human_gaps):.0f} ms median")
        if genai_gaps and human_gaps:
            try:
                _, p = stats.mannwhitneyu(genai_gaps, human_gaps)
                print(f"  Mann-Whitney p = {p:.2e}")
            except Exception:
                pass

    print("\n" + "=" * 70)
    print(f"All figures saved to: {OUTPUT_DIR}")
    print("Done!")


if __name__ == '__main__':
    run_analysis()
