import os
import warnings
from collections import defaultdict

import numpy as np
import pandas as pd
import pywt
from scipy import stats
from scapy.all import rdpcap, IP, TCP, UDP, Raw, conf
from tqdm import tqdm

conf.verb = 0
warnings.filterwarnings('ignore')


def calc_stats(values, prefix):
    if not values or len(values) == 0:
        return {f'{prefix}_{k}': 0 for k in ['mean', 'std', 'min', 'max', 'median', 'sum', 'p25', 'p75', 'p95', 'skew', 'kurtosis', 'count']}

    arr = np.array(values)
    result = {
        f'{prefix}_mean': float(np.mean(arr)),
        f'{prefix}_std': float(np.std(arr)),
        f'{prefix}_min': float(np.min(arr)),
        f'{prefix}_max': float(np.max(arr)),
        f'{prefix}_median': float(np.median(arr)),
        f'{prefix}_sum': float(np.sum(arr)),
        f'{prefix}_p25': float(np.percentile(arr, 25)),
        f'{prefix}_p75': float(np.percentile(arr, 75)),
        f'{prefix}_p95': float(np.percentile(arr, 95)),
        f'{prefix}_count': len(arr)
    }

    if len(arr) >= 3:
        result[f'{prefix}_skew'] = float(stats.skew(arr))
        result[f'{prefix}_kurtosis'] = float(stats.kurtosis(arr))
    else:
        result[f'{prefix}_skew'] = 0
        result[f'{prefix}_kurtosis'] = 0

    return result


def extract_bursts(timestamps, threshold=0.1):
    if len(timestamps) < 2:
        return {'burst_count': 0, 'burst_mean_size': 0, 'burst_max_size': 0, 'burst_mean_duration': 0, 'inter_burst_mean': 0}

    iats = np.diff(sorted(timestamps))
    bursts = []
    current = 1

    for iat in iats:
        if iat < threshold:
            current += 1
        else:
            if current > 1:
                bursts.append(current)
            current = 1

    if current > 1:
        bursts.append(current)

    if not bursts:
        return {'burst_count': 0, 'burst_mean_size': 0, 'burst_max_size': 0, 'burst_mean_duration': 0, 'inter_burst_mean': 0}

    return {
        'burst_count': len(bursts),
        'burst_mean_size': float(np.mean(bursts)),
        'burst_max_size': float(np.max(bursts)),
        'burst_mean_duration': float(np.mean(iats[iats < threshold])) if any(iats < threshold) else 0,
        'inter_burst_mean': float(np.mean(iats[iats >= threshold])) if any(iats >= threshold) else 0
    }


def is_rtp_packet(pkt):
    if UDP not in pkt or Raw not in pkt:
        return False

    payload = bytes(pkt[Raw].load)
    if len(payload) < 12:
        return False

    version = (payload[0] >> 6) & 0x03
    if version != 2:
        return False

    pt = payload[1] & 0x7F
    if pt <= 34 or (96 <= pt <= 127):
        return True

    return False


def extract_request_response_patterns(timestamps, sizes, directions):
    if len(timestamps) < 10:
        return {
            'req_resp_pattern_count': 0,
            'avg_inference_delay': 0,
            'max_inference_delay': 0,
            'response_stream_duration': 0,
            'req_resp_size_ratio': 0
        }

    sorted_indices = np.argsort(timestamps)
    ts = np.array(timestamps)[sorted_indices]
    sz = np.array(sizes)[sorted_indices]
    dirs = np.array(directions)[sorted_indices]

    iats = np.diff(ts)
    pause_threshold = 0.5
    pause_indices = np.where(iats > pause_threshold)[0]

    patterns = []
    inference_delays = []

    for idx in pause_indices:
        start = max(0, idx - 5)
        before_dirs = dirs[start:idx+1]
        end = min(len(dirs), idx + 20)
        after_dirs = dirs[idx+1:end]

        if len(before_dirs) > 0 and len(after_dirs) > 0:
            before_outgoing_ratio = np.sum(before_dirs == 1) / len(before_dirs)
            after_incoming_ratio = np.sum(after_dirs == -1) / len(after_dirs)

            if before_outgoing_ratio > 0.5 and after_incoming_ratio > 0.5:
                patterns.append(idx)
                inference_delays.append(iats[idx])

    response_durations = []
    for idx in patterns:
        end = min(len(ts), idx + 50)
        response_ts = ts[idx+1:end]
        if len(response_ts) > 1:
            response_durations.append(response_ts[-1] - response_ts[0])

    outgoing_bytes = np.sum(sz[dirs == 1])
    incoming_bytes = np.sum(sz[dirs == -1])
    size_ratio = outgoing_bytes / incoming_bytes if incoming_bytes > 0 else 0

    return {
        'req_resp_pattern_count': len(patterns),
        'avg_inference_delay': float(np.mean(inference_delays)) if inference_delays else 0,
        'max_inference_delay': float(np.max(inference_delays)) if inference_delays else 0,
        'response_stream_duration': float(np.mean(response_durations)) if response_durations else 0,
        'req_resp_size_ratio': float(size_ratio)
    }


def extract_connection_features(connections, dst_ips):
    unique_dst_ips = len(set(dst_ips))
    unique_connections = len(set(connections))

    ip_counts = defaultdict(int)
    for ip in dst_ips:
        ip_counts[ip] += 1

    counts = list(ip_counts.values())

    if counts:
        max_concentration = max(counts) / sum(counts)
        ip_entropy = stats.entropy(counts) if len(counts) > 1 else 0
    else:
        max_concentration = 0
        ip_entropy = 0

    return {
        'unique_dst_ips': unique_dst_ips,
        'unique_connections': unique_connections,
        'ip_concentration': float(max_concentration),
        'ip_entropy': float(ip_entropy),
        'is_single_server': 1 if unique_dst_ips <= 2 else 0
    }


def extract_bitrate_features(timestamps, sizes, window=1.0):
    if len(timestamps) < 2:
        return {
            'bitrate_mean': 0, 'bitrate_std': 0, 'bitrate_max': 0,
            'bitrate_min': 0, 'bitrate_cv': 0
        }

    ts = np.array(timestamps)
    sz = np.array(sizes)

    min_t, max_t = ts.min(), ts.max()
    if max_t - min_t < window:
        total_bits = sum(sz) * 8
        duration = max_t - min_t if max_t > min_t else 1
        br = total_bits / duration
        return {
            'bitrate_mean': br, 'bitrate_std': 0, 'bitrate_max': br,
            'bitrate_min': br, 'bitrate_cv': 0
        }

    bitrates = []
    t = min_t
    while t < max_t:
        mask = (ts >= t) & (ts < t + window)
        window_bytes = sz[mask].sum()
        bitrates.append(window_bytes * 8 / window)
        t += window

    bitrates = np.array(bitrates)
    mean_br = np.mean(bitrates)
    std_br = np.std(bitrates)

    return {
        'bitrate_mean': float(mean_br),
        'bitrate_std': float(std_br),
        'bitrate_max': float(np.max(bitrates)),
        'bitrate_min': float(np.min(bitrates)),
        'bitrate_cv': float(std_br / mean_br) if mean_br > 0 else 0
    }


def extract_wavelet_features(series, prefix, wavelet='db4', max_level=4):
    """Decompose *series* with a discrete wavelet transform and extract
    energy / mean / std / entropy per coefficient level."""
    if len(series) < 2:
        out = {}
        for lvl in range(max_level + 1):
            tag = f'{prefix}_wl{lvl}'
            for stat in ['energy', 'mean', 'std', 'entropy']:
                out[f'{tag}_{stat}'] = 0.0
        return out

    arr = np.array(series, dtype=np.float64)
    actual_level = min(max_level, pywt.dwt_max_level(len(arr), pywt.Wavelet(wavelet).dec_len))
    if actual_level < 1:
        actual_level = 1
    coeffs = pywt.wavedec(arr, wavelet, level=actual_level)

    out = {}
    for lvl, c in enumerate(coeffs):
        tag = f'{prefix}_wl{lvl}'
        c_abs = np.abs(c)
        energy = float(np.sum(c ** 2))
        out[f'{tag}_energy'] = energy
        out[f'{tag}_mean'] = float(np.mean(c_abs))
        out[f'{tag}_std'] = float(np.std(c_abs))
        # Shannon entropy of normalised squared coefficients
        p = (c ** 2)
        p_sum = p.sum()
        if p_sum > 0:
            p = p / p_sum
            p = p[p > 0]
            out[f'{tag}_entropy'] = float(-np.sum(p * np.log2(p)))
        else:
            out[f'{tag}_entropy'] = 0.0

    # Pad missing levels with zeros so every sample has the same columns
    for lvl in range(len(coeffs), max_level + 1):
        tag = f'{prefix}_wl{lvl}'
        for stat in ['energy', 'mean', 'std', 'entropy']:
            out[f'{tag}_{stat}'] = 0.0

    return out


def extract_entropy_features(directions, packet_sizes, fwd_iats, bwd_iats):
    """Direction entropy, direction-bigram entropy, packet-size distribution
    entropy, fwd IAT entropy, bwd IAT entropy."""
    out = {}

    # Direction entropy
    if len(directions) > 1:
        _, counts = np.unique(directions, return_counts=True)
        out['direction_entropy'] = float(stats.entropy(counts, base=2))
    else:
        out['direction_entropy'] = 0.0

    # Direction bigram entropy
    if len(directions) > 2:
        bigrams = [f'{directions[i]}_{directions[i+1]}' for i in range(len(directions) - 1)]
        _, counts = np.unique(bigrams, return_counts=True)
        out['direction_bigram_entropy'] = float(stats.entropy(counts, base=2))
    else:
        out['direction_bigram_entropy'] = 0.0

    # Packet size distribution entropy (bin into 50-byte buckets)
    if len(packet_sizes) > 1:
        bins = np.arange(0, max(packet_sizes) + 51, 50)
        hist, _ = np.histogram(packet_sizes, bins=bins)
        hist = hist[hist > 0]
        out['pkt_size_dist_entropy'] = float(stats.entropy(hist, base=2))
    else:
        out['pkt_size_dist_entropy'] = 0.0

    # Forward IAT entropy
    if len(fwd_iats) > 1:
        bins = np.linspace(0, max(fwd_iats) + 1e-9, 20)
        hist, _ = np.histogram(fwd_iats, bins=bins)
        hist = hist[hist > 0]
        out['fwd_iat_entropy'] = float(stats.entropy(hist, base=2))
    else:
        out['fwd_iat_entropy'] = 0.0

    # Backward IAT entropy
    if len(bwd_iats) > 1:
        bins = np.linspace(0, max(bwd_iats) + 1e-9, 20)
        hist, _ = np.histogram(bwd_iats, bins=bins)
        hist = hist[hist > 0]
        out['bwd_iat_entropy'] = float(stats.entropy(hist, base=2))
    else:
        out['bwd_iat_entropy'] = 0.0

    return out


def extract_features(filepath, sequences_dir=None, file_id=None):
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return None

    if len(packets) == 0:
        return None

    features = {}
    timestamps, packet_sizes, payload_sizes = [], [], []
    tcp_count, udp_count, other_count, tls_count, rtp_count = 0, 0, 0, 0, 0
    forward_sizes, backward_sizes = [], []
    forward_timestamps, backward_timestamps = [], []
    connections = []
    dst_ips = []
    directions = []
    flows = defaultdict(lambda: {'packets': 0, 'bytes': 0})

    WELL_KNOWN_PORTS = set(range(1, 1024)) | {8080, 8443, 3478, 5349}
    flow_forward_key = {}

    def get_direction(src_ip, src_port, dst_ip, dst_port, flow_key):
        if flow_key not in flow_forward_key:
            if dst_port in WELL_KNOWN_PORTS and src_port not in WELL_KNOWN_PORTS:
                flow_forward_key[flow_key] = (src_ip, src_port)
            elif src_port in WELL_KNOWN_PORTS and dst_port not in WELL_KNOWN_PORTS:
                flow_forward_key[flow_key] = (dst_ip, dst_port)
            else:
                flow_forward_key[flow_key] = (src_ip, src_port)
        fwd_src = flow_forward_key[flow_key]
        return 1 if (src_ip, src_port) == fwd_src else -1

    for pkt in packets:
        timestamps.append(float(pkt.time))
        pkt_size = len(pkt)
        packet_sizes.append(pkt_size)

        if IP in pkt:
            ip_pkt = pkt[IP]
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            payload_size = len(ip_pkt.payload) if ip_pkt.payload else 0
            payload_sizes.append(payload_size)
            dst_ips.append(dst_ip)

            if TCP in pkt:
                tcp_count += 1
                tcp_pkt = pkt[TCP]
                src_port = tcp_pkt.sport
                dst_port = tcp_pkt.dport
                conn = (src_ip, dst_ip, src_port, dst_port)
                connections.append(conn)
                flow_key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
                flows[flow_key]['packets'] += 1
                flows[flow_key]['bytes'] += pkt_size

                direction = get_direction(src_ip, src_port, dst_ip, dst_port, flow_key)
                directions.append(direction)
                if direction == 1:
                    forward_sizes.append(pkt_size)
                    forward_timestamps.append(float(pkt.time))
                else:
                    backward_sizes.append(pkt_size)
                    backward_timestamps.append(float(pkt.time))

                if src_port == 443 or dst_port == 443:
                    tls_count += 1

            elif UDP in pkt:
                udp_count += 1
                udp_pkt = pkt[UDP]
                src_port = udp_pkt.sport
                dst_port = udp_pkt.dport
                conn = (src_ip, dst_ip, src_port, dst_port)
                connections.append(conn)
                flow_key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
                flows[flow_key]['packets'] += 1
                flows[flow_key]['bytes'] += pkt_size

                if is_rtp_packet(pkt):
                    rtp_count += 1

                direction = get_direction(src_ip, src_port, dst_ip, dst_port, flow_key)
                directions.append(direction)
                if direction == 1:
                    forward_sizes.append(pkt_size)
                    forward_timestamps.append(float(pkt.time))
                else:
                    backward_sizes.append(pkt_size)
                    backward_timestamps.append(float(pkt.time))

                if src_port == 443 or dst_port == 443:
                    tls_count += 1
            else:
                other_count += 1
                directions.append(0)
        else:
            payload_sizes.append(0)
            directions.append(0)

    flow_duration = max(timestamps) - min(timestamps) if timestamps else 0
    features['flow_duration'] = flow_duration
    features['total_packets'] = len(packets)
    features['total_bytes'] = sum(packet_sizes)

    if flow_duration > 0:
        features['packets_per_second'] = len(packets) / flow_duration
        features['bytes_per_second'] = sum(packet_sizes) / flow_duration
    else:
        features['packets_per_second'] = 0
        features['bytes_per_second'] = 0

    total_proto = tcp_count + udp_count + other_count
    if total_proto > 0:
        features['tcp_ratio'] = tcp_count / total_proto
        features['udp_ratio'] = udp_count / total_proto
        features['tls_ratio'] = tls_count / total_proto
        features['rtp_ratio'] = rtp_count / total_proto
    else:
        features['tcp_ratio'] = features['udp_ratio'] = features['tls_ratio'] = features['rtp_ratio'] = 0

    features['rtp_count'] = rtp_count
    features['is_rtp_traffic'] = 1 if rtp_count > 10 else 0

    features.update(calc_stats(packet_sizes, 'pkt_size'))
    features.update(calc_stats(payload_sizes, 'payload_size'))

    if len(timestamps) > 1:
        iats = np.diff(sorted(timestamps))
        features.update(calc_stats(iats.tolist(), 'iat'))
    else:
        features.update(calc_stats([], 'iat'))

    features.update(calc_stats(forward_sizes, 'fwd_pkt_size'))
    features['fwd_packets'] = len(forward_sizes)
    features['fwd_bytes'] = sum(forward_sizes) if forward_sizes else 0

    features.update(calc_stats(backward_sizes, 'bwd_pkt_size'))
    features['bwd_packets'] = len(backward_sizes)
    features['bwd_bytes'] = sum(backward_sizes) if backward_sizes else 0

    if features['bwd_packets'] > 0:
        features['fwd_bwd_packet_ratio'] = features['fwd_packets'] / features['bwd_packets']
        features['fwd_bwd_byte_ratio'] = features['fwd_bytes'] / features['bwd_bytes'] if features['bwd_bytes'] > 0 else 0
    else:
        features['fwd_bwd_packet_ratio'] = features['fwd_packets'] if features['fwd_packets'] > 0 else 0
        features['fwd_bwd_byte_ratio'] = features['fwd_bytes'] if features['fwd_bytes'] > 0 else 0

    features.update(extract_bursts(timestamps))

    if len(forward_timestamps) > 1:
        features.update(calc_stats(np.diff(sorted(forward_timestamps)).tolist(), 'fwd_iat'))
    else:
        features.update(calc_stats([], 'fwd_iat'))

    if len(backward_timestamps) > 1:
        features.update(calc_stats(np.diff(sorted(backward_timestamps)).tolist(), 'bwd_iat'))
    else:
        features.update(calc_stats([], 'bwd_iat'))

    # IAT coefficient of variation: direct measure of streaming regularity
    # (LLM token streaming produces unusually regular backward IATs → low CV)
    features['fwd_iat_cv'] = features['fwd_iat_std'] / features['fwd_iat_mean'] if features['fwd_iat_mean'] > 0 else 0
    features['bwd_iat_cv'] = features['bwd_iat_std'] / features['bwd_iat_mean'] if features['bwd_iat_mean'] > 0 else 0

    features.update(extract_connection_features(connections, dst_ips))
    features.update(extract_request_response_patterns(timestamps, packet_sizes, directions))
    features.update(extract_bitrate_features(timestamps, packet_sizes))

    features['num_flows'] = len(flows)
    if flows:
        flow_packets = [f['packets'] for f in flows.values()]
        flow_bytes = [f['bytes'] for f in flows.values()]
        features['avg_packets_per_flow'] = float(np.mean(flow_packets))
        features['avg_bytes_per_flow'] = float(np.mean(flow_bytes))
        features['max_packets_per_flow'] = float(np.max(flow_packets))
        features['flow_size_std'] = float(np.std(flow_bytes)) if len(flow_bytes) > 1 else 0
    else:
        features['avg_packets_per_flow'] = 0
        features['avg_bytes_per_flow'] = 0
        features['max_packets_per_flow'] = 0
        features['flow_size_std'] = 0

    # --- Wavelet features ---
    combined_sizes = forward_sizes + backward_sizes
    fwd_iats = np.diff(sorted(forward_timestamps)).tolist() if len(forward_timestamps) > 1 else []
    bwd_iats = np.diff(sorted(backward_timestamps)).tolist() if len(backward_timestamps) > 1 else []
    features.update(extract_wavelet_features(forward_sizes, 'fwd_size'))
    features.update(extract_wavelet_features(backward_sizes, 'bwd_size'))
    features.update(extract_wavelet_features(combined_sizes, 'comb_size'))
    features.update(extract_wavelet_features(fwd_iats, 'fwd_iat_wv'))
    features.update(extract_wavelet_features(bwd_iats, 'bwd_iat_wv'))

    # --- Entropy features ---
    features.update(extract_entropy_features(directions, packet_sizes, fwd_iats, bwd_iats))

    # Save raw packet sequences as .npy for deep learning models
    if sequences_dir and file_id:
        min_len = min(len(timestamps), len(packet_sizes), len(directions))
        seq_ts = np.array(timestamps[:min_len])
        seq_ts = seq_ts - seq_ts[0] if len(seq_ts) > 0 else seq_ts
        seq_sizes = np.array(packet_sizes[:min_len])
        seq_dirs = np.array(directions[:min_len])
        sequence_data = np.stack([seq_ts, seq_sizes, seq_dirs], axis=1)
        save_name = os.path.splitext(file_id)[0] + '.npy'
        np.save(os.path.join(sequences_dir, save_name), sequence_data)

    return features


def process_dataset(data_dir, labels_path, output_path):
    labels_df = pd.read_csv(labels_path)
    results = []

    sequences_dir = os.path.join(os.path.dirname(output_path), 'sequences')
    os.makedirs(sequences_dir, exist_ok=True)

    print(f"Processing {len(labels_df)} files...")
    print(f"Saving sequences to: {sequences_dir}")

    for _, row in tqdm(labels_df.iterrows(), total=len(labels_df)):
        filepath = os.path.join(data_dir, row['category'], row['subcategory'], row['filename'])

        if not os.path.exists(filepath):
            print(f"File not found: {filepath}")
            continue

        features = extract_features(filepath, sequences_dir=sequences_dir, file_id=row['filename'])
        if features is None:
            continue

        features['filename'] = row['filename']
        features['category'] = row['category']
        features['subcategory'] = row['subcategory']
        features['app'] = row['app']
        features['is_genai'] = row['is_genai']
        results.append(features)

    df = pd.DataFrame(results)
    meta_cols = ['filename', 'category', 'subcategory', 'app', 'is_genai']
    feature_cols = [c for c in df.columns if c not in meta_cols]
    df = df[meta_cols + sorted(feature_cols)]

    df.to_csv(output_path, index=False)
    print(f"Saved {output_path} — shape: {df.shape}")
    return df


if __name__ == '__main__':
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_dir = os.path.join(base_dir, 'data', 'raw')
    labels_path = os.path.join(data_dir, 'labels.csv')

    processed_dir = os.path.join(base_dir, 'data', 'processed')
    os.makedirs(processed_dir, exist_ok=True)
    output_path = os.path.join(processed_dir, 'features.csv')

    df = process_dataset(data_dir, labels_path, output_path)

    print(f"\nTotal samples: {len(df)}")
    print(f"Features: {len([c for c in df.columns if c not in ['filename', 'category', 'subcategory', 'app', 'is_genai']])}")
    print(f"\nClass distribution:\n{df['is_genai'].value_counts()}")
