from __future__ import annotations

import pandas as pd
import networkx as nx

SRC_COL = "Source IP"
DST_COL = "Destination IP"
LABEL_COL = "Label"
TIMESTAMP_COL = "Timestamp"
BENIGN_LABEL = "BENIGN"

FWD_PACKETS_COL = "Total Fwd Packets"
BWD_PACKETS_COL = "Total Backward Packets"
FWD_BYTES_COL = "Total Length of Fwd Packets"
BWD_BYTES_COL = "Total Length of Bwd Packets"

def _read_csv_robust(csv_path: str, **kwargs) -> pd.DataFrame:
    """
    A handful of CIC-IDS-2017 files (notably the Web Attack labels, which
    contain an en-dash: "Web Attack – Brute Force") are not valid
    UTF-8. Try UTF-8 first since it is correct for most files, and fall
    back to cp1252 (Windows-1252) - what these files were actually
    exported as - only if UTF-8 decoding fails.
    """
    try:
        return pd.read_csv(csv_path, low_memory=False, encoding="utf-8", **kwargs)
    except UnicodeDecodeError:
        return pd.read_csv(csv_path, low_memory=False, encoding="cp1252", **kwargs)


def load_flow_logs(csv_path: str, nrows: int | None = None) -> pd.DataFrame:
    df = _read_csv_robust(csv_path, nrows=nrows)
    df.columns = [c.strip() for c in df.columns]

    if TIMESTAMP_COL in df.columns:
        # CIC-IDS-2017 timestamps look like "03/07/2017 08:55:58" (day/month/year).
        df[TIMESTAMP_COL] = pd.to_datetime(
            df[TIMESTAMP_COL], errors="coerce", dayfirst=True
        )

    return df

def sample_labeled_flows(
    csv_path: str,
    n: int = 30,
    want: str = "attack",
    label_col: str = LABEL_COL,
    benign_label: str = BENIGN_LABEL,
    chunksize: int = 20000,
    max_chunks: int = 100,
) -> pd.DataFrame:
    """
    Scan a CIC-IDS-2017 CSV in chunks and return the first `n` rows matching
    the requested label class, without loading the whole (often 100MB+) file
    into memory and without assuming attack rows are near the top.

    Why this exists: CIC-IDS-2017 flows are stored in chronological order,
    and an attack (e.g. a DDoS window) is usually a narrow slice well into
    the file - a plain `pd.read_csv(path, nrows=200)` frequently returns
    zero attack rows purely because the attack hasn't started yet at row
    200. That silently breaks any downstream "show me an attack" plot
    without raising an error, which is worse than a crash.

    want="attack"  -> rows where Label != benign_label
    want="benign"  -> rows where Label == benign_label
    """
    if want not in ("attack", "benign"):
        raise ValueError("want must be 'attack' or 'benign'")

    def _scan(encoding: str):
        collected = []
        last_columns = None
        total = 0
        for i, chunk in enumerate(
            pd.read_csv(csv_path, chunksize=chunksize, low_memory=False, encoding=encoding)
        ):
            chunk.columns = [c.strip() for c in chunk.columns]
            last_columns = chunk.columns
            labels = chunk[label_col].astype(str).str.strip().str.upper()
            matches = (
                chunk[labels != benign_label.upper()]
                if want == "attack"
                else chunk[labels == benign_label.upper()]
            )
            if len(matches):
                collected.append(matches)
                total += len(matches)
            if total >= n or (i + 1) >= max_chunks:
                break
        return collected, last_columns

    try:
        collected, last_columns = _scan("utf-8")
    except UnicodeDecodeError:
        # A handful of CIC-IDS-2017 files (Web Attack labels contain an
        # en-dash) are actually Windows-1252, not UTF-8. Restart the scan
        # with the correct encoding rather than failing partway through.
        collected, last_columns = _scan("cp1252")

    if not collected:
        return pd.DataFrame(columns=last_columns if last_columns is not None else [])

    out = pd.concat(collected, ignore_index=True).head(n)
    if TIMESTAMP_COL in out.columns:
        out[TIMESTAMP_COL] = pd.to_datetime(out[TIMESTAMP_COL], errors="coerce", dayfirst=True)
    return out

def add_time_windows(df: pd.DataFrame, window: str = "5min") -> pd.DataFrame:
    if TIMESTAMP_COL not in df.columns:
        raise ValueError(f"Expected a '{TIMESTAMP_COL}' column to build time windows from.")

    out = df.copy()
    out["time_window"] = out[TIMESTAMP_COL].dt.floor(window)
    return out

def build_communication_graph(
    df: pd.DataFrame,
    src_col: str = SRC_COL,
    dst_col: str = DST_COL,
    label_col: str = LABEL_COL,
    benign_label: str = BENIGN_LABEL,
) -> nx.Graph:
    required = [src_col, dst_col, label_col]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required column(s): {missing}")

    G = nx.Graph()

    for _, row in df.iterrows():
        u, v = row[src_col], row[dst_col]
        if pd.isna(u) or pd.isna(v):
            continue

        is_attack = str(row[label_col]).strip().upper() != benign_label.upper()

        packets = _safe_sum(row, FWD_PACKETS_COL, BWD_PACKETS_COL)
        num_bytes = _safe_sum(row, FWD_BYTES_COL, BWD_BYTES_COL)

        if G.has_edge(u, v):
            edge = G[u][v]
            edge["flow_count"] += 1
            edge["total_packets"] += packets
            edge["total_bytes"] += num_bytes
            edge["attack_flows"] += int(is_attack)
        else:
            G.add_edge(
                u,
                v,
                flow_count=1,
                total_packets=packets,
                total_bytes=num_bytes,
                attack_flows=int(is_attack),
            )

        for node in (u, v):
            G.nodes[node]["is_malicious"] = bool(
                G.nodes[node].get("is_malicious", False) or is_attack
            )

    return G

def build_windowed_graphs(df: pd.DataFrame, window: str = "5min") -> dict:
    windowed = add_time_windows(df, window=window)
    graphs = {}
    for window_start, group in windowed.groupby("time_window"):
        graphs[window_start] = build_communication_graph(group)
    return graphs

def _safe_sum(row: pd.Series, *cols: str) -> float:
    total = 0.0
    for c in cols:
        if c in row.index and pd.notna(row[c]):
            total += float(row[c])
    return total

def graph_summary(G: nx.Graph) -> dict:
    n_malicious_nodes = sum(1 for _, d in G.nodes(data=True) if d.get("is_malicious"))
    n_attack_edges = sum(1 for _, _, d in G.edges(data=True) if d.get("attack_flows", 0) > 0)
    degrees = [d for _, d in G.degree()]
    return {
        "nodes": G.number_of_nodes(),
        "edges": G.number_of_edges(),
        "nodes_touching_an_attack_flow": n_malicious_nodes,
        "edges_with_at_least_one_attack_flow": n_attack_edges,
        "avg_degree": (sum(degrees) / len(degrees)) if degrees else 0.0,
        "sum_of_degrees_equals_2x_edges": sum(degrees) == 2 * G.number_of_edges(),
    }

if __name__ == "__main__":
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "sample_flows.csv"
    flows = load_flow_logs(path)
    print(f"Loaded {len(flows)} flows from {path}")

    G = build_communication_graph(flows)
    print("Graph summary:", graph_summary(G))
