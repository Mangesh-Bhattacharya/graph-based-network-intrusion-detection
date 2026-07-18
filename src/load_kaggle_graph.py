from __future__ import annotations
import networkx as nx
import pandas as pd

EDGE_ATTRIBUTE_MEANINGS = {
    "TotPkts": "total packets in the flow (z-scored)",
    "TotBytes": "total bytes in the flow (z-scored)",
    "SrcBytes": "bytes sent by the source (z-scored)",
    "Dur": "flow duration (z-scored)",
    "Proto_encoded": "encoded transport protocol (z-scored)",
    "Dir_encoded": "encoded flow direction (z-scored)",
    "State_encoded": "encoded connection state (z-scored)",
    "ActivityLabel": "0 = benign, 1 = malicious (ground-truth label)",
}

def load_graphml(path: str) -> nx.Graph:
    return nx.read_graphml(path)


def mark_malicious_nodes(G: nx.Graph, label_key: str = "ActivityLabel") -> nx.Graph:
    for node in G.nodes():
        G.nodes[node]["is_malicious"] = False

    for u, v, data in G.edges(data=True):
        if float(data.get(label_key, 0)) != 0:
            G.nodes[u]["is_malicious"] = True
            G.nodes[v]["is_malicious"] = True

    return G

def summarize_graph(G: nx.Graph, name: str = "") -> dict:
    is_multigraph = G.is_multigraph()
    label_key = "ActivityLabel"
    attack_edges = sum(
        1 for _, _, d in G.edges(data=True) if float(d.get(label_key, 0)) != 0
    )
    return {
        "name": name or getattr(G, "name", ""),
        "nodes": G.number_of_nodes(),
        "edges": G.number_of_edges(),
        "is_multigraph": is_multigraph,
        "is_directed": G.is_directed(),
        "attack_labeled_edges": attack_edges,
        "attack_edge_pct": round(100 * attack_edges / max(G.number_of_edges(), 1), 2),
    }

def compare_graph_variants(paths: dict) -> pd.DataFrame:
    rows = []
    for name, path in paths.items():
        G = load_graphml(path)
        rows.append(summarize_graph(G, name=name))
    return pd.DataFrame(rows).set_index("name")

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        G = load_graphml(sys.argv[1])
        print(summarize_graph(G, name=sys.argv[1]))
    else:
        print("Usage: python load_kaggle_graph.py <path-to-graphml>")
