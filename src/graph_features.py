from __future__ import annotations
import pandas as pd
import networkx as nx

def compute_degree_centrality(G: nx.Graph) -> dict:
    return nx.degree_centrality(G)

def compute_closeness_centrality(G: nx.Graph) -> dict:
    return nx.closeness_centrality(G)

def compute_betweenness_centrality(G: nx.Graph) -> dict:
    return nx.betweenness_centrality(G, normalized=True)

def compute_pagerank(G: nx.Graph, beta: float = 0.85) -> dict:
    return nx.pagerank(G, alpha=beta)

def compute_clustering_coefficient(G: nx.Graph) -> dict:
    return dict(nx.clustering(G))

def compute_all_features(G: nx.Graph, beta: float = 0.85) -> pd.DataFrame:
    degree = compute_degree_centrality(G)
    closeness = compute_closeness_centrality(G)
    betweenness = compute_betweenness_centrality(G)
    pagerank = compute_pagerank(G, beta=beta)
    clustering = compute_clustering_coefficient(G)

    rows = []
    for node in G.nodes():
        rows.append(
            {
                "node": node,
                "degree_centrality": degree[node],
                "closeness_centrality": closeness[node],
                "betweenness_centrality": betweenness[node],
                "pagerank": pagerank[node],
                "clustering_coefficient": clustering[node],
                "raw_degree": G.degree(node),
                "is_malicious": G.nodes[node].get("is_malicious", False),
            }
        )

    return pd.DataFrame(rows).set_index("node")

def verify_features(G: nx.Graph, features: pd.DataFrame, tol: float = 1e-6) -> dict:
    degree_check = sum(dict(G.degree()).values()) == 2 * G.number_of_edges()
    pagerank_sum = features["pagerank"].sum()
    pagerank_check = abs(pagerank_sum - 1.0) < 1e-3  # power iteration tolerance, not exact

    return {
        "sum_of_degrees_equals_2x_edges": degree_check,
        "pagerank_sums_to_approximately_1": pagerank_check,
        "pagerank_sum_value": pagerank_sum,
    }

if __name__ == "__main__":
    import sys

    sys.path.insert(0, ".")
    from graph_construction import load_flow_logs, build_communication_graph

    path = sys.argv[1] if len(sys.argv) > 1 else "sample_flows.csv"
    flows = load_flow_logs(path)
    G = build_communication_graph(flows)

    features = compute_all_features(G)
    print(features.round(4))
    print()
    print("Verification:", verify_features(G, features))