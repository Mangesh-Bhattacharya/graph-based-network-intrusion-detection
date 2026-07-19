from __future__ import annotations
import math
import os
import matplotlib

try:
    # Prefer the IPython-provided helper if available. If running outside
    # of an interactive IPython environment, fall back to the non-interactive
    # Agg backend so figures can be saved without a display.
    from IPython import get_ipython

    if get_ipython() is None:
        matplotlib.use("Agg")
except Exception:
    matplotlib.use("Agg")

import matplotlib.pyplot as plt
import networkx as nx

MALICIOUS_COLOR = "#d62728"   # red
BENIGN_COLOR = "#4c72b0"      # steel blue
SECONDARY_COLOR = "#55a868"   # green, for a third series (e.g. a baseline)
EDGE_COLOR = "#b0b0b0"        # light gray

def _save(fig, save_path: str | None):
    """
    Every plotting function in this module accepts a `save_path`. Passing one
    writes a PNG straight to disk (creating parent folders as needed) so the
    figure can be pulled directly into a slide or report without a manual
    screenshot. If save_path is None, the figure is only returned/shown
    inline, as before - nothing about existing notebook cells breaks if they
    don't pass one.
    """
    if save_path:
        os.makedirs(os.path.dirname(save_path) or ".", exist_ok=True)
        fig.savefig(save_path, dpi=150, bbox_inches="tight")

def _bottom_legend(fig, handles, ncol: int | None = None, extra_bottom: float = 0.12):
    """
    Places one legend below everything else in the figure, as a horizontal
    strip, instead of overlapping the plotted data. Used by every plotting
    function in this module so every exported figure is self-explanatory on
    its own, with no separate caption needed, once dropped into a slide.
    """
    ncol = ncol or min(len(handles), 4)
    fig.legend(handles=handles, loc="lower center", ncol=ncol, frameon=False, fontsize=9,
               bbox_to_anchor=(0.5, 0.0))
    fig.tight_layout(rect=(0, extra_bottom, 1, 1))

def get_readable_subgraph(G: nx.Graph, max_nodes: int = 40) -> nx.Graph:
    if G.number_of_nodes() <= max_nodes:
        return G

    top_nodes = sorted(G.degree, key=lambda x: x[1], reverse=True)[:max_nodes]
    node_ids = [n for n, _ in top_nodes]
    return G.subgraph(node_ids).copy()

def _draw_single_graph(ax, G: nx.Graph, title: str, max_nodes: int = 40, seed: int = 42):
    full_n, full_e = G.number_of_nodes(), G.number_of_edges()
    G_plot = get_readable_subgraph(G, max_nodes=max_nodes)
    sampled = G_plot.number_of_nodes() < full_n

    pos = nx.spring_layout(G_plot, seed=seed)

    degrees = dict(G_plot.degree())
    max_deg = max(degrees.values()) if degrees else 1
    node_sizes = [120 + 1200 * (degrees[n] / max_deg) for n in G_plot.nodes()]
    node_colors = [
        MALICIOUS_COLOR if G_plot.nodes[n].get("is_malicious") else BENIGN_COLOR
        for n in G_plot.nodes()
    ]

    nx.draw_networkx_edges(G_plot, pos, ax=ax, edge_color=EDGE_COLOR, width=1.0, alpha=0.6)
    nx.draw_networkx_nodes(
        G_plot, pos, ax=ax, node_size=node_sizes, node_color=node_colors, alpha=0.9
    )
    # get_readable_subgraph() already caps this to max_nodes before we get here,
    # so the subgraph being plotted is always small enough to label - no need to
    # additionally suppress labels past some node count.
    nx.draw_networkx_labels(G_plot, pos, ax=ax, font_size=6)

    subtitle = (
        f"top {G_plot.number_of_nodes()} of {full_n} nodes"
        if sampled
        else f"{full_n} nodes, {full_e} edges"
    )
    ax.set_title(f"{title}\n({subtitle})", fontsize=10)
    ax.axis("off")

def _graph_legend_handles():
    return [
        plt.Line2D([0], [0], marker="o", color="w", label="Benign", markerfacecolor=BENIGN_COLOR, markersize=10), # noqa: E501
        plt.Line2D([0], [0], marker="o", color="w", label="Touched an attack flow", markerfacecolor=MALICIOUS_COLOR, markersize=10), # noqa: E501
        plt.Line2D([0], [0], color=EDGE_COLOR, lw=2, label="Communication (edge)"),
    ]

def plot_graph(
    G: nx.Graph,
    title: str = "Network Communication Graph",
    max_nodes: int = 40,
    figsize: tuple = (10, 8),
    seed: int = 42,
    save_path: str | None = None,
):
    fig, ax = plt.subplots(figsize=figsize)
    _draw_single_graph(ax, G, title, max_nodes=max_nodes, seed=seed)
    _bottom_legend(fig, _graph_legend_handles(), ncol=3)
    _save(fig, save_path)
    return fig

def plot_multiple_graphs(
    graphs: dict,
    max_nodes: int = 30,
    ncols: int = 2,
    panel_size: tuple = (5, 5),
    suptitle: str | None = None,
    seed: int = 42,
    save_path: str | None = None,
):
    n = len(graphs)
    if n == 0:
        raise ValueError("graphs must contain at least one entry")

    ncols = min(ncols, n)
    nrows = math.ceil(n / ncols)

    fig, axes = plt.subplots(
        nrows, ncols, figsize=(panel_size[0] * ncols, panel_size[1] * nrows)
    )
    axes = [axes] if n == 1 else list(axes.flat) if hasattr(axes, "flat") else list(axes)

    for ax, (panel_title, G) in zip(axes, graphs.items()):
        _draw_single_graph(ax, G, str(panel_title), max_nodes=max_nodes, seed=seed)

    # Hide any unused panels (e.g. 3 graphs in a 2x2 grid)
    for ax in axes[n:]:
        ax.axis("off")

    if suptitle:
        fig.suptitle(suptitle, fontsize=13)
    _bottom_legend(fig, _graph_legend_handles(), ncol=3, extra_bottom=0.10)
    _save(fig, save_path)
    return fig

def plot_feature_distribution(features, column: str, title: str | None = None, save_path: str | None = None):
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.hist(features[column], bins=20, color=BENIGN_COLOR, edgecolor="white")
    ax.set_xlabel(column.replace("_", " ").title())
    ax.set_ylabel("Number of nodes")
    ax.set_title(title or f"Distribution of {column.replace('_', ' ')}")
    handles = [plt.Rectangle((0, 0), 1, 1, color=BENIGN_COLOR,
                              label=f"Nodes binned by {column.replace('_', ' ')} (n={len(features)})")]
    _bottom_legend(fig, handles, ncol=1)
    _save(fig, save_path)
    return fig

def plot_degree_distribution(G: nx.Graph, title: str = "Degree Distribution", loglog: bool = True, save_path: str | None = None):
    """
    Plots how degree is distributed across all nodes in G (not a sampled
    subgraph - the whole thing, since this is just counting, not drawing
    node-link positions, so it scales fine to large graphs).

    Real NetFlow-style communication graphs are frequently hub-dominated
    (a small number of nodes - often a gateway or heavily-used server -
    account for a large share of all edges, while most nodes only appear
    once). A log-log scatter makes that pattern visible as a roughly
    straight downward line; a linear histogram would just show one huge
    bar at low degree and nothing else, hiding the hub(s) entirely.
    """
    from collections import Counter

    degrees = [d for _, d in G.degree()]
    fig, ax = plt.subplots(figsize=(7, 5))

    if loglog:
        counts = Counter(degrees)
        xs = sorted(counts)
        ys = [counts[x] for x in xs]
        ax.scatter(xs, ys, s=25, color=BENIGN_COLOR, alpha=0.75, edgecolor="white", linewidth=0.5)
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel("Degree (log scale)")
        ax.set_ylabel("Number of nodes (log scale)")
        legend_label = "Each point = one distinct degree value in the graph"
    else:
        ax.hist(degrees, bins=50, color=BENIGN_COLOR, edgecolor="white")
        ax.set_xlabel("Degree")
        ax.set_ylabel("Number of nodes")
        legend_label = "Each bar = a range of degree values"

    ax.set_title(title)
    handles = [plt.Line2D([0], [0], marker="o", color="w", label=legend_label, markerfacecolor=BENIGN_COLOR, markersize=8)]
    _bottom_legend(fig, handles, ncol=1)
    _save(fig, save_path)
    return fig

def get_subgraph_excluding_nodes(G: nx.Graph, exclude: list, max_nodes: int = 40) -> nx.Graph:
    """
    Returns a readable top-degree subgraph AFTER removing the given nodes
    (e.g. one or two dominant hubs). A single super-hub can make every
    other structure in the graph invisible in a plot, since everything
    else gets pushed to the edges as tiny leaves - removing it reveals the
    "second tier" structure (secondary hubs, small clusters, chains) that
    is otherwise hidden behind the hub's shadow.
    """
    H = G.copy()
    H.remove_nodes_from([n for n in exclude if n in H])
    return get_readable_subgraph(H, max_nodes=max_nodes)

def plot_bar(
    labels,
    values,
    title: str,
    xlabel: str = "",
    ylabel: str = "",
    horizontal: bool = True,
    color: str = BENIGN_COLOR,
    legend_label: str | None = None,
    save_path: str | None = None,
    figsize: tuple = (7, 5),
):
    """
    A single generic labeled bar chart, used for anything counted-and-ranked
    (top nodes by triangle count, feature importances, ...) so every bar
    chart in this project shares the same look, and the same
    below-the-axes-legend convention as every other plot.
    """
    fig, ax = plt.subplots(figsize=figsize)
    if horizontal:
        ax.barh(labels, values, color=color)
        ax.set_xlabel(xlabel)
        ax.invert_yaxis()  # so the first/largest label ends up on top
    else:
        ax.bar(labels, values, color=color)
        ax.set_ylabel(ylabel)
        ax.tick_params(axis="x", rotation=30)
    ax.set_title(title)

    handles = [plt.Rectangle((0, 0), 1, 1, color=color, label=legend_label or title)]
    _bottom_legend(fig, handles, ncol=1)
    _save(fig, save_path)
    return fig

def plot_scatter_2d(
    x, y, is_malicious, title: str, xlabel: str = "", ylabel: str = "",
    save_path: str | None = None, figsize: tuple = (7, 6),
):
    """
    A generic 2D scatter colored by benign/malicious - used for the Node2Vec
    PCA projection, kept separate from the graph-drawing functions above
    since this plots points in an abstract embedding space, not node
    positions in the network itself.
    """
    import numpy as np
    x, y, is_malicious = np.asarray(x), np.asarray(y), np.asarray(is_malicious, dtype=bool)

    fig, ax = plt.subplots(figsize=figsize)
    ax.scatter(x[~is_malicious], y[~is_malicious], s=15, alpha=0.6, color=BENIGN_COLOR)
    ax.scatter(x[is_malicious], y[is_malicious], s=15, alpha=0.6, color=MALICIOUS_COLOR)
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)

    handles = [
        plt.Line2D([0], [0], marker="o", color="w", label="Benign", markerfacecolor=BENIGN_COLOR, markersize=10),
        plt.Line2D([0], [0], marker="o", color="w", label="Touched an attack flow", markerfacecolor=MALICIOUS_COLOR, markersize=10),
    ]
    _bottom_legend(fig, handles, ncol=2)
    _save(fig, save_path)
    return fig

def plot_model_comparison(results, title: str = "Model comparison", save_path: str | None = None, figsize: tuple = (9, 5)):
    """
    Grouped bar chart comparing accuracy / F1 / ROC-AUC across several
    models at once - `results` is a DataFrame indexed by model name with
    columns "accuracy", "f1", "roc_auc" (exactly what Section 11 and
    Section 12 both produce), so the same function makes the RF/XGBoost
    table and the RF/XGBoost/GCN/GraphSAGE/GAT table equally easy to put on
    one slide.
    """
    import numpy as np

    metrics = [c for c in ("accuracy", "f1", "roc_auc") if c in results.columns]
    colors = [BENIGN_COLOR, SECONDARY_COLOR, MALICIOUS_COLOR][: len(metrics)]
    n_models = len(results)
    x = np.arange(n_models)
    width = 0.8 / len(metrics)

    fig, ax = plt.subplots(figsize=figsize)
    for i, (metric, color) in enumerate(zip(metrics, colors)):
        ax.bar(x + i * width, results[metric].values, width, color=color)
    ax.set_xticks(x + width * (len(metrics) - 1) / 2)
    ax.set_xticklabels(results.index, rotation=20, ha="right")
    ax.set_ylabel("Score")
    ax.set_ylim(0, 1.05)
    ax.set_title(title)

    handles = [
        plt.Rectangle((0, 0), 1, 1, color=color, label=metric.replace("_", " ").upper())
        for metric, color in zip(metrics, colors)
    ]
    _bottom_legend(fig, handles, ncol=len(metrics))
    _save(fig, save_path)
    return fig

if __name__ == "__main__":
    import sys

    sys.path.insert(0, ".")
    from graph_construction import load_flow_logs, build_communication_graph
    from graph_features import compute_all_features

    path = sys.argv[1] if len(sys.argv) > 1 else "sample_flows.csv"
    flows = load_flow_logs(path)
    G = build_communication_graph(flows)
    features = compute_all_features(G)

    plot_graph(G, title="Sample Communication Graph", save_path="sample_graph.png")
    plot_feature_distribution(
        features, "betweenness_centrality", save_path="sample_betweenness_hist.png"
    )
    print("Saved sample_graph.png and sample_betweenness_hist.png")
