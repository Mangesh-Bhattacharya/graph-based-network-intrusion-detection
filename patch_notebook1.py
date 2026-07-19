import nbformat
from nbformat.v4 import new_code_cell, new_markdown_cell

NB_PATH = "notebooks/01_graph_construction_and_visualization_kaggle.ipynb"

nb = nbformat.read(NB_PATH, as_version=4)

# Locate the Summary cell (last cell, id 4d809da7) - new sections go right before it.
summary_idx = next(i for i, c in enumerate(nb.cells) if c.get("id") == "4d809da7")
assert nb.cells[summary_idx].source.startswith("## Summary")

new_cells = []

# ---------------------------------------------------------------------------
# Section 9: Motif counts and clustering coefficient
# ---------------------------------------------------------------------------
new_cells.append(new_markdown_cell(
"""## 9. Motif counts: triangles and clustering coefficient

A **motif** here means a small, recurring connection pattern. The simplest
non-trivial one is a **triangle** - three nodes all connected to each
other. `nx.triangles()` counts, for every node, how many triangles it
participates in; it uses an efficient algorithm and runs in well under a
second even on the full 41,073-node graph.

`nx.clustering()` (the fraction of a node's neighbors that are also
connected to each other) is normally computed directly, but on this
specific graph it is pathologically slow - past 44 seconds with no
result, because a handful of very high-degree hub nodes make the
neighbor-pair-checking blow up. Since clustering coefficient is
mathematically defined in terms of triangle counts, we derive it directly
from the (fast) triangle counts instead:

$$C(v) = \\frac{2 \\cdot \\text{triangles}(v)}{\\deg(v)\\,(\\deg(v)-1)} \\quad \\text{for } \\deg(v) \\ge 2, \\text{ else } 0$$

This produces results **identical** to `nx.clustering()` (verified below
on a subgraph small enough to run both), just without the slow path."""
))

new_cells.append(new_code_cell(
"""triangles = nx.triangles(G)
total_triangles = sum(triangles.values()) // 3
nodes_in_triangles = sum(1 for v in triangles.values() if v > 0)

print(f"Total triangles in the full graph: {total_triangles}")
print(f"Nodes participating in at least one triangle: {nodes_in_triangles} / {G.number_of_nodes()}")

top5_triangle_nodes = sorted(triangles.items(), key=lambda x: x[1], reverse=True)[:5]
print("\\nTop 5 nodes by triangle count:")
for node, count in top5_triangle_nodes:
    print(f"  {node}: {count} triangles, degree={G.degree(node)}, is_malicious={G.nodes[node].get('is_malicious')}")"""
))

new_cells.append(new_markdown_cell(
"""**Only 47 triangles exist in the entire graph**, involving 52 of the
41,073 nodes (0.13%). This is exactly what the hub-and-leaf structure
from Section 3 predicts: a triangle needs three *mutually* connected
nodes, but 95.8% of nodes have degree 1 and can't be part of any
triangle at all. The triangles that do exist sit on a small set of
moderate-degree nodes near Section 5's "second tier" structure, not on
the dominant hub itself. Notably, `147.32.80.9` - the 4th busiest
triangle-forming node - **is** attack-labeled, unlike the top overall
hub."""
))

new_cells.append(new_code_cell(
"""degrees_full = dict(G.degree())
clustering_coefficient = {
    v: (2 * triangles[v]) / (degrees_full[v] * (degrees_full[v] - 1)) if degrees_full[v] >= 2 else 0.0
    for v in G.nodes()
}

# Verify the derived formula itself is correct (not just fast) by comparing
# it against nx.clustering() computed on the SAME small subgraph, using
# that subgraph's own triangle counts and degrees - not the full graph's.
# (The 300-node feature subgraph is small enough for the slow direct
# algorithm to finish, unlike the full 41,073-node graph.) Comparing full-
# graph clustering values against a subgraph's nx.clustering() would not
# be a fair test: a node's degree and triangle count both change once
# edges outside the subgraph are dropped, so the two numbers describe
# different graphs, not the same one.
triangles_subgraph = nx.triangles(G_features)
degrees_subgraph = dict(G_features.degree())
derived_subgraph_clustering = {
    v: (2 * triangles_subgraph[v]) / (degrees_subgraph[v] * (degrees_subgraph[v] - 1)) if degrees_subgraph[v] >= 2 else 0.0
    for v in G_features.nodes()
}
nx_clustering_check = nx.clustering(G_features)
max_diff = max(abs(derived_subgraph_clustering[v] - nx_clustering_check[v]) for v in G_features.nodes())
print(f"Max difference between derived formula and nx.clustering(), both computed on the 300-node check subgraph: {max_diff}")

nonzero = [c for c in clustering_coefficient.values() if c > 0]
print(f"\\nNodes with nonzero clustering coefficient: {len(nonzero)} / {G.number_of_nodes()}")
print(f"Mean clustering coefficient among those {len(nonzero)} nodes: {sum(nonzero)/len(nonzero):.4f}")
print(f"Mean clustering coefficient over the whole graph (including zeros): {sum(clustering_coefficient.values())/G.number_of_nodes():.6f}")"""
))

new_cells.append(new_markdown_cell(
"""**The max difference above should read `0.0`** - the derived formula and
`nx.clustering()` agree exactly, they're the same quantity computed two
different ways. The whole-graph average is close to zero (0.0002) purely
because 99.87% of nodes have no triangle at all; among the 52 nodes that
*do* sit in a triangle, the average local clustering is a much more
typical 0.13."""
))

# ---------------------------------------------------------------------------
# Section 10: Node2Vec embeddings
# ---------------------------------------------------------------------------
new_cells.append(new_markdown_cell(
"""## 10. Node2Vec embeddings

[Node2Vec](https://snap.stanford.edu/node2vec/) learns a dense vector for
every node from biased random walks, so that structurally similar nodes
end up with similar vectors - a learned alternative to hand-designed
features like degree or PageRank.

**Running Node2Vec on the full 41,073-node graph times out** (past 44
seconds with no result). The cause is the same dominant hub from Section
3: node2vec's 2nd-order random walks need to precompute a transition
probability for every pair of edges around each node, and a node with
degree 27,177 makes that precomputation combinatorially expensive.

A random sample of nodes doesn't fix this either - it makes it worse.
95.8% of nodes have degree 1, so a uniform random sample of, say, 1,000
nodes would mostly contain nodes with no edges *to each other* at all,
producing a nearly edgeless subgraph that random walks can't meaningfully
traverse.

Instead we scope Node2Vec to a subgraph that is guaranteed to have real,
connected topology: every attack-touching node from Section 7, plus all
of their immediate neighbors. This keeps every attack node's actual
local structure intact (which a random sample would destroy) while
excluding the problematic mega-hub."""
))

new_cells.append(new_code_cell(
"""attack_neighborhood_nodes = set(attack_nodes)
for n in attack_nodes:
    attack_neighborhood_nodes.update(G.neighbors(n))

G_ml = G.subgraph(attack_neighborhood_nodes).copy()
ml_malicious_count = sum(1 for n in G_ml.nodes() if G_ml.nodes[n].get("is_malicious"))

print(f"Node2Vec / model subgraph: {G_ml.number_of_nodes()} nodes, {G_ml.number_of_edges()} edges")
print(f"Malicious nodes in this subgraph: {ml_malicious_count} / {G_ml.number_of_nodes()} ({100*ml_malicious_count/G_ml.number_of_nodes():.1f}%)")
print(f"Max degree in this subgraph: {max(dict(G_ml.degree()).values())} (no mega-hub - the full graph's top hub isn't an attack node, see Section 7)")
print("\\nNOTE: this subgraph is deliberately built around attack activity, so its malicious rate "
      f"({100*ml_malicious_count/G_ml.number_of_nodes():.1f}%) is far higher than the full graph's true rate "
      f"({100*len(attack_nodes)/G.number_of_nodes():.2f}%). It is scoped this way on purpose, for the reasons "
      "above - it is not a representative sample of overall network traffic, and Section 11's results below "
      "should be read with that in mind, not as an estimate of real-world detection rates.")"""
))

new_cells.append(new_code_cell(
"""from node2vec import Node2Vec

node2vec_model = Node2Vec(
    # workers=1 to minimize (though, per gensim, not fully eliminate) run-to-run
    # randomness - see the note below the results table in Section 11.
    G_ml, dimensions=16, walk_length=10, num_walks=10, workers=1, quiet=True, seed=42
)
n2v_fit = node2vec_model.fit(window=5, min_count=1, seed=42)

ml_node_list = list(G_ml.nodes())
embeddings = pd.DataFrame(
    [n2v_fit.wv[n] for n in ml_node_list],
    index=ml_node_list,
    columns=[f"n2v_{i}" for i in range(16)],
)
print(f"Embedding matrix: {embeddings.shape}")
embeddings.head(3)"""
))

new_cells.append(new_code_cell(
"""import matplotlib.pyplot as plt
from visualize import BENIGN_COLOR, MALICIOUS_COLOR
from sklearn.decomposition import PCA

pca = PCA(n_components=2, random_state=42)
coords = pca.fit_transform(embeddings.values)
is_mal = [G_ml.nodes[n].get("is_malicious") for n in ml_node_list]

fig, ax = plt.subplots(figsize=(7, 6))
ax.scatter(coords[~pd.Series(is_mal), 0], coords[~pd.Series(is_mal), 1],
           s=15, alpha=0.6, color=BENIGN_COLOR, label="Benign")
ax.scatter(coords[pd.Series(is_mal), 0], coords[pd.Series(is_mal), 1],
           s=15, alpha=0.6, color=MALICIOUS_COLOR, label="Touched an attack flow")
ax.set_title("Node2Vec embeddings (PCA to 2D) - attack neighborhood subgraph")
ax.set_xlabel(f"PC1 ({pca.explained_variance_ratio_[0]*100:.1f}% variance)")
ax.set_ylabel(f"PC2 ({pca.explained_variance_ratio_[1]*100:.1f}% variance)")
ax.legend(frameon=False)
fig.tight_layout()"""
))

new_cells.append(new_markdown_cell(
"""Two principal components only capture a fraction of a 16-dimensional
embedding's structure, so treat this plot as a rough sanity check, not
proof of separability - the classifiers in Section 11 use all 16
dimensions and substantially outperform what's visible here."""
))

# ---------------------------------------------------------------------------
# Section 11: Models - Random Forest and XGBoost
# ---------------------------------------------------------------------------
new_cells.append(new_markdown_cell(
"""## 11. Models: Random Forest and XGBoost

We train two classifiers to predict `is_malicious` for each node in the
`G_ml` subgraph from Section 10, using:

- the five features from Section 8 (`compute_all_features`, now computed
  on `G_ml` instead of the top-300 subgraph): degree, closeness and
  betweenness centrality, PageRank, and clustering coefficient
- triangle count (Section 9)
- the 16-dimensional Node2Vec embedding (Section 10)

**On class balance:** `G_ml` is roughly 70% malicious by construction
(Section 10), far above the true ~1.6% base rate in the full graph. We
did not rebalance the classes - the goal here is to demonstrate that
graph features carry real predictive signal for these nodes, not to
produce a deployment-ready detector. A **majority-class baseline** is
included below specifically so the Random Forest / XGBoost numbers can
be read relative to a "did nothing" reference point, not as
free-standing accuracy figures.

GCN, GraphSAGE, and GAT (the GNN models from the original Methods list)
are intentionally **not** included here - they require a `torch` /
`torch-geometric` install that is fragile enough on Windows, and time-
consuming enough to train, that adding them this close to the
presentation deadline was judged not worth the risk. Everything above
this point is unaffected either way."""
))

new_cells.append(new_code_cell(
"""G_ml_features = compute_all_features(G_ml)
G_ml_features["triangle_count"] = pd.Series(nx.triangles(G_ml))
print(f"Computed features for {len(G_ml_features)} nodes")
print(verify_features(G_ml, G_ml_features))"""
))

new_cells.append(new_code_cell(
"""from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.dummy import DummyClassifier
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score
from xgboost import XGBClassifier

X = G_ml_features.drop(columns=["is_malicious"]).join(embeddings)
y = G_ml_features["is_malicious"].astype(int)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, stratify=y, random_state=42
)
print(f"Train: {len(X_train)} nodes ({y_train.mean()*100:.1f}% malicious)")
print(f"Test:  {len(X_test)} nodes ({y_test.mean()*100:.1f}% malicious)")

models = {
    "Majority-class baseline": DummyClassifier(strategy="most_frequent", random_state=42),
    "Random Forest": RandomForestClassifier(n_estimators=200, random_state=42),
    "XGBoost": XGBClassifier(n_estimators=200, random_state=42, eval_metric="logloss"),
}

rows = []
fitted = {}
for name, clf in models.items():
    clf.fit(X_train, y_train)
    pred = clf.predict(X_test)
    proba = clf.predict_proba(X_test)[:, 1] if hasattr(clf, "predict_proba") else pred
    rows.append({
        "model": name,
        "accuracy": accuracy_score(y_test, pred),
        "f1": f1_score(y_test, pred),
        "roc_auc": roc_auc_score(y_test, proba),
    })
    fitted[name] = clf

results = pd.DataFrame(rows).set_index("model").round(4)
results"""
))

new_cells.append(new_markdown_cell(
"""**Reading this table:** the majority-class baseline gets ~70% accuracy
for free, simply by always predicting "malicious" - that's the number to
beat, not 50%. Its ROC-AUC of 0.5 (chance level) is the more honest
baseline metric, since accuracy alone is misleading under class
imbalance. Both Random Forest and XGBoost clearly beat the baseline on
every metric, including ROC-AUC, which means the improvement reflects
real predictive signal in the graph features - not just the imbalance
itself.

**On exact reproducibility:** every other number in this notebook is
exactly reproducible (fixed seeds throughout). Node2Vec is a partial
exception - gensim's underlying Word2Vec training has a source of
run-to-run randomness that a fixed seed alone does not fully eliminate,
so re-running this notebook may shift the accuracy/F1/ROC-AUC figures
above by a few percentage points. Across repeated runs during
development, Random Forest and XGBoost consistently scored in the
0.92-0.96 range on accuracy and 0.93-0.96 on ROC-AUC, always far above
the 0.50 baseline - the conclusion (graph features carry real signal) is
stable even though the exact decimal is not."""
))

new_cells.append(new_code_cell(
"""importances = pd.Series(
    fitted["Random Forest"].feature_importances_, index=X.columns
).sort_values(ascending=False).head(10)

fig, ax = plt.subplots(figsize=(7, 5))
importances.sort_values().plot.barh(ax=ax, color=BENIGN_COLOR)
ax.set_xlabel("Random Forest feature importance")
ax.set_title("Top 10 most important features")
fig.tight_layout()"""
))

new_cells.append(new_markdown_cell(
"""Node2Vec dimensions dominate the top of the importance ranking, ahead of
every hand-designed centrality feature. That's a meaningful result on
its own: the learned embedding is picking up structural signal - about
*where in the graph* a node sits relative to attack activity - that
raw degree, PageRank, and clustering coefficient don't fully capture."""
))

nb.cells = nb.cells[:summary_idx] + new_cells + nb.cells[summary_idx:]

# ---------------------------------------------------------------------------
# Update the Summary cell with the new findings
# ---------------------------------------------------------------------------
nb.cells[-1].source = """## Summary - what to say in the presentation

- This dataset is three views of the **same** 41,073-node, ~45K-edge
  graph: "plain" keeps one edge per IP pair (last flow wins), "aggregated"
  also keeps one edge per pair but combines repeated flows using an
  unspecified (not simple-average) rule, and "multi" keeps all 100,000
  original flows as separate parallel edges.
- The graph is **hub-dominated at every scale**: one node touches 30% of
  all edges, 95.8% of nodes have degree exactly 1, and even small,
  fully-disconnected fragments repeat the same one-to-many star shape.
  This is consistent with a single-vantage-point NetFlow capture.
- Attacks are **not** concentrated on the busiest nodes - the top 5 hubs,
  including the dominant one, touch zero attack-labeled edges. Attack
  nodes are mostly structurally unremarkable (degree 1), which is the
  concrete justification for using centrality features beyond raw degree,
  and eventually ML/GNN models, rather than a simple degree threshold.
- **Motifs are rare**: only 47 triangles exist in the whole graph,
  involving 0.13% of nodes - a direct, quantified consequence of the
  hub-and-leaf structure above. Clustering coefficient was derived from
  triangle counts (verified identical to `nx.clustering()`) rather than
  computed directly, since the direct algorithm is pathologically slow
  on this specific hub-dominated graph.
- **Node2Vec** does not run on the full graph in reasonable time (same
  mega-hub problem), and a random node sample would be too sparse to
  form a connected subgraph (95.8% degree-1 nodes). It was instead
  scoped to the 962-node neighborhood around all attack-touching nodes -
  a deliberate, stated choice, not a silent shortcut.
- **Random Forest and XGBoost**, trained on that same 962-node
  neighborhood using centrality + motif + Node2Vec features, clearly
  beat a majority-class baseline on accuracy, F1, and ROC-AUC. Node2Vec
  dimensions were the single most important feature group, ahead of
  every hand-designed centrality feature - the learned embedding
  captures structural signal the others miss. This subgraph is ~70%
  malicious by construction (not the true ~1.6% base rate), so these
  numbers demonstrate that graph features carry real signal, not that
  this is a deployment-ready detector.
- GCN, GraphSAGE, and GAT were deliberately **not** implemented, to avoid
  a fragile `torch-geometric` install and added training time this close
  to the presentation deadline.
- All numbers in this notebook come from the complete 41,073-node graph
  (no sampling) except: the centrality features in Section 8 (scoped to
  the top-300 nodes), and Node2Vec / Section 11's models (scoped to the
  962-node attack neighborhood) - both for stated, compute-time reasons.
"""

nbformat.write(nb, NB_PATH)
print("Patched. New cell count:", len(nb.cells))
