# Network-Based Intrusion Detection Using Graph Features

This repository contains the implementation for the Complex Networks course project:  
**Network-Based Intrusion Detection Using Graph Features**.

We model network traffic as a graph, extract graph-theoretic features, and apply
machine learning and graph neural network (GNN) models to detect malicious behavior.

---

## Project Overview
Traditional intrusion detection systems treat network flows as isolated records.
Our project instead represents network communication as a **graph**, where:

- **Nodes** = IP addresses / devices  
- **Edges** = communication flows  
- **Edge attributes** = packets, bytes, duration, protocol  
- **Labels** = benign or attack  

We evaluate whether graph features improve intrusion detection performance.

---

## Datasets Used
- **CIC-IDS-2017** — raw, labeled network flow logs (`data/cic-ids-2017/`). Used to build
  communication graphs directly from flow data (`src/graph_construction.py`,
  `notebooks/02_graph_construction_and_visualization_ids_2017.ipynb`).
- **Kaggle NetFlow-style graph dataset** ("0.1M-Stratified") — a pre-built graph derived from
  100,000 sampled NetFlow records, provided in three variants: plain, multi, and aggregated
  (`data/kaggle/`). Used in `notebooks/01_graph_construction_and_visualization_kaggle.ipynb`.

CIC-IoT-2023, UNSW-NB15, TON_IoT, and Bot-IoT were considered during dataset selection but are
not used in the current implementation.

---

## Methods
### 1. Graph Construction
- Build communication graphs from flow logs  
- Aggregate flows by time windows  
- Add edge weights and attributes  

### 2. Graph Feature Extraction
- Degree, betweenness, closeness  
- PageRank  
- Clustering coefficient  
- Motif counts  
- Node2Vec embeddings  

### 3. Models
- Random Forest, XGBoost  
- GCN, GraphSAGE, GAT  
- Evaluation: Accuracy, F1, ROC-AUC  

---

## Project Timeline
**Week 1-2:** Dataset selection, preprocessing  
**Week 3-4:** Graph construction + feature extraction  
**Week 5-6:** ML/GNN model training  
**Week 7:** Visualization + analysis  
**Week 8:** Final report + presentation  

---

## Team Members
- Jothi Jayaraman
- Mangesh Bhattacharya
- Salmaan Kuthpudeen
- Vishnuprasath Sathyanarayanan

---

## License
[**MIT License**](https://github.com/Mangesh-Bhattacharya/graph-based-network-intrusion-detection/blob/main/LICENSE)

---

## Repository Structure

```
graph-based-network-intrusion-detection/
├── data/
│   ├── cic-ids-2017/GeneratedLabelledFlows/   # raw flow-log CSVs (one file per capture day)
│   └── kaggle/                                # pre-built graphs (plain / multi / aggregated .graphml)
├── src/
│   ├── graph_construction.py   # flow logs -> communication graph, time-windowed aggregation
│   ├── graph_features.py       # degree, closeness, betweenness, PageRank, clustering + verification checks
│   ├── visualize.py            # readable graph plots (auto-samples large graphs) and feature histograms
│   └── load_kaggle_graph.py    # loads/compares the pre-built data/kaggle/*.graphml graphs
├── notebooks/
│   ├── 01_graph_construction_and_visualization_kaggle.ipynb    # Kaggle graph dataset walkthrough
│   ├── 02_graph_construction_and_visualization_ids_2017.ipynb  # CIC-IDS-2017 flow-log walkthrough
│   └── 01_graph_construction_and_visualization.ipynb           # retired, see its first cell for why
├── requirements.txt
└── README.md
```

**Note on cloning this repository.** `data/` is tracked with [Git LFS](https://git-lfs.com/)
because the raw flow-log CSVs and pre-built graph files exceed GitHub's normal file size limits.
Install Git LFS (`git lfs install`) before cloning, or run `git lfs pull` after a normal clone,
otherwise the files in `data/` will appear as small text pointers instead of the actual data.

**Why two notebooks instead of one.** The two data sources need different
loading code (`load_kaggle_graph.py` reads pre-built `.graphml` files;
`graph_construction.py` builds a graph from raw `.csv` flow logs) and answer
different questions, so splitting them keeps each notebook focused on one
dataset and one set of real, verified numbers — a reader is never unsure
which dataset a given plot came from. Notebook 1 covers `data/kaggle/`: the
plain/multi/aggregated variants, degree distribution and hub structure,
connected components, where attacks sit structurally, feature extraction,
motif counts, Node2Vec embeddings, and Random Forest / XGBoost
classification, all on the complete, real 41,073-node graph (with two
deliberately scoped-down subsections, stated explicitly where they occur).
Notebook 2 covers `data/cic-ids-2017/`: it builds communication graphs from
scratch from raw flow logs — a benign baseline day (Monday) plus four real
attack types (DDoS, PortScan, Web Attack, Infiltration), time-window
aggregation, and feature extraction with verification checks.

The original combined notebook also had a real, since-fixed bug: it read the
first 200 rows of the DDoS attack file, which (because CIC-IDS-2017 files are
stored chronologically) are all benign, so its "attack" plot never actually
showed an attack. Notebook 2 uses a corrected `sample_labeled_flows()` helper
(`src/graph_construction.py`) that scans the file in chunks until it finds
real attack rows, wherever they occur.

**Current status of the Methods section above.** Notebook 1
(`01_graph_construction_and_visualization_kaggle.ipynb`) now covers all
three Methods sections: Graph Construction, Graph Feature Extraction
(including motif counts and Node2Vec embeddings), and Models (Random
Forest, XGBoost, GCN, GraphSAGE, GAT), with the same "real numbers, stated
scope, verification checks" standard as the rest of the project. Node2Vec
and every model are deliberately scoped to a 962-node subgraph (all
attack-touching nodes plus their immediate neighbors) rather than the full
41,073-node graph — the full graph's dominant hub makes Node2Vec's
random-walk precomputation infeasible, and a uniform random sample would be
too sparse to form a connected subgraph at all, since 95.8% of nodes have
degree exactly 1. This is explained in notebook 1 itself, where it occurs.

**One caveat on Section 12 (GCN/GraphSAGE/GAT) specifically:** unlike every
other cell in this project, that section could not be execution-tested in
the sandboxed environment used to build it — that environment's network
policy blocks the official CPU-only PyTorch package index and instead
resolves a multi-gigabyte CUDA-bundled build that doesn't fit the
time/disk available there. On a normal machine, `pip install torch` (or the
explicit CPU-only command in `requirements.txt`) is small and fast, with
none of that problem. The code follows standard PyTorch Geometric patterns
and was checked carefully, and the non-`torch` parts (building the graph's
tensors) were separately verified with plain NumPy, but please run Section
12 once before presenting and treat any error the same as any other bug in
this project.

Notebook 2 (`02_graph_construction_and_visualization_ids_2017.ipynb`)
covers Graph Construction and Graph Feature Extraction only; its samples
are intentionally small and illustrative, not sized for model training.

**Every plot in both notebooks** now has a legend placed below the axes
(not overlapping the data) and is saved as a PNG under
`notebooks/figures/` when the notebook runs, so figures can be pulled
directly into slides or the written report without a manual screenshot.

**Cross-platform note.** Both notebooks' first code cell installs
dependencies via `!{sys.executable} -m pip install -r ../requirements.txt`
— this always resolves to the exact Python running the current kernel, so
it installs correctly on Windows, macOS, and Linux, and inside any venv or
conda environment, unlike a hardcoded interpreter path.
