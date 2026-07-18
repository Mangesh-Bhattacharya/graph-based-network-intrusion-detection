# Network-Based Intrusion Detection Using Graph Features

This repository contains the implementation for the Complex Networks course project:  
**Network-Based Intrusion Detection Using Graph Features**.

We model network traffic as a graph, extract graph-theoretic features, and apply
machine learning and graph neural network (GNN) models to detect malicious behavior.

---

## 🔍 Project Overview
Traditional intrusion detection systems treat network flows as isolated records.
Our project instead represents network communication as a **graph**, where:

- **Nodes** = IP addresses / devices  
- **Edges** = communication flows  
- **Edge attributes** = packets, bytes, duration, protocol  
- **Labels** = benign or attack  

We evaluate whether graph features improve intrusion detection performance.

---

## 📊 Datasets Used
- **CIC-IDS-2017**  
- **CIC-IoT-2023**  
- **UNSW-NB15**  
- (Optional) TON_IoT, Bot-IoT

All datasets contain flow-level network traffic suitable for graph construction.

---

## 🧠 Methods
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

## 📅 Project Timeline
**Week 1-2:** Dataset selection, preprocessing  
**Week 3-4:** Graph construction + feature extraction  
**Week 5-6:** ML/GNN model training  
**Week 7:** Visualization + analysis  
**Week 8:** Final report + presentation  

---

## 👥 Team Members
- Jothi Jayaraman  
- Mangesh Bhattacharya 
- Salmaan Kuthpudeen
- Vishnuprasath Sathyanarayanan

---

## 📄 License
[**MIT License**](https://github.com/Mangesh-Bhattacharya/graph-based-network-intrusion-detection/blob/main/LICENSE)

---

## 📂 Repository Structure

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
│   ├── 01_graph_construction_and_visualization_kaggle.ipynb   # data/kaggle/ only: plain vs multi vs
│   │   aggregated variants, degree distribution & hub structure, connected components, where attacks
│   │   sit structurally, and feature extraction — all on the complete, real 41,073-node graph
│   ├── 02_graph_construction_and_visualization_ids_2017.ipynb # data/cic-ids-2017/ only: builds
│   │   communication graphs from scratch from raw flow logs — a benign baseline day (Monday) plus
│   │   four real attack types (DDoS, PortScan, Web Attack, Infiltration), time-window aggregation,
│   │   and feature extraction with verification checks
│   └── 01_graph_construction_and_visualization.ipynb           # retired — superseded by the two
│       notebooks above; kept only so existing links aren't broken, see its first cell for why
├── requirements.txt
└── README.md
```

**Why two notebooks instead of one.** The two data sources need different
loading code (`load_kaggle_graph.py` reads pre-built `.graphml` files;
`graph_construction.py` builds a graph from raw `.csv` flow logs) and answer
different questions, so splitting them keeps each notebook focused on one
dataset and one set of real, verified numbers — a reader is never unsure
which dataset a given plot came from. The original combined notebook also
had a real, since-fixed bug: it read the first 200 rows of the DDoS attack
file, which (because CIC-IDS-2017 files are stored chronologically) are all
benign, so its "attack" plot never actually showed an attack. Notebook 2 uses
a corrected `sample_labeled_flows()` helper (`src/graph_construction.py`)
that scans the file in chunks until it finds real attack rows, wherever they
occur.

Sections 2 (Node2Vec embeddings, motif counts) and 3 (Random Forest, XGBoost,
GCN, GraphSAGE, GAT) of the Methods above are not yet implemented - the
current code covers Graph Construction and the non-embedding half of
Feature Extraction, with an emphasis on results that are easy to read and
easy to double-check.
