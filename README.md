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
