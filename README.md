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
- **Kaggle**

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

## 📂 Repository Structure (in-progress)

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
│   ├── 02_graph_construction_and_visualization_ids_2017.ipynb # data/cic-ids-2017/ only: builds
│   └── 01_graph_construction_and_visualization.ipynb           # retired - superseded by the two
├── requirements.txt
└── README.md

```

**Why two notebooks instead of one.**

The loading code for the two data sources is intentionally different. The script that loads a pre‑built .graphml file (``load_kaggle_graph.py``) is not the same as the code that loads raw flow logs from a Kaggle dataset. This separation keeps each notebook focused on one dataset and one set of verified numbers. The graph_construction.py file builds a graph directly from the .csv flow logs and answers a series of questions based on that graph, so a reader never has to wonder which dataset produced the results.

There is also a real, previously fixed bug worth noting. The first 200 rows of the DDoS file are benign because the file is stored in chronological order. In the original combined notebook, the first 200 rows were sampled as if they contained attacks, which meant the notebook never actually saw any attack traffic in that portion of the file.

For this notebook, we use a helper function called ``sample_labeled_flows()``, with the corrected implementation in ``sample_labeled_flows.py``. It reads the file in chunks and searches for genuine attack rows wherever they appear, so the sample reflects real labeled traffic instead of just the earliest rows in the file.

Sections 2 (Node2Vec embeddings, motif counts) and 3 (Random Forest, XGBoost,
GCN, GraphSAGE, GAT) of the Methods above are not yet implemented the
current code covers Graph Construction and the non-embedding half of
Feature Extraction, with an emphasis on results that are easy to read and
easy to double-check.
