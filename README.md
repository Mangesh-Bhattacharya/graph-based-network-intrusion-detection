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
[**MIT License**](https://opensource.org/licenses/MIT)

---

## 📂 Repository Structure (in-progress)
