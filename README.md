# CyberTelX — AI-Driven Cybersecurity & Transactional Behaviour Correlation

**Team Name**: TheMysterious  
**Team Members**: Manish Praveen Athvar, Krithik K  
**Submission Date**: 7/9/2026  
**Live Site**: [cybertelx-threat-correlation.vercel.app](https://cybertelx-threat-correlation.vercel.app)

[![Deploy with Vercel](https://vercel.com/button)](https://cybertelx-threat-correlation.vercel.app)


CyberTelX is a next-generation real-time threat intelligence and fraud correlation platform designed for enterprise banking environments. It bridges the gap between cybersecurity network telemetry and core transaction activity to proactively stop security breaches, block fraudulent transfers, and monitor rising post-quantum harvesting threats (Harvest-Now-Decrypt-Later).

## 🚀 Key Features

* **Cross-Domain Graph Correlation**: Combines SIEM (security logins, EDR alerts, network firewall telemetry) and Transaction records (transfers, wire logs, merchant payments) into a unified heterogeneous entity relationship graph.
* **Proactive Real-Time AI Detection**: Uses Graph Neural Networks (GNN) and temporal transformers to identify patterns (like credential sharing or account takeover chains) with an average latency of **14ms** — blocking suspicious transactions *before* settlement.
* **Post-Quantum Cryptography (PQC) Sentinel**: Monitors TLS negotiation handshakes for forced classical cipher downgrades and scans network flow logs for bulk data transfers that match **Harvest-Now-Decrypt-Later (HNDL)** attack profiles.
* **Explainable AI (XAI) Diagnostics**: Translates multi-dimensional neural network vectors and SHAP feature importances into plain-English narratives to reduce false positive fatigue and provide audit-ready documentation for SOC analysts and compliance regulators.

## 🛠️ Technology Stack

* **Data Ingestion**: Apache Kafka (stream queuing), Apache Flink (real-time stream joins).
* **AI & Machine Learning**: PyTorch Geometric (Graph Neural Networks), HuggingFace Transformers (LLM narratives), XGBoost & Scikit-Learn (classification baseline).
* **Security & Cryptography**: HashiCorp Vault (secrets & keys rotation), NIST-compliant CRYSTALS-Kyber and Dilithium libraries.
* **Infrastructure**: Docker & Kubernetes, Terraform Infrastructure-as-Code.
* **Analyst Interface**: Vanilla HTML, CSS, JavaScript dynamic dashboard with SVG-based live GNN graph rendering.

## 📁 Repository Structure

```
cybertelx-threat-correlation/
├── dashboard/               # Frontend Analyst Dashboard Code
│   ├── index.html           # Shell Layout & KPIs
│   ├── styles.css           # Premium Dark Mode Stylesheet
│   └── app.js               # SVG Graph Rendering & Mock Data Streams
├── src/                     # Core Backend Processing Logic
│   ├── simulator.py         # Real-Time Telemetry & Transaction Stream Generator
│   ├── gnn_correlation.py   # Heterogeneous networkx Graph Link-Risk Evaluator
│   ├── quantum_monitor.py   # HNDL Exfiltration Sensor & TLS Downgrade Auditor
│   └── explainability.py    # SHAP Attribution & Natural Language Narrative Engine
├── assets/                  # Embedded presentation assets & screenshots
│   ├── cybertelx_architecture.jpg
│   └── cybertelx_dashboard.jpg
├── LICENSE                  # MIT Open-Source License
└── README.md                # System Documentation (This file)
```

## ⚙️ Quick Start

### 1. Run the Backend Simulation
To verify the telemetry simulator, GNN risk scoring, and post-quantum exfiltration monitors, execute the core modules:

```bash
# Run the simulator to see normal vs. anomalous data logs
python src/simulator.py

# Evaluate GNN risk graph paths
python src/gnn_correlation.py

# Audit TLS handshakes and check for quantum HNDL exfiltration signals
python src/quantum_monitor.py
```

### 2. View the Live Analyst Dashboard
To interact with the analyst interface, simply open the dashboard file in any standard web browser:

```bash
# Open the web dashboard
start dashboard/index.html
```
Click on any correlated alert in the queue to view its dynamic Graph connection path, SHAP feature importance percentages, cryptographic cipher analysis, and auto-generated AI diagnostic narrative!
