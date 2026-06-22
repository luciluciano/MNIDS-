# M-NIDS: Machine Learning Network Intrusion Detection System

M-NIDS is a lightweight, high-performance security platform that combines traditional packet sniffing with Local Machine Learning (Random Forest) and Cloud-based AI (Llama-3.1) to detect and analyze network threats.

---

## � Execution & Deployment Guide

Follow these steps in order to set up and launch the entire M-NIDS ecosystem.

### 1. Prerequisites
*   **Python 3.8+** installed.
*   **MySQL Server** installed and running.
*   **Npcap** (Windows only): [Download here](https://npcap.com/). *Crucial for live packet sniffing.*

### 2. Environment Setup
Install all necessary dependencies:
```powershell
pip install -r requirements.txt
```

### 3. Database Initialization
Create the database and required tables (Alerts, Users, Scan History):
1. Open your MySQL client.
2. Run the provided SQL script:
```sql
SOURCE setup_db.sql;
```
*(Alternatively, you can run `python init_db.py` to initialize automatically via Python)*

### 4. Launching the Entire System (Recommended)
M-NIDS features an **Orchestrator** script that starts the Web Dashboard, the AI Engine, and the Live Packet Sniffer in a single command.
**Note: Open your terminal as Administrator.**
```powershell
python run_mnids.py
```
*   **Dashboard**: `http://127.0.0.1:5000`
*   **Admin Access**: `admin` / `admin123`
*   **User Access**: `user` / `user123`

---

## �📊 CSV Ingestion & Security Checking

One of the core features of M-NIDS is the ability to analyze historical traffic logs or captured datasets via CSV upload.

### 🚀 How to Check a CSV File
1.  **Access the User Portal**: Log in as a standard user (`user`/`user123`).
2.  **Navigate to 'Upload CSV'**: This section is designed for deep file analysis.
3.  **Select a Dataset**: You can use the pre-generated files in the `sample_data/` directory.
4.  **Run Analysis**: 
    - The system first uses the **MLEngine** (Random Forest) to perform row-by-row classification.
    - It calculates a **Safety Score** based on the percentage of normal vs. malicious flows.
    - It sends the aggregated metrics to the **Llama-3.1 AI** via Hugging Face for a professional summary.

### 🧪 Sample Datasets Description (`sample_data/`)
We have provided 10 diverse test files to verify the system's accuracy:

| File Name | Primary Traffic Type | Expected Result |
| :--- | :--- | :--- |
| `traffic_normal_1.csv` | Standard Office Activity | High Safety Score (95-100%) |
| `attack_ddos_high_volume.csv` | UDP Flooding (1500 bytes) | Low Safety Score (0-5%) |
| `scan_syn_stealth.csv` | TCP SYN Reconnaissance | Medium/Low Score |
| `attack_icmp_flood.csv` | ICMP (Ping) Burst | Threat Detected |
| `data_exfiltration_detect.csv` | Large payloads, long duration | Anomaly Detected |
| `traffic_mixed_daily.csv` | Realistic mix of safe and risky | Variable Score |

---

## 🔬 Data Features & ML Logic

The `MLEngine` utilizes a **Random Forest Classifier** to evaluate security posture. Below is a breakdown of the specific fields extracted from network traffic and how the model interprets them:

### 1. Packet Size (`packet_size`)
*   **Definition**: The total size of the network packet in bytes.
*   **ML Usage**: 
    - **Large packets (1400-1500 bytes)** consistent with UDP are often flagged as potential **DDoS** or **Exfiltration**.
    - **Tiny packets (40-66 bytes)** are characteristic of **TCP Scans** (SYN/ACK).

### 2. Protocol (`protocol`)
*   **Transformation**: Converted to numeric values (TCP=6, UDP=17, ICMP=1, IP=0).
*   **ML Usage**: Helps the model differentiate between attack types. For example, ICMP protocols are rarely used for high-volume traffic in normal office environments, so high frequency alerts the model to **ICMP Flooding**.

### 3. TCP Flags (`tcp_flags`)
*   **Transformation**: Converted to a bitmask value:
    - `S` (SYN) = 1
    - `A` (ACK) = 2
    - `P` (PSH) = 4
    - `F` (FIN) = 8
    - `R` (RST) = 16
*   **ML Usage**: Flags reveal the "intent" of a connection. 
    - A burst of packets with only the `S` (1) flag is a classic **SYN Scan**.
    - Flags like `FPU` (Xmas Scan) are mathematically rare and trigger high anomaly scores.

### 4. Duration (`duration`)
*   **Definition**: The time in seconds between the start and end of a packet flow.
*   **ML Usage**: 
    - **Ultra-short durations (<0.01s)** with many packets indicate **automated scripts** or floods.
    - **Long durations (>10s)** with high byte counts are analyzed for potential **data exfiltration**.

---

## � ML Model Lifecycle

The heart of M-NIDS is the `MLEngine`, which manages the entire lifecycle of the security model from data generation to real-time inference.

### 1. Model Architecture
The system employs a **Random Forest Classifier** (via `scikit-learn`). This model was chosen for its:
*   **Non-linear Detection**: Ability to find complex patterns in network flags and timing.
*   **High Resilience**: Low risk of over-fitting on small datasets.
*   **Confidence Scoring**: Provides a probability percentage (`predict_proba`) for every alert, showing how "sure" the model is about a threat.

### 2. Training Methodology
The training process (`MLEngine.train_model`) follows a hybrid approach:
*   **Data Sourcing**: The model first attempts to learn from real alerts stored in the MySQL database.
*   **Synthetic Augmentation**: If fewer than 50 real records exist, the engine automatically generates a synthetic dataset containing:
    - **Normal Baseline**: Randomized legitimate traffic.
    - **DDoS Signatures**: High-volume, static-size UDP bursts.
    - **Reconnaissance**: Low-latency, SYN-flagged TCP scans.
*   **Optimization**: Features are split using an 80/20 train-test ratio. A `LabelEncoder` is used to map string-based attack names (e.g., "DDoS Attack") to numeric categories that the algorithm can process.
*   **Persistence**: Once trained, the model and its encoder are serialized into `nids_model.pkl` and `label_encoder.pkl` for instant loading without retraining.

### 3. Prediction & Inference Logic
When a packet is captured by the sniffer or uploaded via CSV, the following logic is applied:
1.  **Feature Extraction**: The raw packet is stripped into 4 core features: `packet_size`, `protocol`, `tcp_flags`, and `duration`.
2.  **Numerical Embedding**: 
    - Protocols are mapped (TCP=6, etc.).
    - Flags are converted into a unique integer bitmask (e.g., `S` + `A` = 3).
3.  **Classification**: The numeric array is fed into the Random Forest.
4.  **Result Retrieval**: The class index is mapped back to a human-readable string (e.g., "ICMP Packet Detected"), and the confidence score is calculated based on the agreement between the internal forest "trees."

---

## �🤖 AI Security Insight
After processing, the system generates an actionable report including:
*   **Risk Explanation**: Why the traffic was flagged (e.g., "High volume of UDP traffic suggests a DDoS attempt").
*   **Safety Score**: A quantitative measure of the dataset's integrity.
*   **Actionable Steps**: 3 professional recommendations provided by the AI Analyst (Llama-3.1).

---

## 🛠️ Technical Workflow

1.  **Pre-processing**: The `MLEngine` cleans input data, handles missing flags (iterating over strings only), and normalizes column headers.
2.  **Local Inference**: Uses `nids_model.pkl` (Random Forest) to predict the outcome for every packet in the CSV.
3.  **AI Orchestration**: The `app.py` passes the stats to the Hugging Face Router, ensuring high availability across multiple LLM models.
4.  **Persistence**: Every scan—including the AI summary—is saved in the MySQL `scan_history` table for future auditing.

---

## 🚦 System Execution

To run the full suite (Sniffer + Web Dash):
```powershell
python run_mnids.py
```

To generate new test CSVs:
```powershell
python generate_test_csvs.py
```
