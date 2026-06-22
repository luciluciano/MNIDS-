# M-NIDS: Machine Learning & Data Architecture

This document provides a deep dive into how M-NIDS processes network data, trains its intelligence, and performs security classifications.

---

## 📂 CSV Data Structure

To analyze traffic via CSV, M-NIDS expects a specific set of features. The system includes a **normalization layer** that automatically maps common aliases to our standard fields.

### Core Features (Used by ML)
| Field | Type | Description | ML Rationale |
| :--- | :--- | :--- | :--- |
| `packet_size` | Integer | Total bytes in the packet. | Helps detect floods (large packets) vs scans (small packets). |
| `protocol` | String | TCP, UDP, or ICMP. | Directs the model to protocol-specific attack signatures. |
| `tcp_flags`| String | S, A, P, F, R, etc. | Reveals connection intent (e.g., SYN for scanning). |
| `duration` | Float | Flow time in seconds. | Identifies automated bursts (short) vs exfiltration (long). |

### Metadata Fields (For Logging)
*   `source_ip` / `dest_ip`: Used for IP-based filtering and alert attribution.
*   `timestamp`: Records when the flow occurred for historical analysis.

---

## 🛠️ ML Model Creation

M-NIDS uses a **Random Forest Classifier** as its primary detection engine.

### Why Random Forest?
1.  **Attribute Independence**: It handles different types of data (binary flags + numeric sizes) without requiring complex scaling.
2.  **Ensemble Learning**: By using multiple "decision trees," the model reduces the risk of false positives from noisy network spikes.
3.  **Efficiency**: It provides near-instant inference (sub-1ms), which is critical for real-time packet sniffing.

---

## 🏋️ Training Pipeline

The training process is automated via `ml_engine.py` and follows these specific stages:

### 1. Data Ingestion
The engine pulls data from two sources:
*   **Active Database**: Real alerts previously logged by the system.
*   **Synthetic Generator**: If the database is empty, the engine creates **200+ synthetic samples** representing four scenarios: Normal, SYN Scan, ICMP Flood, and DDoS.

### 2. Feature Engineering
Before the data enters the model, it is transformed:
*   **Protocol Mapping**: String protocols are converted to standard IANA numbers (TCP=6, etc).
*   **Flag Bitmasking**: TCP flags are converted into a unique integer using power-of-two mapping (S=1, A=2, P=4...).
*   **Label Encoding**: String-based attack names (e.g., "DDoS") are indexed into numeric classes using `LabelEncoder`.

### 3. Training & Validation
*   **Split**: Data is divided into **80% Training** and **20% Testing**.
*   **Fitting**: The Random Forest is fit using 100 internal estimators (trees).
*   **Persistence**: The resulting model is saved as `nids_model.pkl` and the encoder as `label_encoder.pkl`.

---

## ⚡ Prediction & Scoring

When a new flow is detected (either live or via CSV), the following happens:

1.  **Vectorization**: The flow metrics are converted into a 1D numeric array `[packet_size, proto_num, flags_num, duration]`.
2.  **Classification**: The model predicts the numeric class and calculates a **Probability Score** (Confidence).
3.  **Safety Calculation**: For CSV uploads, the system calculates a global **Safety Score**:
    `((Total Rows - Threat Rows) / Total Rows) * 100`
4.  **AI Analysis**: The final metrics are sent to the **Llama-3.1 AI Agent** to provide a human-readable summary of the findings.
