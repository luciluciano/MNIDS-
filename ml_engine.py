import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib
import os
from config import Database

class MLEngine:
    def __init__(self):
        self.model_path = "nids_model.pkl"
        self.encoder_path = "label_encoder.pkl"
        self.model = None
        self.le = LabelEncoder()
        self.db = Database(db_name="mnids")
        
        # Standard features we extract from traffic
        self.feature_columns = ['packet_size', 'protocol_num', 'tcp_flags_num', 'duration']
        
        # Load existing model if available
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            if os.path.exists(self.encoder_path):
                self.le = joblib.load(self.encoder_path)

    def protocol_to_num(self, proto):
        protos = {"TCP": 6, "UDP": 17, "ICMP": 1, "IP": 0}
        return protos.get(proto, 0)

    def flags_to_num(self, flags):
        # Sparse binary representation of common flags
        flag_map = {"S": 1, "A": 2, "P": 4, "F": 8, "R": 16, "N/A": 0}
        val = 0
        
        # Handle NaN or non-string values from pandas
        if not isinstance(flags, str):
            return 0
            
        for char in flags:
            val += flag_map.get(char, 0)
        return val

    def train_model(self):
        print("[INIT] Fetching data for training...")
        # Get data from alerts and flows
        alerts = self.db.fetchall("SELECT packet_size, protocol, tcp_flags, alert_type FROM alerts")
        
        if len(alerts) < 50:
            print("[INFO] Not enough real data. Generating synthetic data for training...")
            data = self._generate_synthetic_data()
        else:
            print(f"[INFO] Found {len(alerts)} records. Preparing training set...")
            df = pd.DataFrame(alerts)
            df['protocol_num'] = df['protocol'].apply(self.protocol_to_num)
            df['tcp_flags_num'] = df['tcp_flags'].apply(self.flags_to_num)
            df['duration'] = np.random.uniform(0.1, 2.0, len(df)) # Placeholder for duration
            data = df[['packet_size', 'protocol_num', 'tcp_flags_num', 'duration', 'alert_type']]

        X = data[self.feature_columns]
        y = self.le.fit_transform(data['alert_type'])
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)
        
        # Save model
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.le, self.encoder_path)
        
        accuracy = self.model.score(X_test, y_test)
        print(f"[TRAIN] Model Trained! Accuracy: {accuracy*100:.2f}%")
        return accuracy

    def predict(self, packet_size, protocol, tcp_flags, duration):
        if self.model is None:
            # Fallback if no model exists
            return "Unknown (No Model)", 0.0

        proto_num = self.protocol_to_num(protocol)
        flags_num = self.flags_to_num(tcp_flags)
        
        features = np.array([[packet_size, proto_num, flags_num, duration]])
        prediction_idx = self.model.predict(features)[0]
        confidence = np.max(self.model.predict_proba(features))
        
        attack_type = self.le.inverse_transform([prediction_idx])[0]
        return attack_type, round(float(confidence), 2)

    def _generate_synthetic_data(self):
        # Helper to create a base model when project is new
        rows = []
        # Normal Traffic
        for _ in range(200):
            rows.append([np.random.randint(60, 1500), 6, np.random.randint(0, 32), np.random.uniform(0.1, 5), 'Normal'])
        # SYN Scan
        for _ in range(50):
            rows.append([66, 6, 1, np.random.uniform(0.01, 0.1), 'Possible SYN Scan'])
        # ICMP Flood
        for _ in range(50):
            rows.append([98, 1, 0, np.random.uniform(0.01, 0.05), 'ICMP Packet Detected'])
        # DDoS
        for _ in range(50):
            rows.append([1500, 17, 0, np.random.uniform(0.001, 0.01), 'DDoS Attack'])
        
        return pd.DataFrame(rows, columns=self.feature_columns + ['alert_type'])

    def scan_csv(self, df):
        # Normalize columns if needed
        col_map = {
            'packet_size': ['packet_size', 'length', 'size'],
            'protocol': ['protocol', 'proto'],
            'tcp_flags': ['tcp_flags', 'flags'],
            'duration': ['duration', 'time']
        }
        
        for standard, aliases in col_map.items():
            if standard not in df.columns:
                for alias in aliases:
                    if alias in df.columns:
                        df[standard] = df[alias]
                        break
                if standard not in df.columns:
                    # Default values
                    if standard == 'packet_size': df[standard] = 64
                    elif standard == 'protocol': df[standard] = 'TCP'
                    elif standard == 'tcp_flags': df[standard] = 'S'
                    elif standard == 'duration': df[standard] = 0.1
        
        # Clean data: Fill NaNs to avoid 'float is not iterable' or 'float not a string' errors
        df['packet_size'] = pd.to_numeric(df['packet_size'], errors='coerce').fillna(64)
        df['duration'] = pd.to_numeric(df['duration'], errors='coerce').fillna(0.1)
        df['protocol'] = df['protocol'].fillna('TCP').astype(str)
        df['tcp_flags'] = df['tcp_flags'].fillna('').astype(str)

        threats = 0
        total = len(df)
        
        for _, row in df.iterrows():
            prediction, confidence = self.predict(row['packet_size'], row['protocol'], row['tcp_flags'], row['duration'])
            if prediction != 'Normal':
                threats += 1
        
        safety_score = round(((total - threats) / total) * 100, 2) if total > 0 else 100
        return total, threats, safety_score

if __name__ == "__main__":
    engine = MLEngine()
    engine.train_model()
