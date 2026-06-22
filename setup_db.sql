CREATE DATABASE IF NOT EXISTS mnids;
USE mnids;

CREATE TABLE IF NOT EXISTS alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    protocol VARCHAR(10),
    packet_size INT,
    tcp_flags VARCHAR(20),
    alert_type VARCHAR(100),
    ml_prediction VARCHAR(100) DEFAULT 'Normal',
    confidence_score FLOAT DEFAULT 0.0,
    description TEXT,
    severity VARCHAR(20) DEFAULT 'Medium'
);

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert default accounts (In a real app, use hashed passwords)
INSERT IGNORE INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin');
INSERT IGNORE INTO users (username, password, role) VALUES ('user', 'user123', 'user');

CREATE TABLE IF NOT EXISTS flow_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    end_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45),
    source_port INT,
    destination_ip VARCHAR(45),
    destination_port INT,
    protocol VARCHAR(10),
    packet_count INT DEFAULT 1,
    byte_count INT DEFAULT 0,
    tcp_flags VARCHAR(20),
    duration_sec FLOAT DEFAULT 0,
    flow_status VARCHAR(20) DEFAULT 'Active'
);

CREATE TABLE IF NOT EXISTS logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    packet_info TEXT
);

CREATE TABLE IF NOT EXISTS scan_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    filename VARCHAR(255),
    total_flows INT,
    threats INT,
    safety_score FLOAT,
    ai_summary TEXT
);
