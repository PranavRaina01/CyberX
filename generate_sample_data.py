import pandas as pd
import numpy as np
from datetime import datetime, timedelta

def generate_sample_data(num_samples=10000):
    """Generate synthetic network traffic data for testing"""
    
    # Set random seed for reproducibility
    np.random.seed(42)
    
    # Generate features
    data = {
        'protocol_type': np.random.choice([0, 1, 2], size=num_samples),  # TCP, UDP, ICMP
        'service': np.random.choice([0, 1, 2, 3], size=num_samples),     # HTTP, FTP, SMTP, SSH
        'src_bytes': np.random.exponential(1000, num_samples).astype(int),
        'dst_bytes': np.random.exponential(800, num_samples).astype(int),
        'duration': np.random.exponential(30, num_samples).astype(int),
    }
    
    # Calculate derived features
    data['bytes_ratio'] = data['src_bytes'] / (data['dst_bytes'] + 1)
    data['total_bytes'] = data['src_bytes'] + data['dst_bytes']
    data['bytes_per_second'] = data['total_bytes'] / (data['duration'] + 1)
    
    # Generate labels (0: normal, 1: threat)
    # Make threats more likely when:
    # - bytes_ratio is very high or low
    # - total_bytes is unusually high
    # - duration is very short with high bytes
    threat_probability = (
        (np.abs(data['bytes_ratio'] - 1) > 2) * 0.3 +
        (data['total_bytes'] > np.percentile(data['total_bytes'], 95)) * 0.4 +
        ((data['duration'] < 1) & (data['total_bytes'] > np.mean(data['total_bytes']))) * 0.3
    )
    data['label'] = (np.random.random(num_samples) < threat_probability).astype(int)
    
    # Convert to DataFrame
    df = pd.DataFrame(data)
    
    # Save to CSV
    df.to_csv('UNSW_NB15.csv', index=False)
    print(f"Generated {num_samples} samples with {df['label'].sum()} threats")
    
if __name__ == '__main__':
    generate_sample_data()