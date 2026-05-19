import numpy as np

def extract_features_from_live_packet(packet):
    """Extract features from live packets for IDS prediction"""
    # This should match exactly with your training feature extraction
    features = np.zeros(46)  # Your 46 features
    
    try:
        # Map packet fields to your training features
        # You need to customize this based on your actual training data
        
        # Example mapping (you need to adjust this):
        if 'flow_duration' in packet:
            features[0] = packet.get('flow_duration', 0)
        if 'Header_Length' in packet:
            features[1] = packet.get('Header_Length', 0)
        # ... continue for all 46 features
        
        return features
    except Exception as e:
        print(f"Feature extraction error: {e}")
        return None