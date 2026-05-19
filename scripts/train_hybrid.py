import os
import sys
import pandas as pd
import numpy as np
from tqdm import tqdm
import warnings
warnings.filterwarnings('ignore')

# Add the hybrid model to path
sys.path.append('../scripts')
from hybrid_model import MemoryEfficientHybridDLMLModel

def train_hybrid_model():
    """Train the hybrid model on CICIoT2023 dataset with memory efficiency"""
    
    # Configuration - UPDATE THIS PATH to match your dataset location
    DATASET_DIRECTORY = '../datasets/CICIoT2023/'
    HYBRID_MODEL_FILENAME = "../models/hybrid_dl_ml_model.pkl"
    
    # Feature columns
    X_columns = [
        'flow_duration', 'Header_Length', 'Protocol Type', 'Duration',
        'Rate', 'Srate', 'Drate', 'fin_flag_number', 'syn_flag_number',
        'rst_flag_number', 'psh_flag_number', 'ack_flag_number',
        'ece_flag_number', 'cwr_flag_number', 'ack_count',
        'syn_count', 'fin_count', 'urg_count', 'rst_count', 
        'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP',
        'UDP', 'DHCP', 'ARP', 'ICMP', 'IPv', 'LLC', 'Tot sum', 'Min',
        'Max', 'AVG', 'Std', 'Tot size', 'IAT', 'Number', 'Magnitue',
        'Radius', 'Covariance', 'Variance', 'Weight', 
    ]
    y_column = 'label'
    
    # Load and prepare data
    print("📁 Loading dataset files...")
    df_sets = [k for k in os.listdir(DATASET_DIRECTORY) if k.endswith('.csv')]
    df_sets.sort()
    training_sets = df_sets[:int(len(df_sets)*.8)]
    test_sets = df_sets[int(len(df_sets)*.8):]
    
    print(f"Found {len(training_sets)} training files and {len(test_sets)} test files")
    
    # Load training data in chunks to save memory
    print("🔄 Loading training data in chunks...")
    X_chunks = []
    y_chunks = []
    
    # Process training files with progress bar
    for train_set in tqdm(training_sets, desc="Loading training files"):
        try:
            # Read only necessary columns to save memory
            df_chunk = pd.read_csv(os.path.join(DATASET_DIRECTORY, train_set), 
                                 usecols=X_columns + [y_column])
            X_chunks.append(df_chunk[X_columns])
            y_chunks.extend(df_chunk[y_column].values)
        except Exception as e:
            print(f"Warning: Could not load {train_set}: {e}")
            continue
    
    if not X_chunks:
        raise ValueError("No training data loaded!")
    
    # Concatenate all chunks
    X_train = pd.concat(X_chunks, ignore_index=True)
    y_train = np.array(y_chunks)
    
    # Clear memory
    del X_chunks, y_chunks
    
    # Apply grouping (8-class classification)
    print("🎯 Applying class grouping...")
    dict_7classes = {
        'DDoS-RSTFINFlood': 'DDoS', 'DDoS-PSHACK_Flood': 'DDoS', 'DDoS-SYN_Flood': 'DDoS',
        'DDoS-UDP_Flood': 'DDoS', 'DDoS-TCP_Flood': 'DDoS', 'DDoS-ICMP_Flood': 'DDoS',
        'DDoS-SynonymousIP_Flood': 'DDoS', 'DDoS-ACK_Fragmentation': 'DDoS',
        'DDoS-UDP_Fragmentation': 'DDoS', 'DDoS-ICMP_Fragmentation': 'DDoS',
        'DDoS-SlowLoris': 'DDoS', 'DDoS-HTTP_Flood': 'DDoS', 'DoS-UDP_Flood': 'DoS',
        'DoS-SYN_Flood': 'DoS', 'DoS-TCP_Flood': 'DoS', 'DoS-HTTP_Flood': 'DoS',
        'Mirai-greeth_flood': 'Mirai', 'Mirai-greip_flood': 'Mirai', 'Mirai-udpplain': 'Mirai',
        'Recon-PingSweep': 'Recon', 'Recon-OSScan': 'Recon', 'Recon-PortScan': 'Recon',
        'VulnerabilityScan': 'Recon', 'Recon-HostDiscovery': 'Recon', 'DNS_Spoofing': 'Spoofing',
        'MITM-ArpSpoofing': 'Spoofing', 'BenignTraffic': 'Benign', 'BrowserHijacking': 'Web',
        'Backdoor_Malware': 'Web', 'XSS': 'Web', 'Uploading_Attack': 'Web', 'SqlInjection': 'Web',
        'CommandInjection': 'Web', 'DictionaryBruteForce': 'BruteForce'
    }
    
    y_train_grouped = np.array([dict_7classes.get(k, 'Unknown') for k in y_train])
    
    # Determine number of classes
    unique_classes = np.unique(y_train_grouped)
    num_classes = len(unique_classes)
    
    print(f"🧮 Training with {num_classes} classes: {list(unique_classes)}")
    print(f"📊 Training data shape: {X_train.shape}")
    
    # Memory optimization: Use subset for testing if system memory is low
    USE_SUBSET = True  # Set to False to use all data
    if USE_SUBSET:
        print("🔧 Using 20% subset for memory efficiency...")
        subset_size = len(X_train) // 5
        indices = np.random.choice(len(X_train), subset_size, replace=False)
        X_train = X_train.iloc[indices]
        y_train_grouped = y_train_grouped[indices]
        print(f"📊 Reduced training data shape: {X_train.shape}")
    
    # Initialize and train memory-efficient hybrid model
    print("🤖 Initializing Memory-Efficient Hybrid DL-ML Model...")
    hybrid_model = MemoryEfficientHybridDLMLModel(num_classes=num_classes)
    
    # Train the model with memory-efficient settings
    print("🚀 Starting memory-efficient training...")
    print("⚠️  This may take a while. Training in progress...")
    
    history = hybrid_model.fit(
        X_train.values, 
        y_train_grouped, 
        epochs=15,           # Reduced epochs for memory
        batch_size=2048,     # Larger batches for efficiency
        validation_split=0.1 # Smaller validation split
    )
    
    # Create models directory
    os.makedirs('../models', exist_ok=True)
    
    # Save the model
    print("💾 Saving trained model...")
    hybrid_model.save(HYBRID_MODEL_FILENAME)
    
    # Evaluate on test data (using smaller subset for memory)
    print("🧪 Evaluating on test data subset...")
    evaluate_model_performance(hybrid_model, test_sets, DATASET_DIRECTORY, X_columns, y_column, dict_7classes)
    
    return hybrid_model, history

def evaluate_model_performance(hybrid_model, test_sets, dataset_dir, X_columns, y_column, class_mapping, max_test_files=5):
    """Evaluate model performance on a subset of test data"""
    
    from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score, classification_report, confusion_matrix
    import seaborn as sns
    import matplotlib.pyplot as plt
    
    y_test_all = []
    y_pred_all = []
    
    # Use only first few test files to save memory and time
    test_files_to_use = test_sets[:max_test_files]
    
    print(f"🧪 Testing on {len(test_files_to_use)} test files...")
    
    for test_set in tqdm(test_files_to_use, desc="Testing"):
        try:
            # Read only necessary columns
            df_test = pd.read_csv(os.path.join(dataset_dir, test_set), 
                                usecols=X_columns + [y_column])
            X_test = df_test[X_columns].values
            
            # Apply class mapping
            y_test = [class_mapping.get(k, 'Unknown') for k in df_test[y_column]]
            y_test_all.extend(y_test)
            
            # Make predictions in batches
            y_pred = hybrid_model.predict(X_test, batch_size=5000)
            y_pred_all.extend(y_pred)
            
        except Exception as e:
            print(f"Warning: Could not process {test_set}: {e}")
            continue
    
    if not y_test_all:
        print("❌ No test data processed!")
        return
    
    # Calculate metrics
    accuracy = accuracy_score(y_test_all, y_pred_all)
    recall = recall_score(y_test_all, y_pred_all, average='macro')
    precision = precision_score(y_test_all, y_pred_all, average='macro')
    f1 = f1_score(y_test_all, y_pred_all, average='macro')
    
    print("\n" + "="*60)
    print("✅ HYBRID MODEL PERFORMANCE RESULTS")
    print("="*60)
    print(f"🎯 Accuracy:  {accuracy:.4f}")
    print(f"📈 Recall:    {recall:.4f}")
    print(f"🎯 Precision: {precision:.4f}")
    print(f"⚖️  F1-Score:  {f1:.4f}")
    print("="*60)
    
    # Detailed classification report
    print("\n📊 Detailed Classification Report:")
    print("="*60)
    print(classification_report(y_test_all, y_pred_all, digits=4))
    
    # Confusion Matrix (optional - requires matplotlib)
    try:
        plt.figure(figsize=(10, 8))
        cm = confusion_matrix(y_test_all, y_pred_all)
        classes = sorted(set(y_test_all))
        
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=classes, yticklabels=classes)
        plt.title('Confusion Matrix - Hybrid DL-ML Model')
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        plt.xticks(rotation=45)
        plt.yticks(rotation=0)
        plt.tight_layout()
        plt.savefig('../models/confusion_matrix.png', dpi=300, bbox_inches='tight')
        print("📈 Confusion matrix saved as 'confusion_matrix.png'")
        plt.close()
    except Exception as e:
        print(f"Note: Could not generate confusion matrix: {e}")
    
    return accuracy, recall, precision, f1

def memory_usage_optimization():
    """Optimize memory usage for large dataset processing"""
    import gc
    import tensorflow as tf
    
    # Clear TensorFlow session
    tf.keras.backend.clear_session()
    
    # Force garbage collection
    gc.collect()
    
    # Limit GPU memory growth (if using GPU)
    gpus = tf.config.experimental.list_physical_devices('GPU')
    if gpus:
        try:
            for gpu in gpus:
                tf.config.experimental.set_memory_growth(gpu, True)
        except RuntimeError as e:
            print(f"GPU memory config error: {e}")

if __name__ == "__main__":
    print("="*70)
    print("🚀 CICIoT2023 Memory-Efficient Hybrid DL-ML Model Training")
    print("="*70)
    
    # Apply memory optimizations
    memory_usage_optimization()
    
    try:
        # Train the hybrid model
        hybrid_model, history = train_hybrid_model()
        
        print("\n" + "🎉 TRAINING COMPLETED SUCCESSFULLY!")
        print("="*70)
        print("📁 Model saved to: ../models/hybrid_dl_ml_model.pkl")
        print("📁 DL component saved to: dl_model_component.h5")
        print("="*70)
        
        # Print training history summary
        if history and hasattr(history, 'history'):
            final_train_acc = history.history['accuracy'][-1]
            final_val_acc = history.history['val_accuracy'][-1] if 'val_accuracy' in history.history else 'N/A'
            print(f"📊 Final Training Accuracy: {final_train_acc:.4f}")
            if final_val_acc != 'N/A':
                print(f"📊 Final Validation Accuracy: {final_val_acc:.4f}")
        
    except MemoryError as e:
        print("\n❌ MEMORY ERROR: System ran out of memory!")
        print("💡 Solutions:")
        print("   1. Set USE_SUBSET = True to use smaller dataset")
        print("   2. Close other applications to free up memory")
        print("   3. Reduce batch_size in hybrid_model.fit()")
        print("   4. Use a machine with more RAM")
        print(f"   Error details: {e}")
        
    except Exception as e:
        print(f"\n❌ ERROR during training: {e}")
        print("💡 Check if:")
        print("   - Dataset path is correct")
        print("   - All required packages are installed")
        print("   - You have sufficient disk space")
        
    finally:
        # Clean up
        memory_usage_optimization()