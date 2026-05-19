import threading
import time
import queue
import numpy as np
from collections import deque, defaultdict
from ids_logger import logger

class AsyncPredictor:
    def __init__(self, model, batch_size=10, max_queue_size=100):
        self.model = model
        self.batch_size = batch_size
        self.packet_queue = queue.Queue(maxsize=max_queue_size)
        self.result_queue = queue.Queue()
        self.is_running = False
        self.processing_thread = None
        self.stats = {
            'packets_processed': 0,
            'threats_detected': 0,
            'avg_processing_time': 0,
            'last_update': time.time()
        }
        
    def start(self):
        """Start the async prediction thread"""
        self.is_running = True
        self.processing_thread = threading.Thread(target=self._process_packets, daemon=True)
        self.processing_thread.start()
        logger.logger.info("🔄 Async predictor started")
        
    def stop(self):
        """Stop the async prediction thread"""
        self.is_running = False
        if self.processing_thread:
            self.processing_thread.join(timeout=5)
        logger.logger.info("🛑 Async predictor stopped")
        
    def add_packet(self, packet):
        """Add packet to processing queue (non-blocking)"""
        try:
            self.packet_queue.put(packet, block=False)
            return True
        except queue.Full:
            # Queue full, drop packet to prevent lag
            return False
            
    def get_results(self):
        """Get prediction results (non-blocking)"""
        results = []
        while not self.result_queue.empty():
            try:
                results.append(self.result_queue.get_nowait())
            except queue.Empty:
                break
        return results
        
    def _process_packets(self):
        """Main processing loop running in separate thread"""
        batch = []
        processing_times = deque(maxlen=100)  # Keep last 100 processing times
        
        while self.is_running:
            try:
                # Get packet with timeout to allow checking is_running
                packet = self.packet_queue.get(timeout=0.1)
                batch.append(packet)
                
                # Process batch when we have enough packets or after timeout
                if len(batch) >= self.batch_size:
                    self._process_batch(batch, processing_times)
                    batch = []
                    
            except queue.Empty:
                # Process remaining packets in batch
                if batch:
                    self._process_batch(batch, processing_times)
                    batch = []
                continue
            except Exception as e:
                logger.logger.error(f"❌ Prediction error: {e}")
                continue
                
        # Process any remaining packets before shutdown
        if batch:
            self._process_batch(batch, processing_times)

    def _process_batch(self, batch, processing_times):
        
        start_time = time.time()
        try:
            features_batch = []
            valid_packets = []

            # Extract features
            for packet in batch:
                features = self._extract_features(packet)
                if features is not None:
                    features_batch.append(features)
                    valid_packets.append(packet)

            if features_batch:
                X_batch = np.array(features_batch)
                predictions = self.model.predict(X_batch)

                # Get confidence for each prediction
                if hasattr(self.model, "predict_proba"):
                    probas = self.model.predict_proba(X_batch)
                    # probability of predicted class
                    probs_for_pred = [probas[i][np.argmax(probas[i])] for i in range(len(predictions))]
                else:
                    # fallback: if your model returns tuple (label, confidence)
                    probs_for_pred = []
                    new_predictions = []
                    for pred in predictions:
                        if isinstance(pred, (tuple, list)) and len(pred) == 2:
                            label, conf = pred
                            new_predictions.append(label)
                            probs_for_pred.append(conf / 100 if conf > 1 else conf)
                        else:
                            new_predictions.append(pred)
                            probs_for_pred.append(1.0)
                    predictions = new_predictions

                # Apply threshold logic
                for i, (packet, prediction) in enumerate(zip(valid_packets, predictions)):
                    confidence = probs_for_pred[i]

                    # If confidence < 0.7, mark as Benign
                    if prediction != "Benign" and confidence < 0.7:
                        prediction = "Benign"

                    # Always store string for GUI
                    packet['threat_level'] = str(prediction)
                    packet['is_attack'] = prediction != "Benign"

                    # Log prediction
                    logger.log_prediction(packet, prediction, confidence)

                    # Update stats
                    self.stats['packets_processed'] += 1
                    if packet['is_attack']:
                        self.stats['threats_detected'] += 1

                    # Send to result queue
                    self.result_queue.put(packet)

        except Exception as e:
            logger.logger.error(f"❌ Batch processing error: {e}")

        finally:
            processing_time = time.time() - start_time
            processing_times.append(processing_time)
            self.stats['avg_processing_time'] = np.mean(processing_times) if processing_times else 0


    def _extract_features(self, packet):
       
        try:
            features = np.zeros(46)  # Your 46 features
            
            # Basic feature extraction (CUSTOMIZE THIS BASED ON YOUR TRAINING DATA)
            features[0] = packet.get('length', 0)
            
            # Protocol mapping
            protocol_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'ARP': 2}
            features[2] = protocol_map.get(packet.get('protocol', 'Unknown'), 0)
            
            # Port information
            features[18] = packet.get('sport', 0) if 'sport' in packet else 0
            features[19] = packet.get('dport', 0) if 'dport' in packet else 0
            
            # Add more feature extraction based on your training...s
            
            return features
            
        except Exception as e:
            logger.logger.error(f"❌ Feature extraction error: {e}")
            return None
            
    def get_stats(self):
        """Get current statistics"""
        return self.stats.copy()