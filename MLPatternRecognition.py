import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import json
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
from colorama import Fore
import warnings
warnings.filterwarnings('ignore')

class MLPatternRecognizer:
    def __init__(self):
        self.scaler = StandardScaler()
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.attack_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.cluster_model = DBSCAN(eps=0.5, min_samples=5)
        self.feature_names = []
        self.models_trained = False
        
    def extract_features(self, transactions_data):
        """Extract features from transaction data for ML analysis"""
        features = []
        
        for address, tx_data in transactions_data.items():
            if not tx_data:
                continue
                
            # Basic statistics
            values = [float(tx.get('value', 0)) / 1e18 for tx in tx_data]
            gas_prices = [int(tx.get('gasPrice', 0)) for tx in tx_data]
            gas_used = [int(tx.get('gasUsed', 0)) for tx in tx_data]
            timestamps = [int(tx.get('timeStamp', 0)) for tx in tx_data]
            
            # Time-based features
            time_diffs = []
            if len(timestamps) > 1:
                sorted_times = sorted(timestamps)
                time_diffs = [sorted_times[i+1] - sorted_times[i] for i in range(len(sorted_times)-1)]
            
            # Calculate features
            feature_dict = {
                'address': address,
                'total_transactions': len(tx_data),
                'total_value': sum(values),
                'avg_value': np.mean(values) if values else 0,
                'std_value': np.std(values) if values else 0,
                'max_value': max(values) if values else 0,
                'min_value': min(values) if values else 0,
                'avg_gas_price': np.mean(gas_prices) if gas_prices else 0,
                'std_gas_price': np.std(gas_prices) if gas_prices else 0,
                'avg_gas_used': np.mean(gas_used) if gas_used else 0,
                'std_gas_used': np.std(gas_used) if gas_used else 0,
                'avg_time_between_tx': np.mean(time_diffs) if time_diffs else 0,
                'std_time_between_tx': np.std(time_diffs) if time_diffs else 0,
                'min_time_between_tx': min(time_diffs) if time_diffs else 0,
                'unique_counterparties': len(set([tx.get('to', '') for tx in tx_data] + [tx.get('from', '') for tx in tx_data])),
                'activity_duration': max(timestamps) - min(timestamps) if timestamps else 0,
                'weekend_activity_ratio': self._calculate_weekend_ratio(timestamps),
                'night_activity_ratio': self._calculate_night_ratio(timestamps),
                'gas_price_volatility': np.std(gas_prices) / np.mean(gas_prices) if gas_prices and np.mean(gas_prices) > 0 else 0,
                'value_concentration': self._calculate_gini_coefficient(values),
                'burst_activity_score': self._calculate_burst_score(timestamps),
                'round_number_ratio': self._calculate_round_number_ratio(values),
                'failed_tx_ratio': sum(1 for tx in tx_data if tx.get('isError', '0') == '1') / len(tx_data) if tx_data else 0
            }
            
            features.append(feature_dict)
        
        return pd.DataFrame(features)
    
    def _calculate_weekend_ratio(self, timestamps):
        """Calculate ratio of weekend transactions"""
        if not timestamps:
            return 0
        
        weekend_count = 0
        for ts in timestamps:
            dt = datetime.fromtimestamp(ts)
            if dt.weekday() >= 5:  # Saturday = 5, Sunday = 6
                weekend_count += 1
        
        return weekend_count / len(timestamps)
    
    def _calculate_night_ratio(self, timestamps):
        """Calculate ratio of night transactions (10PM - 6AM UTC)"""
        if not timestamps:
            return 0
        
        night_count = 0
        for ts in timestamps:
            dt = datetime.fromtimestamp(ts)
            if dt.hour >= 22 or dt.hour <= 6:
                night_count += 1
        
        return night_count / len(timestamps)
    
    def _calculate_gini_coefficient(self, values):
        """Calculate Gini coefficient for value distribution"""
        if not values or len(values) < 2:
            return 0
        
        sorted_values = sorted(values)
        n = len(sorted_values)
        index = np.arange(1, n + 1)
        return (2 * np.sum(index * sorted_values)) / (n * np.sum(sorted_values)) - (n + 1) / n
    
    def _calculate_burst_score(self, timestamps):
        """Calculate burst activity score"""
        if len(timestamps) < 3:
            return 0
        
        sorted_times = sorted(timestamps)
        time_diffs = [sorted_times[i+1] - sorted_times[i] for i in range(len(sorted_times)-1)]
        
        # Count rapid sequences (< 1 hour between transactions)
        rapid_sequences = sum(1 for diff in time_diffs if diff < 3600)
        return rapid_sequences / len(time_diffs) if time_diffs else 0
    
    def _calculate_round_number_ratio(self, values):
        """Calculate ratio of round number transactions"""
        if not values:
            return 0
        
        round_count = 0
        for value in values:
            if value > 0:
                # Check if value is a round number (ends in multiple zeros)
                value_str = f"{value:.18f}".rstrip('0').rstrip('.')
                if len(value_str) <= 3:  # Very round numbers
                    round_count += 1
        
        return round_count / len(values)
    
    def detect_anomalies(self, features_df):
        """Detect anomalous addresses using Isolation Forest"""
        if features_df.empty:
            return pd.DataFrame()
        
        # Prepare features for anomaly detection
        feature_cols = [col for col in features_df.columns if col != 'address']
        X = features_df[feature_cols].fillna(0)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Detect anomalies
        anomaly_scores = self.anomaly_detector.fit_predict(X_scaled)
        anomaly_probs = self.anomaly_detector.score_samples(X_scaled)
        
        # Add results to dataframe
        features_df['anomaly_score'] = anomaly_scores
        features_df['anomaly_probability'] = anomaly_probs
        features_df['is_anomaly'] = anomaly_scores == -1
        
        self.feature_names = feature_cols
        
        return features_df[features_df['is_anomaly']].sort_values('anomaly_probability')
    
    def cluster_addresses(self, features_df):
        """Cluster addresses by behavior patterns"""
        if features_df.empty:
            return features_df
        
        feature_cols = [col for col in features_df.columns if col not in ['address', 'anomaly_score', 'anomaly_probability', 'is_anomaly']]
        X = features_df[feature_cols].fillna(0)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Perform clustering
        cluster_labels = self.cluster_model.fit_predict(X_scaled)
        features_df['cluster'] = cluster_labels
        
        return features_df
    
    def train_attack_classifier(self, labeled_data):
        """Train a classifier to identify known attack patterns"""
        if labeled_data.empty or 'label' not in labeled_data.columns:
            print(f"{Fore.YELLOW}No labeled data available for training attack classifier")
            return False
        
        feature_cols = [col for col in labeled_data.columns if col not in ['address', 'label', 'anomaly_score', 'anomaly_probability', 'is_anomaly', 'cluster']]
        X = labeled_data[feature_cols].fillna(0)
        y = labeled_data['label']
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train classifier
        self.attack_classifier.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.attack_classifier.predict(X_test_scaled)
        
        print(f"{Fore.GREEN}Attack Classifier Performance:")
        print(classification_report(y_test, y_pred))
        
        self.models_trained = True
        return True
    
    def predict_attack_type(self, features_df):
        """Predict attack types for new addresses"""
        if not self.models_trained:
            print(f"{Fore.YELLOW}Attack classifier not trained. Training with sample data...")
            self._create_sample_training_data(features_df)
        
        feature_cols = [col for col in features_df.columns if col not in ['address', 'anomaly_score', 'anomaly_probability', 'is_anomaly', 'cluster']]
        X = features_df[feature_cols].fillna(0)
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Predict
        predictions = self.attack_classifier.predict(X_scaled)
        prediction_probs = self.attack_classifier.predict_proba(X_scaled)
        
        features_df['predicted_attack_type'] = predictions
        features_df['prediction_confidence'] = np.max(prediction_probs, axis=1)
        
        return features_df
    
    def _create_sample_training_data(self, features_df):
        """Create sample training data based on heuristics"""
        training_data = features_df.copy()
        
        # Label based on behavioral patterns
        def assign_label(row):
            if row['burst_activity_score'] > 0.8 and row['avg_time_between_tx'] < 300:
                return 'sandwich_attack'
            elif row['round_number_ratio'] > 0.5 and row['unique_counterparties'] > 100:
                return 'money_laundering'
            elif row['night_activity_ratio'] > 0.8 and row['failed_tx_ratio'] > 0.1:
                return 'bot_activity'
            elif row['max_value'] > 1000 and row['total_transactions'] < 10:
                return 'whale_manipulation'
            else:
                return 'normal'
        
        training_data['label'] = training_data.apply(assign_label, axis=1)
        self.train_attack_classifier(training_data)
    
    def analyze_temporal_patterns(self, features_df):
        """Analyze temporal patterns in the data"""
        temporal_analysis = {
            'peak_activity_hours': {},
            'day_of_week_patterns': {},
            'suspicious_timing_clusters': []
        }
        
        # This would require access to raw timestamp data
        # For now, return basic analysis
        if 'night_activity_ratio' in features_df.columns:
            night_addresses = features_df[features_df['night_activity_ratio'] > 0.7]
            temporal_analysis['suspicious_timing_clusters'] = night_addresses['address'].tolist()
        
        return temporal_analysis
    
    def generate_ml_report(self, features_df, output_file='ml_analysis_report.json'):
        """Generate comprehensive ML analysis report"""
        # Detect anomalies
        anomalies = self.detect_anomalies(features_df.copy())
        
        # Cluster addresses
        clustered_data = self.cluster_addresses(features_df.copy())
        
        # Predict attack types
        predictions = self.predict_attack_type(clustered_data.copy())
        
        # Analyze temporal patterns
        temporal_patterns = self.analyze_temporal_patterns(features_df)
        
        # Generate summary statistics
        cluster_summary = predictions.groupby('cluster').agg({
            'address': 'count',
            'total_value': 'mean',
            'predicted_attack_type': lambda x: x.value_counts().index[0] if len(x) > 0 else 'unknown'
        }).to_dict('index')
        
        attack_type_summary = predictions['predicted_attack_type'].value_counts().to_dict()
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'analysis_type': 'machine_learning_pattern_recognition',
            'total_addresses_analyzed': len(features_df),
            'anomalies_detected': len(anomalies),
            'clusters_found': len(set(predictions['cluster'].dropna())),
            'anomalous_addresses': anomalies[['address', 'anomaly_probability']].to_dict('records'),
            'cluster_summary': cluster_summary,
            'attack_type_distribution': attack_type_summary,
            'high_risk_predictions': predictions[
                (predictions['predicted_attack_type'] != 'normal') & 
                (predictions['prediction_confidence'] > 0.7)
            ][['address', 'predicted_attack_type', 'prediction_confidence']].to_dict('records'),
            'temporal_patterns': temporal_patterns,
            'feature_importance': self._get_feature_importance() if self.models_trained else {},
            'model_metrics': {
                'anomaly_detection_contamination': 0.1,
                'classifier_trained': self.models_trained,
                'clustering_algorithm': 'DBSCAN'
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"{Fore.GREEN}ML analysis report saved to {output_file}")
        return report
    
    def _get_feature_importance(self):
        """Get feature importance from trained models"""
        if not self.models_trained or not hasattr(self.attack_classifier, 'feature_importances_'):
            return {}
        
        importance_dict = {}
        if self.feature_names:
            for i, importance in enumerate(self.attack_classifier.feature_importances_):
                if i < len(self.feature_names):
                    importance_dict[self.feature_names[i]] = float(importance)
        
        # Sort by importance
        return dict(sorted(importance_dict.items(), key=lambda x: x[1], reverse=True))
    
    def save_models(self, model_dir='models'):
        """Save trained models"""
        import os
        os.makedirs(model_dir, exist_ok=True)
        
        joblib.dump(self.scaler, f'{model_dir}/scaler.pkl')
        joblib.dump(self.anomaly_detector, f'{model_dir}/anomaly_detector.pkl')
        joblib.dump(self.attack_classifier, f'{model_dir}/attack_classifier.pkl')
        joblib.dump(self.cluster_model, f'{model_dir}/cluster_model.pkl')
        
        print(f"{Fore.GREEN}Models saved to {model_dir}/")
    
    def load_models(self, model_dir='models'):
        """Load pre-trained models"""
        try:
            self.scaler = joblib.load(f'{model_dir}/scaler.pkl')
            self.anomaly_detector = joblib.load(f'{model_dir}/anomaly_detector.pkl')
            self.attack_classifier = joblib.load(f'{model_dir}/attack_classifier.pkl')
            self.cluster_model = joblib.load(f'{model_dir}/cluster_model.pkl')
            self.models_trained = True
            print(f"{Fore.GREEN}Models loaded from {model_dir}/")
            return True
        except FileNotFoundError:
            print(f"{Fore.YELLOW}No pre-trained models found in {model_dir}/")
            return False

# Example usage
if __name__ == "__main__":
    import requests
    import os
    
    # Sample function to fetch transaction data
    def fetch_sample_data(api_key, addresses):
        transactions_data = {}
        
        for address in addresses[:3]:  # Limit for demo
            params = {
                'module': 'account',
                'action': 'txlist',
                'address': address,
                'startblock': 0,
                'endblock': 99999999,
                'sort': 'desc',
                'apikey': api_key
            }
            
            try:
                response = requests.get("https://api.etherscan.io/api", params=params)
                data = response.json().get("result", [])
                if isinstance(data, list):
                    transactions_data[address] = data[:100]  # Limit transactions
            except Exception as e:
                print(f"Error fetching data for {address}: {e}")
                transactions_data[address] = []
        
        return transactions_data
    
    # Initialize ML analyzer
    analyzer = MLPatternRecognizer()
    
    # Load addresses
    try:
        with open('attackersOutput.txt', 'r') as f:
            addresses = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        addresses = ['0x1234567890abcdef1234567890abcdef12345678']  # Example
    
    api_key = os.getenv('ETHERSCAN_API_KEY')
    if not api_key:
        print(f"{Fore.RED}Please set ETHERSCAN_API_KEY environment variable")
        # Create sample data for demo
        sample_data = {addr: [] for addr in addresses[:3]}
    else:
        print(f"{Fore.YELLOW}Fetching transaction data...")
        sample_data = fetch_sample_data(api_key, addresses)
    
    if sample_data:
        print(f"{Fore.YELLOW}Extracting features...")
        features = analyzer.extract_features(sample_data)
        
        print(f"{Fore.YELLOW}Running ML analysis...")
        report = analyzer.generate_ml_report(features)
        
        print(f"{Fore.YELLOW}Saving models...")
        analyzer.save_models()
        
        print(f"{Fore.GREEN}ML pattern recognition analysis complete!")
    else:
        print(f"{Fore.RED}No transaction data available for analysis")