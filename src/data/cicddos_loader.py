import os
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import joblib

class CICDDoSLoader:
    def __init__(self, data_path, scaler_path):
        self.data_file = data_path
        self.scaler_file = scaler_path
        self.data = None
        self.scaler = None
        self.feature_names = None

    def load_data(self):
        try:
            print(f"Loading data from {self.data_file}")
            if not os.path.exists(self.data_file):
                raise FileNotFoundError(f"Data file not found: {self.data_file}")
            
            self.data = np.load(self.data_file, allow_pickle=True)
            
            print(f"Loading scaler from {self.scaler_file}")
            if not os.path.exists(self.scaler_file):
                raise FileNotFoundError(f"Scaler file not found: {self.scaler_file}")
            
            self.scaler = joblib.load(self.scaler_file)
            self.feature_names = self.data['feature_names']
            print("Data and scaler loaded successfully.")
            print(f"Loaded data shapes:")
            print(f"X_train: {self.data['X_train'].shape}")
            print(f"y_train: {self.data['y_train'].shape}")
            print(f"X_test: {self.data['X_test'].shape}")
            print(f"y_test: {self.data['y_test'].shape}")
            return self
        except Exception as e:
            print(f"Error loading data: {str(e)}")
            raise

    def _check_data_loaded(self):
        if self.data is None:
            raise ValueError("Data not loaded. Call load_data() first.")

    def get_train_data(self):
        self._check_data_loaded()
        X_train = pd.DataFrame(self.data['X_train'], columns=self.feature_names)
        return X_train, self.data['y_train']

    def get_test_data(self):
        self._check_data_loaded()
        X_test = pd.DataFrame(self.data['X_test'], columns=self.feature_names)
        return X_test, self.data['y_test']

    def get_feature_names(self):
        self._check_data_loaded()
        return self.feature_names

    def transform_new_data(self, X):
        self._check_data_loaded()
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X, columns=self.feature_names)
        else:
            X = X.reindex(columns=self.feature_names)
        return pd.DataFrame(self.scaler.transform(X), columns=self.feature_names)

    def generate_traffic(self, num_packets, attack_type=None):
        self._check_data_loaded()
        
        X, y = self.get_train_data()
        
        if attack_type is not None:
            subset_indices = np.where(y == attack_type)[0]
            if len(subset_indices) == 0:
                raise ValueError(f"No samples found for attack_type {attack_type}")
        else:
            subset_indices = np.arange(len(y))

        sampled_indices = np.random.choice(subset_indices, size=num_packets, replace=True)
        sampled_X = X.iloc[sampled_indices]
        sampled_y = y[sampled_indices]

        df = sampled_X.copy()
        df['Label'] = sampled_y

        print(f"Generated {num_packets} traffic samples")
        print(f"Attack samples: {sum(sampled_y)}")
        print(f"Normal samples: {num_packets - sum(sampled_y)}")

        return df

    def get_attack_types(self):
        self._check_data_loaded()
        attack_types = np.unique(self.data['y_train'])
        print(f"Attack types: {attack_types}")
        return attack_types

    def get_data_summary(self):
        self._check_data_loaded()
        summary = {
            'num_features': len(self.feature_names),
            'num_train_samples': len(self.data['y_train']),
            'num_test_samples': len(self.data['y_test']),
            'attack_types': self.get_attack_types().tolist(),
            'class_distribution': np.bincount(self.data['y_train']).tolist()
        }
        print("Data summary:")
        for key, value in summary.items():
            print(f"{key}: {value}")
        return summary

    def __str__(self):
        return f"CICDDoSLoader with {len(self.feature_names) if self.feature_names else 'unknown number of'} features"