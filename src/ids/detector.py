# src/ids/detector.py

import numpy as np
import xgboost as xgb
import pandas as pd
from sklearn.preprocessing import StandardScaler
import logging
import joblib
import os
from src.data.cicddos_loader import CICDDoSLoader

class IDS:
    def __init__(self, config):
        self.config = config
        self.thresholds = config['ids']['detection_thresholds']
        self.buffer_zone = config['ids']['buffer_zone']
        self.model_path = config['ids']['xgb_model_path']
        self.data_path = config['ids']['data_path']
        self.scaler_path = config['ids']['scaler_path']
        
        self.model = None
        self.logger = logging.getLogger("IDS")
        
        # Initialize data loader
        self.data_loader = CICDDoSLoader(self.data_path, self.scaler_path)
        self.data_loader.load_data()
        self.scaler = self.data_loader.scaler
        
        # Performance tracking
        self.y_true = []
        self.y_pred = []
        self.y_pred_proba = []
        
        self._load_model()

    def _load_model(self):
        """Load the pre-trained XGBoost model."""
        try:
            if not os.path.exists(self.model_path):
                raise FileNotFoundError(f"Model file not found: {self.model_path}")
            
            self.model = joblib.load(self.model_path)
            self.logger.info(f"Model loaded successfully from {self.model_path}")
            
        except Exception as e:
            self.logger.error(f"Error loading model: {str(e)}")
            raise

    def get_test_data(self):
        """Get test data for experiments."""
        return self.data_loader.get_test_data()

    def detect(self, features, true_label=None):
        """
        Detect potential attacks in traffic.
        """
        try:
            # Handle both XGBoost Booster and XGBClassifier cases
            if isinstance(self.model, xgb.Booster):
                dmatrix = xgb.DMatrix(np.array([features]))
                attack_probability = self.model.predict(dmatrix)[0]
            else:  # XGBClassifier
                attack_probability = self.model.predict_proba(np.array([features]))[0][1]
            
            # Track performance if true label provided
            if true_label is not None:
                self.y_true.append(true_label)
                self.y_pred_proba.append(attack_probability)
                self.y_pred.append(1 if attack_probability >= self.thresholds['high'] else 0)
            
            # Determine risk level using thresholds and buffer zones
            risk_level = self._determine_risk_level(attack_probability)
            
            # Binary prediction
            prediction = 1 if attack_probability >= self.thresholds['high'] else 0
            
            return risk_level, attack_probability, prediction
            
        except Exception as e:
            self.logger.error(f"Error in detection: {str(e)}")
            return 'low', 0.0, 0

    def _determine_risk_level(self, probability):
        """
        Determine risk level based on probability and thresholds with buffer zones.
        """
        high_threshold = self.thresholds['high']
        medium_threshold = self.thresholds['medium']
        buffer = self.buffer_zone
        
        if probability >= high_threshold:
            return 'high'
        elif probability >= (high_threshold - buffer) and probability < high_threshold:
            return 'high_buffer'
        elif probability >= medium_threshold:
            return 'medium'
        elif probability >= (medium_threshold - buffer) and probability < medium_threshold:
            return 'medium_buffer'
        else:
            return 'low'

    def get_evaluation_metrics(self):
        """
        Calculate detection performance metrics.
        """
        if not self.y_true:
            return {}
            
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        
        metrics = {
            'accuracy': accuracy_score(self.y_true, self.y_pred),
            'precision': precision_score(self.y_true, self.y_pred),
            'recall': recall_score(self.y_true, self.y_pred),
            'f1': f1_score(self.y_true, self.y_pred)
        }
        
        return metrics

    def get_predictions(self):
        """
        Return all predictions made so far.
        """
        return {
            'y_true': self.y_true,
            'y_pred': self.y_pred,
            'y_pred_proba': self.y_pred_proba
        }

    def clear_predictions(self):
        """
        Clear stored predictions.
        """
        self.y_true = []
        self.y_pred = []
        self.y_pred_proba = []

    