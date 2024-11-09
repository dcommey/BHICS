# train_model.py

import os
import numpy as np
import xgboost as xgb
from sklearn.preprocessing import StandardScaler
import joblib
from src.data.cicddos_loader import CICDDoSLoader

def create_xgboost_model():
    """Create and configure XGBoost classifier."""
    return xgb.XGBClassifier(
        n_estimators=200,
        learning_rate=0.1,
        max_depth=6,
        min_child_weight=1,
        gamma=0,
        subsample=0.8,
        colsample_bytree=0.8,
        objective='binary:logistic',
        eval_metric=['error', 'logloss'],
        random_state=42,
        n_jobs=-1,
        early_stopping_rounds=10
    )

def train_and_save_model():
    # Paths
    data_path = 'data/prepared_data/prepared_data_cicddos2019_tftp.npz'
    scaler_path = 'data/prepared_data/feature_scaler_cicddos2019_tftp.joblib'
    model_output_path = 'models/ids_xgb_model_tftp.joblib'
    
    print("Loading data...")
    data_loader = CICDDoSLoader(data_path, scaler_path)
    data_loader.load_data()
    
    # Get training data
    X_train, y_train = data_loader.get_train_data()
    X_test, y_test = data_loader.get_test_data()
    
    print("Creating and training model...")
    model = create_xgboost_model()
    
    # Train the model
    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=True
    )
    
    # Create models directory if it doesn't exist
    os.makedirs('models', exist_ok=True)
    
    print(f"Saving model to {model_output_path}")
    joblib.dump(model, model_output_path)
    
    # Quick evaluation
    y_pred = model.predict(X_test)
    accuracy = (y_pred == y_test).mean()
    print(f"Test accuracy: {accuracy:.4f}")

if __name__ == "__main__":
    train_and_save_model()