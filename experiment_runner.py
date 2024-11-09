# experiment_runner.py
import os
import logging
import numpy as np
from pathlib import Path
import yaml
from datetime import datetime

from src.network.network import Network
from src.ids.detector import IDS
from src.blockchain.logger import BlockchainLogger
from src.metrics.collector import MetricsCollector

class ExperimentRunner:
    def __init__(self, config_path='config/config.yaml'):
        self.config = self._load_config(config_path)
        self.setup_logging()
        self.results_dir = Path('results/data')
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.ids = IDS(self.config)
        
    def run_experiment(self, scenario_name):
        """Run single experiment scenario."""
        self.logger.info(f"Starting experiment: {scenario_name}")
        
        network = Network(self.config)
        blockchain_logger = BlockchainLogger(self.config)
        metrics_collector = MetricsCollector(self.config)
        
        network.setup_scenario(scenario_name)
        X_test, y_test = self.ids.get_test_data()
        total_steps = min(len(X_test), self.config['experiment']['timesteps'])
        
        # Track metrics
        time_series = {
            'attack_prevention_rate': [],
            'current_compromise_rate': [],
            'cumulative_compromise_rate': [],
            'honeypot_utilization_rate': [],  
            'traffic_loss_rate': [],
            'node_availability_rate': []      
        }
        
        for step in range(total_steps):
            traffic = {
                'features': X_test.iloc[step].values,
                'label': y_test[step],
                'target': 'honeypot' if y_test[step] == 1 and np.random.rand() < 0.8 else 'normal'
            }
            
            risk_level, attack_probability, prediction = self.ids.detect(
                traffic['features'],
                true_label=traffic['label']
            )
            
            result = network.process_traffic(traffic, step)
            
            if attack_probability >= self.config['ids']['detection_thresholds']['high']:
                blockchain_logger.log_attack_detection({
                    'probability': attack_probability,
                    'risk_level': risk_level,
                    'traffic': traffic
                }, step)
            
            # Store metrics for this timestep
            metrics = network.get_metrics(step)
            for metric in time_series.keys():
                if metric in metrics:
                    time_series[metric].append(metrics[metric])
            
            network.update(step)
        
        # Calculate final statistics with blockchain metrics
        final_results = {
            metric: {
                'mean': np.mean(values),
                'std': np.std(values),
                'min': np.min(values),
                'max': np.max(values),
                'time_series': values
            }
            for metric, values in time_series.items()
            if values
        }
        
        # Add blockchain metrics
        blockchain_metrics = blockchain_logger.get_performance_metrics()
        final_results['blockchain_metrics'] = {
            'avg_transaction_time': blockchain_metrics['avg_transaction_time'],
            'total_transactions': blockchain_metrics['total_transactions'],
            'failed_transactions': blockchain_metrics['failed_transactions'],
            'success_rate': blockchain_metrics['success_rate']
        }
        
        return final_results

    def _load_config(self, config_path):
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
            
    def setup_logging(self):
        log_dir = Path('results/logs')
        log_dir.mkdir(parents=True, exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(
                    log_dir / f'experiment_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
                ),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("ExperimentRunner")
