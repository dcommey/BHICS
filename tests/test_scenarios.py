# tests/test_scenarios.py

import sys
import os
import yaml
import numpy as np
import logging
from pathlib import Path
import json
import time

project_root = str(Path(__file__).parent.parent)
sys.path.append(project_root)

from src.network.network import Network
from src.metrics.collector import MetricsCollector
from src.ids.detector import IDS
from src.blockchain.logger import BlockchainLogger

class ScenarioValidator:
    def __init__(self, config):
        self.config = config
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("ScenarioValidator")
        
        try:
            # Initialize components
            self.network = Network(config)
            self.metrics = MetricsCollector(config)
            self.ids = IDS(config)
            self.blockchain_logger = BlockchainLogger(config)
            
            # Get test data once
            self.logger.info("Loading test data...")
            self.X_test, self.y_test = self.ids.get_test_data()
            self.logger.info("Test data loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing components: {str(e)}")
            raise
        
    def generate_test_traffic(self, num_samples=100, scenario_name=None):
        """Generate test traffic using actual dataset features with proper conversion handling."""
        traffic_samples = []
        attack_prop = self.config['traffic']['attack_proportion']
        max_samples = min(len(self.X_test), num_samples)
        
        # Get indices for attack and normal samples
        attack_indices = np.where(self.y_test == 1)[0]
        normal_indices = np.where(self.y_test == 0)[0]
        
        # Calculate number of samples needed
        num_attacks = int(max_samples * attack_prop)
        num_normal = max_samples - num_attacks
        
        self.logger.info(
            f"Generating traffic: {num_attacks} attacks, {num_normal} normal samples "
            f"(attack proportion: {attack_prop})"
        )
        
        # Sample indices
        sampled_attack_indices = np.random.choice(attack_indices, size=num_attacks, replace=True)
        sampled_normal_indices = np.random.choice(normal_indices, size=num_normal, replace=True)
        
        # Combine and shuffle indices
        all_indices = np.concatenate([sampled_attack_indices, sampled_normal_indices])
        np.random.shuffle(all_indices)
        
        # Get thresholds from config
        high_threshold = self.config['ids']['detection_thresholds']['high']
        buffer_zone = self.config['ids']['buffer_zone']
        
        routing_decisions = {'honeypot': 0, 'normal': 0}
        
        for idx in all_indices:
            is_attack = self.y_test[idx] == 1
            features = self.X_test.iloc[idx].values
            
            # Get IDS prediction
            risk_level, prob, pred = self.ids.detect(features)
            
            # Determine target based on scenario and methodology
            target = 'normal'  # Default target
            reason = "Normal traffic"
            
            if is_attack:
                if scenario_name == 'baseline':
                    reason = "Baseline scenario - all traffic to normal nodes"
                elif scenario_name == 'dedicated' or scenario_name == 'dynamic':
                    if prob >= high_threshold:
                        target = 'honeypot'
                        reason = f"High risk (prob={prob:.3f} >= threshold={high_threshold})"
                    elif high_threshold - buffer_zone <= prob < high_threshold:
                        # Random decision in buffer zone
                        target = 'honeypot' if np.random.random() < 0.5 else 'normal'
                        reason = f"Buffer zone decision (prob={prob:.3f})"
                    else:
                        reason = f"Low risk (prob={prob:.3f})"
            
            routing_decisions[target] += 1
            
            traffic = {
                'id': f'traffic_{len(traffic_samples)}',
                'label': int(is_attack),
                'target': target,
                'features': features,
                'risk_probability': prob,
                'risk_level': risk_level,
                'routing_reason': reason
            }
            traffic_samples.append(traffic)
            
        self.logger.info(
            f"Traffic generation complete. Routing decisions: {routing_decisions}"
        )
        return traffic_samples

    def run_scenario_test(self, scenario_name, num_steps=100):
        """Run and validate a specific scenario."""
        self.logger.info(f"Starting scenario test: {scenario_name}")
        
        try:
            # Reset components
            self.network.setup_scenario(scenario_name)
            self.metrics.reset()
            self.blockchain_logger.reset()
            
            # Generate test traffic
            traffic_samples = self.generate_test_traffic(num_steps, scenario_name)
            
            # Process traffic and collect metrics
            for step, traffic in enumerate(traffic_samples):
                # Get IDS prediction
                risk_level, prob, pred = self.ids.detect(
                    traffic['features'],
                    true_label=traffic['label']
                )
                
                # Update network state first
                self.network.update(step)
                
                # Process traffic
                success, proc_time = self.network.process_traffic(traffic, step)
                
                # Log processing result
                self.logger.debug(
                    f"Step {step}: Processing {'attack' if traffic['label'] == 1 else 'normal'} "
                    f"traffic to {traffic['target']}, success={success}, "
                    f"reason: {traffic['routing_reason']}"
                )
                
                # Log to blockchain if high risk
                if prob >= self.config['ids']['detection_thresholds']['high']:
                    start_time = time.time()
                    tx_hash = self.blockchain_logger.log_attack_detection({
                        'probability': prob,
                        'risk_level': risk_level,
                        'traffic': traffic
                    }, step)
                    if tx_hash:
                        self.blockchain_logger.transaction_times.append(time.time() - start_time)
                
                # Get current network state
                network_metrics = self.network.get_metrics(step)
                
                # Update metrics collector
                self.metrics.update_metrics(network_metrics, step)
            
            # Get final results
            complete_metrics = {
                **self.metrics.get_final_metrics(),
                'ids_performance': self.ids.get_evaluation_metrics(),
                'blockchain_performance': self.blockchain_logger.get_performance_metrics(),
                'scenario_summary': self.metrics.get_scenario_summary()
            }
            
            # Validate metrics
            validation_results = self.validate_metrics(
                complete_metrics, 
                self._get_expected_ranges(scenario_name)
            )
            
            self.logger.info(f"Completed scenario test: {scenario_name}")
            return {
                'scenario': scenario_name,
                'metrics': complete_metrics,
                'validation': validation_results,
                'time_series': self.metrics.get_time_series()
            }
            
        except Exception as e:
            self.logger.error(f"Error running scenario test: {str(e)}")
            raise

    def validate_metrics(self, metrics, expected):
        """Validate metrics against expected ranges with better handling."""
        validation_results = {
            'passed': True,
            'discrepancies': [],
            'warnings': []
        }
        
        for metric, expected_range in expected.items():
            try:
                # Get metric value
                value = self._get_nested_metric(metrics, metric)
                
                if value is None:
                    if 'recovery' in metric and not self.config['network']['recovery']['enabled']:
                        continue  # Skip recovery metrics if disabled
                    if metric.startswith('ids_performance') and isinstance(metrics.get('ids_performance', {}), dict):
                        # Handle IDS metrics differently
                        perf_metric = metric.split('.')[-1]
                        value = metrics['ids_performance'].get(perf_metric)
                        if value is None:
                            validation_results['warnings'].append(f"IDS metric {perf_metric} not found")
                            continue
                    else:
                        validation_results['warnings'].append(f"Metric {metric} not found")
                        continue
                
                # Check if value is within expected range
                in_range = expected_range[0] <= value <= expected_range[1]
                
                if not in_range:
                    validation_results['passed'] = False
                    validation_results['discrepancies'].append({
                        'metric': metric,
                        'actual': value,
                        'expected_range': expected_range,
                        'severity': 'medium'
                    })
                    
            except Exception as e:
                self.logger.warning(f"Error validating metric {metric}: {str(e)}")
                validation_results['warnings'].append(f"Error validating {metric}: {str(e)}")
        
        return validation_results

    def _get_nested_metric(self, metrics, metric_path):
        """Get metric value from nested dictionary using dot notation."""
        try:
            current = metrics
            for key in metric_path.split('.'):
                current = current[key]
            return current
        except (KeyError, TypeError):
            return None

    def _get_expected_ranges(self, scenario_name):
        """Define expected metric ranges based on methodology formulas."""
        attack_prop = self.config['traffic']['attack_proportion']
        high_threshold = self.config['ids']['detection_thresholds']['high']
        buffer_zone = self.config['ids']['buffer_zone']
        
        # Calculate base compromise probability
        base_compromise_prob = attack_prop
        
        # Initialize base ranges
        ranges = {}
        
        if scenario_name == 'baseline':
            ranges = {
                'attack_prevention_rate': (0.0, 0.1),
                'current_compromise_rate': (
                    base_compromise_prob * 0.8,
                    min(1.0, base_compromise_prob * 1.2)
                ),
                'cumulative_compromise_rate': (
                    base_compromise_prob * 0.9,
                    min(1.0, base_compromise_prob * 1.3)
                ),
                'traffic_loss_rate': (0.0, 0.15)
            }
            
        elif scenario_name == 'dedicated':
            honeypot_ratio = self.config['scenarios']['dedicated']['initial_honeypots'] / 100
            expected_prevention = honeypot_ratio * (1 + buffer_zone)
            adjusted_compromise = base_compromise_prob * (1 - expected_prevention)
            
            ranges = {
                'attack_prevention_rate': (
                    expected_prevention * 0.8,
                    min(1.0, expected_prevention * 1.2)
                ),
                'current_compromise_rate': (
                    adjusted_compromise * 0.8,
                    min(1.0, adjusted_compromise * 1.2)
                ),
                'cumulative_compromise_rate': (
                    adjusted_compromise * 0.9,
                    min(1.0, adjusted_compromise * 1.3)
                ),
                'honeypot_utilization_rate': (0.7, 1.0),
                'traffic_loss_rate': (0.0, 0.2)
            }
            
        else:  # dynamic scenario
            max_honeypot_ratio = self.config['network']['max_honeypot_ratio']
            expected_prevention = high_threshold * max_honeypot_ratio
            adjusted_compromise = base_compromise_prob * (1 - expected_prevention)
            
            ranges = {
                'attack_prevention_rate': (0.4, 0.8),
                'current_compromise_rate': (
                    adjusted_compromise * 0.5,
                    adjusted_compromise * 0.9
                ),
                'cumulative_compromise_rate': (
                    adjusted_compromise * 0.6,
                    adjusted_compromise * 1.0
                ),
                'honeypot_utilization_rate': (0.3, 0.8),
                'traffic_loss_rate': (0.05, 0.25),
                'node_availability_rate': (0.7, 1.0)
            }
        
        # Add common performance metrics
        ranges.update({
            'ids_performance.accuracy': (0.95, 1.0),
            'ids_performance.precision': (0.95, 1.0),
            'ids_performance.recall': (0.95, 1.0),
            'blockchain_performance.transaction_success_rate': (0.95, 1.0)
        })
        
        # Add recovery expectations if enabled
        if (self.config['network']['recovery']['enabled'] and 
            scenario_name != 'baseline'):  # No recovery tracking for baseline
            recovery_prob = self.config['network']['recovery']['recovery_probability']
            recovery_time = self.config['network']['recovery']['recovery_time']
            
            expected_compromise_time = recovery_time * (1 / recovery_prob)
            
            ranges.update({
                'scenario_summary.recovery_performance.recovery_rate': (
                    recovery_prob * 0.7,
                    recovery_prob * 1.3
                ),
                'scenario_summary.recovery_performance.avg_compromise_duration': (
                    recovery_time,
                    expected_compromise_time
                ),
                'scenario_summary.recovery_performance.recovery_effectiveness': (
                    0.3,  # At least 30% effectiveness
                    1.0
                )
            })
        
        return ranges

def main():
    """Main function to run scenario validation tests."""
    try:
        # Load config
        config_path = os.path.join(project_root, 'config', 'config.yaml')
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
        else:
            config_path = os.path.join(project_root, 'config.json')
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
            else:
                raise FileNotFoundError("No configuration file found")
        
        # Initialize validator
        validator = ScenarioValidator(config)
        
        # Test each scenario
        scenarios = ['baseline', 'dedicated', 'dynamic']
        results = {}
        
        for scenario in scenarios:
            print(f"\nTesting {scenario} scenario...")
            result = validator.run_scenario_test(scenario)
            results[scenario] = result
            
            # Print results
            print(f"\nResults for {scenario}:")
            print("Network Metrics:")
            for metric, value in result['metrics'].items():
                if isinstance(value, dict):
                    print(f"  {metric}:")
                    for sub_metric, sub_value in value.items():
                        if isinstance(sub_value, (int, float)):
                            print(f"    {sub_metric}: {sub_value:.4f}")
                        else:
                            print(f"    {sub_metric}: {sub_value}")
                elif isinstance(value, (int, float)):
                    print(f"  {metric}: {value:.4f}")
                else:
                    print(f"  {metric}: {value}")
                    
            print("\nValidation:")
            print(f"  Passed: {result['validation']['passed']}")
            if result['validation']['discrepancies']:
                print("  Discrepancies:")
                for disc in result['validation']['discrepancies']:
                    print(f"    {disc['metric']}: got {disc['actual']:.4f}, "
                          f"expected range {disc['expected_range']}")
                          
        # Save results
        results_dir = Path('results')
        results_dir.mkdir(exist_ok=True)
        
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        results_file = results_dir / f"scenario_tests_{timestamp}.json"
        
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
            
        print(f"\nResults saved to {results_file}")
        
        return results
        
    except Exception as e:
        print(f"Error running tests: {str(e)}")
        raise

if __name__ == "__main__":
    main()