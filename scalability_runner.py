# scalability_runner.py
import logging
from pathlib import Path
import yaml
import json
import numpy as np
import copy
import os
from datetime import datetime
from experiment_runner import ExperimentRunner

class ScalabilityRunner:
    def __init__(self, config_path='config/config.yaml'):
        self.base_config = self._load_config(config_path)
        self.config_path = config_path
        self.setup_logging()
        self.results_dir = Path('results/data/scalability')
        self.modified_config_dir = self.results_dir / 'configs'
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.modified_config_dir.mkdir(parents=True, exist_ok=True)

    def _load_config(self, config_path):
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("ScalabilityRunner")

    def run_scalability_tests(self):
        """Run all scalability tests."""
        # Structure to hold all results
        all_results = {
            'network_size': {},
            'attack_proportion': {}
        }
        
        # Test 1: Network Size Impact
        self.logger.info("Starting network size scalability tests...")
        sizes = self.base_config['scalability']['network_sizes']['sizes']
        for size in sizes:
            self.logger.info(f"Testing network size: {size}")
            config_path = self._modify_config('network_size', size)
            size_results = self._run_test_scenario(config_path, f"size_{size}")
            all_results['network_size'][size] = size_results
        
        # Test 2: Attack Load Impact
        self.logger.info("Starting attack proportion scalability tests...")
        ratios = self.base_config['scalability']['attack_proportions']['ratios']
        for ratio in ratios:
            self.logger.info(f"Testing attack proportion: {ratio}")
            config_path = self._modify_config('attack_proportion', ratio)
            ratio_results = self._run_test_scenario(config_path, f"ratio_{ratio}")
            all_results['attack_proportion'][ratio] = ratio_results

        # Save complete results
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        results_file = self.results_dir / f"scalability_results_{timestamp}.json"
        with open(results_file, 'w') as f:
            json.dump(all_results, f, indent=2)

        self.logger.info(f"Complete results saved to {results_file}")
        return all_results

    def _run_test_scenario(self, config_path, scenario_id):
        """Run a single test scenario with multiple runs."""
        runner = ExperimentRunner(config_path)
        scenario_results = {
            'runs': [],
            'aggregated': {},
            'blockchain_metrics': {}
        }

        # Multiple runs for statistical significance
        num_runs = self.base_config['scalability']['runs_per_test']
        for run in range(num_runs):
            self.logger.info(f"Run {run + 1}/{num_runs}")
            run_results = runner.run_experiment('dynamic')
            scenario_results['runs'].append(run_results)

        # Aggregate results across runs (matching main.py structure)
        metrics = [metric for metric in scenario_results['runs'][0].keys() 
                  if metric != 'blockchain_metrics']
        
        scenario_results['aggregated'] = {
            metric: {
                'mean': np.mean([run[metric]['mean'] for run in scenario_results['runs']]),
                'std': np.mean([run[metric]['std'] for run in scenario_results['runs']]),
                'confidence_interval': np.std([run[metric]['mean'] for run in scenario_results['runs']]) * 1.96 / np.sqrt(num_runs),
                'time_series': {
                    str(step): {
                        'mean': np.mean([run[metric]['time_series'][step] for run in scenario_results['runs']]),
                        'std': np.std([run[metric]['time_series'][step] for run in scenario_results['runs']]),
                        'confidence_interval': np.std([run[metric]['time_series'][step] 
                                                    for run in scenario_results['runs']]) * 1.96 / np.sqrt(num_runs)
                    }
                    for step in range(len(scenario_results['runs'][0][metric]['time_series']))
                }
            }
            for metric in metrics
        }

        # Add blockchain metrics
        scenario_results['blockchain_metrics'] = {
            'avg_transaction_time': {
                'mean': np.mean([run['blockchain_metrics']['avg_transaction_time'] 
                               for run in scenario_results['runs']]),
                'std': np.std([run['blockchain_metrics']['avg_transaction_time'] 
                             for run in scenario_results['runs']]),
                'confidence_interval': np.std([run['blockchain_metrics']['avg_transaction_time'] 
                                            for run in scenario_results['runs']]) * 1.96 / np.sqrt(num_runs)
            },
            'success_rate': {
                'mean': np.mean([run['blockchain_metrics']['success_rate'] 
                               for run in scenario_results['runs']]),
                'std': np.std([run['blockchain_metrics']['success_rate'] 
                             for run in scenario_results['runs']]),
                'confidence_interval': np.std([run['blockchain_metrics']['success_rate'] 
                                            for run in scenario_results['runs']]) * 1.96 / np.sqrt(num_runs)
            },
            'total_transactions': int(np.sum([run['blockchain_metrics']['total_transactions'] 
                                            for run in scenario_results['runs']])),
            'failed_transactions': int(np.sum([run['blockchain_metrics']['failed_transactions'] 
                                             for run in scenario_results['runs']]))
        }

        # Save individual test results
        results_file = self.results_dir / f"{scenario_id}_results.yaml"
        with open(results_file, 'w') as f:
            yaml.dump({
                'scenario_id': scenario_id,
                'aggregated_results': scenario_results['aggregated'],
                'blockchain_metrics': scenario_results['blockchain_metrics'],
                'configuration': {
                    'num_runs': num_runs,
                    'timesteps': runner.config['experiment']['timesteps']
                }
            }, f)

        # Clean up temporary config
        os.remove(config_path)
        
        return scenario_results

    def _modify_config(self, parameter, value):
        """Create modified config file and return its path."""
        modified_config = copy.deepcopy(self.base_config)
        
        if parameter == 'network_size':
            modified_config['network']['num_devices'] = value
            config_filename = f'config_size_{value}.yaml'
        elif parameter == 'attack_proportion':
            modified_config['traffic']['attack_proportion'] = value
            config_filename = f'config_attack_{value}.yaml'
        
        config_path = self.modified_config_dir / config_filename
        
        with open(config_path, 'w') as f:
            yaml.dump(modified_config, f)
        
        return str(config_path)

if __name__ == "__main__":
    runner = ScalabilityRunner()
    runner.run_scalability_tests()