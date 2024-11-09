# main.py
import yaml
import json
import logging
from pathlib import Path
import argparse
import numpy as np
from datetime import datetime
from experiment_runner import ExperimentRunner

def main():
    parser = argparse.ArgumentParser(description='Run BHICS experiments')
    parser.add_argument('--config', type=str, default='config/config.yaml',
                      help='Path to configuration file')
    parser.add_argument('--scenario', type=str, choices=['baseline', 'dedicated', 'dynamic'],
                      help='Specific scenario to run')
    args = parser.parse_args()
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger("Main")
    
    results_dir = Path('results/data')
    results_dir.mkdir(parents=True, exist_ok=True)
    
    runner = ExperimentRunner(args.config)
    scenarios = [args.scenario] if args.scenario else ['baseline', 'dedicated', 'dynamic']
    
    # Structure to hold all experimental results
    all_results = {
        scenario: {
            'runs': [],
            'aggregated': {},
            'blockchain_metrics': {}
        }
        for scenario in scenarios
    }
    
    # Run experiments
    for scenario in scenarios:
        logger.info(f"Running scenario: {scenario}")
        
        # Multiple runs for statistical significance
        num_runs = runner.config['experiment']['num_runs']
        for run in range(num_runs):
            logger.info(f"Run {run + 1}/{num_runs}")
            run_results = runner.run_experiment(scenario)
            all_results[scenario]['runs'].append(run_results)
        
        # Aggregate results across runs
        metrics = [metric for metric in all_results[scenario]['runs'][0].keys() 
                  if metric != 'blockchain_metrics']
        
        all_results[scenario]['aggregated'] = {
            metric: {
                'mean': np.mean([run[metric]['mean'] for run in all_results[scenario]['runs']]),
                'std': np.mean([run[metric]['std'] for run in all_results[scenario]['runs']]),
                'confidence_interval': np.std([run[metric]['mean'] for run in all_results[scenario]['runs']]) * 1.96 / np.sqrt(num_runs),
                'time_series': {
                    str(step): {
                        'mean': np.mean([run[metric]['time_series'][step] for run in all_results[scenario]['runs']]),
                        'std': np.std([run[metric]['time_series'][step] for run in all_results[scenario]['runs']]),
                        'confidence_interval': np.std([run[metric]['time_series'][step] for run in all_results[scenario]['runs']]) * 1.96 / np.sqrt(num_runs)
                    }
                    for step in range(len(all_results[scenario]['runs'][0][metric]['time_series']))
                }
            }
            for metric in metrics
        }
        
        # Add blockchain metrics separately with statistical analysis
        all_results[scenario]['blockchain_metrics'] = {
            'avg_transaction_time': {
                'mean': np.mean([run['blockchain_metrics']['avg_transaction_time'] 
                               for run in all_results[scenario]['runs']]),
                'std': np.std([run['blockchain_metrics']['avg_transaction_time'] 
                             for run in all_results[scenario]['runs']]),
                'confidence_interval': np.std([run['blockchain_metrics']['avg_transaction_time'] 
                                            for run in all_results[scenario]['runs']]) * 1.96 / np.sqrt(num_runs)
            },
            'success_rate': {
                'mean': np.mean([run['blockchain_metrics']['success_rate'] 
                               for run in all_results[scenario]['runs']]),
                'std': np.std([run['blockchain_metrics']['success_rate'] 
                             for run in all_results[scenario]['runs']]),
                'confidence_interval': np.std([run['blockchain_metrics']['success_rate'] 
                                            for run in all_results[scenario]['runs']]) * 1.96 / np.sqrt(num_runs)
            },
            'total_transactions': int(np.sum([run['blockchain_metrics']['total_transactions'] 
                                            for run in all_results[scenario]['runs']])),
            'failed_transactions': int(np.sum([run['blockchain_metrics']['failed_transactions'] 
                                             for run in all_results[scenario]['runs']]))
        }
        
        # Save individual scenario results
        with open(results_dir / f"{scenario}_results.yaml", 'w') as f:
            yaml.dump({
                'scenario': scenario,
                'aggregated_results': all_results[scenario]['aggregated'],
                'blockchain_metrics': all_results[scenario]['blockchain_metrics'],
                'configuration': {
                    'num_runs': num_runs,
                    'timesteps': runner.config['experiment']['timesteps']
                }
            }, f)
    
    # Save complete results including time series
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    complete_results_file = results_dir / f"complete_results_{timestamp}.json"
    with open(complete_results_file, 'w') as f:
        json.dump(all_results, f, indent=2)
    
    logger.info(f"Complete results saved to {complete_results_file}")
    logger.info("Experiments completed")

if __name__ == "__main__":
    main()