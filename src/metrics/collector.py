# src/metrics/collector.py

from collections import defaultdict
import numpy as np
import logging
from scipy import stats
from typing import Dict, List, Tuple

class MetricsCollector:
    def __init__(self, config): 
        self.logger = logging.getLogger("MetricsCollector")
        self.config = config 
        self.initialize_metrics()

    def initialize_metrics(self):
        """Initialize all metric containers."""
        # Time series data to track metrics over time
        self.time_series = defaultdict(list)
        
        # Current state metrics
        self.current_state = {
            'active_honeypots': 0,
            'current_compromised': set(),
            'unique_compromised': set()
        }
        
        # Cumulative metrics
        self.cumulative_metrics = {
            'total_attacks': 0,
            'prevented_attacks': 0,
            'total_traffic': 0,
            'dropped_traffic': 0,
            'normal_to_honeypot': 0,
            'processed_traffic': 0,
            'queued_traffic': 0,
            'total_conversions': 0
        }

    def update_metrics(self, network_metrics, current_step):
        """Update metrics with proper rate calculations."""
        # Update state tracking
        self.current_state['active_honeypots'] = network_metrics['current_honeypots']
        self.current_state['current_compromised'] = set(network_metrics['currently_compromised'])
        self.current_state['unique_compromised'].update(network_metrics['ever_compromised'])
        
        # Update cumulative metrics
        for metric in ['total_attacks', 'prevented_attacks', 'total_traffic', 
                    'dropped_traffic', 'processed_traffic', 'queued_traffic',
                    'total_conversions']:
            self.cumulative_metrics[metric] = network_metrics[metric]
        
        # Store time series data with validation
        metrics_to_store = {
            'honeypot_utilization_rate': network_metrics['honeypot_utilization_rate'],  
            'attack_prevention_rate': network_metrics['attack_prevention_rate'],         
            'current_compromise_rate': network_metrics['current_compromise_rate'],
            'cumulative_compromise_rate': network_metrics['cumulative_compromise_rate'],
            'traffic_loss_rate': network_metrics['traffic_loss_rate'],
            'node_availability_rate': network_metrics.get('node_availability_rate', 1.0)  
        }
        
        # Validate and store metrics
        for metric, value in metrics_to_store.items():
            # Ensure rates are between 0 and 1
            validated_value = min(1.0, max(0.0, value))
            self.time_series[metric].append((current_step, validated_value))


    def get_final_metrics(self):
        """Calculate final metrics for experiment evaluation."""
        if not self.time_series['current_compromise']:
            return {}
            
        # Get latest values from time series
        final_metrics = {
            metric: values[-1][1] 
            for metric, values in self.time_series.items()
        }
        
        # Add cumulative metrics
        final_metrics.update({
            'total_attacks': self.cumulative_metrics['total_attacks'],
            'prevented_attacks': self.cumulative_metrics['prevented_attacks'],
            'total_compromises': len(self.current_state['unique_compromised']),
            'total_traffic': self.cumulative_metrics['total_traffic'],
            'dropped_traffic': self.cumulative_metrics['dropped_traffic'],
            'processed_traffic': self.cumulative_metrics['processed_traffic'],
            'total_conversions': self.cumulative_metrics['total_conversions']
        })
        
        return final_metrics

    def get_time_series(self):
        """Get time series data for analysis."""
        return {
            'metrics_over_time': dict(self.time_series),
            'total_samples': len(next(iter(self.time_series.values()), [])),
            'metrics_tracked': list(self.time_series.keys())
        }
    
    def get_instantaneous_rates(self, window_size=5):
        """Calculate instantaneous rates over a sliding window."""
        instant_rates = defaultdict(list)
        
        for metric, values in self.time_series.items():
            if len(values) < window_size:
                continue
                
            for i in range(len(values) - window_size + 1):
                window = values[i:i+window_size]
                times, rates = zip(*window)
                
                avg_rate = np.mean(rates)
                instant_rates[metric].append((times[-1], avg_rate))
        
        return dict(instant_rates)

    def calculate_statistics(self):
        """Calculate statistical measures for metrics with confidence intervals."""
        stats_results = {}
        
        for metric, values in self.time_series.items():
            if values:
                values_array = np.array([v[1] for v in values])
                
                # Basic statistics
                mean = np.mean(values_array)
                std = np.std(values_array, ddof=1)  # Use N-1 for sample std
                
                # Calculate 95% confidence interval
                if len(values_array) > 1:
                    # Fixed confidence level to 0.95
                    confidence = 0.95
                    degrees_of_freedom = len(values_array) - 1
                    t_value = stats.t.ppf((1 + confidence) / 2, degrees_of_freedom)
                    margin_of_error = t_value * (std / np.sqrt(len(values_array)))
                    ci = (mean - margin_of_error, mean + margin_of_error)
                else:
                    ci = (mean, mean)
                
                stats_results[metric] = {
                    'mean': mean,
                    'std': std,
                    'min': np.min(values_array),
                    'max': np.max(values_array),
                    'median': np.median(values_array),
                    'ci_lower': ci[0],
                    'ci_upper': ci[1]
                }
                
                # Calculate rate of change if enough samples
                if len(values_array) > 1:
                    time_steps = np.array([v[0] for v in values])
                    rate_of_change = np.diff(values_array) / np.diff(time_steps)
                    stats_results[metric]['rate_of_change'] = {
                        'mean': np.mean(rate_of_change),
                        'std': np.std(rate_of_change) if len(rate_of_change) > 1 else 0
                    }
        
        return stats_results

    def get_scenario_summary(self):
        """Get comprehensive scenario summary with recovery statistics."""
        stats = self.calculate_statistics()
        
        summary = {
            'attack_prevention': {
                'rate': stats['attack_prevention_rate']['mean'],                
                'rate_ci': (stats['attack_prevention_rate']['ci_lower'],       
                        stats['attack_prevention_rate']['ci_upper']),
                'total_prevented': self.cumulative_metrics['prevented_attacks'],
                'total_attacks': self.cumulative_metrics['total_attacks'],
                'prevention_effectiveness': (
                    self.cumulative_metrics['prevented_attacks'] /
                    max(1, (self.cumulative_metrics['total_attacks'] -
                        self.cumulative_metrics['queued_traffic']))
                )
            },
            'node_compromise': {
                'current_rate': stats['current_compromise_rate']['mean'],       
                'current_rate_ci': (stats['current_compromise_rate']['ci_lower'], 
                                stats['current_compromise_rate']['ci_upper']),
                'peak_rate': stats['current_compromise_rate']['max'],          
                'unique_compromised': len(self.current_state['unique_compromised']),
                'currently_compromised': len(self.current_state['current_compromised']),
                'compromise_trend': stats['current_compromise_rate'].get(      
                    'rate_of_change', {}).get('mean', 0)
            },
            'honeypot_performance': {
                'utilization_rate': stats['honeypot_utilization_rate']['mean'],  
                'utilization_ci': (stats['honeypot_utilization_rate']['ci_lower'], 
                                stats['honeypot_utilization_rate']['ci_upper']),
                'total_conversions': self.cumulative_metrics['total_conversions'],
                'utilization_stability': stats['honeypot_utilization_rate']['std'] 
            },
            'traffic_handling': {
                'loss_rate': stats['traffic_loss_rate']['mean'],              
                'loss_rate_ci': (stats['traffic_loss_rate']['ci_lower'],      
                                stats['traffic_loss_rate']['ci_upper']),
                'total_traffic': self.cumulative_metrics['total_traffic'],
                'dropped_traffic': self.cumulative_metrics['dropped_traffic'],
                'processed_traffic': self.cumulative_metrics['processed_traffic'],
                'processing_efficiency': (
                    self.cumulative_metrics['processed_traffic'] /
                    max(1, self.cumulative_metrics['total_traffic'])
                )
            }
        }
        
        # Add recovery metrics if available
        if 'recovery_statistics' in stats:
            summary['recovery_performance'] = {
                'recovery_rate': stats['recovery_statistics']['recovery_rate'],
                'avg_compromise_duration': stats['recovery_statistics']['average_compromise_duration'],
                'total_recoveries': stats['recovery_statistics']['total_recoveries'],
                'recovery_effectiveness': (
                    stats['recovery_statistics']['nodes_ever_recovered'] /
                    max(1, len(self.current_state['unique_compromised']))
                )
            }
        
        return summary

    def reset(self):
        """Reset all metrics."""
        self.initialize_metrics()

    def __str__(self):
        """String representation of current metrics state."""
        return f"MetricsCollector(total_traffic={self.cumulative_metrics['total_traffic']}, " \
               f"total_attacks={self.cumulative_metrics['total_attacks']}, " \
               f"prevented_attacks={self.cumulative_metrics['prevented_attacks']}, " \
               f"unique_compromised={len(self.current_state['unique_compromised'])})"