import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
import json
import yaml
from pathlib import Path
import latexify

# Configure matplotlib for publication quality
plt.rcParams.update({
    'figure.figsize': (8, 6),
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'font.size': 10,
    'font.family': 'serif',
    'axes.titlesize': 10,
    'axes.labelsize': 10,
    'xtick.labelsize': 8,
    'ytick.labelsize': 8,
    'legend.fontsize': 8,
    'legend.frameon': True,
    'legend.framealpha': 0.8,
    'legend.edgecolor': 'black',
    'legend.fancybox': False,
    'axes.grid': True,
    'grid.linestyle': '--',
    'grid.alpha': 0.7,
    'lines.linewidth': 1.5,
    'axes.spines.top': True,
    'axes.spines.right': True,
    'axes.spines.left': True,
    'axes.spines.bottom': True,
    'figure.autolayout': True
})

def load_results(results_file):
    """Load complete results from JSON file."""
    with open(results_file, 'r') as f:
        return json.load(f)

def create_comparison_plot(results):
    """Create bar plot comparing key metrics across scenarios."""
    metrics = ['attack_prevention_rate', 'current_compromise_rate', 
               'cumulative_compromise_rate', 'traffic_loss_rate']
    scenarios = list(results.keys())
    
    data = []
    for scenario in scenarios:
        for metric in metrics:
            # Access the correct nested structure
            mean = results[scenario]['aggregated'][metric]['mean']
            ci = results[scenario]['aggregated'][metric]['confidence_interval']
            data.append({
                'Scenario': scenario,
                'Metric': metric.replace('_', ' ').title(),
                'Value': mean,
                'CI': ci
            })
    
    df = pd.DataFrame(data)
    
    fig, ax = plt.subplots(figsize=(10, 6))
    sns.barplot(x='Metric', y='Value', hue='Scenario', data=df, 
                capsize=0.05, err_kws={'linewidth': 1})
    
    plt.xticks(rotation=45, ha='right')
    plt.ylabel('Rate')
    plt.title('Performance Comparison Across Scenarios')
    plt.tight_layout()
    
    # Save as PDF
    plt.savefig('results/plots/scenario_comparison.pdf', bbox_inches='tight')
    plt.close()

def create_time_series_plot(results, output_dir='results/plots/'):
    """Create time series plots for key metrics."""
    metrics = ['attack_prevention_rate', 'current_compromise_rate', 
               'honeypot_utilization_rate', 'traffic_loss_rate'] 
    
    for metric in metrics:
        fig, ax = plt.subplots(figsize=(10, 6))
        has_data = False  # Track if we plotted any data
        
        for scenario in results:
            try:
                # Skip if metric not present
                if metric not in results[scenario]['aggregated']:
                    print(f"Metric {metric} not found in {scenario} scenario")
                    continue
                    
                # Get time series data
                time_series_data = results[scenario]['aggregated'][metric]['time_series']
                if not time_series_data:  # Skip if no data
                    print(f"No time series data for {metric} in {scenario} scenario")
                    continue
                    
                timesteps = range(len(time_series_data))
                
                mean_values = []
                ci_values = []
                for step in range(len(time_series_data)):
                    step_data = time_series_data[str(step)]
                    mean_values.append(step_data['mean'])
                    ci_values.append(step_data['confidence_interval'])
                
                mean_values = np.array(mean_values)
                ci_values = np.array(ci_values)
                
                # Plot line and confidence interval
                label = scenario.capitalize()
                ax.plot(timesteps, mean_values, label=label, linewidth=1.5)
                ax.fill_between(timesteps, 
                              mean_values - ci_values, 
                              mean_values + ci_values, 
                              alpha=0.2)
                has_data = True
                
            except Exception as e:
                print(f"Error plotting {metric} for {scenario}: {str(e)}")
                continue
        
        if has_data:  # Only add labels and save if we plotted data
            ax.set_xlabel('Time Step')
            ax.set_ylabel(metric.replace('_', ' ').title())
            ax.set_title(f'{metric.replace("_", " ").title()} Over Time')
            ax.legend()
            ax.grid(True, linestyle='--', alpha=0.7)
            
            # Set y-axis limits for rate metrics
            if metric.endswith('_rate'):
                ax.set_ylim(-0.05, 1.05)
            
            plt.tight_layout()
            plt.savefig(f'{output_dir}{metric}_timeseries.pdf', bbox_inches='tight', dpi=300)
        plt.close()

def create_conversion_timeline_plot(results, output_dir='results/plots/'):
    """Create timeline plot for dynamic scenario conversions and compromises."""
    if 'dynamic' not in results:
        print("No dynamic scenario data found")
        return
        
    try:
        utilization_metric = 'honeypot_utilization_rate'
        compromise_metric = 'current_compromise_rate'
        
        # Verify metrics exist
        if 'aggregated' not in results['dynamic']:
            print("No aggregated data found in dynamic scenario")
            return
            
        if utilization_metric not in results['dynamic']['aggregated']:
            print(f"Missing {utilization_metric} in dynamic scenario data")
            return
            
        if compromise_metric not in results['dynamic']['aggregated']:
            print(f"Missing {compromise_metric} in dynamic scenario data")
            return
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8), sharex=True)
        
        # Get time series data
        utilization_data = results['dynamic']['aggregated'][utilization_metric]['time_series']
        compromise_data = results['dynamic']['aggregated'][compromise_metric]['time_series']
        
        if not utilization_data or not compromise_data:
            print("No time series data found")
            return
        
        timesteps = range(len(utilization_data))
        
        # Plot honeypot utilization
        utilization_means = [utilization_data[str(step)]['mean'] for step in timesteps]
        utilization_ci = [utilization_data[str(step)]['confidence_interval'] for step in timesteps]
        
        ax1.plot(timesteps, utilization_means, label='Honeypot Utilization', color='blue')
        ax1.fill_between(timesteps,
                        np.array(utilization_means) - np.array(utilization_ci),
                        np.array(utilization_means) + np.array(utilization_ci),
                        alpha=0.2, color='blue')
        ax1.set_ylabel('Honeypot Utilization Rate')
        ax1.grid(True, linestyle='--', alpha=0.7)
        ax1.legend()
        
        # Plot compromise rates
        compromise_means = [compromise_data[str(step)]['mean'] for step in timesteps]
        compromise_ci = [compromise_data[str(step)]['confidence_interval'] for step in timesteps]
        
        ax2.plot(timesteps, compromise_means, label='Compromise Rate', color='red')
        ax2.fill_between(timesteps,
                        np.array(compromise_means) - np.array(compromise_ci),
                        np.array(compromise_means) + np.array(compromise_ci),
                        alpha=0.2, color='red')
        ax2.set_ylabel('Compromise Rate')
        ax2.set_xlabel('Time Step')
        ax2.grid(True, linestyle='--', alpha=0.7)
        ax2.legend()
        
        # Set y-axis limits for both plots
        ax1.set_ylim(-0.05, 1.05)
        ax2.set_ylim(-0.05, 1.05)
        
        plt.tight_layout()
        plt.savefig(f'{output_dir}conversion_timeline.pdf', bbox_inches='tight', dpi=300)
        plt.close()
        
    except Exception as e:
        print(f"Error creating conversion timeline plot: {str(e)}")
        plt.close()  

def create_latex_tables(results):
    """Create LaTeX tables for the results."""
    # Main results table
    table = [
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{Performance Metrics Across Scenarios}",
        "\\label{tab:performance_metrics}",
        "\\begin{tabular}{lcccc}",
        "\\toprule",
        "Metric & Baseline & Dedicated & Dynamic & p-value \\\\",
        "\\midrule"
    ]
    
    metrics = {
        'attack_prevention_rate': 'Attack Prevention Rate',
        'current_compromise_rate': 'Current Compromise Rate',
        'cumulative_compromise_rate': 'Cumulative Compromise Rate',
        'traffic_loss_rate': 'Traffic Loss Rate'
    }
    
    for metric_key, metric_name in metrics.items():
        row = [metric_name]
        for scenario in ['baseline', 'dedicated', 'dynamic']:
            mean = results[scenario]['aggregated'][metric_key]['mean']
            ci = results[scenario]['aggregated'][metric_key]['confidence_interval']
            row.append(f"{mean:.3f} \\pm {ci:.3f}")
        row.append("*")  # Placeholder for p-value
        table.append(" & ".join(row) + " \\\\")
    
    table.extend([
        "\\bottomrule",
        "\\end{tabular}",
        "\\begin{tablenotes}",
        "\\small",
        "\\item * p < 0.05, ** p < 0.01, *** p < 0.001",
        "\\end{tablenotes}",
        "\\end{table}"
    ])
    
    # Save performance metrics table
    with open('results/tables/performance_metrics.tex', 'w') as f:
        f.write('\n'.join(table))
    
    # Blockchain performance table
    blockchain_table = [
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{Blockchain Performance Metrics}",
        "\\label{tab:blockchain_metrics}",
        "\\begin{tabular}{lcccc}",
        "\\toprule",
        "Scenario & Avg Tx Time (ms) & Total Tx & Failed Tx & Success Rate \\\\",
        "\\midrule"
    ]
    
    # Add blockchain metrics for each scenario
    for scenario in ['baseline', 'dedicated', 'dynamic']:
        metrics = results[scenario]['blockchain_metrics']
        
        # Extract values with defaults
        avg_time = metrics.get('avg_transaction_time', {}).get('mean', 0) * 1000  # Convert to ms
        time_ci = metrics.get('avg_transaction_time', {}).get('confidence_interval', 0) * 1000
        total_tx = metrics.get('total_transactions', 0)
        failed_tx = metrics.get('failed_transactions', 0)
        success_rate = metrics.get('success_rate', {}).get('mean', 0) * 100
        success_ci = metrics.get('success_rate', {}).get('confidence_interval', 0) * 100
        
        row = [
            scenario.title(),
            f"{avg_time:.2f} \\pm {time_ci:.2f}",
            f"{total_tx}",
            f"{failed_tx}",
            f"{success_rate:.1f}\\% \\pm {success_ci:.1f}\\%"
        ]
        blockchain_table.append(" & ".join(row) + " \\\\")
    
    blockchain_table.extend([
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}"
    ])
    
    # Save blockchain table
    with open('results/tables/blockchain_metrics.tex', 'w') as f:
        f.write('\n'.join(blockchain_table))

def main():
    # Create output directories
    Path('results/plots').mkdir(parents=True, exist_ok=True)
    Path('results/tables').mkdir(parents=True, exist_ok=True)
    
    # Find most recent complete results file
    results_dir = Path('results/data')
    results_files = list(results_dir.glob('complete_results_*.json'))
    if not results_files:
        raise FileNotFoundError("No complete results files found")
    
    latest_results_file = max(results_files, key=lambda x: x.stat().st_mtime)
    print(f"Using results file: {latest_results_file}")
    
    # Load results and create visualizations
    results = load_results(latest_results_file)
    create_comparison_plot(results)
    create_time_series_plot(results)
    create_conversion_timeline_plot(results)
    create_latex_tables(results)

if __name__ == "__main__":
    main()