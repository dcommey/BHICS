# visualize_scalability.py

import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
import json
import yaml
from pathlib import Path

def create_scalability_plots(results, output_dir='results/plots/scalability/'):
    """Create visualization plots for scalability results."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    # Plot network size impact
    plot_network_size_impact(results['network_size'], output_dir)
    
    # Plot attack proportion impact
    plot_attack_proportion_impact(results['attack_proportion'], output_dir)

def plot_network_size_impact(size_results, output_dir):
    """Create plots showing impact of network size on performance."""
    metrics = ['attack_prevention_rate', 'current_compromise_rate', 
               'blockchain_metrics.avg_transaction_time.mean']
    
    fig, axes = plt.subplots(len(metrics), 1, figsize=(10, 12))
    fig.suptitle('Impact of Network Size on System Performance')
    
    sizes = sorted([int(size) for size in size_results.keys()])
    
    for i, metric in enumerate(metrics):
        means = []
        cis = []
        
        for size in sizes:
            if 'blockchain_metrics' in metric:
                parts = metric.split('.')
                value = size_results[str(size)]['blockchain_metrics']
                for part in parts[1:]:
                    value = value[part]
                means.append(value)
                cis.append(size_results[str(size)]['blockchain_metrics']['avg_transaction_time']['confidence_interval'])
            else:
                means.append(size_results[str(size)]['aggregated'][metric]['mean'])
                cis.append(size_results[str(size)]['aggregated'][metric]['confidence_interval'])
        
        axes[i].errorbar(sizes, means, yerr=cis, marker='o')
        axes[i].set_xlabel('Network Size (nodes)')
        axes[i].set_ylabel(metric.replace('_', ' ').title())
        axes[i].grid(True)
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}network_size_impact.pdf')
    plt.close()

def plot_attack_proportion_impact(ratio_results, output_dir):
    """Create plots showing impact of attack proportion on performance."""
    metrics = ['attack_prevention_rate', 'current_compromise_rate',
               'blockchain_metrics.avg_transaction_time.mean']
    
    fig, axes = plt.subplots(len(metrics), 1, figsize=(10, 12))
    fig.suptitle('Impact of Attack Proportion on System Performance')
    
    ratios = sorted([float(ratio) for ratio in ratio_results.keys()])
    
    for i, metric in enumerate(metrics):
        means = []
        cis = []
        
        for ratio in ratios:
            if 'blockchain_metrics' in metric:
                parts = metric.split('.')
                value = ratio_results[str(ratio)]['blockchain_metrics']
                for part in parts[1:]:
                    value = value[part]
                means.append(value)
                cis.append(ratio_results[str(ratio)]['blockchain_metrics']['avg_transaction_time']['confidence_interval'])
            else:
                means.append(ratio_results[str(ratio)]['aggregated'][metric]['mean'])
                cis.append(ratio_results[str(ratio)]['aggregated'][metric]['confidence_interval'])
        
        axes[i].errorbar(ratios, means, yerr=cis, marker='o')
        axes[i].set_xlabel('Attack Proportion')
        axes[i].set_ylabel(metric.replace('_', ' ').title())
        axes[i].grid(True)
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}attack_proportion_impact.pdf')
    plt.close()

def create_scalability_tables(results, output_dir='results/tables/'):
    """Create LaTeX tables for scalability results."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    # Network size impact table
    network_table = [
        "\\begin{table}[t]",
        "\\centering",
        "\\caption{Impact of Network Size on System Performance}",
        "\\label{tab:network_size_impact}",
        "\\begin{tabular}{lcccc}",
        "\\toprule",
        "Network & Prevention & Compromise & Tx Time & Success",
        "\\\\",
        "Size & Rate (\\%) & Rate (\\%) & (ms) & Rate (\\%) \\\\",
        "\\midrule"
    ]
    
    sizes = sorted([int(size) for size in results['network_size'].keys()])
    for size in sizes:
        size_data = results['network_size'][str(size)]
        row = [
            f"{size:,d}",  # Add thousands separator
            f"{size_data['aggregated']['attack_prevention_rate']['mean']*100:.1f} $\\pm$ {size_data['aggregated']['attack_prevention_rate']['confidence_interval']*100:.1f}",
            f"{size_data['aggregated']['current_compromise_rate']['mean']*100:.1f} $\\pm$ {size_data['aggregated']['current_compromise_rate']['confidence_interval']*100:.1f}",
            f"{size_data['blockchain_metrics']['avg_transaction_time']['mean']*1000:.2f} $\\pm$ {size_data['blockchain_metrics']['avg_transaction_time']['confidence_interval']*1000:.2f}",
            f"{size_data['blockchain_metrics']['success_rate']['mean']*100:.1f} $\\pm$ {size_data['blockchain_metrics']['success_rate']['confidence_interval']*100:.1f}"
        ]
        network_table.append(" & ".join(row) + " \\\\")
    
    network_table.extend([
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}"
    ])
    
    # Attack proportion impact table
    attack_table = [
        "\\begin{table}[t]",
        "\\centering",
        "\\caption{Impact of Attack Proportion on System Performance}",
        "\\label{tab:attack_proportion_impact}",
        "\\begin{tabular}{lcccc}",
        "\\toprule",
        "Attack & Prevention & Compromise & Tx Time & Success",
        "\\\\",
        "Proportion & Rate (\\%) & Rate (\\%) & (ms) & Rate (\\%) \\\\",
        "\\midrule"
    ]
    
    ratios = sorted([float(ratio) for ratio in results['attack_proportion'].keys()])
    for ratio in ratios:
        ratio_data = results['attack_proportion'][str(ratio)]
        row = [
            f"{ratio:.2f}",
            f"{ratio_data['aggregated']['attack_prevention_rate']['mean']*100:.1f} $\\pm$ {ratio_data['aggregated']['attack_prevention_rate']['confidence_interval']*100:.1f}",
            f"{ratio_data['aggregated']['current_compromise_rate']['mean']*100:.1f} $\\pm$ {ratio_data['aggregated']['current_compromise_rate']['confidence_interval']*100:.1f}",
            f"{ratio_data['blockchain_metrics']['avg_transaction_time']['mean']*1000:.2f} $\\pm$ {ratio_data['blockchain_metrics']['avg_transaction_time']['confidence_interval']*1000:.2f}",
            f"{ratio_data['blockchain_metrics']['success_rate']['mean']*100:.1f} $\\pm$ {ratio_data['blockchain_metrics']['success_rate']['confidence_interval']*100:.1f}"
        ]
        attack_table.append(" & ".join(row) + " \\\\")
    
    attack_table.extend([
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}"
    ])
    
    # Save tables
    with open(f'{output_dir}network_size_impact.tex', 'w') as f:
        f.write('\n'.join(network_table))
    
    with open(f'{output_dir}attack_proportion_impact.tex', 'w') as f:
        f.write('\n'.join(attack_table))

def main():
    # Find most recent scalability results file
    results_dir = Path('results/data/scalability')
    results_files = list(results_dir.glob('scalability_results_*.json'))
    if not results_files:
        raise FileNotFoundError("No scalability results files found")
    
    latest_results_file = max(results_files, key=lambda x: x.stat().st_mtime)
    print(f"Using results file: {latest_results_file}")
    
    # Load results
    with open(latest_results_file, 'r') as f:
        results = json.load(f)
    
    # Create visualizations and tables
    create_scalability_plots(results)
    create_scalability_tables(results)

if __name__ == "__main__":
    main()