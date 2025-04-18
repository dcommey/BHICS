# BHICS: Blockchain-enabled Honeypot IoT Conversion System

## Overview
BHICS is a dynamic honeypot management system for IoT networks that employs ML-based threat detection to trigger node conversion. The system implements a state-driven approach where network nodes can transition through distinct phases: normal operation, isolation, conversion, and honeypot operation. When suspicious activity is detected, the system initiates a rapid isolation protocol for selected nodes, followed by their conversion into honeypots.

## Features
- Dynamic node conversion based on real-time threat detection
- Machine learning-based intrusion detection using XGBoost
- Blockchain-based security event logging
- State-driven node management
- Scalable from 100 to 1,000+ nodes
- Adaptive resource allocation

## Architecture
The system comprises four primary components:
- Network Management System
- ML-based Intrusion Detection System
- Conversion Engine
- Blockchain Logger

## Requirements
- Python 3.8+
- XGBoost
- Truffle/Ganache for blockchain
- Required Python packages:
  ```
  numpy
  pandas
  sklearn
  xgboost
  web3
  pyyaml
  ```

## Installation
```bash
# Clone the repository
git clone https://github.com/dcommey/BHICS.git
cd BHICS

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Configure blockchain environment
truffle migrate --reset
```

## Usage
```bash
# Run with default configuration
python main.py

# Run specific scenario
python main.py --scenario dynamic

# Run scalability tests
python scalability_runner.py
```

## Configuration
Configuration file (`config/config.yaml`) parameters:
```yaml
network:
  num_devices: 100
  num_gateways: 10
  max_honeypot_ratio: 0.6
  min_normal_ratio: 0.4

ids:
  detection_thresholds:
    high: 0.6
  buffer_zone: 0.15

experiment:
  timesteps: 1000
  num_runs: 30
```

## Performance
- Attack Prevention Rate: 76.5% (±0.9%)
- Network Compromise Rate: 22.3% (±0.9%)
- Blockchain Transaction Time: 15.17ms (±0.03ms)
- Zero Traffic Loss During Conversion

## Dataset
The system is evaluated using the CICDDoS2019 dataset, which includes various attack types:
- Volumetric attacks (UDP flood, DNS amplification)
- Protocol attacks (SYN flood, ICMP flood)
- Application-layer attacks (HTTP flood, Slowloris)

## Model Analysis
The detailed model analysis and comparison for the IDS component is available at:
https://github.com/dcommey/BHICS_IDS

## Citation
If you use BHICS in your research, please cite:
```bibtex
@article{commey2025bhics,
  title={Blockchain-Enabled Dynamic Honeypot Conversion for Resource-Efficient IoT Security},
  author={Commey, Daniel and Nkoom, Matilda and Hounsinou, Sena G. and Crosby, Garth V.},
  journal={Journal of Information Security and Applications},
  year={2025},
  publisher={Elsevier}
}
```

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact
- Author: Daniel Commey
- Email: dcommey@tamu.edu
- Project Link: https://github.com/dcommey/BHICS
