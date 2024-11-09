# src/blockchain/logger.py

import json
import time
import logging
import numpy as np
from web3 import Web3
from eth_account import Account

class BlockchainLogger:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger("BlockchainLogger")
        
        # Connect to blockchain
        self.w3 = Web3(Web3.HTTPProvider(config['blockchain']['node_url']))
        self.account = Account.from_key(config['blockchain']['private_key'])
        
        # Load contract ABI
        try:
            with open('src/blockchain/build/contracts/BHICSLog.json', 'r') as f:
                contract_json = json.load(f)
                self.contract_abi = contract_json['abi']
        except Exception as e:
            self.logger.error(f"Failed to load contract ABI: {str(e)}")
            raise
        
        # Initialize contract
        self.contract = self.w3.eth.contract(
            address=self.config['blockchain']['contract_address'],
            abi=self.contract_abi
        )
        
        # Performance tracking
        self.transaction_times = []
        self.total_transactions = 0
        self.failed_transactions = 0
        
        self.logger.info("BlockchainLogger initialized")

    def _sanitize_data(self, data):
        """Convert numpy types to Python native types."""
        if isinstance(data, dict):
            return {k: self._sanitize_data(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._sanitize_data(item) for item in data]
        elif isinstance(data, np.ndarray):
            return data.tolist()
        elif isinstance(data, (np.int8, np.int16, np.int32, np.int64,
                             np.uint8, np.uint16, np.uint32, np.uint64)):
            return int(data)
        elif isinstance(data, (np.float16, np.float32, np.float64)):
            return float(data)
        return data

    def _send_transaction(self, event_type, id_str, data_str):
        """Send transaction to blockchain."""
        try:
            start_time = time.time()  # Start timing
            
            # Build transaction
            tx = self.contract.functions.log(
                event_type,
                id_str,
                data_str
            ).build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': 200000,
                'gasPrice': self.w3.eth.gas_price,
                'chainId': self.w3.eth.chain_id
            })
            
            # Sign and send transaction
            signed_tx = self.account.sign_transaction(tx)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            
            # Wait for receipt
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            end_time = time.time()  # End timing
            
            if receipt['status'] == 1:
                self.total_transactions += 1
                self.transaction_times.append(end_time - start_time)  # Record transaction time
                return tx_hash.hex()
            else:
                self.failed_transactions += 1
                self.logger.error(f"Transaction failed: {receipt}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error sending transaction: {str(e)}")
            self.failed_transactions += 1
            return None

    def log_attack_detection(self, attack_info, current_step):
        """Log attack detection event."""
        try:
            # Prepare summary data
            summary = {
                'probability': attack_info['probability'],
                'risk_level': attack_info['risk_level']
            }
            
            # Convert to strings for blockchain
            event_type = "attack_detection"
            id_str = str(current_step)
            data_str = json.dumps(self._sanitize_data(summary))
            
            return self._send_transaction(event_type, id_str, data_str)
            
        except Exception as e:
            self.logger.error(f"Error logging attack detection: {str(e)}")
            return None

    def log_node_conversion(self, node_id, new_type, current_step):
        """Log node conversion event."""
        try:
            data = {
                'node_id': node_id,
                'new_type': str(new_type)
            }
            return self._send_transaction(
                'node_conversion',
                str(current_step),
                json.dumps(data)
            )
        except Exception as e:
            self.logger.error(f"Error logging node conversion: {str(e)}")
            return None

    def log_attack_prevention(self, prevention_info, current_step):
        """Log attack prevention event."""
        try:
            return self._send_transaction(
                'attack_prevention',
                str(current_step),
                json.dumps(self._sanitize_data(prevention_info))
            )
        except Exception as e:
            self.logger.error(f"Error logging attack prevention: {str(e)}")
            return None

    def get_performance_metrics(self):
        """Get blockchain logging performance metrics."""
        if not self.transaction_times:
            return {
                'avg_transaction_time': 0,
                'total_transactions': self.total_transactions,
                'failed_transactions': self.failed_transactions,
                'success_rate': 0
            }
            
        return {
            'avg_transaction_time': sum(self.transaction_times) / len(self.transaction_times),
            'total_transactions': self.total_transactions,
            'failed_transactions': self.failed_transactions,
            'success_rate': (self.total_transactions - self.failed_transactions) / 
                          self.total_transactions if self.total_transactions > 0 else 0
        }
    
    def reset(self):
        """Reset performance tracking metrics."""
        self.transaction_times = []
        self.total_transactions = 0
        self.failed_transactions = 0
        self.logger.info("BlockchainLogger metrics reset")