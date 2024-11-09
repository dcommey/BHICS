# test_blockchain.py

import yaml
import logging
from web3 import Web3
from src.blockchain.logger import BlockchainLogger

def verify_config():
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("BlockchainTest")

    # Load config
    with open('config/config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    # Check blockchain config
    blockchain_config = config.get('blockchain', {})
    required_fields = ['node_url', 'private_key', 'contract_address', 'transaction_timeout']
    
    missing_fields = [field for field in required_fields if field not in blockchain_config]
    if missing_fields:
        logger.error(f"Missing required blockchain config fields: {missing_fields}")
        return None
        
    logger.info("Config verification passed")
    return config

def test_connection():
    config = verify_config()
    if not config:
        print("❌ Invalid configuration")
        return
    
    try:
        # Initialize logger
        logger = BlockchainLogger(config)
        
        # Try logging a test event
        result = logger.log_event(
            'test',
            {'message': 'Test event'}, 
            0
        )
        
        if result:
            print("✅ Successfully connected to blockchain and logged event!")
            print(f"Transaction hash: {result}")
        else:
            print("❌ Failed to connect or log event")
            
    except Exception as e:
        print(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    test_connection()