# src/network/node.py

from enum import Enum
import random
import logging

class NodeType(Enum):
    NORMAL = "normal"
    HONEYPOT = "dedicated_honeypot"
    CONVERTED_HONEYPOT = "converted_honeypot"
    GATEWAY = "gateway"

class NodeStatus(Enum):
    NORMAL = "normal"
    ISOLATING = "isolating"
    CONVERTING = "converting"
    OPERATIONAL = "operational"

class Node:
    def __init__(self, node_id, node_type, config):
        self.id = node_id
        self.type = node_type
        self.status = NodeStatus.NORMAL
        self.is_compromised = False
        self.compromise_time = None
        self.busy_until = 0
        self.connections = []
        self.conversion_timeline = None
        self.last_conversion_time = None
        self.last_reversion_time = None
        self.recovery_count = 0
        self.total_compromise_time = 0
        self.last_compromise_duration = 0
        self.last_honeypot_use = None
        self.config = config  # Store full config
        
        # Initialize logger
        self.logger = logging.getLogger(f"Node_{self.id}")
        
        # Load timing configurations from network section
        network_config = config['network']
        self.honeypot_cooldown = network_config['timing'].get('honeypot_cooldown', 2)  
        self.normal_processing_time = network_config['timing']['normal_processing_time']
        self.attack_processing_time = network_config['timing']['attack_processing_time']
        self.honeypot_processing_time = network_config['timing']['honeypot_processing_time']
        self.conversion_cooldown = network_config['timing']['conversion_cooldown']
        self.reversion_cooldown = network_config['timing']['reversion_cooldown']

    def is_available(self, current_step):
        """Check if node is available."""
        if self.status in [NodeStatus.ISOLATING, NodeStatus.CONVERTING]:
            return False
            
        if current_step < self.busy_until:
            return False
            
        # Honeypot cooldown check
        if self.type in [NodeType.HONEYPOT, NodeType.CONVERTED_HONEYPOT]:
            if (self.last_honeypot_use is not None and 
                current_step - self.last_honeypot_use < self.honeypot_cooldown):
                return False
            return True
            
        # Normal nodes are only available if not compromised
        return not self.is_compromised

    def process_traffic(self, traffic, current_step):
        """Process traffic with honeypot tracking."""
        if not self.is_available(current_step):
            return None, False
            
        is_attack = traffic['label'] == 1
        was_compromised = False
        
        # Get processing time
        processing_time = self._get_processing_time(is_attack)
        
        # Handle potential compromise
        if (is_attack and 
            self.type == NodeType.NORMAL and 
            self.status == NodeStatus.NORMAL):
            was_compromised = self.compromise(current_step)
            
        # Update busy status
        self.busy_until = current_step + processing_time
        
        # Track honeypot usage
        if self.type in [NodeType.HONEYPOT, NodeType.CONVERTED_HONEYPOT]:
            self.last_honeypot_use = current_step
        
        return processing_time, was_compromised

    def _get_processing_time(self, is_attack):
        """Determine processing time based on methodology."""
        if self.type in [NodeType.HONEYPOT, NodeType.CONVERTED_HONEYPOT]:
            return self.honeypot_processing_time  # 3 timesteps
        elif is_attack:
            return self.attack_processing_time  # 2 timesteps
        return self.normal_processing_time  # 1 timestep
    
    def can_convert(self, current_step):
        """Check if node can be converted to honeypot with explicit condition checking."""
        # Basic type check
        if self.type != NodeType.NORMAL:
            return False
            
        # Status check
        if self.status != NodeStatus.NORMAL:
            return False
            
        # Compromise check
        if self.is_compromised:
            return False
            
        # Cooldown checks
        if self.last_conversion_time is not None:
            if current_step - self.last_conversion_time < self.conversion_cooldown:
                return False
                
        if self.last_reversion_time is not None:
            if current_step - self.last_reversion_time < self.reversion_cooldown:
                return False
                
        # Availability check
        if current_step < self.busy_until:
            return False
            
        return True
    
    def check_recovery(self, current_step):
        """Check and handle node recovery with enhanced tracking."""
        network_config = self.config['network']
        if not network_config['recovery']['enabled'] or not self.is_compromised:
            return False
            
        recovery_time = network_config['recovery']['recovery_time']
        recovery_prob = network_config['recovery']['recovery_probability']
        
        if current_step - self.compromise_time >= recovery_time:
            if random.random() < recovery_prob:
                # Track compromise duration
                duration = current_step - self.compromise_time
                self.total_compromise_time += duration
                self.last_compromise_duration = duration
                self.recovery_count += 1
                
                # Reset compromise state
                self.is_compromised = False
                self.compromise_time = None
                
                self.logger.info(
                    f"Node {self.id} recovered at step {current_step}. "
                    f"Duration: {duration}, Total recoveries: {self.recovery_count}, "
                    f"Total compromise time: {self.total_compromise_time}"
                )
                return True
        return False
    
    def get_compromise_stats(self):
        """Get node compromise statistics."""
        return {
            'recovery_count': self.recovery_count,
            'total_compromise_time': self.total_compromise_time,
            'last_compromise_duration': self.last_compromise_duration,
            'average_compromise_duration': (
                self.total_compromise_time / max(1, self.recovery_count)
            )
        }

    def convert_to_honeypot(self, current_step, isolation_time, conversion_time):
        """Convert node to honeypot with proper state management."""
        if not self.can_convert(current_step):
            return False
            
        # Set conversion timeline first to ensure proper state tracking
        self.conversion_timeline = {
            'start': current_step,
            'isolation_end': current_step + isolation_time,
            'conversion_end': current_step + isolation_time + conversion_time
        }
        
        # Update node properties
        self.type = NodeType.CONVERTED_HONEYPOT
        self.status = NodeStatus.ISOLATING
        self.last_conversion_time = current_step
        self.busy_until = self.conversion_timeline['conversion_end']
        
        self.logger.info(f"Node {self.id} starting conversion process at step {current_step}")
        return True

    def revert_to_normal(self, current_step):
        """Revert honeypot back to normal node."""
        if self.type != NodeType.CONVERTED_HONEYPOT:
            return False
            
        self.type = NodeType.NORMAL
        self.status = NodeStatus.NORMAL
        self.last_reversion_time = current_step
        self.conversion_timeline = None
        self.busy_until = current_step
        return True

    def compromise(self, current_step):
        """Compromise node if it's vulnerable according to methodology."""
        if (self.type == NodeType.NORMAL and 
            not self.is_compromised and 
            self.status == NodeStatus.NORMAL):  # Not in conversion
            self.is_compromised = True
            self.compromise_time = current_step
            self.logger.info(f"Node {self.id} compromised at step {current_step}")
            return True
        return False

    def update_status(self, current_step):
        """Update node status and check recovery."""
        # Handle conversion status updates
        if self.conversion_timeline:
            if current_step >= self.conversion_timeline['conversion_end']:
                if self.status == NodeStatus.CONVERTING:
                    self.status = NodeStatus.OPERATIONAL
                    self.type = NodeType.CONVERTED_HONEYPOT 
                    self.logger.info(f"Node {self.id} now operational as honeypot")
                    self.conversion_timeline = None
            elif current_step >= self.conversion_timeline['isolation_end']:
                if self.status == NodeStatus.ISOLATING:
                    self.status = NodeStatus.CONVERTING
                    self.logger.debug(f"Node {self.id} transitioning to CONVERTING state")
        
        # Check for recovery if compromised
        if self.is_compromised:
            self.check_recovery(current_step)