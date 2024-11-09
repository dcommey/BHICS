# src/network/network.py

from collections import defaultdict
import heapq
import logging
import random
from .node import Node, NodeType, NodeStatus

class Network:
    def __init__(self, config):
        self.config = config
        self.nodes = {}
        self.honeypots = {}
        self.gateways = {}
        self.traffic_queue = []
        self.scenario_name = None
        
        # Initialize logger
        self.logger = logging.getLogger("Network")
        
        # Initialize metrics with proper tracking
        self.metrics = {
            'total_attacks': 0,
            'prevented_attacks': 0,
            'processed_traffic': 0,
            'queued_traffic': 0,
            'dropped_traffic': 0,
            'total_traffic': 0,
            'currently_compromised': set(),  # Currently compromised nodes
            'ever_compromised': set(),      # All nodes that were ever compromised
            'total_conversions': 0,
        }
        
        # Configure network
        self._initialize_network()
    
    def setup_scenario(self, scenario_name):
        """Setup network for specific scenario."""
        self.scenario_name = scenario_name
        self._initialize_network()
        
    def _initialize_network(self):
        """Initialize network based on configuration."""
        # Clear existing nodes
        self.nodes = {}
        self.honeypots = {}
        self.gateways = {}
        
        # Create normal nodes
        num_devices = self.config['network']['num_devices']
        if self.scenario_name:
            num_honeypots = self.config['scenarios'][self.scenario_name]['initial_honeypots']
            num_devices -= num_honeypots
        
        # Create normal nodes
        for i in range(num_devices):
            node = Node(f"node_{i}", NodeType.NORMAL, self.config)  # Pass full config
            self.nodes[node.id] = node
            
        # Create gateway nodes
        for i in range(self.config['network']['num_gateways']):
            gateway = Node(f"gateway_{i}", NodeType.GATEWAY, self.config)  # Pass full config
            self.gateways[gateway.id] = gateway
            
        # Initialize dedicated honeypots if specified in scenario
        if self.scenario_name and num_honeypots > 0:
            for i in range(num_honeypots):
                honeypot = Node(f"honeypot_{i}", NodeType.HONEYPOT, self.config)  # Pass full config
                self.honeypots[honeypot.id] = honeypot

    def process_traffic(self, traffic, current_step):
        """Process incoming traffic with comprehensive error handling."""
        try:
            # Only increment metrics for new traffic, not queued traffic
            if not traffic.get('_from_queue', False):
                self.metrics['total_traffic'] += 1
                if traffic['label'] == 1:
                    self.metrics['total_attacks'] += 1
            
            # Process queued traffic first
            self._process_queued_traffic(current_step)
            
            # Process new traffic based on target
            if traffic['target'] == 'honeypot':
                success, proc_time = self._process_honeypot_traffic(traffic, current_step)
            else:
                success, proc_time = self._process_normal_traffic(traffic, current_step)
            
            # Only increment processed_traffic for successfully processed new traffic
            if success and not traffic.get('_from_queue', False):
                self.metrics['processed_traffic'] += 1
                
            return success, proc_time
            
        except Exception as e:
            self.logger.error(f"Error processing traffic: {str(e)}")
            return False, 0

    def _process_honeypot_traffic(self, traffic, current_step):
        """Process honeypot traffic with correct conversion and queuing logic."""
        available_honeypot = self._get_available_honeypot(current_step)
        
        if available_honeypot:
            processing_time, _ = available_honeypot.process_traffic(traffic, current_step)
            if traffic['label'] == 1:
                self.metrics['prevented_attacks'] += 1
                self.logger.info(
                    f"Attack prevented by honeypot {available_honeypot.id} at step {current_step}"
                )
            return True, processing_time
        
        # Try conversion if no honeypot available and this is dynamic scenario
        if (self.scenario_name == 'dynamic' and self._can_convert_node(current_step)):
            if self._convert_node(current_step):
                # Queue the traffic to be processed after conversion
                if self._queue_traffic(traffic, current_step):
                    self.logger.info(f"Traffic queued during conversion at step {current_step}")
                    return True, 0
        
        # If no conversion possible, try to queue
        if self._queue_traffic(traffic, current_step):
            self.logger.info(
                f"Traffic queued at step {current_step}, no honeypots available. "
                f"Queue size: {len(self.traffic_queue)}/{self.config['network']['max_queue_size']}"
            )
            return True, 0
        
        # Only fall back to normal processing if queue is full
        self.logger.info(f"Queue full at step {current_step}, processing with normal node")
        return self._process_normal_traffic(traffic, current_step)

    def _process_normal_traffic(self, traffic, current_step):
        """Process traffic for normal nodes."""
        available_node = self._get_available_normal_node(current_step)
        
        if available_node:
            processing_time, was_compromised = available_node.process_traffic(traffic, current_step)
            if was_compromised:
                self.metrics['currently_compromised'].add(available_node.id)
                self.metrics['ever_compromised'].add(available_node.id)
            return True, processing_time
        
        # Try to queue if no node available
        if self._queue_traffic(traffic, current_step):
            self.metrics['queued_traffic'] += 1
            return True, 0
        
        self.metrics['dropped_traffic'] += 1
        return False, 0

    def _can_convert_node(self, current_step):
        """Check if node conversion is possible with scenario check."""
        if self.scenario_name != 'dynamic':
            return False
            
        total_nodes = len(self.nodes) + len(self.honeypots)
        current_honeypots = len(self.honeypots) + sum(
            1 for node in self.nodes.values() 
            if node.type == NodeType.CONVERTED_HONEYPOT
        )
        current_normal = len([node for node in self.nodes.values() 
                            if node.type == NodeType.NORMAL])
        
        max_honeypots = int(self.config['network']['max_honeypot_ratio'] * total_nodes)
        min_normal = int(self.config['network']['min_normal_ratio'] * total_nodes)
        
        can_convert = (current_honeypots < max_honeypots and 
                    current_normal > min_normal)
                    
        if can_convert:
            self.logger.debug(
                f"Conversion possible at step {current_step}: "
                f"Current honeypots: {current_honeypots}/{max_honeypots}, "
                f"Normal nodes: {current_normal}/{min_normal}"
            )
        
        return can_convert

    def _convert_node(self, current_step):
        """Convert a normal node to honeypot with proper state tracking."""
        if not self._can_convert_node(current_step):
            return False
            
        # Find conversion candidates
        candidates = [
            node for node in self.nodes.values()
            if node.can_convert(current_step)
        ]
        
        if not candidates:
            return False
            
        # Select random candidate and attempt conversion
        node = random.choice(candidates)
        try:
            success = node.convert_to_honeypot(
                current_step,
                self.config['network']['timing']['isolation_time'], 
                self.config['network']['timing']['conversion_time']
            )
            
            if success:
                self.metrics['total_conversions'] += 1
                self.logger.info(f"Node {node.id} conversion started at step {current_step}")
                
                # Log to blockchain if available
                if hasattr(self, 'blockchain_logger') and self.blockchain_logger:
                    self.blockchain_logger.log_conversion({
                        'node_id': node.id,
                        'timestamp': current_step,
                        'type': 'conversion_start'
                    })
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error converting node: {str(e)}")
            return False

    def update(self, current_step):
        """Update network state with recovery checks."""
        # Update node states
        for node in list(self.nodes.values()) + list(self.honeypots.values()):
            node.update_status(current_step)
            
            # Handle recoveries
            if node.check_recovery(current_step):
                self.metrics['currently_compromised'].discard(node.id)
            
        # Process queued traffic
        self._process_queued_traffic(current_step)

    def get_metrics(self, current_step):
        """Get network metrics with enhanced statistics."""
        # Calculate basic metrics
        total_convertible_nodes = len(self.nodes) + len(self.honeypots)
        total_normal_nodes = len([node for node in self.nodes.values() 
                                if node.type == NodeType.NORMAL])
        
        # Calculate current honeypots based on scenario
        if self.scenario_name == 'dedicated':
            max_honeypots = self.config['scenarios']['dedicated']['initial_honeypots']
        else:
            max_honeypots = int(self.config['network']['max_honeypot_ratio'] * 
                            total_convertible_nodes)
        
        current_honeypots = len(self.honeypots) + sum(
            1 for node in self.nodes.values() 
            if node.type == NodeType.CONVERTED_HONEYPOT
        )
        
        # Calculate rates according to methodology
        total_attack_traffic = self.metrics['total_attacks']
        prevented_attacks = self.metrics['prevented_attacks']
        
        metrics = {
            'attack_prevention_rate': (
                prevented_attacks / total_attack_traffic
                if total_attack_traffic > 0 
                else 0.0
            ),
            'current_compromise_rate': (
                len(self.metrics['currently_compromised']) / total_normal_nodes
                if total_normal_nodes > 0 
                else 0.0
            ),
            'cumulative_compromise_rate': (
                len(self.metrics['ever_compromised']) / total_convertible_nodes
                if total_convertible_nodes > 0
                else 0.0
            ),
            'honeypot_utilization_rate': (  # Changed to match visualization
                current_honeypots / max_honeypots
                if max_honeypots > 0
                else 0.0
            ),
            'traffic_loss_rate': (
                self.metrics['dropped_traffic'] / self.metrics['total_traffic']
                if self.metrics['total_traffic'] > 0 
                else 0.0
            ),
            'node_availability_rate': (  # Added for completeness
                1.0 - (len(self.metrics['currently_compromised']) / total_normal_nodes)
                if total_normal_nodes > 0 
                else 1.0
            )
        }
        
        # Add raw counts
        metrics.update({
            'total_nodes': total_convertible_nodes,
            'total_normal_nodes': total_normal_nodes,
            'current_honeypots': current_honeypots,
            'total_attacks': self.metrics['total_attacks'],
            'prevented_attacks': self.metrics['prevented_attacks'],
            'processed_traffic': self.metrics['processed_traffic'],
            'queued_traffic': self.metrics['queued_traffic'],
            'dropped_traffic': self.metrics['dropped_traffic'],
            'total_traffic': self.metrics['total_traffic'],
            'currently_compromised': list(self.metrics['currently_compromised']),
            'ever_compromised': list(self.metrics['ever_compromised']),
            'total_conversions': self.metrics['total_conversions']
        })
        
        # Add recovery statistics
        normal_nodes = [n for n in self.nodes.values() if n.type == NodeType.NORMAL]
        recovered_nodes = [n for n in normal_nodes if n.recovery_count > 0]
        
        total_compromise_time = sum(n.total_compromise_time for n in normal_nodes)
        total_recoveries = sum(n.recovery_count for n in normal_nodes)
        
        metrics['recovery_statistics'] = {
            'recovery_rate': len(recovered_nodes) / max(1, len(normal_nodes)),
            'average_compromise_duration': (
                total_compromise_time / max(1, total_recoveries)
            ),
            'total_recoveries': total_recoveries,
            'nodes_ever_recovered': len(recovered_nodes)
        }
        
        # Validate metrics consistency
        self._validate_metrics(metrics)
        
        return metrics

    # Helper methods
    def _get_available_honeypot(self, current_step):
        """Get a single available honeypot."""
        available_honeypots = [
            hp for hp in list(self.honeypots.values()) + 
            [n for n in self.nodes.values() if n.type == NodeType.CONVERTED_HONEYPOT]
            if hp.is_available(current_step)
        ]
        return random.choice(available_honeypots) if available_honeypots else None

    def _get_all_available_honeypots(self, current_step):
        """Get list of all available honeypots."""
        return [hp for hp in list(self.honeypots.values()) + 
                [n for n in self.nodes.values() if n.type == NodeType.CONVERTED_HONEYPOT]
                if hp.is_available(current_step)]

    def _get_available_normal_node(self, current_step):
        """Get an available normal node."""
        available = [
            node for node in self.nodes.values()
            if node.type == NodeType.NORMAL and node.is_available(current_step)
        ]
        return random.choice(available) if available else None

    def _queue_traffic(self, traffic, current_step):
        """Queue traffic with priority handling."""
        if len(self.traffic_queue) >= self.config['network']['max_queue_size']:
            return False
        
        # Create a copy of traffic to avoid modifying the original
        traffic_copy = traffic.copy()
        traffic_copy['_from_queue'] = True
        
        # Higher priority for attack traffic
        priority = 2 if traffic_copy['label'] == 1 else 1
        
        # Add to queue with priority, timestamp, and target
        queue_item = {
            'traffic': traffic_copy,
            'queue_time': current_step,
            'priority': priority,
            'target': traffic_copy['target']
        }
        
        self.traffic_queue.append(queue_item)
        self.metrics['queued_traffic'] += 1
        return True

    def _process_queued_traffic(self, current_step):
        """Process queued traffic with improved handling."""
        if not self.traffic_queue:
            return
        
        sorted_queue = sorted(
            self.traffic_queue,
            key=lambda x: (-x['priority'], x['queue_time'])
        )
        
        remaining_queue = []
        queue_timeout = self.config['network']['timing'].get('queue_timeout', 5)
        
        for item in sorted_queue:
            traffic = item['traffic']
            queue_time = item['queue_time']
            original_target = traffic.get('target', 'normal')
            
            # Check for timeout
            if current_step - queue_time > queue_timeout:
                self.metrics['dropped_traffic'] += 1
                self.metrics['queued_traffic'] -= 1
                continue
            
            # Process traffic based on original target
            success = False
            if original_target == 'honeypot':
                available_honeypot = self._get_available_honeypot(current_step)
                if available_honeypot:
                    _, _ = available_honeypot.process_traffic(traffic, current_step)
                    if traffic['label'] == 1:
                        self.metrics['prevented_attacks'] += 1
                    success = True
            
            # If honeypot processing failed or original target was normal
            if not success:
                available_node = self._get_available_normal_node(current_step)
                if available_node:
                    _, was_compromised = available_node.process_traffic(
                        traffic, current_step
                    )
                    if was_compromised:
                        self.metrics['currently_compromised'].add(available_node.id)
                        self.metrics['ever_compromised'].add(available_node.id)
                    success = True
            
            if success:
                self.metrics['queued_traffic'] -= 1
            else:
                remaining_queue.append(item)
        
        self.traffic_queue = remaining_queue

    def _get_required_wait_time(self, traffic):
        """Get required processing time based on traffic type."""
        if traffic['target'] == 'honeypot':
            return self.config['network']['timing']['honeypot_processing_time']
        return (self.config['network']['timing']['attack_processing_time'] 
                if traffic['label'] == 1 
                else self.config['network']['timing']['normal_processing_time'])
    
    def _validate_metrics(self, metrics):
        """Validate metrics consistency."""
        try:
            # Validate traffic counts
            total = metrics['total_traffic']
            processed = metrics['processed_traffic']
            queued = metrics['queued_traffic']
            dropped = metrics['dropped_traffic']
            
            # Each piece of traffic should be in exactly one state
            expected_total = processed + queued + dropped
            if total != expected_total:
                self.logger.warning(
                    f"Traffic count mismatch: total={total}, sum={expected_total} "
                    f"(processed={processed}, queued={queued}, dropped={dropped})"
                )
            
            # Check prevention rate bounds
            if metrics['attack_prevention_rate'] > 1.0:
                self.logger.warning(
                    f"Prevention rate exceeds 1.0 ({metrics['attack_prevention_rate']})"
                )
                metrics['attack_prevention_rate'] = 1.0
            
            # Validate honeypot counts
            total_honeypots = (len(self.honeypots) + 
                            sum(1 for n in self.nodes.values() 
                                if n.type == NodeType.CONVERTED_HONEYPOT))
            if total_honeypots != metrics['current_honeypots']:
                self.logger.warning(
                    f"Honeypot count mismatch. "
                    f"Calculated: {total_honeypots}, "
                    f"Reported: {metrics['current_honeypots']}"
                )
                metrics['current_honeypots'] = total_honeypots
                
        except Exception as e:
            self.logger.error(f"Error validating metrics: {str(e)}")

    def _get_honeypot_count(self):
        """Get current honeypot count."""
        return len(self.honeypots) + sum(
            1 for n in self.nodes.values() 
            if n.type == NodeType.CONVERTED_HONEYPOT
        )

    def _get_normal_count(self):
        """Get current normal node count."""
        return len([n for n in self.nodes.values() if n.type == NodeType.NORMAL])