import requests
import json
from datetime import datetime, timedelta
import pandas as pd
from colorama import Fore
import time

class CrossChainAnalyzer:
    def __init__(self, api_keys):
        """
        Initialize with API keys for different chains
        api_keys should be a dict like:
        {
            'ethereum': 'your_etherscan_key',
            'bsc': 'your_bscscan_key',
            'polygon': 'your_polygonscan_key',
            'arbitrum': 'your_arbiscan_key'
        }
        """
        self.api_keys = api_keys
        self.chain_configs = {
            'ethereum': {
                'api_url': 'https://api.etherscan.io/api',
                'decimals': 18,
                'native_token': 'ETH'
            },
            'bsc': {
                'api_url': 'https://api.bscscan.com/api',
                'decimals': 18,
                'native_token': 'BNB'
            },
            'polygon': {
                'api_url': 'https://api.polygonscan.com/api',
                'decimals': 18,
                'native_token': 'MATIC'
            },
            'arbitrum': {
                'api_url': 'https://api.arbiscan.io/api',
                'decimals': 18,
                'native_token': 'ETH'
            }
        }
        
        # Known bridge addresses for cross-chain detection
        self.bridge_addresses = {
            'ethereum': {
                'polygon_bridge': '0x40ec5b33f54e0e8a33a975908c5ba1c14e5bbbdf',
                'arbitrum_bridge': '0x8315177ab297ba92a06054ce80a67ed4dbd7ed3a',
                'bsc_bridge': '0x533e3c0e6b48010873b947bddc4721b1bdff9648'
            },
            'polygon': {
                'ethereum_bridge': '0x86e4dc95c7fbdbf52e33d563bbdb00823894c287'
            },
            'arbitrum': {
                'ethereum_bridge': '0x5288c571fd7ad117bea99bf60fe0846c4e84f933'
            },
            'bsc': {
                'ethereum_bridge': '0x533e3c0e6b48010873b947bddc4721b1bdff9648'
            }
        }
        
        self.cross_chain_flows = []
        self.analysis_results = {}
    
    def fetch_transactions(self, address, chain, max_transactions=1000):
        """Fetch transactions for an address on a specific chain"""
        if chain not in self.chain_configs:
            print(f"{Fore.RED}Unsupported chain: {chain}")
            return []
        
        config = self.chain_configs[chain]
        api_key = self.api_keys.get(chain)
        
        if not api_key:
            print(f"{Fore.RED}No API key provided for {chain}")
            return []
        
        params = {
            'module': 'account',
            'action': 'txlist',
            'address': address,
            'startblock': 0,
            'endblock': 99999999,
            'sort': 'desc',
            'apikey': api_key
        }
        
        try:
            response = requests.get(config['api_url'], params=params)
            data = response.json().get("result", [])
            
            if isinstance(data, list):
                return data[:max_transactions]
            else:
                print(f"{Fore.YELLOW}Warning: Unexpected response format for {chain}")
                return []
                
        except Exception as e:
            print(f"{Fore.RED}Error fetching transactions for {chain}: {e}")
            return []
    
    def analyze_cross_chain_activity(self, address):
        """Analyze cross-chain activity for a given address"""
        cross_chain_data = {}
        
        for chain in self.chain_configs.keys():
            if chain in self.api_keys:
                print(f"{Fore.YELLOW}Analyzing {address} on {chain}...")
                transactions = self.fetch_transactions(address, chain)
                
                cross_chain_data[chain] = {
                    'total_transactions': len(transactions),
                    'bridge_interactions': [],
                    'total_value': 0,
                    'first_activity': None,
                    'last_activity': None
                }
                
                # Analyze each transaction
                for tx in transactions:
                    timestamp = datetime.fromtimestamp(int(tx.get('timeStamp', 0)))
                    value = float(tx.get('value', 0)) / (10 ** self.chain_configs[chain]['decimals'])
                    
                    # Update activity timeline
                    if not cross_chain_data[chain]['first_activity'] or timestamp < cross_chain_data[chain]['first_activity']:
                        cross_chain_data[chain]['first_activity'] = timestamp
                    if not cross_chain_data[chain]['last_activity'] or timestamp > cross_chain_data[chain]['last_activity']:
                        cross_chain_data[chain]['last_activity'] = timestamp
                    
                    cross_chain_data[chain]['total_value'] += value
                    
                    # Check for bridge interactions
                    to_addr = tx.get('to', '').lower()
                    from_addr = tx.get('from', '').lower()
                    
                    for bridge_name, bridge_addr in self.bridge_addresses.get(chain, {}).items():
                        if to_addr == bridge_addr.lower() or from_addr == bridge_addr.lower():
                            cross_chain_data[chain]['bridge_interactions'].append({
                                'bridge': bridge_name,
                                'tx_hash': tx.get('hash'),
                                'timestamp': timestamp,
                                'value': value,
                                'direction': 'outgoing' if to_addr == bridge_addr.lower() else 'incoming'
                            })
                
                time.sleep(0.2)  # Rate limiting
        
        return cross_chain_data
    
    def detect_cross_chain_patterns(self, addresses):
        """Detect cross-chain movement patterns for multiple addresses"""
        all_results = {}
        
        for address in addresses:
            print(f"{Fore.CYAN}Analyzing cross-chain activity for {address}")
            all_results[address] = self.analyze_cross_chain_activity(address)
        
        # Analyze patterns
        patterns = {
            'multi_chain_addresses': [],
            'rapid_cross_chain_transfers': [],
            'bridge_clustering': {},
            'timing_correlations': []
        }
        
        for address, data in all_results.items():
            active_chains = [chain for chain, info in data.items() if info['total_transactions'] > 0]
            
            if len(active_chains) > 1:
                patterns['multi_chain_addresses'].append({
                    'address': address,
                    'active_chains': active_chains,
                    'total_chains': len(active_chains)
                })
            
            # Check for rapid cross-chain transfers
            bridge_interactions = []
            for chain, info in data.items():
                for interaction in info['bridge_interactions']:
                    bridge_interactions.append({
                        'chain': chain,
                        'timestamp': interaction['timestamp'],
                        'bridge': interaction['bridge'],
                        'value': interaction['value']
                    })
            
            # Sort by timestamp
            bridge_interactions.sort(key=lambda x: x['timestamp'])
            
            # Look for rapid sequences
            for i in range(1, len(bridge_interactions)):
                time_diff = bridge_interactions[i]['timestamp'] - bridge_interactions[i-1]['timestamp']
                if time_diff < timedelta(hours=1):  # Within 1 hour
                    patterns['rapid_cross_chain_transfers'].append({
                        'address': address,
                        'transfer_1': bridge_interactions[i-1],
                        'transfer_2': bridge_interactions[i],
                        'time_difference': time_diff
                    })
        
        self.analysis_results = {
            'individual_results': all_results,
            'patterns': patterns,
            'summary': {
                'total_addresses_analyzed': len(addresses),
                'multi_chain_addresses': len(patterns['multi_chain_addresses']),
                'rapid_transfers_detected': len(patterns['rapid_cross_chain_transfers'])
            }
        }
        
        return self.analysis_results
    
    def generate_cross_chain_report(self, output_file='cross_chain_analysis.json'):
        """Generate comprehensive cross-chain analysis report"""
        if not self.analysis_results:
            print(f"{Fore.RED}No analysis results available. Run detect_cross_chain_patterns first.")
            return
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'analysis_type': 'cross_chain_forensics',
            'chains_analyzed': list(self.chain_configs.keys()),
            'results': self.analysis_results,
            'risk_assessment': self._assess_cross_chain_risk()
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"{Fore.GREEN}Cross-chain analysis report saved to {output_file}")
        return report
    
    def _assess_cross_chain_risk(self):
        """Assess risk level based on cross-chain patterns"""
        risk_factors = {
            'high_risk_indicators': [],
            'medium_risk_indicators': [],
            'low_risk_indicators': []
        }
        
        if not self.analysis_results:
            return risk_factors
        
        patterns = self.analysis_results['patterns']
        
        # High risk: Multiple rapid cross-chain transfers
        if len(patterns['rapid_cross_chain_transfers']) > 3:
            risk_factors['high_risk_indicators'].append({
                'type': 'frequent_rapid_transfers',
                'count': len(patterns['rapid_cross_chain_transfers']),
                'description': 'Multiple rapid cross-chain transfers detected'
            })
        
        # Medium risk: Active on multiple chains
        multi_chain_count = len(patterns['multi_chain_addresses'])
        if multi_chain_count > 0:
            risk_level = 'high_risk_indicators' if multi_chain_count > 5 else 'medium_risk_indicators'
            risk_factors[risk_level].append({
                'type': 'multi_chain_activity',
                'count': multi_chain_count,
                'description': f'{multi_chain_count} addresses active on multiple chains'
            })
        
        return risk_factors
    
    def visualize_cross_chain_flows(self, output_file='cross_chain_flows.png'):
        """Create visualization of cross-chain flows"""
        try:
            import matplotlib.pyplot as plt
            import networkx as nx
            
            if not self.analysis_results:
                print(f"{Fore.RED}No analysis results available.")
                return
            
            G = nx.DiGraph()
            
            # Add nodes for each chain
            for chain in self.chain_configs.keys():
                G.add_node(chain, node_type='chain')
            
            # Add edges for cross-chain transfers
            for address, data in self.analysis_results['individual_results'].items():
                for chain, info in data.items():
                    for interaction in info['bridge_interactions']:
                        bridge_chain = interaction['bridge'].replace('_bridge', '')
                        if bridge_chain in self.chain_configs:
                            G.add_edge(chain, bridge_chain, weight=interaction['value'])
            
            plt.figure(figsize=(12, 8))
            pos = nx.spring_layout(G, k=3, iterations=50)
            
            # Draw chain nodes
            nx.draw_networkx_nodes(G, pos, node_size=3000, node_color='lightblue', alpha=0.8)
            
            # Draw edges with thickness based on value
            edges = G.edges(data=True)
            if edges:
                weights = [edge[2].get('weight', 1) for edge in edges]
                max_weight = max(weights) if weights else 1
                edge_widths = [min(5, (w / max_weight) * 5) for w in weights]
                nx.draw_networkx_edges(G, pos, width=edge_widths, alpha=0.6, edge_color='red')
            
            # Add labels
            nx.draw_networkx_labels(G, pos, font_size=12, font_weight='bold')
            
            plt.title("Cross-Chain Transaction Flows")
            plt.axis('off')
            plt.tight_layout()
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            print(f"{Fore.GREEN}Cross-chain flow visualization saved to {output_file}")
            
        except ImportError:
            print(f"{Fore.YELLOW}matplotlib not available. Skipping visualization.")

# Example usage
if __name__ == "__main__":
    import os
    
    # Set up API keys
    api_keys = {
        'ethereum': os.getenv('ETHERSCAN_API_KEY'),
        'bsc': os.getenv('BSCSCAN_API_KEY'),
        'polygon': os.getenv('POLYGONSCAN_API_KEY'),
        'arbitrum': os.getenv('ARBISCAN_API_KEY')
    }
    
    # Filter out None values
    api_keys = {k: v for k, v in api_keys.items() if v is not None}
    
    if not api_keys:
        print(f"{Fore.RED}No API keys found. Please set environment variables.")
        exit(1)
    
    # Load addresses
    try:
        with open('attackersOutput.txt', 'r') as f:
            addresses = [line.strip() for line in f.readlines()][:3]  # Limit for demo
    except FileNotFoundError:
        addresses = ['0x1234567890abcdef1234567890abcdef12345678']
    
    analyzer = CrossChainAnalyzer(api_keys)
    
    print(f"{Fore.YELLOW}Starting cross-chain analysis for {len(addresses)} addresses...")
    results = analyzer.detect_cross_chain_patterns(addresses)
    
    print(f"{Fore.YELLOW}Generating report...")
    analyzer.generate_cross_chain_report()
    
    print(f"{Fore.YELLOW}Creating visualization...")
    analyzer.visualize_cross_chain_flows()
    
    print(f"{Fore.GREEN}Cross-chain analysis complete!")