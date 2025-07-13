import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
import requests
from datetime import datetime
import json
from colorama import Fore

class TransactionGraphAnalyzer:
    def __init__(self, api_key):
        self.api_key = api_key
        self.graph = nx.DiGraph()
        self.transaction_data = {}
        
    def fetch_transactions(self, address, max_transactions=1000):
        """Fetch transactions for a given address"""
        params = {
            'module': 'account',
            'action': 'txlist',
            'address': address,
            'startblock': 0,
            'endblock': 99999999,
            'sort': 'desc',
            'apikey': self.api_key
        }
        
        response = requests.get("https://api.etherscan.io/api", params=params)
        data = response.json().get("result", [])
        
        return data[:max_transactions] if isinstance(data, list) else []
    
    def build_graph(self, addresses, depth=2):
        """Build transaction graph for multiple addresses with specified depth"""
        processed_addresses = set()
        
        for address in addresses:
            if address not in processed_addresses:
                self._build_graph_recursive(address, depth, processed_addresses)
                
        print(f"{Fore.GREEN}Graph built with {self.graph.number_of_nodes()} nodes and {self.graph.number_of_edges()} edges")
    
    def _build_graph_recursive(self, address, depth, processed_addresses):
        """Recursively build graph to specified depth"""
        if depth <= 0 or address in processed_addresses:
            return
            
        processed_addresses.add(address)
        transactions = self.fetch_transactions(address)
        
        for tx in transactions:
            from_addr = tx.get('from', '').lower()
            to_addr = tx.get('to', '').lower()
            value = float(tx.get('value', 0)) / 1e18  # Convert Wei to ETH
            
            if from_addr and to_addr:
                # Add edge with transaction details
                if self.graph.has_edge(from_addr, to_addr):
                    self.graph[from_addr][to_addr]['weight'] += value
                    self.graph[from_addr][to_addr]['count'] += 1
                else:
                    self.graph.add_edge(from_addr, to_addr, weight=value, count=1)
                
                # Store transaction details
                tx_hash = tx.get('hash')
                self.transaction_data[tx_hash] = {
                    'from': from_addr,
                    'to': to_addr,
                    'value': value,
                    'timestamp': datetime.fromtimestamp(int(tx.get('timeStamp', 0))),
                    'gas_used': int(tx.get('gasUsed', 0)),
                    'gas_price': int(tx.get('gasPrice', 0))
                }
                
                # Recursively process connected addresses
                if depth > 1:
                    self._build_graph_recursive(to_addr, depth - 1, processed_addresses)
    
    def find_suspicious_patterns(self):
        """Identify suspicious transaction patterns"""
        suspicious_patterns = {
            'high_value_flows': [],
            'rapid_transfers': [],
            'circular_flows': [],
            'mixing_patterns': []
        }
        
        # High value flows
        for edge in self.graph.edges(data=True):
            if edge[2]['weight'] > 100:  # More than 100 ETH
                suspicious_patterns['high_value_flows'].append({
                    'from': edge[0],
                    'to': edge[1],
                    'value': edge[2]['weight'],
                    'count': edge[2]['count']
                })
        
        # Circular flows (simplified cycle detection)
        try:
            cycles = list(nx.simple_cycles(self.graph))
            suspicious_patterns['circular_flows'] = cycles[:10]  # Top 10 cycles
        except:
            pass
        
        # Mixing patterns (addresses with high in/out degree)
        for node in self.graph.nodes():
            in_degree = self.graph.in_degree(node)
            out_degree = self.graph.out_degree(node)
            
            if in_degree > 50 and out_degree > 50:  # Potential mixer
                suspicious_patterns['mixing_patterns'].append({
                    'address': node,
                    'in_degree': in_degree,
                    'out_degree': out_degree
                })
        
        return suspicious_patterns
    
    def visualize_graph(self, output_file='transaction_graph.png', max_nodes=100):
        """Visualize the transaction graph"""
        # Create subgraph with most connected nodes for better visualization
        if self.graph.number_of_nodes() > max_nodes:
            # Get nodes with highest degree
            node_degrees = dict(self.graph.degree())
            top_nodes = sorted(node_degrees.items(), key=lambda x: x[1], reverse=True)[:max_nodes]
            subgraph = self.graph.subgraph([node[0] for node in top_nodes])
        else:
            subgraph = self.graph
        
        plt.figure(figsize=(15, 10))
        pos = nx.spring_layout(subgraph, k=1, iterations=50)
        
        # Draw nodes with size based on degree
        node_sizes = [subgraph.degree(node) * 50 for node in subgraph.nodes()]
        nx.draw_networkx_nodes(subgraph, pos, node_size=node_sizes, 
                              node_color='lightblue', alpha=0.7)
        
        # Draw edges with thickness based on weight
        edge_weights = [subgraph[u][v]['weight'] for u, v in subgraph.edges()]
        max_weight = max(edge_weights) if edge_weights else 1
        edge_widths = [min(5, (w / max_weight) * 5) for w in edge_weights]
        
        nx.draw_networkx_edges(subgraph, pos, width=edge_widths, 
                              alpha=0.5, edge_color='gray')
        
        # Add labels for important nodes
        important_nodes = {node: node[:8] + '...' for node in subgraph.nodes() 
                          if subgraph.degree(node) > 5}
        nx.draw_networkx_labels(subgraph, pos, important_nodes, font_size=8)
        
        plt.title("Transaction Flow Graph")
        plt.axis('off')
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"{Fore.GREEN}Graph visualization saved to {output_file}")
    
    def generate_report(self, output_file='graph_analysis_report.json'):
        """Generate detailed analysis report"""
        patterns = self.find_suspicious_patterns()
        
        # Calculate network metrics
        metrics = {
            'total_nodes': self.graph.number_of_nodes(),
            'total_edges': self.graph.number_of_edges(),
            'density': nx.density(self.graph),
            'average_clustering': nx.average_clustering(self.graph.to_undirected()),
        }
        
        # Top addresses by volume
        address_volumes = {}
        for edge in self.graph.edges(data=True):
            from_addr, to_addr = edge[0], edge[1]
            weight = edge[2]['weight']
            
            address_volumes[from_addr] = address_volumes.get(from_addr, 0) + weight
            address_volumes[to_addr] = address_volumes.get(to_addr, 0) + weight
        
        top_addresses = sorted(address_volumes.items(), key=lambda x: x[1], reverse=True)[:20]
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'network_metrics': metrics,
            'suspicious_patterns': patterns,
            'top_addresses_by_volume': [{'address': addr, 'volume': vol} for addr, vol in top_addresses],
            'analysis_summary': {
                'high_risk_addresses': len(patterns['high_value_flows']),
                'potential_mixers': len(patterns['mixing_patterns']),
                'circular_flows_detected': len(patterns['circular_flows'])
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"{Fore.GREEN}Analysis report saved to {output_file}")
        return report

# Example usage
if __name__ == "__main__":
    import os
    
    api_key = os.getenv('ETHERSCAN_API_KEY')
    if not api_key:
        print(f"{Fore.RED}Please set ETHERSCAN_API_KEY environment variable")
        exit(1)
    
    # Load attacker addresses
    try:
        with open('attackersOutput.txt', 'r') as f:
            addresses = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        addresses = ['0x1234567890abcdef1234567890abcdef12345678']  # Example address
    
    analyzer = TransactionGraphAnalyzer(api_key)
    
    print(f"{Fore.YELLOW}Building transaction graph for {len(addresses)} addresses...")
    analyzer.build_graph(addresses[:5], depth=2)  # Limit for demo
    
    print(f"{Fore.YELLOW}Analyzing suspicious patterns...")
    patterns = analyzer.find_suspicious_patterns()
    
    print(f"{Fore.YELLOW}Generating visualization...")
    analyzer.visualize_graph()
    
    print(f"{Fore.YELLOW}Generating report...")
    report = analyzer.generate_report()
    
    print(f"{Fore.GREEN}Analysis complete!")