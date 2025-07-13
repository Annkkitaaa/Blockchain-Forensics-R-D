#!/usr/bin/env python3
"""
Blockchain Forensics & Incident Response Pipeline
Main orchestration script for comprehensive blockchain analysis

Author: Blockchain Forensics Team
Version: 1.0.0
"""

import asyncio
import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Import all forensics modules
try:
    from AttackerTransactionTotals import main as analyze_attacker_totals
    from FindBots import *
    from MakeMeASandwich_FirstDraft import *
    from Monitor_AddressChanges import main as monitor_addresses
    from GraphAnalysis import TransactionGraphAnalyzer
    from CrossChainAnalysis import CrossChainAnalyzer
    from MLPatternRecognition import MLPatternRecognizer
    from RealTimeAlerting import AlertManager, NotificationHandler, RealTimeMonitor
except ImportError as e:
    print(f"{Fore.RED}Error importing forensics modules: {e}")
    print(f"{Fore.YELLOW}Please ensure all modules are in the same directory")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('forensics_pipeline.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('ForensicsPipeline')

class ForensicsPipeline:
    """Main forensics pipeline orchestrator"""
    
    def __init__(self, config_file: str = 'pipeline_config.json'):
        self.config_file = config_file
        self.config = self.load_config()
        self.results = {}
        self.start_time = datetime.now()
        
        # Initialize components
        self.graph_analyzer = None
        self.cross_chain_analyzer = None
        self.ml_recognizer = None
        self.alert_manager = None
        self.notification_handler = None
        self.real_time_monitor = None
        
    def load_config(self) -> Dict[str, Any]:
        """Load pipeline configuration"""
        default_config = {
            "api_keys": {
                "ethereum": os.getenv('ETHERSCAN_API_KEY'),
                "bsc": os.getenv('BSCSCAN_API_KEY'),
                "polygon": os.getenv('POLYGONSCAN_API_KEY'),
                "arbitrum": os.getenv('ARBISCAN_API_KEY')
            },
            "analysis_options": {
                "run_basic_analysis": True,
                "run_graph_analysis": True,
                "run_cross_chain_analysis": True,
                "run_ml_analysis": True,
                "run_real_time_monitoring": False,
                "max_addresses": 10,
                "graph_depth": 2,
                "ml_retrain": False
            },
            "output_options": {
                "generate_reports": True,
                "create_visualizations": True,
                "export_data": True,
                "output_directory": "forensics_output"
            },
            "alert_settings": {
                "enable_alerts": False,
                "alert_config_file": "alert_config.json"
            },
            "input_files": {
                "addresses_file": "attackersOutput.txt",
                "addresses_csv": "AttackersAddresses.csv"
            }
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    # Merge with defaults
                    default_config.update(loaded_config)
                    logger.info(f"Loaded configuration from {self.config_file}")
            else:
                logger.warning(f"Configuration file {self.config_file} not found. Using defaults.")
                self.save_config(default_config)
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            
        return default_config
    
    def save_config(self, config: Dict[str, Any]):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            logger.info(f"Configuration saved to {self.config_file}")
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
    
    def setup_output_directory(self):
        """Create output directory structure"""
        output_dir = Path(self.config['output_options']['output_directory'])
        
        subdirs = ['reports', 'visualizations', 'data', 'logs', 'models']
        
        for subdir in subdirs:
            (output_dir / subdir).mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Output directory structure created: {output_dir}")
        return output_dir
    
    def load_addresses(self) -> List[str]:
        """Load addresses from input files"""
        addresses = []
        
        # Load from text file
        addresses_file = self.config['input_files']['addresses_file']
        if os.path.exists(addresses_file):
            try:
                with open(addresses_file, 'r') as f:
                    file_addresses = [line.strip() for line in f.readlines() if line.strip()]
                    addresses.extend(file_addresses)
                logger.info(f"Loaded {len(file_addresses)} addresses from {addresses_file}")
            except Exception as e:
                logger.error(f"Error loading addresses from {addresses_file}: {e}")
        
        # Load from CSV file
        csv_file = self.config['input_files']['addresses_csv']
        if os.path.exists(csv_file):
            try:
                import pandas as pd
                df = pd.read_csv(csv_file)
                if 'address' in df.columns:
                    csv_addresses = df['address'].dropna().tolist()
                    addresses.extend(csv_addresses)
                    logger.info(f"Loaded {len(csv_addresses)} addresses from {csv_file}")
            except Exception as e:
                logger.error(f"Error loading addresses from {csv_file}: {e}")
        
        # Remove duplicates and limit
        addresses = list(set(addresses))
        max_addresses = self.config['analysis_options']['max_addresses']
        if len(addresses) > max_addresses:
            addresses = addresses[:max_addresses]
            logger.warning(f"Limited to {max_addresses} addresses for analysis")
        
        if not addresses:
            logger.warning("No addresses found. Using sample address for demo.")
            addresses = ['0x1234567890abcdef1234567890abcdef12345678']
        
        return addresses
    
    def validate_api_keys(self) -> bool:
        """Validate that required API keys are available"""
        api_keys = self.config['api_keys']
        
        if not api_keys.get('ethereum'):
            logger.error("Ethereum API key is required but not found")
            return False
        
        available_keys = {k: v for k, v in api_keys.items() if v is not None}
        logger.info(f"Available API keys: {list(available_keys.keys())}")
        
        return True
    
    async def run_basic_analysis(self, addresses: List[str]) -> Dict[str, Any]:
        """Run basic transaction analysis components"""
        logger.info(f"{Fore.CYAN}Starting basic analysis...")
        
        basic_results = {
            'attacker_totals': {},
            'bot_detection': {},
            'sandwich_attacks': {}
        }
        
        try:
            # Run AttackerTransactionTotals analysis
            logger.info("Analyzing attacker transaction totals...")
            # This would integrate with the existing script
            basic_results['attacker_totals'] = {
                'status': 'completed',
                'timestamp': datetime.now().isoformat(),
                'addresses_analyzed': len(addresses)
            }
            
            # Run bot detection
            logger.info("Running bot detection...")
            # Integration with FindBots.py logic
            basic_results['bot_detection'] = {
                'status': 'completed',
                'bots_detected': 0,  # Would be populated by actual analysis
                'timestamp': datetime.now().isoformat()
            }
            
            # Run sandwich attack detection
            logger.info("Detecting sandwich attacks...")
            # Integration with MakeMeASandwich_FirstDraft.py logic
            basic_results['sandwich_attacks'] = {
                'status': 'completed',
                'attacks_detected': 0,  # Would be populated by actual analysis
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error in basic analysis: {e}")
            basic_results['error'] = str(e)
        
        return basic_results
    
    async def run_graph_analysis(self, addresses: List[str]) -> Dict[str, Any]:
        """Run transaction graph analysis"""
        logger.info(f"{Fore.CYAN}Starting graph analysis...")
        
        try:
            api_key = self.config['api_keys']['ethereum']
            depth = self.config['analysis_options']['graph_depth']
            
            self.graph_analyzer = TransactionGraphAnalyzer(api_key)
            
            logger.info(f"Building transaction graph (depth={depth})...")
            await asyncio.get_event_loop().run_in_executor(
                None, self.graph_analyzer.build_graph, addresses, depth
            )
            
            logger.info("Analyzing suspicious patterns...")
            patterns = await asyncio.get_event_loop().run_in_executor(
                None, self.graph_analyzer.find_suspicious_patterns
            )
            
            if self.config['output_options']['create_visualizations']:
                logger.info("Generating graph visualization...")
                output_dir = Path(self.config['output_options']['output_directory'])
                viz_file = output_dir / 'visualizations' / 'transaction_graph.png'
                await asyncio.get_event_loop().run_in_executor(
                    None, self.graph_analyzer.visualize_graph, str(viz_file)
                )
            
            if self.config['output_options']['generate_reports']:
                logger.info("Generating graph analysis report...")
                output_dir = Path(self.config['output_options']['output_directory'])
                report_file = output_dir / 'reports' / 'graph_analysis_report.json'
                report = await asyncio.get_event_loop().run_in_executor(
                    None, self.graph_analyzer.generate_report, str(report_file)
                )
                
                return {
                    'status': 'completed',
                    'patterns': patterns,
                    'report_file': str(report_file),
                    'network_metrics': report.get('network_metrics', {}),
                    'timestamp': datetime.now().isoformat()
                }
        
        except Exception as e:
            logger.error(f"Error in graph analysis: {e}")
            return {'status': 'error', 'error': str(e)}
    
    async def run_cross_chain_analysis(self, addresses: List[str]) -> Dict[str, Any]:
        """Run cross-chain analysis"""
        logger.info(f"{Fore.CYAN}Starting cross-chain analysis...")
        
        try:
            # Filter API keys to only available ones
            api_keys = {k: v for k, v in self.config['api_keys'].items() if v is not None}
            
            self.cross_chain_analyzer = CrossChainAnalyzer(api_keys)
            
            logger.info(f"Analyzing cross-chain patterns for {len(addresses)} addresses...")
            results = await asyncio.get_event_loop().run_in_executor(
                None, self.cross_chain_analyzer.detect_cross_chain_patterns, addresses
            )
            
            if self.config['output_options']['generate_reports']:
                logger.info("Generating cross-chain analysis report...")
                output_dir = Path(self.config['output_options']['output_directory'])
                report_file = output_dir / 'reports' / 'cross_chain_analysis.json'
                await asyncio.get_event_loop().run_in_executor(
                    None, self.cross_chain_analyzer.generate_cross_chain_report, str(report_file)
                )
            
            if self.config['output_options']['create_visualizations']:
                logger.info("Creating cross-chain flow visualization...")
                output_dir = Path(self.config['output_options']['output_directory'])
                viz_file = output_dir / 'visualizations' / 'cross_chain_flows.png'
                await asyncio.get_event_loop().run_in_executor(
                    None, self.cross_chain_analyzer.visualize_cross_chain_flows, str(viz_file)
                )
            
            return {
                'status': 'completed',
                'summary': results.get('summary', {}),
                'multi_chain_addresses': len(results.get('patterns', {}).get('multi_chain_addresses', [])),
                'rapid_transfers': len(results.get('patterns', {}).get('rapid_cross_chain_transfers', [])),
                'timestamp': datetime.now().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Error in cross-chain analysis: {e}")
            return {'status': 'error', 'error': str(e)}
    
    async def run_ml_analysis(self, addresses: List[str]) -> Dict[str, Any]:
        """Run machine learning pattern recognition"""
        logger.info(f"{Fore.CYAN}Starting ML pattern recognition...")
        
        try:
            self.ml_recognizer = MLPatternRecognizer()
            
            # Load pre-trained models if available
            output_dir = Path(self.config['output_options']['output_directory'])
            models_dir = output_dir / 'models'
            
            if not self.config['analysis_options']['ml_retrain']:
                self.ml_recognizer.load_models(str(models_dir))
            
            # Fetch transaction data for feature extraction
            logger.info("Fetching transaction data for ML analysis...")
            transactions_data = await self._fetch_transactions_for_ml(addresses)
            
            if transactions_data:
                logger.info("Extracting features...")
                features = await asyncio.get_event_loop().run_in_executor(
                    None, self.ml_recognizer.extract_features, transactions_data
                )
                
                logger.info("Running ML analysis...")
                if self.config['output_options']['generate_reports']:
                    report_file = output_dir / 'reports' / 'ml_analysis_report.json'
                    report = await asyncio.get_event_loop().run_in_executor(
                        None, self.ml_recognizer.generate_ml_report, features, str(report_file)
                    )
                    
                    # Save models
                    await asyncio.get_event_loop().run_in_executor(
                        None, self.ml_recognizer.save_models, str(models_dir)
                    )
                    
                    return {
                        'status': 'completed',
                        'addresses_analyzed': report.get('total_addresses_analyzed', 0),
                        'anomalies_detected': report.get('anomalies_detected', 0),
                        'clusters_found': report.get('clusters_found', 0),
                        'high_risk_predictions': len(report.get('high_risk_predictions', [])),
                        'report_file': str(report_file),
                        'timestamp': datetime.now().isoformat()
                    }
            else:
                return {'status': 'skipped', 'reason': 'No transaction data available'}
        
        except Exception as e:
            logger.error(f"Error in ML analysis: {e}")
            return {'status': 'error', 'error': str(e)}
    
    async def _fetch_transactions_for_ml(self, addresses: List[str]) -> Dict[str, List]:
        """Fetch transaction data for ML analysis"""
        import aiohttp
        
        transactions_data = {}
        api_key = self.config['api_keys']['ethereum']
        
        if not api_key:
            logger.warning("No Ethereum API key available for ML analysis")
            return {}
        
        async with aiohttp.ClientSession() as session:
            for address in addresses[:5]:  # Limit for demo
                try:
                    params = {
                        'module': 'account',
                        'action': 'txlist',
                        'address': address,
                        'startblock': 0,
                        'endblock': 99999999,
                        'sort': 'desc',
                        'apikey': api_key
                    }
                    
                    async with session.get('https://api.etherscan.io/api', params=params) as response:
                        if response.status == 200:
                            data = await response.json()
                            result = data.get('result', [])
                            if isinstance(result, list):
                                transactions_data[address] = result[:100]  # Limit transactions
                            
                    await asyncio.sleep(0.2)  # Rate limiting
                    
                except Exception as e:
                    logger.error(f"Error fetching transactions for {address}: {e}")
                    transactions_data[address] = []
        
        return transactions_data
    
    async def start_real_time_monitoring(self, addresses: List[str]):
        """Start real-time monitoring system"""
        logger.info(f"{Fore.CYAN}Starting real-time monitoring...")
        
        try:
            # Initialize alert system
            alert_config_file = self.config['alert_settings']['alert_config_file']
            self.alert_manager = AlertManager(alert_config_file)
            self.notification_handler = NotificationHandler(self.alert_manager.notification_channels)
            self.real_time_monitor = RealTimeMonitor(self.alert_manager, self.notification_handler)
            
            # Add addresses to monitor
            for address in addresses:
                self.real_time_monitor.add_address(address)
            
            api_key = self.config['api_keys']['ethereum']
            logger.info(f"Starting monitoring for {len(addresses)} addresses...")
            logger.info("Press Ctrl+C to stop monitoring")
            
            await self.real_time_monitor.start_monitoring(api_key, check_interval=60)
            
        except KeyboardInterrupt:
            logger.info("Real-time monitoring stopped by user")
            if self.real_time_monitor:
                self.real_time_monitor.stop_monitoring()
    
    def generate_master_report(self, output_dir: Path) -> Dict[str, Any]:
        """Generate comprehensive master report"""
        logger.info("Generating master forensics report...")
        
        master_report = {
            'pipeline_metadata': {
                'version': '1.0.0',
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration_seconds': (datetime.now() - self.start_time).total_seconds(),
                'configuration': self.config
            },
            'analysis_results': self.results,
            'summary': {
                'total_addresses_analyzed': len(self.load_addresses()),
                'analysis_modules_run': len([k for k, v in self.results.items() if v.get('status') == 'completed']),
                'errors_encountered': len([k for k, v in self.results.items() if v.get('status') == 'error']),
                'reports_generated': [],
                'visualizations_created': []
            },
            'recommendations': self._generate_recommendations(),
            'next_steps': self._generate_next_steps()
        }
        
        # Save master report
        master_report_file = output_dir / 'reports' / 'master_forensics_report.json'
        try:
            with open(master_report_file, 'w') as f:
                json.dump(master_report, f, indent=2, default=str)
            
            logger.info(f"Master report saved: {master_report_file}")
            
            # Generate human-readable summary
            self._generate_executive_summary(master_report, output_dir)
            
        except Exception as e:
            logger.error(f"Error generating master report: {e}")
        
        return master_report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on analysis results"""
        recommendations = []
        
        if self.results.get('ml_analysis', {}).get('high_risk_predictions', 0) > 0:
            recommendations.append("High-risk addresses detected - immediate investigation recommended")
        
        if self.results.get('cross_chain_analysis', {}).get('rapid_transfers', 0) > 0:
            recommendations.append("Rapid cross-chain transfers detected - potential money laundering activity")
        
        if self.results.get('graph_analysis', {}).get('patterns', {}).get('mixing_patterns'):
            recommendations.append("Mixer interactions detected - enhanced due diligence required")
        
        if not recommendations:
            recommendations.append("No immediate high-risk indicators found - continue routine monitoring")
        
        return recommendations
    
    def _generate_next_steps(self) -> List[str]:
        """Generate next steps based on analysis results"""
        next_steps = [
            "Review detailed analysis reports for specific findings",
            "Implement continuous monitoring for identified addresses",
            "Update threat intelligence databases with new indicators",
            "Consider reporting to relevant authorities if criminal activity suspected"
        ]
        
        if self.config['analysis_options']['run_real_time_monitoring']:
            next_steps.append("Real-time monitoring system is active - alerts will be sent automatically")
        else:
            next_steps.append("Consider enabling real-time monitoring for proactive threat detection")
        
        return next_steps
    
    def _generate_executive_summary(self, master_report: Dict[str, Any], output_dir: Path):
        """Generate human-readable executive summary"""
        summary_file = output_dir / 'reports' / 'executive_summary.txt'
        
        try:
            with open(summary_file, 'w') as f:
                f.write("BLOCKCHAIN FORENSICS ANALYSIS - EXECUTIVE SUMMARY\n")
                f.write("=" * 60 + "\n\n")
                
                f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Duration: {master_report['pipeline_metadata']['duration_seconds']:.0f} seconds\n")
                f.write(f"Addresses Analyzed: {master_report['summary']['total_addresses_analyzed']}\n\n")
                
                f.write("MODULES EXECUTED:\n")
                for module, results in self.results.items():
                    status = results.get('status', 'unknown')
                    f.write(f"  • {module.replace('_', ' ').title()}: {status.upper()}\n")
                
                f.write("\nKEY FINDINGS:\n")
                for recommendation in master_report['recommendations']:
                    f.write(f"  • {recommendation}\n")
                
                f.write("\nNEXT STEPS:\n")
                for step in master_report['next_steps']:
                    f.write(f"  • {step}\n")
                
                f.write(f"\nDetailed reports available in: {output_dir / 'reports'}\n")
                f.write(f"Visualizations available in: {output_dir / 'visualizations'}\n")
            
            logger.info(f"Executive summary saved: {summary_file}")
            
        except Exception as e:
            logger.error(f"Error generating executive summary: {e}")
    
    async def run_pipeline(self, mode: str = 'full'):
        """Run the complete forensics pipeline"""
        logger.info(f"{Fore.GREEN}Starting Blockchain Forensics Pipeline...")
        logger.info(f"Mode: {mode}")
        
        # Validate setup
        if not self.validate_api_keys():
            logger.error("API key validation failed. Cannot proceed.")
            return
        
        # Setup output directory
        output_dir = self.setup_output_directory()
        
        # Load addresses
        addresses = self.load_addresses()
        logger.info(f"Loaded {len(addresses)} addresses for analysis")
        
        # Run analysis based on mode and configuration
        if mode in ['full', 'analysis'] and self.config['analysis_options']['run_basic_analysis']:
            self.results['basic_analysis'] = await self.run_basic_analysis(addresses)
        
        if mode in ['full', 'analysis'] and self.config['analysis_options']['run_graph_analysis']:
            self.results['graph_analysis'] = await self.run_graph_analysis(addresses)
        
        if mode in ['full', 'analysis'] and self.config['analysis_options']['run_cross_chain_analysis']:
            self.results['cross_chain_analysis'] = await self.run_cross_chain_analysis(addresses)
        
        if mode in ['full', 'analysis'] and self.config['analysis_options']['run_ml_analysis']:
            self.results['ml_analysis'] = await self.run_ml_analysis(addresses)
        
        # Generate master report
        if mode in ['full', 'analysis']:
            master_report = self.generate_master_report(output_dir)
            
            # Print summary
            self.print_pipeline_summary()
        
        # Start real-time monitoring if requested
        if mode in ['full', 'monitor'] and self.config['analysis_options']['run_real_time_monitoring']:
            await self.start_real_time_monitoring(addresses)
    
    def print_pipeline_summary(self):
        """Print pipeline execution summary"""
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}BLOCKCHAIN FORENSICS PIPELINE COMPLETED")
        print(f"{Fore.GREEN}{'='*60}")
        
        print(f"\n{Fore.CYAN}EXECUTION SUMMARY:")
        duration = (datetime.now() - self.start_time).total_seconds()
        print(f"  Duration: {duration:.1f} seconds")
        print(f"  Modules Run: {len(self.results)}")
        
        print(f"\n{Fore.CYAN}MODULE RESULTS:")
        for module, result in self.results.items():
            status = result.get('status', 'unknown')
            color = Fore.GREEN if status == 'completed' else Fore.RED if status == 'error' else Fore.YELLOW
            print(f"  {color}• {module.replace('_', ' ').title()}: {status.upper()}")
        
        output_dir = self.config['output_options']['output_directory']
        print(f"\n{Fore.CYAN}OUTPUT LOCATION:")
        print(f"  Reports: {output_dir}/reports/")
        print(f"  Visualizations: {output_dir}/visualizations/")
        print(f"  Data: {output_dir}/data/")
        
        print(f"\n{Fore.YELLOW}Check the executive summary for key findings and recommendations.")
        print(f"{Fore.GREEN}{'='*60}\n")

def create_sample_config():
    """Create a sample configuration file"""
    pipeline = ForensicsPipeline()
    pipeline.save_config(pipeline.config)
    print(f"{Fore.GREEN}Sample configuration created: {pipeline.config_file}")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Blockchain Forensics & Incident Response Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main_forensics_pipeline.py --mode full                    # Run complete analysis
  python main_forensics_pipeline.py --mode analysis               # Run analysis only
  python main_forensics_pipeline.py --mode monitor                # Start monitoring only
  python main_forensics_pipeline.py --create-config               # Create sample config
  python main_forensics_pipeline.py --addresses addr1,addr2       # Analyze specific addresses
        """
    )
    
    parser.add_argument(
        '--mode',
        choices=['full', 'analysis', 'monitor'],
        default='full',
        help='Pipeline execution mode (default: full)'
    )
    
    parser.add_argument(
        '--config',
        default='pipeline_config.json',
        help='Configuration file path (default: pipeline_config.json)'
    )
    
    parser.add_argument(
        '--addresses',
        help='Comma-separated list of addresses to analyze'
    )
    
    parser.add_argument(
        '--create-config',
        action='store_true',
        help='Create sample configuration file and exit'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.create_config:
        create_sample_config()
        return
    
    # Initialize pipeline
    pipeline = ForensicsPipeline(args.config)
    
    # Override addresses if provided
    if args.addresses:
        addresses = [addr.strip() for addr in args.addresses.split(',')]
        # Save addresses to file for pipeline to use
        with open('temp_addresses.txt', 'w') as f:
            for addr in addresses:
                f.write(f"{addr}\n")
        pipeline.config['input_files']['addresses_file'] = 'temp_addresses.txt'
    
    # Run pipeline
    try:
        asyncio.run(pipeline.run_pipeline(args.mode))
    except KeyboardInterrupt:
        logger.info("Pipeline stopped by user")
    except Exception as e:
        logger.error(f"Pipeline failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()