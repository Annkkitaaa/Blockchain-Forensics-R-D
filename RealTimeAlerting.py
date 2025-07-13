import asyncio
import aiohttp
import json
import smtplib
import logging
from datetime import datetime, timedelta
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from colorama import Fore
import os
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('forensics_alerts.log'),
        logging.StreamHandler()
    ]
)

@dataclass
class AlertRule:
    """Define alert rules for different types of suspicious activity"""
    name: str
    description: str
    threshold_value: float
    threshold_type: str  # 'greater_than', 'less_than', 'equals', 'contains'
    severity: str  # 'low', 'medium', 'high', 'critical'
    enabled: bool = True
    cooldown_seconds: int = 300  # 5 minutes default cooldown

@dataclass
class Alert:
    """Alert data structure"""
    timestamp: datetime
    rule_name: str
    severity: str
    address: str
    message: str
    details: Dict[str, Any]
    alert_id: str

class AlertManager:
    def __init__(self, config_file='alert_config.json'):
        self.rules = {}
        self.alert_history = []
        self.last_alert_times = {}
        self.notification_channels = []
        self.config_file = config_file
        self.load_config()
        self.setup_default_rules()
        
    def load_config(self):
        """Load alert configuration from file"""
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                self.notification_channels = config.get('notification_channels', [])
                rules_data = config.get('rules', {})
                
                for rule_name, rule_data in rules_data.items():
                    self.rules[rule_name] = AlertRule(**rule_data)
                    
        except FileNotFoundError:
            logging.warning(f"Config file {self.config_file} not found. Using defaults.")
            self.notification_channels = []
    
    def setup_default_rules(self):
        """Setup default alert rules"""
        default_rules = [
            AlertRule(
                name="high_value_transaction",
                description="Transaction value exceeds threshold",
                threshold_value=100.0,
                threshold_type="greater_than",
                severity="high"
            ),
            AlertRule(
                name="rapid_transactions",
                description="Multiple transactions in short time period",
                threshold_value=10,
                threshold_type="greater_than",
                severity="medium"
            ),
            AlertRule(
                name="sandwich_attack_detected",
                description="Potential sandwich attack pattern detected",
                threshold_value=0.8,
                threshold_type="greater_than",
                severity="critical"
            ),
            AlertRule(
                name="bridge_interaction",
                description="Cross-chain bridge interaction detected",
                threshold_value=1,
                threshold_type="greater_than",
                severity="medium"
            ),
            AlertRule(
                name="mixer_interaction",
                description="Interaction with known mixer service",
                threshold_value=1,
                threshold_type="greater_than",
                severity="high"
            ),
            AlertRule(
                name="anomaly_score",
                description="ML anomaly detection triggered",
                threshold_value=-0.5,
                threshold_type="less_than",
                severity="high"
            )
        ]
        
        for rule in default_rules:
            if rule.name not in self.rules:
                self.rules[rule.name] = rule
    
    def evaluate_transaction(self, tx_data: Dict[str, Any]) -> List[Alert]:
        """Evaluate a transaction against all alert rules"""
        alerts = []
        current_time = datetime.now()
        
        for rule_name, rule in self.rules.items():
            if not rule.enabled:
                continue
                
            # Check cooldown
            last_alert = self.last_alert_times.get(f"{rule_name}_{tx_data.get('address', '')}")
            if last_alert and (current_time - last_alert).seconds < rule.cooldown_seconds:
                continue
            
            # Evaluate rule
            triggered = self._evaluate_rule(rule, tx_data)
            
            if triggered:
                alert = Alert(
                    timestamp=current_time,
                    rule_name=rule_name,
                    severity=rule.severity,
                    address=tx_data.get('address', 'unknown'),
                    message=self._generate_alert_message(rule, tx_data),
                    details=tx_data,
                    alert_id=f"{rule_name}_{current_time.timestamp()}"
                )
                
                alerts.append(alert)
                self.alert_history.append(alert)
                self.last_alert_times[f"{rule_name}_{tx_data.get('address', '')}"] = current_time
                
                logging.warning(f"ALERT: {alert.message}")
        
        return alerts
    
    def _evaluate_rule(self, rule: AlertRule, data: Dict[str, Any]) -> bool:
        """Evaluate a single rule against transaction data"""
        value = self._extract_value(rule.name, data)
        
        if value is None:
            return False
        
        if rule.threshold_type == "greater_than":
            return value > rule.threshold_value
        elif rule.threshold_type == "less_than":
            return value < rule.threshold_value
        elif rule.threshold_type == "equals":
            return value == rule.threshold_value
        elif rule.threshold_type == "contains":
            return rule.threshold_value in str(value)
        
        return False
    
    def _extract_value(self, rule_name: str, data: Dict[str, Any]) -> Optional[float]:
        """Extract relevant value from transaction data based on rule name"""
        if rule_name == "high_value_transaction":
            return float(data.get('value_eth', 0))
        elif rule_name == "rapid_transactions":
            return data.get('transactions_last_hour', 0)
        elif rule_name == "sandwich_attack_detected":
            return data.get('sandwich_probability', 0)
        elif rule_name == "bridge_interaction":
            return len(data.get('bridge_interactions', []))
        elif rule_name == "mixer_interaction":
            return len(data.get('mixer_interactions', []))
        elif rule_name == "anomaly_score":
            return data.get('anomaly_score', 0)
        
        return None
    
    def _generate_alert_message(self, rule: AlertRule, data: Dict[str, Any]) -> str:
        """Generate human-readable alert message"""
        address = data.get('address', 'unknown')
        value = self._extract_value(rule.name, data)
        
        base_msg = f"{rule.severity.upper()}: {rule.description}"
        
        if rule.name == "high_value_transaction":
            return f"{base_msg} - Address: {address}, Value: {value} ETH"
        elif rule.name == "rapid_transactions":
            return f"{base_msg} - Address: {address}, Count: {value} transactions"
        elif rule.name == "sandwich_attack_detected":
            return f"{base_msg} - Address: {address}, Probability: {value:.2f}"
        elif rule.name == "bridge_interaction":
            return f"{base_msg} - Address: {address}, Interactions: {value}"
        elif rule.name == "mixer_interaction":
            return f"{base_msg} - Address: {address}, Mixer interactions: {value}"
        elif rule.name == "anomaly_score":
            return f"{base_msg} - Address: {address}, Anomaly score: {value:.3f}"
        
        return f"{base_msg} - Address: {address}"

class NotificationHandler:
    def __init__(self, channels):
        self.channels = channels
    
    async def send_alert(self, alert: Alert):
        """Send alert through all configured channels"""
        tasks = []
        
        for channel in self.channels:
            if channel['type'] == 'email':
                tasks.append(self.send_email(alert, channel))
            elif channel['type'] == 'webhook':
                tasks.append(self.send_webhook(alert, channel))
            elif channel['type'] == 'discord':
                tasks.append(self.send_discord(alert, channel))
            elif channel['type'] == 'telegram':
                tasks.append(self.send_telegram(alert, channel))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def send_email(self, alert: Alert, config: Dict[str, str]):
        """Send email notification"""
        try:
            smtp_server = config.get('smtp_server', 'smtp.gmail.com')
            smtp_port = config.get('smtp_port', 587)
            username = config.get('username')
            password = config.get('password')
            to_email = config.get('to_email')
            
            msg = MimeMultipart()
            msg['From'] = username
            msg['To'] = to_email
            msg['Subject'] = f"Blockchain Forensics Alert - {alert.severity.upper()}"
            
            body = f"""
            Alert Details:
            - Time: {alert.timestamp}
            - Severity: {alert.severity}
            - Rule: {alert.rule_name}
            - Address: {alert.address}
            - Message: {alert.message}
            
            Additional Details:
            {json.dumps(alert.details, indent=2, default=str)}
            """
            
            msg.attach(MimeText(body, 'plain'))
            
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(username, password)
            server.send_message(msg)
            server.quit()
            
            logging.info(f"Email alert sent for {alert.alert_id}")
            
        except Exception as e:
            logging.error(f"Failed to send email alert: {e}")
    
    async def send_webhook(self, alert: Alert, config: Dict[str, str]):
        """Send webhook notification"""
        try:
            url = config.get('url')
            headers = config.get('headers', {'Content-Type': 'application/json'})
            
            payload = {
                'alert_id': alert.alert_id,
                'timestamp': alert.timestamp.isoformat(),
                'severity': alert.severity,
                'rule_name': alert.rule_name,
                'address': alert.address,
                'message': alert.message,
                'details': alert.details
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, headers=headers) as response:
                    if response.status == 200:
                        logging.info(f"Webhook alert sent for {alert.alert_id}")
                    else:
                        logging.error(f"Webhook failed with status {response.status}")
                        
        except Exception as e:
            logging.error(f"Failed to send webhook alert: {e}")
    
    async def send_discord(self, alert: Alert, config: Dict[str, str]):
        """Send Discord notification"""
        try:
            webhook_url = config.get('webhook_url')
            
            color = {'low': 0x00ff00, 'medium': 0xffff00, 'high': 0xff8800, 'critical': 0xff0000}
            
            embed = {
                'title': f"🚨 Blockchain Forensics Alert",
                'description': alert.message,
                'color': color.get(alert.severity, 0x808080),
                'fields': [
                    {'name': 'Severity', 'value': alert.severity.upper(), 'inline': True},
                    {'name': 'Address', 'value': f"`{alert.address}`", 'inline': True},
                    {'name': 'Rule', 'value': alert.rule_name, 'inline': True},
                    {'name': 'Time', 'value': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'), 'inline': False}
                ],
                'timestamp': alert.timestamp.isoformat()
            }
            
            payload = {'embeds': [embed]}
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as response:
                    if response.status == 204:
                        logging.info(f"Discord alert sent for {alert.alert_id}")
                    else:
                        logging.error(f"Discord webhook failed with status {response.status}")
                        
        except Exception as e:
            logging.error(f"Failed to send Discord alert: {e}")
    
    async def send_telegram(self, alert: Alert, config: Dict[str, str]):
        """Send Telegram notification"""
        try:
            bot_token = config.get('bot_token')
            chat_id = config.get('chat_id')
            
            message = f"""
🚨 *Blockchain Forensics Alert*

*Severity:* {alert.severity.upper()}
*Rule:* {alert.rule_name}
*Address:* `{alert.address}`
*Time:* {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}

*Message:* {alert.message}
            """
            
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {
                'chat_id': chat_id,
                'text': message,
                'parse_mode': 'Markdown'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status == 200:
                        logging.info(f"Telegram alert sent for {alert.alert_id}")
                    else:
                        logging.error(f"Telegram API failed with status {response.status}")
                        
        except Exception as e:
            logging.error(f"Failed to send Telegram alert: {e}")

class RealTimeMonitor:
    def __init__(self, alert_manager: AlertManager, notification_handler: NotificationHandler):
        self.alert_manager = alert_manager
        self.notification_handler = notification_handler
        self.running = False
        self.monitored_addresses = set()
        
    def add_address(self, address: str):
        """Add address to monitoring list"""
        self.monitored_addresses.add(address.lower())
        logging.info(f"Added {address} to monitoring list")
    
    def remove_address(self, address: str):
        """Remove address from monitoring list"""
        self.monitored_addresses.discard(address.lower())
        logging.info(f"Removed {address} from monitoring list")
    
    async def start_monitoring(self, api_key: str, check_interval: int = 30):
        """Start real-time monitoring"""
        self.running = True
        logging.info("Starting real-time blockchain monitoring...")
        
        while self.running:
            try:
                await self._check_addresses(api_key)
                await asyncio.sleep(check_interval)
            except Exception as e:
                logging.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(check_interval)
    
    async def _check_addresses(self, api_key: str):
        """Check all monitored addresses for new activity"""
        tasks = []
        
        for address in self.monitored_addresses:
            tasks.append(self._check_single_address(address, api_key))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _check_single_address(self, address: str, api_key: str):
        """Check a single address for suspicious activity"""
        try:
            # Fetch recent transactions
            params = {
                'module': 'account',
                'action': 'txlist',
                'address': address,
                'startblock': 0,
                'endblock': 99999999,
                'sort': 'desc',
                'apikey': api_key
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get('https://api.etherscan.io/api', params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        transactions = data.get('result', [])
                        
                        if isinstance(transactions, list) and transactions:
                            await self._analyze_transactions(address, transactions)
                    else:
                        logging.error(f"API request failed for {address}: {response.status}")
                        
        except Exception as e:
            logging.error(f"Error checking address {address}: {e}")
    
    async def _analyze_transactions(self, address: str, transactions: List[Dict]):
        """Analyze transactions for suspicious patterns"""
        # Recent activity analysis
        current_time = datetime.now()
        recent_txs = []
        
        for tx in transactions:
            tx_time = datetime.fromtimestamp(int(tx.get('timeStamp', 0)))
            if (current_time - tx_time) < timedelta(hours=1):
                recent_txs.append(tx)
        
        # Prepare analysis data
        analysis_data = {
            'address': address,
            'value_eth': max([float(tx.get('value', 0)) / 1e18 for tx in recent_txs], default=0),
            'transactions_last_hour': len(recent_txs),
            'sandwich_probability': self._calculate_sandwich_probability(recent_txs),
            'bridge_interactions': self._detect_bridge_interactions(recent_txs),
            'mixer_interactions': self._detect_mixer_interactions(recent_txs),
            'anomaly_score': self._calculate_anomaly_score(recent_txs),
            'recent_transactions': recent_txs
        }
        
        # Evaluate against rules
        alerts = self.alert_manager.evaluate_transaction(analysis_data)
        
        # Send notifications
        for alert in alerts:
            await self.notification_handler.send_alert(alert)
    
    def _calculate_sandwich_probability(self, transactions: List[Dict]) -> float:
        """Calculate probability of sandwich attack"""
        if len(transactions) < 2:
            return 0.0
        
        # Look for rapid buy-sell patterns with similar gas prices
        gas_prices = [int(tx.get('gasPrice', 0)) for tx in transactions]
        time_diffs = []
        
        if len(transactions) >= 2:
            times = sorted([int(tx.get('timeStamp', 0)) for tx in transactions])
            time_diffs = [times[i+1] - times[i] for i in range(len(times)-1)]
        
        # Simple heuristic: rapid transactions with varying gas prices
        rapid_count = sum(1 for diff in time_diffs if diff < 300)  # 5 minutes
        gas_variance = len(set(gas_prices)) > 1
        
        if rapid_count > 0 and gas_variance:
            return min(1.0, rapid_count * 0.3)
        
        return 0.0
    
    def _detect_bridge_interactions(self, transactions: List[Dict]) -> List[str]:
        """Detect interactions with known bridge contracts"""
        bridge_addresses = [
            '0x40ec5b33f54e0e8a33a975908c5ba1c14e5bbbdf',  # Polygon bridge
            '0x8315177ab297ba92a06054ce80a67ed4dbd7ed3a',  # Arbitrum bridge
            '0x533e3c0e6b48010873b947bddc4721b1bdff9648'   # BSC bridge
        ]
        
        interactions = []
        for tx in transactions:
            to_addr = tx.get('to', '').lower()
            if to_addr in [addr.lower() for addr in bridge_addresses]:
                interactions.append(tx.get('hash', ''))
        
        return interactions
    
    def _detect_mixer_interactions(self, transactions: List[Dict]) -> List[str]:
        """Detect interactions with known mixer services"""
        mixer_addresses = [
            '0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3',  # Tornado Cash (example)
            '0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936',  # Another mixer
        ]
        
        interactions = []
        for tx in transactions:
            to_addr = tx.get('to', '').lower()
            if to_addr in [addr.lower() for addr in mixer_addresses]:
                interactions.append(tx.get('hash', ''))
        
        return interactions
    
    def _calculate_anomaly_score(self, transactions: List[Dict]) -> float:
        """Calculate simple anomaly score"""
        if not transactions:
            return 0.0
        
        # Simple scoring based on transaction patterns
        score = 0.0
        
        # High frequency
        if len(transactions) > 10:
            score -= 0.3
        
        # Unusual gas prices
        gas_prices = [int(tx.get('gasPrice', 0)) for tx in transactions]
        if gas_prices:
            avg_gas = sum(gas_prices) / len(gas_prices)
            if any(gp > avg_gas * 2 for gp in gas_prices):
                score -= 0.2
        
        # Failed transactions
        failed_count = sum(1 for tx in transactions if tx.get('isError', '0') == '1')
        if failed_count > len(transactions) * 0.1:
            score -= 0.2
        
        return score
    
    def stop_monitoring(self):
        """Stop the monitoring process"""
        self.running = False
        logging.info("Stopping real-time monitoring...")

# Configuration and usage example
def create_sample_config():
    """Create sample configuration file"""
    config = {
        "notification_channels": [
            {
                "type": "email",
                "smtp_server": "smtp.gmail.com",
                "smtp_port": 587,
                "username": "your_email@gmail.com",
                "password": "your_app_password",
                "to_email": "alerts@yourcompany.com"
            },
            {
                "type": "discord",
                "webhook_url": "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL"
            },
            {
                "type": "telegram",
                "bot_token": "YOUR_BOT_TOKEN",
                "chat_id": "YOUR_CHAT_ID"
            },
            {
                "type": "webhook",
                "url": "https://your-api.com/alerts",
                "headers": {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer YOUR_TOKEN"
                }
            }
        ],
        "rules": {
            "high_value_transaction": {
                "name": "high_value_transaction",
                "description": "Transaction value exceeds threshold",
                "threshold_value": 50.0,
                "threshold_type": "greater_than",
                "severity": "high",
                "enabled": True,
                "cooldown_seconds": 300
            },
            "rapid_transactions": {
                "name": "rapid_transactions",
                "description": "Multiple transactions in short time period",
                "threshold_value": 5,
                "threshold_type": "greater_than",
                "severity": "medium",
                "enabled": True,
                "cooldown_seconds": 600
            }
        }
    }
    
    with open('alert_config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"{Fore.GREEN}Sample configuration created: alert_config.json")

async def main():
    """Main function to run the real-time monitoring system"""
    # Load API key
    api_key = os.getenv('ETHERSCAN_API_KEY')
    if not api_key:
        print(f"{Fore.RED}Please set ETHERSCAN_API_KEY environment variable")
        return
    
    # Create sample config if it doesn't exist
    if not os.path.exists('alert_config.json'):
        create_sample_config()
    
    # Initialize components
    alert_manager = AlertManager('alert_config.json')
    notification_handler = NotificationHandler(alert_manager.notification_channels)
    monitor = RealTimeMonitor(alert_manager, notification_handler)
    
    # Load addresses to monitor
    try:
        with open('attackersOutput.txt', 'r') as f:
            addresses = [line.strip() for line in f.readlines()]
            for addr in addresses[:5]:  # Limit for demo
                monitor.add_address(addr)
    except FileNotFoundError:
        print(f"{Fore.YELLOW}attackersOutput.txt not found. Using sample address.")
        monitor.add_address('0x1234567890abcdef1234567890abcdef12345678')
    
    print(f"{Fore.GREEN}Starting real-time monitoring...")
    print(f"{Fore.YELLOW}Monitoring {len(monitor.monitored_addresses)} addresses")
    print(f"{Fore.YELLOW}Press Ctrl+C to stop")
    
    try:
        await monitor.start_monitoring(api_key, check_interval=60)  # Check every minute
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}Monitoring stopped by user")
        monitor.stop_monitoring()

if __name__ == "__main__":
    asyncio.run(main())
                