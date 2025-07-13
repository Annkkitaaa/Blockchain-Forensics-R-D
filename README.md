# Blockchain Forensics & Incident Response Toolkit

A comprehensive Python-based toolkit for blockchain forensics, incident response, and real-time threat detection. This project demonstrates advanced capabilities in analyzing blockchain transactions, detecting suspicious patterns, and providing automated incident response for Ethereum and other EVM-compatible networks.

## 🚀 Key Features

### Core Analysis Components
- **Transaction Pattern Analysis**: Advanced detection of MEV attacks, sandwich attacks, and bot activities
- **Cross-Chain Investigation**: Multi-blockchain analysis across Ethereum, BSC, Polygon, and Arbitrum
- **Graph Analytics**: Network analysis and visualization of transaction flows
- **Machine Learning Detection**: AI-powered anomaly detection and attack classification
- **Real-Time Monitoring**: Automated alerting system with multiple notification channels

### Incident Response Capabilities
- **Automated Threat Detection**: Continuous monitoring of suspicious addresses
- **Real-Time Alerting**: Instant notifications via Email, Discord, Telegram, and Webhooks
- **Pattern Recognition**: ML models for identifying new attack vectors
- **Compliance Reporting**: Generate detailed forensic reports for regulatory purposes
- **Attribution Analysis**: Tools for linking addresses to real-world entities

## 📋 Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Core Components](#core-components)
- [Usage Examples](#usage-examples)
- [Advanced Features](#advanced-features)
- [API Documentation](#api-documentation)
- [Case Studies](#case-studies)
- [Contributing](#contributing)

## 🛠 Installation

### Prerequisites
```bash
Python 3.8+
pip install -r requirements.txt
```

### Required Dependencies
```bash
pip install requests pandas numpy matplotlib networkx scikit-learn
pip install aiohttp colorama asyncio smtplib
pip install joblib web3 datetime json logging
```

### API Keys Required
- **Etherscan API Key**: For Ethereum transaction data
- **BSCScan API Key**: For Binance Smart Chain data
- **PolygonScan API Key**: For Polygon network data
- **Arbiscan API Key**: For Arbitrum network data

Set environment variables:
```bash
export ETHERSCAN_API_KEY="your_etherscan_key"
export BSCSCAN_API_KEY="your_bscscan_key"
export POLYGONSCAN_API_KEY="your_polygonscan_key"
export ARBISCAN_API_KEY="your_arbiscan_key"
```

## ⚙️ Configuration

### Initial Setup
1. Clone the repository
2. Install dependencies
3. Set up API keys
4. Configure alert settings in `alert_config.json`
5. Add addresses to monitor in `attackersOutput.txt`

### Alert Configuration
Create `alert_config.json` with notification channels:
```json
{
  "notification_channels": [
    {
      "type": "email",
      "smtp_server": "smtp.gmail.com",
      "username": "alerts@yourcompany.com",
      "password": "app_password"
    },
    {
      "type": "discord",
      "webhook_url": "your_discord_webhook"
    }
  ]
}
```

## 📦 Core Components

### 1. AttackerTransactionTotals.py
**Purpose**: Analyzes financial flows to suspicious addresses

**Key Features**:
- Tracks total ETH values received by attacker addresses
- Fetches internal transactions via Etherscan API
- Calculates cumulative financial impact
- Generates value flow reports

**Use Case**: Quantifying financial damage in security incidents

### 2. FindBots.py & MakeMeASandwich_FirstDraft.py
**Purpose**: MEV attack detection and sandwich attack identification

**Key Features**:
- Real-time sandwich attack detection
- Bot behavior pattern analysis
- Gas price manipulation detection
- Transaction timing analysis

**Use Case**: Identifying and preventing MEV exploitation

### 3. Monitor_AddressChanges.py
**Purpose**: Continuous threat intelligence gathering

**Key Features**:
- Monitors GitHub repositories for new threat indicators
- Automatic address list updates
- Timestamp tracking for new threats
- Automated database maintenance

**Use Case**: Maintaining up-to-date threat intelligence

### 4. GraphAnalysis.py
**Purpose**: Network analysis and visualization

**Key Features**:
- Transaction flow mapping
- Suspicious pattern detection
- Network topology analysis
- Interactive graph visualization
- Circular flow detection

**Use Case**: Understanding complex money laundering schemes

### 5. CrossChainAnalysis.py
**Purpose**: Multi-blockchain investigation

**Key Features**:
- Cross-chain transaction tracking
- Bridge interaction detection
- Multi-network correlation analysis
- Rapid transfer sequence identification

**Use Case**: Tracking assets across different blockchains

### 6. MLPatternRecognition.py
**Purpose**: AI-powered threat detection

**Key Features**:
- Anomaly detection using Isolation Forest
- Attack classification with Random Forest
- Behavioral clustering with DBSCAN
- Feature engineering for blockchain data
- Model persistence and retraining

**Use Case**: Identifying previously unknown attack patterns

### 7. RealTimeAlerting.py
**Purpose**: Automated incident response

**Key Features**:
- Real-time transaction monitoring
- Multi-channel alerting (Email, Discord, Telegram, Webhooks)
- Configurable alert rules
- Cooldown periods to prevent spam
- Severity-based escalation

**Use Case**: Immediate notification of suspicious activities

## 🔍 Usage Examples

### Basic Analysis Workflow

1. **Initialize Monitoring**:
```bash
python Monitor_AddressChanges.py
```

2. **Analyze Transaction Patterns**:
```bash
python FindBots.py
```

3. **Generate Financial Reports**:
```bash
python AttackerTransactionTotals.py
```

4. **Perform Graph Analysis**:
```bash
python GraphAnalysis.py
```

5. **Cross-Chain Investigation**:
```bash
python CrossChainAnalysis.py
```

6. **ML Pattern Detection**:
```bash
python MLPatternRecognition.py
```

7. **Start Real-Time Monitoring**:
```bash
python RealTimeAlerting.py
```

### Advanced Investigation Workflow

For comprehensive incident response:

1. **Threat Intelligence Gathering**: Use `Monitor_AddressChanges.py` to gather latest threat indicators
2. **Multi-Chain Analysis**: Deploy `CrossChainAnalysis.py` to track cross-chain movements
3. **Pattern Recognition**: Apply `MLPatternRecognition.py` for unknown threat detection
4. **Network Mapping**: Utilize `GraphAnalysis.py` for relationship mapping
5. **Real-Time Response**: Implement `RealTimeAlerting.py` for continuous monitoring

## 🎯 Advanced Features

### Machine Learning Capabilities
- **Anomaly Detection**: Identifies unusual transaction patterns
- **Attack Classification**: Categorizes threats (sandwich attacks, money laundering, etc.)
- **Behavioral Clustering**: Groups similar address behaviors
- **Feature Engineering**: Extracts 20+ behavioral features from transaction data

### Real-Time Monitoring
- **Continuous Surveillance**: 24/7 monitoring of suspicious addresses
- **Smart Alerting**: Configurable rules with severity levels
- **Multiple Channels**: Email, Discord, Telegram, webhook notifications
- **Rate Limiting**: Prevents alert fatigue with cooldown periods

### Cross-Chain Intelligence
- **Multi-Network Support**: Ethereum, BSC, Polygon, Arbitrum
- **Bridge Detection**: Identifies cross-chain fund movements
- **Correlation Analysis**: Links activities across different networks
- **Rapid Transfer Detection**: Identifies suspicious cross-chain sequences

### Graph Analytics
- **Network Visualization**: Interactive transaction flow graphs
- **Centrality Analysis**: Identifies key addresses in networks
- **Community Detection**: Finds clusters of related addresses
- **Path Analysis**: Traces fund flows between addresses

## 📊 Output Examples

### Generated Reports
- `graph_analysis_report.json`: Network analysis results
- `cross_chain_analysis.json`: Multi-blockchain investigation findings
- `ml_analysis_report.json`: Machine learning detection results
- `forensics_alerts.log`: Real-time monitoring logs

### Visualizations
- `transaction_graph.png`: Network topology visualization
- `cross_chain_flows.png`: Cross-chain movement patterns
- Alert dashboards via configured notification channels

## 🔧 Customization

### Adding New Alert Rules
```python
new_rule = AlertRule(
    name="custom_rule",
    description="Custom detection logic",
    threshold_value=100.0,
    threshold_type="greater_than",
    severity="high"
)
```

### Extending ML Features
Add new behavioral features in `MLPatternRecognition.py`:
```python
def _extract_custom_feature(self, transactions):
    # Custom feature extraction logic
    return calculated_value
```

### Adding New Notification Channels
Extend `NotificationHandler` class in `RealTimeAlerting.py`:
```python
async def send_custom_notification(self, alert, config):
    # Custom notification implementation
    pass
```

