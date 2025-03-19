# BlockchainInsight Agent
( ACCESIBLE AT - https://openserv-hmgnbnhacthqdme2.uksouth-01.azurewebsites.net )
An advanced on-chain data analytics agent built on OpenServ's platform providing comprehensive blockchain insights across multiple networks.


## 🏆 Competition Submission

This project is a submission for the OpenServ Labs Agent Challenge. See how BlockchainInsight meets each judging criterion:

- [**Judging Criteria Guide**](./JUDGING_CRITERIA.md) - Detailed explanations for each criterion
- [**OpenServ Integration Guide**](./OPENSERV_INTEGRATION.md) - Documentation on platform integration

## 📊 Features

- **Smart Contract Analysis**: Verification details and security vulnerability detection using AI
- **Transaction History**: Detailed transaction analysis with pattern recognition
- **Token Holder Distribution**: Concentration metrics and whale detection
- **Liquidity Pool Analytics**: Comprehensive DEX pool analysis with impermanent loss simulation
- **Yield Opportunities**: Find and assess DeFi yield opportunities with risk ratings
- **Smart Money Tracking**: Track whale movements and significant transactions
- **DeFi Trend Analysis**: Track protocol TVL, volume, and growth metrics
- **Token Information**: Comprehensive token data including price, liquidity, socials, and trading pairs
- **DEX Analytics**: Deep analysis of trading pairs, volumes, and market health



## multi-agent workflow
- **Use it with General assistant (by openserv) to create a detailed report

  ## Use Cases

### For Investors
- Assess token distribution risk
- Analyze whale movements
- Find yield opportunities across DeFi protocols

### For Developers
- Verify contract code
- Check for security vulnerabilities
- Analyze protocol adoption metrics

### For Traders
- Get comprehensive token data
- Track liquidity across pools
- Analyze trading pairs and market conditions

### For Security Researchers
- Analyze transaction patterns
- Detect anomalies in blockchain activity
- Assess contract risk and potential vulnerabilities

## Example Queries

### Smart Contract Security Analysis
Ask the agent to analyze any smart contract by providing its address:
```
Analyze the security of smart contract 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D. Identify critical vulnerabilities and provide a risk assessment.
```

### Wallet Transaction Analysis
Request detailed analysis of wallet activity:
```
Examine transaction history for wallet 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 over the past month. Identify significant transactions, recurring patterns, and calculate total value transferred.
```

### Token Concentration Analysis
Understand token distribution and whale concentration:
```
Analyze holder distribution for the EDGE token on Ethereum. Determine concentration risk level and how many wallets control the majority of tokens.
```

### DeFi Position Assessment
Calculate impermanent loss and get strategy recommendations:
```
Calculate impermanent loss for an ETH/USDT liquidity position if ETH price changes by +25%. Provide a recommended strategy for minimizing this risk.
```

### Yield Optimization Recommendation
Find the best yield opportunities based on your risk profile:
```
Based on a moderate risk profile, identify the best yield opportunities currently available across major DeFi protocols. Include expected APY and relevant risk factors.
```

### Historical Performance Comparison
Compare blockchain metrics over time:
```
Compare transaction volume and price correlation between ETH and BNB over the last quarter. Determine which blockchain showed more consistent growth patterns.
```

### Cross-Chain Analysis
Analyze bridge transactions and security:
```
Analyze recent bridge transactions between Ethereum and Arbitrum. Identify unusual patterns and potential security concerns in cross-chain transfers.
```

### Wallet Security Assessment
Check wallet security and interaction history:
```
Perform a security analysis on wallet 0x742d35Cc6634C0532925a3b844Bc454e4438f44e. Has it interacted with flagged contracts or shown suspicious transaction patterns?
```

### Liquidity Pool Analysis
Get insights on specific liquidity pools:
```
Analyze liquidity pool 0x8ad599c3a0ff1de082011efddc58f1908eb6e6d8 on Ethereum. Provide depth, volume, and impermanent loss risk assessment.
```

## 🚀 Getting Started

### Prerequisites

- Node.js (v16 or higher)
- npm or yarn
- API keys for blockchain data services

### Installation

1. Clone the repository
2. Install dependencies:

```bash
npm install
```

3. Set up environment variables (see [Environment Variables](#-environment-variables))
4. Build the project:

```bash
npm run build
```

5. Start the agent:

```bash
npm run start
```

## 🔑 Environment Variables

Create a `.env` file in the project root with the following variables:

```
# OpenAI API key (required for LLM-powered features)
OPENAI_API_KEY=your_openai_api_key

# Blockchain explorer API keys (at least one required)
ETHEREUM_SCAN_API_KEY=your_etherscan_api_key
POLYGON_SCAN_API_KEY=your_polygonscan_api_key
BSC_SCAN_API_KEY=your_bscscan_api_key
OPTIMISM_SCAN_API_KEY=your_optimismscan_api_key
ARBITRUM_SCAN_API_KEY=your_arbiscan_api_key
AVALANCHE_SCAN_API_KEY=your_snowtrace_api_key
FANTOM_SCAN_API_KEY=your_ftmscan_api_key

# Chainbase API key (required for token analytics)
CHAINBASE_API_KEY=your_chainbase_api_key

# OpenServ API key (for deployment)
OPENSERV_API_KEY=your_openserv_api_key
```

## 📋 API Reference

### Available Capabilities

| Capability | Description | Example Usage |
|------------|-------------|---------------|
| `getContractDetails` | Analyze smart contract verification and security | `{"contractAddress": "0x...", "chain": "ethereum"}` |
| `getTransactionHistory` | Retrieve and analyze wallet transactions | `{"address": "0x...", "chain": "ethereum", "limit": 20}` |
| `getTokenHolders` | Analyze token holder distribution | `{"tokenAddress": "0x...", "chain": "ethereum", "limit": 50}` |
| `getLiquidityPoolAnalytics` | Analyze DEX liquidity pools | `{"poolAddress": "0x...", "chain": "ethereum"}` |
| `getYieldOpportunities` | Find and assess yield opportunities | `{"chain": "ethereum", "minApy": 5, "maxRisk": "medium"}` |
| `getWhaleActivity` | Track significant wallet movements | `{"timeframe": "24h", "minValue": 1000000}` |
| `getDeFiTrends` | Analyze protocol TVL and growth | `{"category": "lending", "timeframe": "30d"}` |
| `getTokenInfo` | Get comprehensive token data | `{"address": "0x...", "chain": "ethereum"}` |
| `getDEXAnalytics` | Analyze DEX trading activity | `{"dex": "uniswap", "chain": "ethereum"}` |

For detailed parameter information, see the [API Documentation](docs/API.md).



## 📝 Documentation

- [OpenServ Integration Guide](./OPENSERV_INTEGRATION.md)
- [Judging Criteria Guide](./JUDGING_CRITERIA.md)
- [API Documentation](docs/API.md)
- [Architecture Overview](docs/ARCHITECTURE.md)

## 📈 Project Roadmap

- [x] Initial release with 9 core capabilities
- [x] Multi-chain support
- [x] API documentation
- [ ] Enhanced visualizations
- [ ] Mobile app integration
- [ ] Browser extension
- [ ] Historical data analysis
- [ ] Predictive trend analysis




## 🙏 Acknowledgements

- [OpenServ Labs](https://openserv.ai)
- [Etherscan API](https://etherscan.io/apis)
- [DexScreener API](https://docs.dexscreener.com/api/reference)
- [Chainbase API](https://docs.chainbase.com/)
- [DeFi Llama API](https://defillama.com/docs/api)
