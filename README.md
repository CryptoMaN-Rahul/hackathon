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

## 🎯 Use Cases

- **For Investors**: Assess token distribution risk, analyze whale movements, and find yield opportunities
- **For Developers**: Verify contract code, check for security vulnerabilities, and analyze protocol adoption
- **For Traders**: Get comprehensive token data, track liquidity, and analyze trading pairs
- **For Security Researchers**: Analyze transaction patterns, detect anomalies, and assess contract risk

## multi-agent workflow
- ** Use it with General assistant (by openserv) to create a detailed report 

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
- [Security Best Practices](docs/SECURITY.md)

## 📈 Project Roadmap

- [x] Initial release with 9 core capabilities
- [x] Multi-chain support
- [x] API documentation
- [ ] Enhanced visualizations
- [ ] Mobile app integration
- [ ] Browser extension
- [ ] Historical data analysis
- [ ] Predictive trend analysis

## 🔧 Advanced Configuration

See the [Advanced Configuration Guide](docs/ADVANCED_CONFIG.md) for details on:
- Chain-specific settings
- API provider fallbacks
- Custom data sources
- Rate limit handling
- Cache configuration



## 🙏 Acknowledgements

- [OpenServ Labs](https://openserv.ai)
- [Etherscan API](https://etherscan.io/apis)
- [DexScreener API](https://docs.dexscreener.com/api/reference)
- [Chainbase API](https://docs.chainbase.com/)
- [DeFi Llama API](https://defillama.com/docs/api)
