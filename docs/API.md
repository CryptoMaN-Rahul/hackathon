# BlockchainInsight API Reference

This document provides detailed information on each capability of the BlockchainInsight agent, including parameters, response formats, and examples.

## Table of Contents

1. [Contract Details](#1-contract-details)
2. [Transaction History](#2-transaction-history)
3. [Token Holders](#3-token-holders)
4. [Liquidity Pool Analytics](#4-liquidity-pool-analytics)
5. [Yield Opportunities](#5-yield-opportunities)
6. [Whale Activity](#6-whale-activity)
7. [DeFi Trends](#7-defi-trends)
8. [Token Information](#8-token-information)
9. [DEX Analytics](#9-dex-analytics)

## 1. Contract Details

Retrieves verification details and performs security analysis on a smart contract.

### Capability Name: `getContractDetails`

### Parameters

| Parameter | Type | Required | Description | Default | Constraints |
|-----------|------|----------|-------------|---------|-------------|
| `contractAddress` | string | Yes | The contract address to analyze | - | Must be a valid Ethereum address (0x + 40 hex chars) |
| `chain` | string | No | The blockchain to query | "ethereum" | One of: "ethereum", "polygon", "bsc", "optimism", "arbitrum", "avalanche", "fantom" |

### Example Request

```json
{
  "contractAddress": "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984",
  "chain": "ethereum"
}
```

### Example Response

```json
{
  "status": "success",
  "contractAddress": "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984",
  "chain": "ethereum",
  "contractDetails": {
    "name": "Uniswap",
    "symbol": "UNI",
    "verified": true,
    "implementation": null,
    "abi": "[...]",
    "sourceCode": "// SPDX-License-Identifier: ...",
    "contractType": "ERC20",
    "creationDate": "2020-09-16T22:05:00Z",
    "creationTxHash": "0x..."
  },
  "securityAnalysis": {
    "flags": ["AccessControl", "TimeManipulation"],
    "riskLevel": "Low",
    "verified": true,
    "summary": "Contract is verified and has passed basic security checks...",
    "criticalIssues": []
  },
  "metaData": {
    "timestamp": "2023-06-01T12:00:00Z",
    "apiProvider": "etherscan.io"
  }
}
```

## 2. Transaction History

Fetches and analyzes transaction history for an address.

### Capability Name: `getTransactionHistory`

### Parameters

| Parameter | Type | Required | Description | Default | Constraints |
|-----------|------|----------|-------------|---------|-------------|
| `address` | string | Yes | The wallet or contract address to analyze | - | Must be a valid Ethereum address (0x + 40 hex chars) |
| `chain` | string | No | The blockchain to query | "ethereum" | One of: "ethereum", "polygon", "bsc", "optimism", "arbitrum", "avalanche", "fantom" |
| `page` | number | No | Page number for pagination | 1 | - |
| `limit` | number | No | Number of transactions per page | 20 | Min: 1, Max: 100 |
| `includeTokenTransfers` | boolean | No | Include ERC20 token transfers | true | - |
| `startBlock` | number | No | Starting block number | - | - |
| `endBlock` | number | No | Ending block number | - | - |

### Example Request

```json
{
  "address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
  "chain": "ethereum",
  "limit": 10,
  "includeTokenTransfers": true
}
```

### Example Response

```json
{
  "status": "success",
  "address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
  "chain": "ethereum",
  "balance": "1.234567 ETH",
  "transactions": [
    {
      "hash": "0x...",
      "from": "0x...",
      "to": "0x...",
      "value": "0.5 ETH",
      "timestamp": "2023-05-30T15:20:30Z",
      "status": "Success",
      "isOutgoing": true,
      "gasUsed": "21000",
      "gasPrice": "15 Gwei"
    },
    // More transactions...
  ],
  "tokenTransfers": [
    {
      "hash": "0x...",
      "from": "0x...",
      "to": "0x...",
      "tokenAddress": "0x...",
      "tokenName": "Uniswap",
      "tokenSymbol": "UNI",
      "value": "100",
      "timestamp": "2023-05-29T10:15:00Z",
      "isOutgoing": false
    },
    // More token transfers...
  ],
  "analysis": {
    "totalTransactions": 10,
    "successfulTransactions": 9,
    "failedTransactions": 1,
    "incomingTransactions": 4,
    "outgoingTransactions": 6,
    "totalTokenTransfers": 5,
    "incomingTokenTransfers": 2,
    "outgoingTokenTransfers": 3,
    "uniqueInteractions": 8
  },
  "pagination": {
    "page": 1,
    "limit": 10,
    "hasMoreData": true
  },
  "metaData": {
    "timestamp": "2023-06-01T12:00:00Z",
    "apiProvider": "etherscan.io"
  }
}
```

## 3. Token Holders

Analyzes token holder distribution and concentration metrics.

### Capability Name: `getTokenHolders`

### Parameters

| Parameter | Type | Required | Description | Default | Constraints |
|-----------|------|----------|-------------|---------|-------------|
| `tokenAddress` | string | Yes | The token contract address | - | Must be a valid Ethereum address (0x + 40 hex chars) |
| `chain` | string | No | The blockchain to query | "ethereum" | One of: "ethereum", "polygon", "bsc", "optimism", "arbitrum", "avalanche", "fantom" |
| `limit` | number | No | Number of holders to return | 50 | Min: 1, Max: 100 |
| `excludeZeroBalances` | boolean | No | Exclude addresses with zero balance | true | - |
| `excludeContracts` | boolean | No | Exclude contract addresses | false | - |

### Example Request

```json
{
  "tokenAddress": "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984",
  "chain": "ethereum",
  "limit": 20
}
```

### Example Response

```json
{
  "status": "success",
  "tokenAddress": "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984",
  "chain": "ethereum",
  "tokenInfo": {
    "name": "Uniswap",
    "symbol": "UNI",
    "decimals": 18,
    "totalSupply": "1000000000",
    "circulatingSupply": "750000000"
  },
  "holders": [
    {
      "address": "0x...",
      "balance": "100000000",
      "percentage": "10.00",
      "isContract": false,
      "tags": ["Exchange"]
    },
    // More holders...
  ],
  "concentrationAnalysis": {
    "top10Percentage": "45.67",
    "top50Percentage": "78.9",
    "top100Percentage": "85.4",
    "giniCoefficient": 0.82,
    "riskLevel": "High",
    "interpretation": "Token ownership is concentrated, with potential for market impact from large holders."
  },
  "metaData": {
    "timestamp": "2023-06-01T12:00:00Z",
    "apiProvider": "chainbase.online"
  }
}
```

## 4. Liquidity Pool Analytics

Analyzes liquidity pools with impermanent loss simulation.

### Capability Name: `getLiquidityPoolAnalytics`

### Parameters

| Parameter | Type | Required | Description | Default | Constraints |
|-----------|------|----------|-------------|---------|-------------|
| `poolAddress` | string | Yes | The pool contract address | - | Must be a valid Ethereum address (0x + 40 hex chars) |
| `chain` | string | No | The blockchain to query | "ethereum" | One of: "ethereum", "polygon", "bsc", "optimism", "arbitrum", "avalanche", "fantom" |
| `timeframe` | string | No | Timeframe for historical data | "30d" | One of: "7d", "30d", "90d", "180d", "1y", "all" |
| `simulateImpermanentLoss` | boolean | No | Run impermanent loss simulation | true | - |

### Example Request

```json
{
  "poolAddress": "0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8",
  "chain": "ethereum",
  "timeframe": "30d",
  "simulateImpermanentLoss": true
}
```

### Example Response

```json
{
  "status": "success",
  "poolAddress": "0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8",
  "chain": "ethereum",
  "poolInfo": {
    "dex": "Uniswap V3",
    "token0": {
      "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
      "symbol": "WETH",
      "decimals": 18
    },
    "token1": {
      "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      "symbol": "USDC",
      "decimals": 6
    },
    "fee": 0.3,
    "tvlUsd": 50000000,
    "volume24h": 5000000,
    "apy": 12.5
  },
  "liquidity": {
    "totalLiquidity": "50000000",
    "token0Reserves": "12500.5",
    "token1Reserves": "25000000",
    "liquidityDistribution": [
      {"price": 1750, "percentage": 10},
      {"price": 1800, "percentage": 25},
      {"price": 1850, "percentage": 30},
      {"price": 1900, "percentage": 25},
      {"price": 1950, "percentage": 10}
    ]
  },
  "impermanentLoss": {
    "scenarios": [
      {
        "priceChange": "+10%",
        "impermanentLoss": -0.25,
        "comparedToHodl": -125000
      },
      {
        "priceChange": "+25%",
        "impermanentLoss": -1.57,
        "comparedToHodl": -785000
      },
      {
        "priceChange": "-10%",
        "impermanentLoss": -0.25,
        "comparedToHodl": -125000
      },
      {
        "priceChange": "-25%",
        "impermanentLoss": -1.57,
        "comparedToHodl": -785000
      }
    ],
    "breakevenDays": 48
  },
  "historicalData": {
    "tvl": [
      {"date": "2023-05-01", "value": 48000000},
      // More data points...
    ],
    "volume": [
      {"date": "2023-05-01", "value": 4800000},
      // More data points...
    ],
    "apy": [
      {"date": "2023-05-01", "value": 13.2},
      // More data points...
    ]
  },
  "metaData": {
    "timestamp": "2023-06-01T12:00:00Z",
    "apiProviders": ["dexscreener.com", "llama.fi"]
  }
}
```

## 5. Yield Opportunities

Discovers and assesses DeFi yield opportunities.

### Capability Name: `getYieldOpportunities`

### Parameters

| Parameter | Type | Required | Description | Default | Constraints |
|-----------|------|----------|-------------|---------|-------------|
| `chain` | string | No | The blockchain to query | "ethereum" | One of: "ethereum", "polygon", "bsc", "optimism", "arbitrum", "avalanche", "fantom" |
| `minApy` | number | No | Minimum APY percentage | 0 | Min: 0 |
| `maxRisk` | string | No | Maximum risk level | "high" | One of: "low", "medium", "high", "very_high" |
| `category` | string | No | Protocol category | - | One of: "lending", "staking", "lp", "farming", "options" |
| `token` | string | No | Filter by token | - | Token symbol or address |
| `limit` | number | No | Number of opportunities to return | 20 | Min: 1, Max: 100 |

### Example Request

```json
{
  "chain": "ethereum",
  "minApy": 5,
  "maxRisk": "medium",
  "category": "lending",
  "limit": 10
}
```

### Example Response

```json
{
  "status": "success",
  "chain": "ethereum",
  "filters": {
    "minApy": 5,
    "maxRisk": "medium",
    "category": "lending"
  },
  "opportunities": [
    {
      "protocol": "Aave",
      "poolName": "USDC",
      "chain": "ethereum",
      "tvlUsd": 500000000,
      "apyBase": 3.5,
      "apyReward": 1.8,
      "apyTotal": 5.3,
      "token": "USDC",
      "ilRisk": "none",
      "exposure": ["stablecoin"],
      "riskLevel": "low",
      "riskFactors": ["Smart Contract Audited", "Large TVL"],
      "poolLink": "https://app.aave.com/reserve-overview/?underlyingAsset=0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48&marketName=proto_mainnet",
      "recommendation": "This is a safe, stable yield from a well-established protocol."
    },
    // More opportunities...
  ],
  "metaData": {
    "timestamp": "2023-06-01T12:00:00Z",
    "apiProvider": "llama.fi",
    "totalOpportunities": 10,
    "avgApy": 7.8
  }
}
```

## 6. Whale Activity

Tracks significant wallet movements and whale activity.

### Capability Name: `getWhaleActivity`

### Parameters

| Parameter | Type | Required | Description | Default | Constraints |
|-----------|------|----------|-------------|---------|-------------|
| `timeframe` | string | No | Time period to analyze | "24h" | One of: "1h", "6h", "24h", "7d", "30d" |
| `minValue` | number | No | Minimum USD value of transactions | 1000000 | Min: 10000 |
| `chain` | string | No | The blockchain to query | "ethereum" | One of: "ethereum", "polygon", "bsc", "optimism", "arbitrum", "avalanche", "fantom" |
| `token` | string | No | Filter by token | - | Token symbol or address |
| `limit` | number | No | Number of transactions to return | 20 | Min: 1, Max: 100 |

### Example Request

```json
{
  "timeframe": "24h",
  "minValue": 1000000,
  "chain": "ethereum",
  "limit": 10
}
```

### Example Response

```json
{
  "status": "success",
  "timeframe": "24h",
  "chain": "ethereum",
  "filters": {
    "minValue": 1000000
  },
  "whaleTransactions": [
    {
      "type": "transfer",
      "hash": "0x...",
      "timestamp": "2023-05-31T15:20:30Z",
      "from": {
        "address": "0x...",
        "label": "Binance",
        "type": "exchange"
      },
      "to": {
        "address": "0x...",
        "label": "Unknown Whale",
        "type": "wallet"
      },
      "token": "ETH",
      "amount": "1500.00",
      "valueUsd": 2850000,
      "blockNumber": 17123456
    },
    // More transactions...
  ],
  "whaleAddresses": [
    {
      "address": "0x...",
      "label": "Unknown Whale",
      "type": "wallet",
      "transactions": 5,
      "totalValueUsd": 12500000,
      "netFlow": 8500000,
      "topTokens": ["ETH", "USDC", "UNI"]
    },
    // More whale addresses...
  ],
  "analysis": {
    "totalTransactions": 10,
    "totalValueUsd": 25000000,
    "netExchangeOutflow": 15000000,
    "largestTransaction": {
      "hash": "0x...",
      "valueUsd": 5000000
    },
    "mostActiveWallet": {
      "address": "0x...",
      "transactions": 5
    }
  },
  "metaData": {
    "timestamp": "2023-06-01T12:00:00Z",
    "apiProvider": "etherscan.io"
  }
}
```

## 7. DeFi Trends

Analyzes DeFi protocol growth, TVL, and trends.

### Capability Name: `getDeFiTrends`

### Parameters

| Parameter | Type | Required | Description | Default | Constraints |
|-----------|------|----------|-------------|---------|-------------|
| `category` | string | No | Protocol category | - | One of: "lending", "dex", "yield", "bridge", "derivatives", "all" |
| `chain` | string | No | The blockchain to filter | - | One of blockchain names or "all" |
| `timeframe` | string | No | Time period to analyze | "30d" | One of: "7d", "30d", "90d", "180d", "1y", "all" |
| `sortBy` | string | No | Sort results by | "tvl" | One of: "tvl", "tvlChange", "volume" |
| `limit` | number | No | Number of protocols to return | 20 | Min: 1, Max: 100 |

### Example Request

```json
{
  "category": "lending",
  "timeframe": "30d",
  "sortBy": "tvl",
  "limit": 10
}
```

### Example Response

```json
{
  "status": "success",
  "category": "lending",
  "timeframe": "30d",
  "trends": {
    "totalTvl": 25000000000,
    "tvlChange": -5.2,
    "totalVolume": 12500000000,
    "volumeChange": 8.7,
    "categoryDistribution": [
      {"category": "lending", "tvl": 25000000000, "percentage": 28.5},
      {"category": "dex", "tvl": 35000000000, "percentage": 39.8},
      // More categories...
    ],
    "chainDistribution": [
      {"chain": "ethereum", "tvl": 45000000000, "percentage": 51.2},
      {"chain": "polygon", "tvl": 12000000000, "percentage": 13.7},
      // More chains...
    ]
  },
  "protocols": [
    {
      "name": "Aave",
      "category": "lending",
      "tvl": 5000000000,
      "tvlChange": -3.5,
      "dominance": 20.0,
      "chains": ["ethereum", "polygon", "avalanche"],
      "volumeDay": 250000000,
      "mcapTvlRatio": 0.8,
      "url": "https://aave.com"
    },
    // More protocols...
  ],
  "historicalData": {
    "tvl": [
      {"date": "2023-05-01", "value": 26000000000},
      // More data points...
    ],
    "volume": [
      {"date": "2023-05-01", "value": 1200000000},
      // More data points...
    ]
  },
  "trendingProtocols": [
    {
      "name": "Protocol X",
      "category": "lending",
      "tvlChange": 85.4,
      "tvl": 150000000
    },
    // More trending protocols...
  ],
  "metaData": {
    "timestamp": "2023-06-01T12:00:00Z",
    "apiProvider": "llama.fi"
  }
}
```

## 8. Token Information

Retrieves comprehensive token data.

### Capability Name: `getTokenInfo`

### Parameters

| Parameter | Type | Required | Description | Default | Constraints |
|-----------|------|----------|-------------|---------|-------------|
| `address` | string | No | Token contract address | - | Must be a valid address if provided |
| `symbol` | string | No | Token symbol | - | At least one of address or symbol must be provided |
| `chain` | string | No | The blockchain to query | "ethereum" | One of: "ethereum", "polygon", "bsc", "optimism", "arbitrum", "avalanche", "fantom" |
| `includePairs` | boolean | No | Include trading pairs info | true | - |
| `includeHolders` | boolean | No | Include top holders info | true | - |

### Example Request

```json
{
  "address": "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984",
  "chain": "ethereum",
  "includePairs": true,
  "includeHolders": true
}
```

### Example Response

```json
{
  "status": "success",
  "token": {
    "address": "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984",
    "name": "Uniswap",
    "symbol": "UNI",
    "decimals": 18,
    "chain": "ethereum",
    "isVerified": true,
    "logo": "https://...",
    "description": "UNI is the governance token for Uniswap protocol...",
    "totalSupply": "1000000000",
    "circulatingSupply": "750000000",
    "marketCap": 3750000000,
    "fullyDilutedValuation": 5000000000
  },
  "price": {
    "usd": 5.00,
    "eth": 0.0025,
    "btc": 0.000175,
    "change24h": 2.5,
    "change7d": -3.8,
    "ath": 45.00,
    "athDate": "2021-05-03T00:00:00Z",
    "atl": 1.03,
    "atlDate": "2020-09-17T00:00:00Z"
  },
  "market": {
    "volume24h": 75000000,
    "liquidity": 125000000,
    "fdv": 5000000000,
    "exchanges": [
      {"name": "Binance", "volume24h": 25000000, "percentage": 33.3},
      {"name": "Coinbase", "volume24h": 20000000, "percentage": 26.7},
      // More exchanges...
    ]
  },
  "tradingPairs": [
    {
      "pair": "UNI/USDT",
      "exchange": "Binance",
      "price": 5.01,
      "volume24h": 15000000,
      "liquidity": 45000000,
      "priceChange24h": 2.6
    },
    // More trading pairs...
  ],
  "topHolders": [
    {
      "address": "0x...",
      "balance": "100000000",
      "percentage": "10.00",
      "label": "Uniswap Treasury"
    },
    // More holders...
  ],
  "holderDistribution": {
    "top10Percentage": 45.67,
    "top50Percentage": 78.9,
    "top100Percentage": 85.4,
    "concentrationRisk": "High"
  },
  "social": {
    "twitter": "https://twitter.com/Uniswap",
    "website": "https://uniswap.org",
    "github": "https://github.com/Uniswap",
    "telegram": "https://t.me/uniswap",
    "discord": "https://discord.gg/FCfyBSbCU5"
  },
  "metaData": {
    "timestamp": "2023-06-01T12:00:00Z",
    "apiProviders": ["coingecko.com", "dexscreener.com", "chainbase.online"]
  }
}
```

## 9. DEX Analytics

Analyzes DEX trading activity, pairs, and market health.

### Capability Name: `getDEXAnalytics`

### Parameters

| Parameter | Type | Required | Description | Default | Constraints |
|-----------|------|----------|-------------|---------|-------------|
| `dex` | string | Yes | DEX platform name | - | e.g., "uniswap", "pancakeswap", etc. |
| `chain` | string | No | The blockchain to query | "ethereum" | One of: "ethereum", "polygon", "bsc", "optimism", "arbitrum", "avalanche", "fantom" |
| `timeframe` | string | No | Time period to analyze | "24h" | One of: "1h", "24h", "7d", "30d", "all" |
| `sortBy` | string | No | Sort pairs by | "volume" | One of: "volume", "tvl", "priceChange" |
| `limit` | number | No | Number of pairs to return | 20 | Min: 1, Max: 100 |

### Example Request

```json
{
  "dex": "uniswap",
  "chain": "ethereum",
  "timeframe": "24h",
  "sortBy": "volume",
  "limit": 10
}
```

### Example Response

```json
{
  "status": "success",
  "dex": "uniswap",
  "chain": "ethereum",
  "timeframe": "24h",
  "overview": {
    "totalTvl": 5000000000,
    "tvlChange": 2.5,
    "volume24h": 750000000,
    "volumeChange": 12.8,
    "fees24h": 2250000,
    "transactions24h": 250000,
    "uniqueUsers24h": 85000,
    "marketShare": 65.8,
    "versionDistribution": [
      {"version": "V2", "tvl": 1500000000, "percentage": 30},
      {"version": "V3", "tvl": 3500000000, "percentage": 70}
    ]
  },
  "tradingPairs": [
    {
      "pairAddress": "0x...",
      "name": "ETH/USDC",
      "token0": {
        "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        "symbol": "WETH",
        "name": "Wrapped Ether"
      },
      "token1": {
        "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "symbol": "USDC",
        "name": "USD Coin"
      },
      "version": "V3",
      "tvlUsd": 500000000,
      "volume24h": 150000000,
      "volumeChange": 15.3,
      "fees24h": 450000,
      "feesTier": 0.3,
      "priceNative": 0.00055,
      "priceUsd": 1800,
      "priceChange": 2.1
    },
    // More pairs...
  ],
  "historicalData": {
    "tvl": [
      {"date": "2023-05-31", "value": 4900000000},
      // More data points...
    ],
    "volume": [
      {"date": "2023-05-31", "value": 720000000},
      // More data points...
    ],
    "uniqueUsers": [
      {"date": "2023-05-31", "value": 82000},
      // More data points...
    ]
  },
  "marketHealth": {
    "liquidityScore": 95,
    "volumeToLiquidity": 0.15,
    "stablecoinPercentage": 45.2,
    "topPairsDominance": 35.7,
    "healthScore": 90,
    "healthAssessment": "Excellent liquidity depth and volume distribution across multiple pairs."
  },
  "links": {
    "website": "https://uniswap.org",
    "explorer": "https://info.uniswap.org",
    "documentation": "https://docs.uniswap.org"
  },
  "metaData": {
    "timestamp": "2023-06-01T12:00:00Z",
    "apiProviders": ["dexscreener.com", "llama.fi"]
  }
}
```

## Response Formats

All capabilities return responses in a standardized JSON format with the following structure:

```json
{
  "status": "success|error",
  "message": "Optional message explaining the result (especially for errors)",
  ... capability-specific data ...,
  "metaData": {
    "timestamp": "ISO timestamp of when the data was fetched",
    "apiProvider": "The data source(s) used",
    ... other metadata ...
  }
}
```

## Error Handling

If an error occurs, the response will follow this format:

```json
{
  "status": "error",
  "message": "Clear description of what went wrong",
  "details": "More detailed error information (if available)",
  "errorCode": "Optional error code for programmatic handling",
  "timestamp": "ISO timestamp of when the error occurred"
}
```

## Rate Limiting

The BlockchainInsight agent respects the rate limits of the underlying APIs. If you encounter rate limit errors, please reduce the frequency of your requests.

## Authentication

All requests to the BlockchainInsight agent are authenticated through the OpenServ platform. No additional authentication is required when using the agent through OpenServ. 