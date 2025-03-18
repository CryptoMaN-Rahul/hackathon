# BlockchainInsight OpenServ Integration Guide

This document provides comprehensive details on how the BlockchainInsight agent integrates with OpenServ's platform, meeting the requirements of the judging criteria.

## Integration with OpenServ

The BlockchainInsight agent is built using the OpenServ SDK and follows its agent design patterns, ensuring full compatibility with the OpenServ platform.

### Integration Components

1. **SDK Implementation**: The agent uses the `@openserv-labs/sdk` package to create and define all capabilities.
2. **Agent Initialization**: The agent is initialized with OpenServ-compatible configurations including system prompts and LLM provider settings.
3. **Capability Structure**: Each capability follows OpenServ's recommended structure with clear schemas, descriptions, and formatted outputs.
4. **Platform Deployment**: The agent can be deployed directly to the OpenServ platform using the OpenServ API.

## Agent Configuration

### Core Configuration

```typescript
const blockchainAgent = new Agent({
    systemPrompt: SYSTEM_PROMPT,
    
});
```

### Capabilities in the Team

The BlockchainInsight agent includes the following capabilities:

1. **Contract Analysis** (`getContractDetails`): Analyzes smart contracts for verification status and security vulnerabilities.
2. **Transaction History** (`getTransactionHistory`): Retrieves and analyzes wallet transaction history.
3. **Token Holders** (`getTokenHolders`): Analyzes token distribution and concentration metrics.
4. **Liquidity Pool Analytics** (`getLiquidityPoolAnalytics`): Provides detailed DEX pool analysis.
5. **Yield Opportunities** (`getYieldOpportunities`): Discovers and assesses DeFi yield opportunities.
6. **Smart Money Tracking** (`getWhaleActivity`): Tracks significant wallet movements.
7. **DeFi Trend Analysis** (`getDeFiTrends`): Analyzes TVL and protocol growth metrics.
8. **Token Information** (`getTokenInfo`): Retrieves comprehensive token data.
9. **DEX Analytics** (`getDEXAnalytics`): Analyzes DEX trading pairs and volumes.

## Prompting Strategy

The agent uses a specialized system prompt that defines its role, capabilities, and behavioral guidelines:

```
You are BlockchainInsight, an advanced agent specialized in fetching and analyzing on-chain data across multiple blockchain networks.

You can retrieve information about:
- Smart contract verification details and security analysis
- Transaction history and analytics with pattern recognition
- Token holder distribution with concentration metrics
- Liquidity Pool analytics with impermanent loss calculation
- DeFi yield opportunities with risk assessment
- Whale wallet tracking and movement analysis
- DeFi trend analysis with predictive indicators
- Token information by address or name/ticker
- DEX token analytics including trading pairs and volumes

You provide objective data and analysis without making investment recommendations.
Your insights are sourced from blockchain APIs and are presented in a clear, analytical manner with visualization hints where appropriate.
```

## OpenServ Deployment Instructions

To deploy the agent to OpenServ:

1. Ensure you have an OpenServ API key in your environment variables
2. Build the project: `npm run build`


## Testing the Integration

To verify the OpenServ integration is working correctly:

1. Run the test suite: `node dist/test.js`
2. Check that all capabilities return properly formatted responses
3. Verify that the OpenServ SDK is correctly handling the agent's responses

## Troubleshooting OpenServ Integration

If you encounter issues with the OpenServ integration:

1. Verify your OpenServ API key is valid and properly set in the environment
2. Check that the OpenServ SDK version is compatible with the platform
3. Ensure all capability schemas are properly defined with Zod
4. Verify that responses are correctly formatted as JSON strings

## Additional Resources

- [OpenServ SDK Documentation](https://docs.openserv.ai/sdk)
- [OpenServ Platform Guide](https://docs.openserv.ai/platform)
- [Agent Design Patterns](https://docs.openserv.ai/patterns) 