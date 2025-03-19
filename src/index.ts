import { z } from "zod";
import { Agent } from "@openserv-labs/sdk";
import "dotenv/config";
import axios from "axios";
import { createHash } from "crypto";
import OpenAI from "openai";
import express from 'express';


// Enhanced system prompt that defines the agent's capabilities and behavior
const SYSTEM_PROMPT = `
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
`;
// Initialize the blockchain agent with enhanced configuration
console.log('Starting application...');
const PORT = Number(process.env.PORT) || 7378;
const blockchainAgent = new Agent({
    systemPrompt: SYSTEM_PROMPT,
    llmProvider:'gemini',
    port: PORT
});
console.log('Agent initialized');

// Add logging to debug route registration
console.log('Registering capabilities...');





// Initialize OpenAI client if API key is available
const openai = process.env.OPENAI_API_KEY
    ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY , baseURL: "https://generativelanguage.googleapis.com/v1beta/openai/"}) 
    : null;

// Define API rate limiting and retry configuration
const API_RETRY_ATTEMPTS = 3;
const API_RETRY_DELAY = 1000; // ms
const API_TIMEOUT = 10000; // ms



// Define known API endpoints for better maintainability
const API_ENDPOINTS = {
    etherscan: {
        ethereum: 'https://api.etherscan.io/api',
        polygon: 'https://api.polygonscan.com/api',
        bsc: 'https://api.bscscan.com/api',
        optimism: 'https://api-optimistic.etherscan.io/api',
        arbitrum: 'https://api.arbiscan.io/api',
        avalanche: 'https://api.snowtrace.io/api',
        fantom: 'https://api.ftmscan.com/api',
    },
    defillama: {
        base: 'https://api.llama.fi',
        pools: 'https://yields.llama.fi/pools',
        charts: '/charts',  // For TVL charts
        poolChart: 'https://yields.llama.fi/chart',  // For pool APY charts
        protocols: '/protocols',
        protocol: '/protocol', // For individual protocol data
        historicalChainTvl: '/v2/historicalChainTvl', // For chain TVL history
        prices: '/prices/current' // For token prices
    },
    chainbase: {
        base: 'https://api.chainbase.online/v1',
        tokenHolders: '/token/top-holders'  // Endpoint for token holders
    },
    dexscreener: {
        base: 'https://api.dexscreener.com',
        tokensByAddress: '/tokens/v1', // Get tokens by chainId/address - /tokens/v1/{chainId}/{tokenAddresses}
        tokenPairs: '/token-pairs/v1', // Get pools for token - /token-pairs/v1/{chainId}/{tokenAddress}
        tokenProfiles: '/token-profiles/latest/v1', // Get latest token profiles
        tokenBoosts: '/token-boosts/latest/v1', // Get latest boosted tokens
        dexPairs: '/latest/dex/pairs', // Get pairs - /latest/dex/pairs/{chainId}/{pairId}
        dexSearch: '/latest/dex/search' // Search for pairs - /latest/dex/search?q={query}
    },
    coingecko: {
        base: 'https://api.coingecko.com/api/v3',
        coins: '/coins',  // For detailed token data
        search: '/search'  // For searching tokens
    }
};

// Chain ID mapping for various API providers
const CHAIN_IDS = {
    chainbase: {
        ethereum: '1',
        polygon: '137',
        bsc: '56',
        optimism: '10',
        arbitrum: '42161',
        avalanche: '43114',
        fantom: '250',
    }
};

// Check for required environment variables
const requiredKeys = ['ETHEREUM_SCAN_API_KEY', 'CHAINBASE_API_KEY'];
const missingKeys = requiredKeys.filter(key => !process.env[key]);

if (missingKeys.length > 0) {
    console.warn(`Warning: The following required API keys are missing: ${missingKeys.join(', ')}. Some functionality will be limited.`);
}

// Define some basic types to improve code quality
interface TokenTransfer {
    hash: string;
    from: string;
    to: string;
    contractAddress?: string;
    timeStamp: string;
    value: string;
    tokenSymbol?: string;
    tokenDecimal?: string;
    tokenName?: string;
    tokenID?: string;
    blockNumber: string;
    input?: string;
    isError?: string;
    type?: string;
    gasPrice?: string;
    gasUsed?: string;
}

interface Transaction {
    hash: string;
    from: string;
    to: string;
    timeStamp: string;
    value: string;
    blockNumber: string;
    gasPrice: string;
    gasUsed: string;
    input: string;
    methodId?: string;
    functionName?: string;
    txreceipt_status: string;
    isError?: string;
}

interface SignificantTransaction {
    type: string;
    hash: string;
    timestamp: string;
    from: string;
    to: string;
    token: string;
    tokenId?: string;
    amount?: string;
    valueUsd: string;
    isOutgoing: boolean;
    protocol: string;
    blockNumber: number;
}

// Add this interface for security analysis
interface SecurityAnalysis {
    flags: string[];
    riskLevel: string;
    verified: boolean;
    summary?: string;
    criticalIssues?: Array<{
        type: string;
        impact: string;
        severity: string;
    }>;
}

// Helper function for axios request with retries
async function axiosWithRetry(config: any, attempts = API_RETRY_ATTEMPTS) {
    try {
        return await axios({
            ...config,
            timeout: API_TIMEOUT,
        });
    } catch (error: any) {
        if (attempts <= 1) throw error;
        
        // Log the error but don't fail yet
        console.warn(`API request failed, retrying (${API_RETRY_ATTEMPTS - attempts + 1}/${API_RETRY_ATTEMPTS}):`, error.message);
        
        // Wait before retrying
        await new Promise(resolve => setTimeout(resolve, API_RETRY_DELAY));
        
        // Retry with one less attempt
        return axiosWithRetry(config, attempts - 1);
    }
}

// Utility function to format currency values
function formatCurrency(value: number): string {
    return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD',
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
    }).format(value);
}

// Helper function to get currency symbol for a chain
function getCurrencySymbol(chain: string): string {
    switch (chain) {
        case 'ethereum': return 'ETH';
        case 'polygon': return 'MATIC';
        case 'bsc': return 'BNB';
        case 'optimism': return 'ETH';
        case 'arbitrum': return 'ETH';
        case 'avalanche': return 'AVAX';
        case 'fantom': return 'FTM';
        default: return 'ETH';
    }
}

// Helper function for token concentration risk interpretation
function getConcentrationRiskInterpretation(risk: string): string {
    switch (risk) {
        case "Extreme":
            return "Token ownership is extremely concentrated, posing very high risk of price manipulation.";
        case "Very High":
            return "Token ownership is highly concentrated among a few wallets, suggesting significant centralization.";
        case "High":
            return "Token holders are concentrated, with potential for market impact from large holders.";
        case "Medium":
            return "Moderate concentration of token holders, some large holders could influence price.";
        case "Low":
            return "Token ownership is relatively well-distributed among holders.";
        default:
            return "Unable to determine concentration risk.";
    }
}


// Capability 1: Get Contract Verification Details with Security Analysis
blockchainAgent.addCapability({
    name: 'getContractDetails',
    description: 'Fetch verification details and basic security analysis of a smart contract',
    schema: z.object({
        contractAddress: z.string()
            .regex(/^0x[a-fA-F0-9]{40}$/, {
                message: "Contract address must be a valid Ethereum address starting with 0x followed by 40 hexadecimal characters"
            })
            .describe('The contract address to fetch details for'),
        chain: z.enum(['ethereum', 'polygon', 'bsc', 'optimism', 'arbitrum', 'avalanche', 'fantom'])
            .default('ethereum')
            .describe('The blockchain to query')
    }),
    async run({ args }) {
        try {
            // Get the chain-specific API URL and key
            const apiUrl = API_ENDPOINTS.etherscan[args.chain];
            let apiKey: string | undefined;
            
            switch (args.chain) {
                case 'ethereum':
                    apiKey = process.env.ETHEREUM_SCAN_API_KEY;
                    break;
                case 'polygon':
                    apiKey = process.env.POLYGON_SCAN_API_KEY || process.env.ETHEREUM_SCAN_API_KEY;
                    break;
                case 'bsc':
                    apiKey = process.env.BSC_SCAN_API_KEY || process.env.ETHEREUM_SCAN_API_KEY;
                    break;
                case 'optimism':
                    apiKey = process.env.OPTIMISM_SCAN_API_KEY || process.env.ETHEREUM_SCAN_API_KEY;
                    break;
                case 'arbitrum':
                    apiKey = process.env.ARBITRUM_SCAN_API_KEY || process.env.ETHEREUM_SCAN_API_KEY;
                    break;
                case 'avalanche':
                    apiKey = process.env.AVALANCHE_SCAN_API_KEY || process.env.ETHEREUM_SCAN_API_KEY;
                    break;
                case 'fantom':
                    apiKey = process.env.FANTOM_SCAN_API_KEY || process.env.ETHEREUM_SCAN_API_KEY;
                    break;
            }

            if (!apiKey) {
                return JSON.stringify({
                    status: 'error',
                    message: `API key for ${args.chain} is not available. Please set the appropriate environment variable.`,
                    suggestedAction: 'Obtain an API key from the relevant block explorer website and set the environment variable.',
                    supportedChains: Object.keys(API_ENDPOINTS.etherscan)
                }, null, 2);
            }

            // Fetch contract source code
            const response = await axiosWithRetry({
                method: 'get',
                url: apiUrl,
                params: {
                    module: 'contract',
                    action: 'getsourcecode',
                    address: args.contractAddress,
                    apikey: apiKey,
                },
            });

            if (response.data.status === '0') {
                return JSON.stringify({
                    status: 'error',
                    message: `API Error: ${response.data.message || 'Unknown error'}`,
                    chain: args.chain,
                    contractAddress: args.contractAddress
                }, null, 2);
            }

            const contractInfo = response.data.result[0];
            
            // Check if contract is verified
            const isVerified = contractInfo.SourceCode !== '';
            
            // Get ABI if available
            let abi = [];
            if (isVerified && contractInfo.ABI && contractInfo.ABI !== "Contract source code not verified") {
                try {
                    abi = JSON.parse(contractInfo.ABI);
                } catch (e) {
                    console.warn("Error parsing ABI: ", e);
                }
            }
            
            // Enhanced security analysis using LLM if available
            let securityAnalysis: SecurityAnalysis = {
                flags: [],
                riskLevel: 'Unknown',
                verified: isVerified
            };
            
            if (isVerified) {
                try {
                    if (openai) {
                        // Extract relevant portions of the source code for analysis
                        // Limit size to prevent token limit issues
                        const codeForAnalysis = contractInfo.SourceCode.length > 15000 
                            ? contractInfo.SourceCode.substring(0, 15000) + "..." 
                            : contractInfo.SourceCode;
                        
                        console.log("Performing AI-powered security analysis of contract...");
                        
                        const completion = await openai.chat.completions.create({
                            model: "gemini-2.0-flash",
                            messages: [
                                {
                                    role: "system",
                                    content: `You are a blockchain security expert specializing in smart contract auditing. 
                                    Analyze the provided smart contract code and identify security vulnerabilities, following these guidelines:
                                    
                                    1. Identify common vulnerabilities such as:
                                       - Reentrancy attacks
                                       - Integer overflow/underflow
                                       - Front-running vulnerabilities
                                       - Timestamp dependence
                                       - Access control issues
                                       - Improper error handling
                                       - Use of tx.origin for authentication
                                       - Unsafe delegatecall
                                       - Use of selfdestruct where inappropriate
                                       - Unprotected functions
                                       - Logic errors in fund management
                                       - Gas optimization problems
                                    
                                    2. For each identified vulnerability:
                                       - Explain the issue clearly and concisely
                                       - Provide the severity level (Critical, High, Medium, Low, or Informational)
                                       - Mention the potential impact
                                    
                                    3. Provide an overall risk assessment (Low, Medium, High, Critical)
                                    
                                    Format your response as a JSON object with the following structure:
                                    {
                                      "vulnerabilities": [
                                        {
                                          "type": "string",
                                          "description": "string",
                                          "severity": "Critical|High|Medium|Low|Informational",
                                          "impact": "string"
                                        }
                                      ],
                                      "overallRisk": "Low|Medium|High|Critical",
                                      "summary": "Brief summary of findings"
                                    }
                                    
                                    If no vulnerabilities are found, return an empty array for vulnerabilities, set overallRisk to "Low", and provide an appropriate summary.`
                                },
                                {
                                    role: "user",
                                    content: `Analyze this smart contract for security vulnerabilities:\n\n${codeForAnalysis}`
                                }
                            ],
                            response_format: { type: "json_object" }
                        });
                        
                        if (completion.choices[0].message.content) {
                            try {
                                const analysisResult = JSON.parse(completion.choices[0].message.content);
                                
                                // Extract the flags from the vulnerabilities
                                securityAnalysis.flags = analysisResult.vulnerabilities.map((vuln: any) => 
                                    `[${vuln.severity}] ${vuln.type}: ${vuln.description}`
                                );
                                
                                securityAnalysis.riskLevel = analysisResult.overallRisk;
                                securityAnalysis.summary = analysisResult.summary;
                                
                                // Add any critical or high severity issues to a separate list for emphasis
                                securityAnalysis.criticalIssues = analysisResult.vulnerabilities
                                    .filter((vuln: any) => vuln.severity === 'Critical' || vuln.severity === 'High')
                                    .map((vuln: any) => ({
                                        type: vuln.type,
                                        impact: vuln.impact,
                                        severity: vuln.severity
                                    }));
                                
                            } catch (parseError) {
                                console.error("Error parsing LLM response:", parseError);
                                // Fallback to basic analysis
                                securityAnalysis = performBasicSecurityAnalysis(contractInfo.SourceCode, isVerified);
                            }
                        } else {
                            // Fallback to basic analysis if LLM fails
                            securityAnalysis = performBasicSecurityAnalysis(contractInfo.SourceCode, isVerified);
                        }
                    } else {
                        // If OpenAI API key is not available, fall back to basic analysis
                        securityAnalysis = performBasicSecurityAnalysis(contractInfo.SourceCode, isVerified);
                    }
                } catch (error) {
                    console.error("Error during AI security analysis:", error);
                    // Fallback to basic analysis
                    securityAnalysis = performBasicSecurityAnalysis(contractInfo.SourceCode, isVerified);
                }
            } else {
                securityAnalysis.riskLevel = 'High';
                securityAnalysis.flags.push("Contract not verified: Source code not available for analysis");
            }

            // Get contract creation date if available
            let contractCreation = null;
            try {
                const txListResponse = await axiosWithRetry({
                    method: 'get',
                    url: apiUrl,
                    params: {
                        module: 'account',
                        action: 'txlist',
                        address: args.contractAddress,
                        page: 1,
                        offset: 1,
                        sort: 'asc',
                        apikey: apiKey,
                    },
                });
                
                if (txListResponse.data.status === '1' && txListResponse.data.result.length > 0) {
                    const firstTx = txListResponse.data.result[0];
                    contractCreation = {
                        blockNumber: firstTx.blockNumber,
                        timestamp: new Date(parseInt(firstTx.timeStamp) * 1000).toISOString(),
                        creator: firstTx.from
                    };
                }
            } catch (error) {
                console.warn("Error fetching contract creation: ", error);
            }

            // Format source code for preview
            const sourceCodePreview = contractInfo.SourceCode ?
                `${contractInfo.SourceCode.substring(0, 500)}${contractInfo.SourceCode.length > 500 ? '...' : ''}` :
                'Source code not available';
            
            // Generate contract hash for comparison
            const contractHash = createHash('sha256')
                .update(contractInfo.SourceCode || '')
                .digest('hex')
                .substring(0, 16);
                
            // Calculate number of functions by analyzing ABI
            const functionCount = Array.isArray(abi) 
                ? abi.filter((item: any) => item.type === "function").length 
                : 0;

            // Format the response for better readability
            const result = {
                status: 'success',
                contractDetails: {
                    name: contractInfo.ContractName || 'Name not available',
                    address: args.contractAddress,
                    chain: args.chain,
                compilerVersion: contractInfo.CompilerVersion || 'Not available',
                optimizationUsed: contractInfo.OptimizationUsed === '1' ? 'Yes' : 'No',
                    optimizationRuns: contractInfo.Runs || 'Not specified',
                licenseType: contractInfo.LicenseType || 'Not specified',
                isProxy: contractInfo.Proxy === '1' ? 'Yes' : 'No',
                implementation: contractInfo.Implementation || 'Not a proxy or implementation not available',
                    verified: isVerified ? 'Yes' : 'No',
                    contractHash: contractHash,
                    functionCount: functionCount,
                    isLibrary: contractInfo.SourceCode ? contractInfo.SourceCode.includes('library ') : false,
                    creation: contractCreation,
                },
                securityAnalysis,
                // Only include the first 500 characters of source code if it exists
                sourceCodePreview: sourceCodePreview,
                metaData: {
                    timestamp: new Date().toISOString(),
                    apiProvider: `${args.chain}scan.io`,
                    responseTime: new Date().getTime(),
                }
            };

            return JSON.stringify(result, null, 2);
        }
        catch (error: any) {
            console.error('Error fetching contract details:', error);
            return JSON.stringify({
                status: 'error',
                message: 'Error fetching contract details',
                details: error.message,
                contractAddress: args.contractAddress,
                chain: args.chain,
                timestamp: new Date().toISOString()
            }, null, 2);
        }
    }
});

// Add this function after the getContractDetails capability
// This is a fallback function that performs basic security analysis if the LLM approach fails
function performBasicSecurityAnalysis(sourceCode: string, isVerified: boolean): SecurityAnalysis {
    const securityFlags: string[] = [];
    
    if (isVerified) {
        // Check for reentrancy vulnerabilities
        if (sourceCode.includes("transfer(") && !sourceCode.includes("ReentrancyGuard")) {
            securityFlags.push("Potential reentrancy vulnerability: Uses transfer() without ReentrancyGuard");
        }
        
        // Check for use of tx.origin
        if (sourceCode.includes("tx.origin")) {
            securityFlags.push("Uses tx.origin: Potential phishing vulnerability");
        }
        
        // Check for use of selfdestruct
        if (sourceCode.includes("selfdestruct") || sourceCode.includes("suicide")) {
            securityFlags.push("Contains selfdestruct: Contract can be destroyed");
        }
        
        // Check for use of delegatecall
        if (sourceCode.includes("delegatecall")) {
            securityFlags.push("Uses delegatecall: Potential for malicious code execution if not properly secured");
        }
    }
    
    // Determine risk level based on number of flags
    let riskLevel = 'Low';
    if (securityFlags.length > 3) {
        riskLevel = 'High';
    } else if (securityFlags.length > 0) {
        riskLevel = 'Medium';
    }
    
    return {
        flags: securityFlags,
        riskLevel,
        verified: isVerified,
        summary: securityFlags.length > 0 
            ? "Basic analysis detected potential security issues" 
            : "No obvious security issues detected in basic analysis"
    };
}


// Capability 3: Get Token Holder Distribution with Concentration Analysis
blockchainAgent.addCapability({
    name: 'getTokenHolders',
    description: 'Fetch token holder distribution with concentration analysis for a contract',
  schema: z.object({
        contractAddress: z.string()
            .regex(/^0x[a-fA-F0-9]{40}$/, {
                message: "Contract address must be a valid Ethereum address starting with 0x followed by 40 hexadecimal characters"
            })
            .describe('The token contract address'),
        chain: z.enum(['ethereum', 'polygon', 'bsc', 'optimism', 'arbitrum', 'avalanche', 'fantom'])
            .default('ethereum')
            .describe('The blockchain to query'),
        page: z.number().default(1).describe('Page number'),
        limit: z.number().min(1).max(100).default(20).describe('Number of holders per page (max 100)'),
        includeConcentrationAnalysis: z.boolean().default(true).describe('Include token concentration analysis')
  }),
  async run({ args }) {
        try {
            const apiKey = process.env.CHAINBASE_API_KEY;
            if (!apiKey) {
                return JSON.stringify({
                    status: 'error',
                    message: 'CHAINBASE_API_KEY is not available. Please set the environment variable.',
                    suggestedAction: 'Register for a Chainbase API key at https://chainbase.com',
                    timestamp: new Date().toISOString()
                }, null, 2);
            }

            // Map to Chainbase chain IDs
            let chainId = CHAIN_IDS.chainbase[args.chain];
            if (!chainId) {
                return JSON.stringify({
                    status: 'error',
                    message: `Unsupported chain: ${args.chain} for Chainbase API.`,
                    supportedChains: Object.keys(CHAIN_IDS.chainbase),
                    timestamp: new Date().toISOString()
                }, null, 2);
            }

            console.log(`Fetching token holders for contract ${args.contractAddress} on chain ${args.chain} (chain_id: ${chainId})`);
            
            // Initialize variables for token info that we'll get from other sources
            let tokenName = 'Unknown Token';
            let tokenSymbol = 'UNKNOWN';
            let tokenDecimals = 18;
            let totalSupply = "Unknown";
            
            // Try to get basic token metadata from DexScreener API
            try {
                // Map chain name to DexScreener chain ID
                const dexScreenerChainId = args.chain === 'ethereum' ? 'ethereum' : 
                                          args.chain === 'bsc' ? 'bsc' :
                                          args.chain === 'polygon' ? 'polygon' :
                                          args.chain === 'arbitrum' ? 'arbitrum' :
                                          args.chain === 'optimism' ? 'optimism' : 'ethereum';
                
                // Use the DexScreener tokens endpoint to get token details
                const dexScreenerResponse = await axiosWithRetry({
                    method: 'get',
                    url: `${API_ENDPOINTS.dexscreener.base}${API_ENDPOINTS.dexscreener.tokensByAddress}/${dexScreenerChainId}/${args.contractAddress}`
                });
                
                if (dexScreenerResponse.data && Array.isArray(dexScreenerResponse.data) && dexScreenerResponse.data.length > 0) {
                    // Extract token data from the first pair that contains our token
                    const firstPair = dexScreenerResponse.data[0];
                    
                    if (firstPair && firstPair.baseToken && firstPair.baseToken.address) {
                        // Determine which one is our token
                        const baseTokenAddress = firstPair.baseToken.address.toLowerCase();
                        const contractAddress = args.contractAddress.toLowerCase();
                        
                        if (baseTokenAddress === contractAddress) {
                            tokenName = firstPair.baseToken.name || 'Unknown Token';
                            tokenSymbol = firstPair.baseToken.symbol || 'UNKNOWN';
                        } else if (firstPair.quoteToken && firstPair.quoteToken.address.toLowerCase() === contractAddress) {
                            tokenName = firstPair.quoteToken.name || 'Unknown Token';
                            tokenSymbol = firstPair.quoteToken.symbol || 'UNKNOWN';
                        }
                        
                        // If we have market cap and liquidity data, include it
                        const additionalData = {
                            marketCap: firstPair.marketCap ? formatCurrency(firstPair.marketCap) : 'Unknown',
                            liquidityUSD: firstPair.liquidity && firstPair.liquidity.usd ? formatCurrency(firstPair.liquidity.usd) : 'Unknown',
                            priceUSD: firstPair.priceUsd || 'Unknown'
                        };
                        
                        console.log(`Found token via DexScreener: ${tokenName} (${tokenSymbol})`);
                    }
                }
            } catch (error) {
                console.warn(`Failed to fetch token data from DexScreener:`, error);
                // Continue execution even if DexScreener fails
            }
            
            // Use Chainbase API only for getting top holders as requested
            // Make sure we're using the correct endpoint path
            const holdersUrl = `${API_ENDPOINTS.chainbase.base}${API_ENDPOINTS.chainbase.tokenHolders}`;
            const holdersResponse = await axiosWithRetry({
                method: 'get',
                url: holdersUrl,
                headers: {
                    'x-api-key': apiKey,
                    'accept': 'application/json'
                },
                params: {
                    chain_id: chainId,
                    contract_address: args.contractAddress,
                    page: args.page,
                    limit: Math.min(args.limit, 100) // Ensure we don't exceed API limits
                }
            });

            // Check for error in holders response
            if (holdersResponse.data.code !== 0) {
                const errorMsg = holdersResponse.data.error || holdersResponse.data.message || 'Unknown error';
                console.error('Token holders error:', errorMsg, holdersResponse.data);
                return JSON.stringify({
                    status: 'error',
                    message: `Error fetching token holders: ${errorMsg}. Please verify the contract address and chain.`,
                    contractAddress: args.contractAddress,
                    chain: args.chain,
                    timestamp: new Date().toISOString()
                }, null, 2);
            }

            if (!holdersResponse.data.data || holdersResponse.data.data.length === 0) {
                return JSON.stringify({
                    status: 'success',
                    message: `No token holders found for ${tokenName} (${tokenSymbol}) on ${args.chain}.`,
                    contractAddress: args.contractAddress,
                    chain: args.chain,
                    timestamp: new Date().toISOString()
                }, null, 2);
            }

            const holders = holdersResponse.data.data;
            console.log(`Retrieved ${holders.length} token holders for ${tokenName}`);

            // Calculate total value for percentage
            const totalValue = holders.reduce((sum: number, holder: any) => sum + parseFloat(holder.amount || '0'), 0);

            // Format the holders with percentage
            const formattedHolders = holders.map((holder: any, index: number) => {
                const amount = parseFloat(holder.amount || '0');
                const percentage = (amount / totalValue) * 100;
                    
                // Check if this is a known contract address
                let holderType = "Unknown";
                if (holder.wallet_address.toLowerCase() === args.contractAddress.toLowerCase()) {
                    holderType = "Token Contract";
                } else if (holder.is_contract) {
                    holderType = "Contract";
                } else {
                    holderType = "Wallet";
                }
                    
                return {
                    rank: index + 1 + ((args.page - 1) * args.limit),
                    address: holder.wallet_address,
                    amount: `${holder.amount} ${tokenSymbol}`,
                    percentage: percentage.toFixed(4),
                    formattedPercentage: `${percentage.toFixed(2)}%`,
                    usdValue: holder.usd_value ? formatCurrency(holder.usd_value) : 'N/A',
                    holderType
                };
            });

            // Calculate concentration metrics if requested
            let concentrationAnalysis = null;
            if (args.includeConcentrationAnalysis) {
                // Sort holders by percentage (descending)
                const sortedHolders = [...formattedHolders].sort((a, b) => 
                    parseFloat(b.percentage) - parseFloat(a.percentage)
                );
                
                // Calculate Gini coefficient (measure of inequality)
                let giniCoefficient = 0;
                const percentages = sortedHolders.map(h => parseFloat(h.percentage));
                const n = percentages.length;
                
                if (n > 1) {
                    let sumOfDifferences = 0;
                    for (let i = 0; i < n; i++) {
                        for (let j = 0; j < n; j++) {
                            sumOfDifferences += Math.abs(percentages[i] - percentages[j]);
                        }
                    }
                    giniCoefficient = sumOfDifferences / (2 * n * n * (percentages.reduce((a, b) => a + b, 0) / n));
                }
                
                // Calculate concentration ratios
                const top10Percentage = sortedHolders.slice(0, Math.min(10, sortedHolders.length)).reduce((sum: number, h: { percentage: string }) => 
                    sum + parseFloat(h.percentage), 0);
                const top20Percentage = sortedHolders.slice(0, Math.min(20, sortedHolders.length)).reduce((sum: number, h: { percentage: string }) => 
                    sum + parseFloat(h.percentage), 0);
                const top50Percentage = sortedHolders.slice(0, Math.min(50, sortedHolders.length)).reduce((sum: number, h: { percentage: string }) => 
                    sum + parseFloat(h.percentage), 0);
                
                // Count contracts vs wallets
                const contractCount = formattedHolders.filter((h: { holderType: string }) => h.holderType === "Contract").length;
                const walletCount = formattedHolders.filter((h: { holderType: string }) => h.holderType === "Wallet").length;
                
                // Determine risk level based on concentration
                let concentrationRisk = "Low";
                if (top10Percentage > 80) {
                    concentrationRisk = "Extreme";
                } else if (top10Percentage > 60) {
                    concentrationRisk = "Very High";
                } else if (top10Percentage > 40) {
                    concentrationRisk = "High";
                } else if (top10Percentage > 20) {
                    concentrationRisk = "Medium";
                }
                
                // Build concentration analysis
                concentrationAnalysis = {
                    giniCoefficient: giniCoefficient.toFixed(4),
                    concentrationRatios: {
                        top10: `${top10Percentage.toFixed(2)}%`,
                        top20: `${top20Percentage.toFixed(2)}%`,
                        top50: `${top50Percentage.toFixed(2)}%`,
                    },
                    holderDistribution: {
                        contracts: contractCount,
                        wallets: walletCount,
                        contractPercentage: `${(contractCount / formattedHolders.length * 100).toFixed(2)}%`
                    },
                    riskAssessment: {
                        concentrationRisk,
                        interpretation: getConcentrationRiskInterpretation(concentrationRisk),
                    }
                };
            }

            // Format the response
            const result = {
                status: 'success',
                tokenInfo: {
                    name: tokenName,
                    symbol: tokenSymbol,
                    decimals: tokenDecimals,
                    contractAddress: args.contractAddress,
                    chain: args.chain,
                    totalSupply: totalSupply ? `${totalSupply} ${tokenSymbol}` : "Not available",
                },
                holderStats: {
                totalHolders: holdersResponse.data.count || holders.length,
                page: args.page,
                pageSize: holders.length,
                    holdersShown: formattedHolders.length,
                    hasNextPage: !!holdersResponse.data.next_page
                },
                holders: formattedHolders,
                concentrationAnalysis,
                metaData: {
                    timestamp: new Date().toISOString(),
                    apiProvider: {
                        holders: "Chainbase",
                        metadata: tokenName !== 'Unknown Token' ? (tokenSymbol ? "DexScreener/CoinGecko" : "Not Available") : "Not Available"
                    }
                }
            };

            return JSON.stringify(result, null, 2);
        } catch (error: any) {
            console.error('Error fetching token holders:', error);
            // Enhanced error handling
            if (axios.isAxiosError(error)) {
                const status = error.response?.status;
                const errorData = error.response?.data;
                if (status === 400) {
                    return JSON.stringify({
                        status: 'error',
                        message: `Bad request error: ${errorData?.error || 'Invalid parameters'}. Please check that your contract address is valid and the chain is supported.`,
                        contractAddress: args.contractAddress,
                        chain: args.chain,
                        timestamp: new Date().toISOString()
                    }, null, 2);
                }
                else if (status === 401 || status === 403) {
                    return JSON.stringify({
                        status: 'error',
                        message: `Authentication error: ${errorData?.error || 'Invalid or expired API key'}. Please check your CHAINBASE_API_KEY.`,
                        timestamp: new Date().toISOString()
                    }, null, 2);
                }
                else if (status === 429) {
                    return JSON.stringify({
                        status: 'error',
                        message: `Rate limit exceeded: ${errorData?.error || 'Too many requests'}. Please try again later.`,
                        timestamp: new Date().toISOString()
                    }, null, 2);
                }
                else {
                    return JSON.stringify({
                        status: 'error',
                        message: `Error fetching token holders: ${errorData?.error || error.message || 'Unknown error'}`,
                        contractAddress: args.contractAddress,
                        chain: args.chain,
                        timestamp: new Date().toISOString()
                    }, null, 2);
                }
            }
            return JSON.stringify({
                status: 'error',
                message: `Error fetching token holders: ${error.message || 'Unknown error'}`,
                contractAddress: args.contractAddress,
                chain: args.chain,
                timestamp: new Date().toISOString()
            }, null, 2);
        }
    }
});

// Helper function to calculate impermanent loss for a given price change percentage
function calculateImpermanentLoss(priceChanges: number[]): number {
    // For a pair of assets, impermanent loss depends on the price ratio change
    // Formula: IL = 2 * sqrt(r) / (1 + r) - 1
    // where r is the price ratio change (new ratio / old ratio)
    
    if (priceChanges.length < 1) return 0;
    
    // Convert percentage changes to multipliers
    const multipliers = priceChanges.map(change => 1 + (change / 100));
    
    // Calculate weighted geometric mean
    const weights = [0.5, 0.5]; // Equal weights for a 50/50 pool
    let geometricMean = 1;
    
    for (let i = 0; i < multipliers.length; i++) {
        const weight = i < weights.length ? weights[i] : weights[weights.length - 1];
        geometricMean *= Math.pow(multipliers[i], weight);
    }
    
    // Calculate weighted arithmetic mean
    let arithmeticMean = 0;
    for (let i = 0; i < multipliers.length; i++) {
        const weight = i < weights.length ? weights[i] : weights[weights.length - 1];
        arithmeticMean += multipliers[i] * weight;
    }
    
    // Calculate impermanent loss
    const impermanentLoss = (geometricMean / arithmeticMean) - 1;
    
    // Convert to percentage and return
    return Math.abs(impermanentLoss * 100);
}

// Capability 4: Liquidity Pool Analysis
blockchainAgent.addCapability({
    name: 'analyzeLiquidityPool',
    description: 'Analyze liquidity pool metrics with impermanent loss simulation',
    schema: z.object({
        address: z.string().describe('Pool address'),
        chain: z.enum(['ethereum', 'polygon', 'bsc', 'optimism', 'arbitrum']).default('ethereum').describe('Blockchain network'),
        simulateImpermanentLoss: z.boolean().default(true).describe('Include impermanent loss simulation')
    }),
    async run({ args }) {
        try {
            console.log(`Analyzing liquidity pool ${args.address} on ${args.chain}`);
            
            // First try to get pool information from DexScreener API
            let poolData: null | {
                name: string;
                dex: string;
                chain: string;
                address: string;
                liquidity: number;
                volume24h: number;
                fee: string;
                priceRatio: number;
            } = null;
            
            let token0: null | {
                address: string;
                symbol: string;
                name: string;
                priceUsd: number;
            } = null;
            
            let token1: null | {
                address: string;
                symbol: string;
                name: string;
                priceUsd: number;
            } = null;
            
            let reserves: null | {
                reserve0: number;
                reserve1: number;
            } = null;
            let found = false;
            
            try {
                // Map chain name to DexScreener chain ID format
                const dexScreenerChainId = args.chain === 'ethereum' ? 'ethereum' : 
                                           args.chain === 'bsc' ? 'bsc' :
                                           args.chain === 'polygon' ? 'polygon' :
                                           args.chain === 'arbitrum' ? 'arbitrum' :
                                           args.chain === 'optimism' ? 'optimism' : 'ethereum';
                
                const dexScreenerResponse = await axios.get(
                    `${API_ENDPOINTS.dexscreener.base}${API_ENDPOINTS.dexscreener.dexPairs}/${dexScreenerChainId}/${args.address}`
                );
                
                if (dexScreenerResponse.data && dexScreenerResponse.data.pairs && dexScreenerResponse.data.pairs.length > 0) {
                    found = true;
                    const pair = dexScreenerResponse.data.pairs[0];
                    
                    poolData = {
                        name: `${pair.baseToken.symbol}/${pair.quoteToken.symbol}`,
                        dex: pair.dexId || 'Unknown',
                        chain: pair.chainId || args.chain,
                        address: args.address,
                        liquidity: pair.liquidity?.usd || 0,
                        volume24h: pair.volume?.h24 || 0,
                        fee: pair.dexId?.toLowerCase().includes('uniswap') ? '0.3%' : 'Unknown',
                        priceRatio: parseFloat(pair.priceNative) || 0
                    };
                    
                    token0 = {
                        address: pair.baseToken.address,
                        symbol: pair.baseToken.symbol,
                        name: pair.baseToken.name,
                        priceUsd: parseFloat(pair.priceUsd) || 0
                    };
                    
                    token1 = {
                        address: pair.quoteToken.address,
                        symbol: pair.quoteToken.symbol,
                        name: pair.quoteToken.name,
                        priceUsd: token0.priceUsd / parseFloat(pair.priceNative) || 0
                    };
                    
                    // Estimate reserves based on liquidity and prices
                    if (poolData.liquidity && token0.priceUsd && token1.priceUsd) {
                        const totalLiquidityUsd = poolData.liquidity;
                        const sqrtPriceRatio = Math.sqrt(token0.priceUsd / token1.priceUsd);
                        
                        const value0 = totalLiquidityUsd / (1 + sqrtPriceRatio);
                        const value1 = totalLiquidityUsd / (1 + 1/sqrtPriceRatio);
                        
                        reserves = {
                            reserve0: value0 / token0.priceUsd,
                            reserve1: value1 / token1.priceUsd
                        };
                    }
                }
            } catch (error) {
                console.warn('Failed to fetch pool data from DexScreener:', error);
            }
            
            // If not found in DexScreener, try DeFiLlama pools API
            if (!found) {
                try {
                    const defiLlamaResponse = await axios.get('https://yields.llama.fi/pools');
                    
                    if (defiLlamaResponse.data && defiLlamaResponse.data.data) {
                        // Find a pool that might match our address
                        const pool = defiLlamaResponse.data.data.find((p: any) => 
                            p.pool && p.pool.toLowerCase().includes(args.address.toLowerCase().substring(2, 8))
                        );
                        
                        if (pool) {
                            found = true;
                            poolData = {
                                name: pool.symbol || 'Unknown',
                                dex: pool.project || 'Unknown',
                                chain: pool.chain || args.chain,
                                address: args.address,
                                liquidity: pool.tvlUsd || 0,
                                volume24h: pool.volumeUsd1d || 0,
                                fee: pool.project?.toLowerCase().includes('uniswap') ? '0.3%' : 'Unknown',
                                priceRatio: 0 // Cannot determine from this API
                            };
                            
                            // Try to extract token symbols from pool name
                            if (pool.symbol && pool.symbol.includes('-')) {
                                const symbols = pool.symbol.split('-');
                                token0 = {
                                    address: '', // Cannot get from this API
                                    symbol: symbols[0],
                                    name: symbols[0],
                                    priceUsd: 0 // Cannot get from this API
                                };
                                
                                token1 = {
                                    address: '', // Cannot get from this API
                                    symbol: symbols[1],
                                    name: symbols[1],
                                    priceUsd: 0 // Cannot get from this API
                                };
                            }
                        }
                    }
                } catch (error) {
                    console.warn('Failed to fetch pool data from DeFiLlama:', error);
                }
            }
            
            // If still not found, return error
            if (!found) {
                return JSON.stringify({
                    status: 'error',
                    message: 'Liquidity pool not found in available data sources',
                    pool: args.address,
                    chain: args.chain,
                    timestamp: new Date().toISOString()
                }, null, 2);
            }
            
            // Now calculate key metrics and analyze the pool
            let impermanentLossAnalysis = null;
            let apr = 'Unknown';
            
            // Calculate impermanent loss scenarios if we have enough data and it's requested
            if (args.simulateImpermanentLoss && token0 && token1 && token0.priceUsd && token1.priceUsd && reserves) {
                // Calculate impermanent loss for different price change scenarios
                impermanentLossAnalysis = {
                    initialTokenRatio: token0.priceUsd / token1.priceUsd,
                    scenarios: [
                        calculateImpermanentLoss(20), // +20% price change
                        calculateImpermanentLoss(10), // +10% price change  
                        calculateImpermanentLoss(5),  // +5% price change
                        calculateImpermanentLoss(-5), // -5% price change
                        calculateImpermanentLoss(-10), // -10% price change
                        calculateImpermanentLoss(-20)  // -20% price change
                    ]
                };
                
                function calculateImpermanentLoss(percentChange: number) {
                    // Simplified impermanent loss calculation
                    const priceRatio = token0!.priceUsd / token1!.priceUsd;
                    const newPriceRatio = priceRatio * (1 + percentChange / 100);
                    const sqrtRatio = Math.sqrt(newPriceRatio / priceRatio);
                    
                    // Impermanent loss formula: 2√(p_new/p_old)/(1+p_new/p_old) - 1
                    const impermanentLoss = (2 * sqrtRatio / (1 + sqrtRatio) - 1) * 100;
                    
                    return {
                        percentChange: percentChange,
                        newPrice: `$${(token0!.priceUsd * (1 + percentChange / 100)).toFixed(4)}`,
                        loss: Math.abs(impermanentLoss).toFixed(2)
                    };
                }
            }
            
            // Calculate estimated APR from fees if we have enough data
            if (poolData && poolData.volume24h && poolData.liquidity && poolData.fee) {
                const feePercent = parseFloat(poolData.fee.replace('%', '')) / 100;
                const dailyFeeRevenue = poolData.volume24h * feePercent;
                const yearlyFeeRevenue = dailyFeeRevenue * 365;
                apr = `${((yearlyFeeRevenue / poolData.liquidity) * 100).toFixed(2)}%`;
            }
            
            // Format the final response
            const result = {
                status: 'success',
                timestamp: new Date().toISOString(),
                poolInfo: {
                    name: poolData ? poolData.name : 'Unknown',
                    address: args.address,
                    chain: args.chain,
                    dex: poolData ? poolData.dex : 'Unknown',
                    tokens: [
                        token0 ? { 
                            symbol: token0.symbol,
                            name: token0.name,
                            address: token0.address,
                            priceUsd: token0.priceUsd ? `$${token0.priceUsd.toFixed(6)}` : 'Unknown'
                        } : 'Unknown',
                        token1 ? { 
                            symbol: token1.symbol,
                            name: token1.name,
                            address: token1.address,
                            priceUsd: token1.priceUsd ? `$${token1.priceUsd.toFixed(6)}` : 'Unknown'
                        } : 'Unknown'
                    ],
                    metrics: {
                        liquidity: poolData && poolData.liquidity ? `$${Number(poolData.liquidity).toLocaleString()}` : 'Unknown',
                        volume24h: poolData && poolData.volume24h ? `$${Number(poolData.volume24h).toLocaleString()}` : 'Unknown',
                        fee: poolData ? poolData.fee : 'Unknown',
                        estimatedAPR: apr,
                        priceRatio: poolData && poolData.priceRatio && token0 && token1 ? 
                          `1 ${token0.symbol} = ${poolData.priceRatio.toFixed(6)} ${token1.symbol}` : 'Unknown'
                    }
                },
                impermanentLossAnalysis: impermanentLossAnalysis,
                recommendations: [
                    `Current estimated APR from trading fees: ${apr}`,
                    impermanentLossAnalysis ? 
                    `Impermanent loss risk: ${Number(impermanentLossAnalysis.scenarios[3].loss) > 5 ? 'High' : Number(impermanentLossAnalysis.scenarios[3].loss) > 2 ? 'Medium' : 'Low'}` : 
                    'Impermanent loss calculation not available with current data',
                    token0 && token1 ? 
                    `Consider your outlook for ${token0?.symbol || 'Token0'}/${token1?.symbol || 'Token1'} price ratio before providing liquidity` : 
                    'Research both assets in the pair before providing liquidity'
                ],
                links: {
                    explorer: `https://${args.chain !== 'ethereum' ? args.chain + '.' : ''}etherscan.io/address/${args.address}`
                }
            };

            return JSON.stringify(result, null, 2);
        }
        catch (error) {
            console.error('Liquidity pool analysis error:', error);
            return JSON.stringify({
                status: 'error',
                message: `Error analyzing liquidity pool: ${error instanceof Error ? error.message : 'Unknown error'}`,
                pool: args.address,
                chain: args.chain,
                timestamp: new Date().toISOString()
            }, null, 2);
        }
    }
});

// Capability 5: Yield Opportunity Discovery
blockchainAgent.addCapability({
    name: 'findYieldOpportunities',
    description: 'Find high-yield farming and staking opportunities across different chains and protocols',
    schema: z.object({
        chain: z.enum(['ethereum', 'polygon', 'bsc', 'optimism', 'arbitrum', 'avalanche', 'all']).default('all').describe('Chain to search for opportunities'),
        minApy: z.number().default(5).describe('Minimum APY percentage'),
        stablecoin: z.boolean().default(false).describe('Whether to show only stablecoin opportunities'),
        maxRisk: z.enum(['low', 'medium', 'high', 'any']).default('medium').describe('Maximum risk level'),
        limit: z.number().default(10).describe('Number of results to return')
    }),
    async run({ args }) {
        try {
            console.log(`Finding yield opportunities with minimum ${args.minApy}% APY on ${args.chain === 'all' ? 'all chains' : args.chain}...`);
            
            // Fetch all pools from DeFiLlama
            const response = await axios.get('https://yields.llama.fi/pools');
            
            if (!response.data || !response.data.data || !Array.isArray(response.data.data)) {
                return JSON.stringify({
                    status: 'error',
                    message: 'Failed to fetch yield data from DeFiLlama API',
                    timestamp: new Date().toISOString()
                }, null, 2);
            }
            
            // Filter pools based on criteria
            let pools = response.data.data;
            
            // Filter by chain
            if (args.chain !== 'all') {
                const chainName = args.chain.charAt(0).toUpperCase() + args.chain.slice(1);
                pools = pools.filter((pool: any) => pool.chain && pool.chain.toLowerCase() === args.chain.toLowerCase());
            }
            
            // Filter by minimum APY
            pools = pools.filter((pool: any) => 
                pool.apy && parseFloat(pool.apy) >= args.minApy
            );
            
            // Filter by stablecoin if requested
            if (args.stablecoin) {
                pools = pools.filter((pool: any) => pool.stablecoin === true);
            }
            
            // Determine risk level and filter accordingly
            if (args.maxRisk !== 'any') {
                // Risk assessment based on ilRisk and exposure fields
                pools = pools.filter((pool: any) => {
                    let riskScore = 0;
                    
                    // Impermanent loss risk
                    if (pool.ilRisk === 'yes') riskScore += 2;
                    else if (pool.ilRisk === 'no') riskScore += 0;
                    else riskScore += 1; // 'moderate' or other values
                    
                    // Exposure risk
                    if (pool.exposure === 'single') riskScore += 0;
                    else if (pool.exposure === 'multi') riskScore += 1;
                    else riskScore += 2; // complex exposures
                    
                    // If stablecoin, reduce risk 
                    if (pool.stablecoin) riskScore -= 1;
                    
                    // Apply risk filter
                    if (args.maxRisk === 'low' && riskScore <= 1) return true;
                    if (args.maxRisk === 'medium' && riskScore <= 3) return true;
                    if (args.maxRisk === 'high') return true;
                    
                    return false;
                });
            }
            
            // Sort by APY, highest first
            pools = pools.sort((a: any, b: any) => b.apy - a.apy);
            
            // Limit number of results
            pools = pools.slice(0, args.limit);
            
            // Format each opportunity with helpful details
            const formattedOpportunities = pools.map((pool: any) => {
                // Calculate a simplified risk score from 1-10
                let riskScore = 5; // Default medium risk
                
                // Lower risk for stablecoins and single asset exposures
                if (pool.stablecoin) riskScore -= 2;
                if (pool.exposure === 'single') riskScore -= 1;
                
                // Increase risk for IL risk
                if (pool.ilRisk === 'yes') riskScore += 2;
                
                // Cap the range
                riskScore = Math.min(10, Math.max(1, riskScore));
                
                // Get a risk assessment recommendation
                const recommendation = getYieldRecommendation(riskScore, pool.apy);
                
                return {
                    project: pool.project,
                    chain: pool.chain,
                    pool: pool.symbol,
                    poolMeta: pool.poolMeta || '',
                    tvl: `$${Number(pool.tvlUsd).toLocaleString()}`,
                    apy: {
                        total: `${pool.apy.toFixed(2)}%`,
                        base: pool.apyBase ? `${pool.apyBase.toFixed(2)}%` : 'N/A',
                        reward: pool.apyReward ? `${pool.apyReward.toFixed(2)}%` : 'N/A',
                    },
                    rewardTokens: pool.rewardTokens || [],
                    risk: {
                        score: riskScore,
                        level: riskScore <= 3 ? 'Low' : riskScore <= 7 ? 'Medium' : 'High',
                        ilRisk: pool.ilRisk || 'Unknown',
                        exposure: pool.exposure || 'Unknown',
                        stablecoin: pool.stablecoin ? 'Yes' : 'No'
                    },
                    trends: {
                        '24h': pool.apyPct1D ? `${pool.apyPct1D.toFixed(2)}%` : 'N/A',
                        '7d': pool.apyPct7D ? `${pool.apyPct7D.toFixed(2)}%` : 'N/A',
                        '30d': pool.apyPct30D ? `${pool.apyPct30D.toFixed(2)}%` : 'N/A'
                    },
                    recommendation
                };
            });

            return JSON.stringify({
                status: 'success',
                timestamp: new Date().toISOString(),
                query: {
                chain: args.chain,
                    minApy: args.minApy,
                    stablecoin: args.stablecoin,
                    maxRisk: args.maxRisk
                },
                opportunities: formattedOpportunities,
                count: formattedOpportunities.length,
                note: "APY rates are subject to change and historical performance is not indicative of future results."
            }, null, 2);
        }
        catch (error) {
            console.error('Yield opportunity search error:', error);
            return JSON.stringify({
                status: 'error',
                message: `Error finding yield opportunities: ${error instanceof Error ? error.message : 'Unknown error'}`,
                timestamp: new Date().toISOString()
            }, null, 2);
        }
    }
});

// Helper function for yield opportunity recommendations
function getYieldRecommendation(riskScore: number, apy: number): string {
    if (riskScore <= 3) {
        return "Low risk opportunity suitable for conservative DeFi strategies";
    } else if (riskScore <= 6) {
        return apy > 20 
            ? "Moderate risk with attractive returns, consider partial allocation" 
            : "Balanced opportunity with reasonable risk-reward profile";
    } else {
        return apy > 100
            ? "High risk opportunity - suitable for experienced users with small allocation" 
            : "Higher risk profile - consider limiting exposure and monitoring closely";
    }
}

// Capability 6: Optimized Smart Money Tracker2
blockchainAgent.addCapability({
    name: 'trackSmartMoney',
    description: 'Track recent significant transactions for a whale wallet address',
    schema: z.object({
        walletAddress: z.string()
            .regex(/^0x[a-fA-F0-9]{40}$/, {
                message: "Address must be a valid Ethereum address starting with 0x followed by 40 hexadecimal characters"
            })
            .describe('Wallet address to track'),
        chain: z.enum(['ethereum', 'polygon', 'bsc', 'optimism', 'arbitrum', 'avalanche', 'fantom'])
            .default('ethereum')
            .describe('The blockchain to query'),
        threshold: z.number().default(100000).describe('USD value threshold for significant transactions (min 10000)'),
        maxResults: z.number().default(5).describe('Maximum number of significant transactions to return')
    }),
    async run({ args }) {
        try {
            const apiUrl = API_ENDPOINTS.etherscan[args.chain];
            let apiKey: string | undefined;
            
            switch (args.chain) {
                case 'ethereum':
                    apiKey = process.env.ETHEREUM_SCAN_API_KEY;
                    break;
                case 'polygon':
                    apiKey = process.env.POLYGON_SCAN_API_KEY || process.env.ETHEREUM_SCAN_API_KEY;
                    break;
                case 'bsc':
                    apiKey = process.env.BSC_SCAN_API_KEY || process.env.ETHEREUM_SCAN_API_KEY;
                    break;
                case 'optimism':
                    apiKey = process.env.OPTIMISM_SCAN_API_KEY || process.env.ETHEREUM_SCAN_API_KEY;
                    break;
                case 'arbitrum':
                    apiKey = process.env.ARBITRUM_SCAN_API_KEY || process.env.ETHEREUM_SCAN_API_KEY;
                    break;
                case 'avalanche':
                    apiKey = process.env.AVALANCHE_SCAN_API_KEY || process.env.ETHEREUM_SCAN_API_KEY;
                    break;
                case 'fantom':
                    apiKey = process.env.FANTOM_SCAN_API_KEY || process.env.ETHEREUM_SCAN_API_KEY;
                    break;
            }

            if (!apiKey) {
                return JSON.stringify({
                    status: 'error',
                    message: `API key for ${args.chain} is not available. Please set the appropriate environment variable.`,
                    suggestedAction: 'Obtain an API key from the relevant block explorer website and set the environment variable.',
                    supportedChains: Object.keys(API_ENDPOINTS.etherscan)
                }, null, 2);
            }

            // Make a single API call to get the most recent normal transactions
            // Limiting to 10 transactions to avoid rate limiting
            const response = await axiosWithRetry({
                method: 'get',
                url: apiUrl,
                params: {
                    module: 'account',
                    action: 'txlist',
                    address: args.walletAddress,
                    page: 1,
                    offset: 10, // Reduce the number to avoid rate limiting
                    sort: 'desc',
                    apikey: apiKey,
                },
            });

            // Get account balance for context
            const balanceResponse = await axiosWithRetry({
                method: 'get',
                url: apiUrl,
                params: {
                    module: 'account',
                    action: 'balance',
                    address: args.walletAddress,
                    tag: 'latest',
                    apikey: apiKey,
                },
            });

            if (response.data.status === '0' && response.data.message !== 'No transactions found') {
                return JSON.stringify({
                    status: 'error',
                    message: `API Error: ${response.data.message}`,
                    address: args.walletAddress,
                    chain: args.chain
                }, null, 2);
            }

            const transactions = response.data.status === '1' ? response.data.result : [];
            
            // Filter for significant transactions based on value threshold
            const minThreshold = Math.max(10000, args.threshold); // Minimum 10k USD
            const significantTxs = [];
            
            // Get real-time price for the native currency
            let nativePriceEstimate = 0;
            try {
                const coinIds = {
                    'ethereum': 'ethereum',
                    'bsc': 'binancecoin',
                    'polygon': 'matic-network',
                    'optimism': 'ethereum', // Uses ETH
                    'arbitrum': 'ethereum', // Uses ETH
                    'avalanche': 'avalanche-2',
                    'fantom': 'fantom'
                };
                
                const coinId = coinIds[args.chain] || 'ethereum';
                const priceResponse = await axiosWithRetry({
                    method: 'get',
                    url: `https://api.coingecko.com/api/v3/simple/price`,
                    params: {
                        ids: coinId,
                        vs_currencies: 'usd'
                    }
                });
                
                if (priceResponse.data && priceResponse.data[coinId]) {
                    nativePriceEstimate = priceResponse.data[coinId].usd;
                    console.log(`Got live price for ${args.chain}: $${nativePriceEstimate}`);
                } else {
                    // Fallback prices if API call fails
                    nativePriceEstimate = args.chain === 'ethereum' ? 2000 :
                                          args.chain === 'bsc' ? 300 :
                                          args.chain === 'polygon' ? 0.5 :
                                          args.chain === 'avalanche' ? 10 : 2000;
                    console.log(`Using fallback price for ${args.chain}: $${nativePriceEstimate}`);
                }
            } catch (error) {
                // Fallback prices if API call fails
                nativePriceEstimate = args.chain === 'ethereum' ? 2000 :
                                      args.chain === 'bsc' ? 300 :
                                      args.chain === 'polygon' ? 0.5 :
                                      args.chain === 'avalanche' ? 10 : 2000;
                console.log(`Error getting price, using fallback for ${args.chain}: $${nativePriceEstimate}`);
            }
            
            for (const tx of transactions) {
                // Convert native currency value to USD for comparison
                const nativeValue = parseFloat(tx.value) / 1e18;
                const valueUsd = nativeValue * nativePriceEstimate;
                
                if (valueUsd >= minThreshold) {
                    significantTxs.push({
                        type: 'Native Transfer',
                        hash: tx.hash,
                        timestamp: new Date(parseInt(tx.timeStamp) * 1000).toISOString(),
                        from: tx.from,
                        to: tx.to || 'Contract Creation',
                        token: getCurrencySymbol(args.chain),
                        amount: nativeValue.toFixed(4),
                        valueUsd: `$${valueUsd.toLocaleString()}`,
                        isOutgoing: tx.from.toLowerCase() === args.walletAddress.toLowerCase(),
                        methodId: tx.methodId || 'N/A',
                        functionName: tx.functionName || (tx.input === '0x' ? 'Simple Transfer' : 'Contract Interaction')
                    });
                    
                    // Limit to maxResults
                    if (significantTxs.length >= args.maxResults) break;
                }
            }

            // Get basic account data
            const balance = balanceResponse.data.status === '1' ? 
                parseFloat(balanceResponse.data.result) / 1e18 : 0;
            
            // Calculate metrics
            const whaleScore = balance > 100 ? 3 : balance > 10 ? 1 : 0;
            const isWhale = whaleScore >= 2;

            const result = {
                status: 'success',
                walletInfo: {
                    address: args.walletAddress,
                    chain: args.chain,
                    balance: `${balance.toFixed(4)} ${getCurrencySymbol(args.chain)}`,
                    isWhale,
                    whaleScore,
                },
                transactionSummary: {
                    significant: significantTxs.length,
                    threshold: `$${minThreshold.toLocaleString()}`,
                    outgoing: significantTxs.filter(tx => tx.isOutgoing).length,
                    incoming: significantTxs.filter(tx => !tx.isOutgoing).length
                },
                significantTransactions: significantTxs,
                metaData: {
                    timestamp: new Date().toISOString(),
                    note: "Limited data due to API constraints. This is a snapshot of recent significant transactions.",
                    apiProvider: `${args.chain}scan.io`
                }
            };

            return JSON.stringify(result, null, 2);
        }
        catch (error: any) {
            console.error('Smart money tracking error:', error);
            return JSON.stringify({
                status: 'error',
                message: 'Error tracking wallet activity',
                details: error.message,
                walletAddress: args.walletAddress,
                chain: args.chain,
                timestamp: new Date().toISOString()
            }, null, 2);
        }
    }
});

// Capability 7: DeFi Trend Analysis
blockchainAgent.addCapability({
    name: 'analyzeDeFiTrends',
    description: 'Track protocol TVL, volume, and growth metrics across the DeFi ecosystem',
    schema: z.object({
        timeframe: z.enum(['24h', '7d', '30d']).default('7d').describe('Timeframe for trend analysis'),
        categories: z.array(z.enum(['lending', 'dex', 'yield', 'derivatives', 'all'])).default(['all']).describe('DeFi categories to analyze'),
        chain: z.enum(['ethereum', 'polygon', 'bsc', 'optimism', 'arbitrum', 'all']).default('all').describe('Chain to analyze')
    }),
    async run({ args }) {
        try {
            console.log(`Analyzing DeFi trends for ${args.chain === 'all' ? 'all chains' : args.chain} focusing on ${args.categories.includes('all') ? 'all categories' : args.categories.join(', ')} over the last ${args.timeframe}`);
            
            // Get protocol data from DeFiLlama API - using the updated v2 API
            const protocolsResponse = await axios.get(`${API_ENDPOINTS.defillama.base}/protocols`);
            
            if (!protocolsResponse.data || !Array.isArray(protocolsResponse.data)) {
                return JSON.stringify({
                    status: 'error',
                    message: 'Failed to fetch protocol data from DeFiLlama API',
                    timestamp: new Date().toISOString()
                }, null, 2);
            }

            // Filter protocols based on selected categories and chain
            let protocols = protocolsResponse.data;
            console.log(`Total protocols found: ${protocols.length}`);
            
            // Filter by chain if a specific chain was selected
            if (args.chain !== 'all') {
                protocols = protocols.filter((protocol: any) => 
                    protocol.chains && protocol.chains.some((chain: string) => 
                        chain.toLowerCase() === args.chain.toLowerCase()
                    )
                );
                console.log(`After chain filter (${args.chain}): ${protocols.length} protocols`);
            }
            
            // Filter by category if specific categories were selected
            if (!args.categories.includes('all')) {
                protocols = protocols.filter((protocol: any) => {
                    if (!protocol.category) return false;
                    const category = protocol.category.toLowerCase();
                    return args.categories.some((cat: string) => category.includes(cat));
                });
                console.log(`After category filter: ${protocols.length} protocols`);
            }
            
            if (protocols.length === 0) {
                return JSON.stringify({
                    status: 'warning',
                    message: 'No protocols found matching the selected criteria',
                    timestamp: new Date().toISOString(),
                    chain: args.chain,
                    categories: args.categories
                }, null, 2);
            }
            
            // Process only the top 5 protocols to avoid too many API calls
            const topProtocols = protocols
                .filter((p: any) => p.tvl && p.tvl > 0)
                .sort((a: any, b: any) => (b.tvl || 0) - (a.tvl || 0))
                .slice(0, 5);
            
            // Get TVL changes for each protocol
            const tvlChanges: Record<string, any> = {};
            for (const protocol of topProtocols) {
                try {
                    // Use the protocol endpoint which includes TVL history
                    const response = await axios.get(`${API_ENDPOINTS.defillama.base}/protocol/${protocol.slug}`);
                    if (response.data && response.data.tvl) {
                        // Calculate change based on timeframe
                        const tvlData = response.data.tvl;
                        if (tvlData.length < 2) continue;
                        
                        // Get current TVL
                        const currentTVL = tvlData[tvlData.length - 1].totalLiquidityUSD;
                        
                        // Calculate change for different timeframes
                        let change_1d = 0, change_7d = 0, change_1m = 0;
                        
                        // Find data points for different time periods
                        const now = Date.now() / 1000; // Current time in seconds
                        const oneDayAgo = now - (24 * 60 * 60);
                        const sevenDaysAgo = now - (7 * 24 * 60 * 60);
                        const thirtyDaysAgo = now - (30 * 24 * 60 * 60);
                        
                        // Find closest data points to each time period
                        const findClosestDataPoint = (targetTime: number) => {
                            let closest = tvlData[0];
                            let minDiff = Math.abs(closest.date - targetTime);
                            
                            for (let i = 1; i < tvlData.length; i++) {
                                const diff = Math.abs(tvlData[i].date - targetTime);
                                if (diff < minDiff) {
                                    minDiff = diff;
                                    closest = tvlData[i];
                                }
                            }
                            
                            return closest;
                        };
                        
                        const oneDayPoint = findClosestDataPoint(oneDayAgo);
                        const sevenDayPoint = findClosestDataPoint(sevenDaysAgo);
                        const thirtyDayPoint = findClosestDataPoint(thirtyDaysAgo);
                        
                        // Calculate percentage changes
                        if (oneDayPoint.totalLiquidityUSD > 0) {
                            change_1d = ((currentTVL - oneDayPoint.totalLiquidityUSD) / oneDayPoint.totalLiquidityUSD) * 100;
                        }
                        
                        if (sevenDayPoint.totalLiquidityUSD > 0) {
                            change_7d = ((currentTVL - sevenDayPoint.totalLiquidityUSD) / sevenDayPoint.totalLiquidityUSD) * 100;
                        }
                        
                        if (thirtyDayPoint.totalLiquidityUSD > 0) {
                            change_1m = ((currentTVL - thirtyDayPoint.totalLiquidityUSD) / thirtyDayPoint.totalLiquidityUSD) * 100;
                        }
                        
                        tvlChanges[protocol.slug] = {
                            change_1d,
                            change_7d,
                            change_1m,
                            currentTVL
                        };
                    }
                } catch (error) {
                    console.warn(`Failed to get TVL changes for ${protocol.name}:`, error);
                    // Continue with next protocol
                }
            }

            // Process protocol data to extract key metrics
            const processedData = topProtocols.map((protocol: any) => {
                let changeKey = '';
                let changeValue = 0;
                
                switch (args.timeframe) {
                    case '24h': 
                        changeKey = 'change_1d'; 
                        changeValue = tvlChanges[protocol.slug]?.change_1d || 0;
                        break;
                    case '7d': 
                        changeKey = 'change_7d'; 
                        changeValue = tvlChanges[protocol.slug]?.change_7d || 0;
                        break;
                    case '30d': 
                        changeKey = 'change_1m'; 
                        changeValue = tvlChanges[protocol.slug]?.change_1m || 0;
                        break;
                }

                return {
                    name: protocol.name,
                    category: protocol.category || 'Unknown',
                    chains: protocol.chains || ['Unknown'],
                    tvl: protocol.tvl ? `$${Number(protocol.tvl).toLocaleString()}` : 'N/A',
                    tvlChange: `${changeValue.toFixed(2)}%`,
                    volume24h: protocol.volume24h ? `$${Number(protocol.volume24h).toLocaleString()}` : 'N/A',
                    fees24h: protocol.fees24h ? `$${Number(protocol.fees24h).toLocaleString()}` : 'N/A',
                    url: `https://defillama.com/protocol/${protocol.slug}`
                };
            });

            // Calculate overall DeFi metrics
            let totalTVL = 0;
            let tvlChange = 0;
            
            try {
                // For chain-specific TVL
                if (args.chain !== 'all') {
                    const chainTvlResponse = await axios.get(`${API_ENDPOINTS.defillama.base}/v2/historicalChainTvl/${args.chain}`);
                    if (chainTvlResponse.data && Array.isArray(chainTvlResponse.data.tvl)) {
                        const tvlData = chainTvlResponse.data.tvl;
                        if (tvlData.length > 0) {
                            // Get the most recent TVL
                            totalTVL = tvlData[tvlData.length - 1].totalLiquidityUSD;
                            
                            // Calculate TVL change based on timeframe
                            let referenceIndex = tvlData.length - 1;
                            switch (args.timeframe) {
                                case '24h': referenceIndex = Math.max(0, tvlData.length - 2); break;
                                case '7d': referenceIndex = Math.max(0, tvlData.length - 8); break;
                                case '30d': referenceIndex = Math.max(0, tvlData.length - 31); break;
                            }
                            
                            const referenceTVL = tvlData[referenceIndex].totalLiquidityUSD;
                            if (referenceTVL > 0) {
                                tvlChange = ((totalTVL - referenceTVL) / referenceTVL) * 100;
                            }
                        }
                    }
                }
                // For all chains combined
                else {
                    const globalTvlResponse = await axios.get(`${API_ENDPOINTS.defillama.base}/charts`);
                    if (globalTvlResponse.data && Array.isArray(globalTvlResponse.data)) {
                        const tvlData = globalTvlResponse.data;
                        if (tvlData.length > 0) {
                            // Get the most recent TVL
                            totalTVL = tvlData[tvlData.length - 1].totalLiquidityUSD;
                            
                            // Calculate TVL change based on timeframe
                            let referenceIndex = tvlData.length - 1;
                            switch (args.timeframe) {
                                case '24h': referenceIndex = Math.max(0, tvlData.length - 2); break;
                                case '7d': referenceIndex = Math.max(0, tvlData.length - 8); break;
                                case '30d': referenceIndex = Math.max(0, tvlData.length - 31); break;
                            }
                            
                            const referenceTVL = tvlData[referenceIndex].totalLiquidityUSD;
                            if (referenceTVL > 0) {
                                tvlChange = ((totalTVL - referenceTVL) / referenceTVL) * 100;
                            }
                        }
                    }
                }
            } catch (error) {
                console.warn('Error fetching TVL history:', error);
                // Continue with zeros as fallback
            }
            
            // Format the final response
            const result = {
                status: 'success',
                timestamp: new Date().toISOString(),
                timeframe: args.timeframe,
                overallMetrics: {
                    totalTVL: `$${Number(totalTVL).toLocaleString()}`,
                    tvlChange: `${tvlChange.toFixed(2)}%`,
                    chain: args.chain,
                    categories: args.categories
                },
                topProtocols: processedData,
                trendingProtocols: processedData
                    .sort((a: any, b: any) => {
                        const aChange = parseFloat(a.tvlChange.replace('%', '')) || 0;
                        const bChange = parseFloat(b.tvlChange.replace('%', '')) || 0;
                        return bChange - aChange;
                    })
                    .slice(0, 5)
            };
            
            return JSON.stringify(result, null, 2);
        }
        catch (error) {
            console.error('DeFi trend analysis error:', error);
            return JSON.stringify({
                status: 'error',
                message: `Error analyzing DeFi trends: ${error instanceof Error ? error.message : 'Unknown error'}`,
                timestamp: new Date().toISOString()
            }, null, 2);
        }
    }
});

// Capability 8: Token Information Finder
blockchainAgent.addCapability({
    name: 'getTokenInformation',
    description: 'Find comprehensive token information by ticker or name, including prices, liquidity, volume, social media, website, and trading pairs',
    schema: z.object({
        query: z.string()
            .describe('Token ticker (e.g., "ETH") or name (e.g., "Ethereum") to search for'),
        includeCharts: z.boolean().default(false)
            .describe('Include price chart data if available'),
        includeSocial: z.boolean().default(true)
            .describe('Include social media information if available'),
        includePairs: z.boolean().default(true)
            .describe('Include trading pairs and DEX information')
    }),
    async run({ args }) {
        try {
            const query = args.query.trim();
            console.log(`Searching for token information with query: ${query}`);

            // Step 1: Search for token using CoinGecko free API
            let tokenData = null;
            let coinId = '';
            
            // First search for the token
            try {
                const searchResponse = await axiosWithRetry({
                    method: 'get',
                    url: 'https://api.coingecko.com/api/v3/search',
                    params: { query: query }
                });

                if (searchResponse.data && searchResponse.data.coins && searchResponse.data.coins.length > 0) {
                    // Find the best match
                    const exactMatchBySymbol = searchResponse.data.coins.find(
                        (coin: any) => coin.symbol.toLowerCase() === query.toLowerCase()
                    );
                    
                    const exactMatchByName = searchResponse.data.coins.find(
                        (coin: any) => coin.name.toLowerCase() === query.toLowerCase()
                    );
                    
                    // Prefer exact matches first
                    const bestMatch = exactMatchBySymbol || exactMatchByName || searchResponse.data.coins[0];
                    coinId = bestMatch.id;
                    
                    console.log(`Found token: ${bestMatch.name} (${bestMatch.symbol}) with ID: ${coinId}`);
                } else {
                    return JSON.stringify({
                        status: 'error',
                        message: `No token found matching '${query}'. Try a different search term.`,
                        timestamp: new Date().toISOString()
                    }, null, 2);
                }
                
                // Get detailed token data
                const tokenResponse = await axiosWithRetry({
                    method: 'get',
                    url: `https://api.coingecko.com/api/v3/coins/${coinId}`,
                    params: {
                        localization: false,
                        tickers: true,
                        market_data: true,
                        community_data: args.includeSocial,
                        developer_data: false,
                        sparkline: args.includeCharts
                    }
                });
                
                tokenData = tokenResponse.data;
            } catch (error: any) {
                console.warn("Error fetching from CoinGecko:", error.message);
                // Continue with other APIs even if CoinGecko fails
            }
            
            // Step 2: Get DEX pairs data from DexScreener (free API)
            let pairsData = [];
            if (args.includePairs) {
                try {
                    // Try searching token by symbol first
                    let dexResponse = await axiosWithRetry({
                        method: 'get',
                        url: `https://api.dexscreener.com/latest/dex/search`,
                        params: { q: query }
                    });
                    
                    if (dexResponse.data && dexResponse.data.pairs && dexResponse.data.pairs.length > 0) {
                        // Filter out low liquidity pairs
                        pairsData = dexResponse.data.pairs
                            .filter((pair: any) => parseFloat(pair.liquidity?.usd || '0') > 10000)
                            .slice(0, 10) // Limit to top 10 pairs
                            .map((pair: any) => ({
                                dex: pair.dexId,
                                chain: pair.chainId,
                                pairAddress: pair.pairAddress,
                                baseToken: {
                                    symbol: pair.baseToken.symbol,
                                    name: pair.baseToken.name,
                                    address: pair.baseToken.address
                                },
                                quoteToken: {
                                    symbol: pair.quoteToken.symbol,
                                    name: pair.quoteToken.name,
                                    address: pair.quoteToken.address
                                },
                                priceUsd: pair.priceUsd,
                                priceChange: {
                                    h1: pair.priceChange.h1,
                                    h24: pair.priceChange.h24,
                                    h6: pair.priceChange.h6,
                                    h7d: pair.priceChange.h7d
                                },
                                liquidity: pair.liquidity?.usd || null,
                                volume: {
                                    h24: pair.volume?.h24 || null,
                                    h6: pair.volume?.h6 || null
                                },
                                url: `https://dexscreener.com/${pair.chainId}/${pair.pairAddress}`
                            }));
                    }
                } catch (error: any) {
                    console.warn("Error fetching DEX pairs data:", error.message);
                }
            }
            
            // Format the results with all the gathered data
            const result: any = {
                status: 'success',
                query: args.query
            };
            
            // Standardize basic token information
            if (tokenData) {
                result.token = {
                    name: tokenData.name,
                    symbol: tokenData.symbol.toUpperCase(),
                    logo: tokenData.image?.large || tokenData.image?.small,
                    description: tokenData.description?.en?.slice(0, 300) + (tokenData.description?.en?.length > 300 ? '...' : ''),
                    marketCap: tokenData.market_data?.market_cap?.usd ? formatCurrency(tokenData.market_data.market_cap.usd) : 'Unknown',
                    totalSupply: tokenData.market_data?.total_supply ? 
                        `${parseInt(tokenData.market_data.total_supply).toLocaleString()} ${tokenData.symbol.toUpperCase()}` : 'Unknown',
                    circulatingSupply: tokenData.market_data?.circulating_supply ? 
                        `${parseInt(tokenData.market_data.circulating_supply).toLocaleString()} ${tokenData.symbol.toUpperCase()}` : 'Unknown',
                };
                
                // Add price information
                result.priceData = {
                    currentPrice: tokenData.market_data?.current_price?.usd ? formatCurrency(tokenData.market_data.current_price.usd) : 'Unknown',
                    priceChange: {
                        "24h": tokenData.market_data?.price_change_percentage_24h != null ? 
                            `${tokenData.market_data.price_change_percentage_24h.toFixed(2)}%` : 'Unknown',
                        "7d": tokenData.market_data?.price_change_percentage_7d != null ? 
                            `${tokenData.market_data.price_change_percentage_7d.toFixed(2)}%` : 'Unknown',
                        "30d": tokenData.market_data?.price_change_percentage_30d != null ? 
                            `${tokenData.market_data.price_change_percentage_30d.toFixed(2)}%` : 'Unknown'
                    },
                    athPrice: tokenData.market_data?.ath?.usd ? formatCurrency(tokenData.market_data.ath.usd) : 'Unknown',
                    atlPrice: tokenData.market_data?.atl?.usd ? formatCurrency(tokenData.market_data.atl.usd) : 'Unknown'
                };
                
                // Add volume and liquidity data
                result.volumeData = {
                    volume24h: tokenData.market_data?.total_volume?.usd ? formatCurrency(tokenData.market_data.total_volume.usd) : 'Unknown',
                    // Liquidity is often not available directly, can be estimated from DEX data
                    liquidityEstimate: pairsData.length > 0 ? 
                        formatCurrency(pairsData.reduce((sum: number, pair: any) => sum + parseFloat(pair.liquidity || '0'), 0)) : 'Unknown'
                };
                
                // Add links and social media if requested
                if (args.includeSocial) {
                    result.links = {
                        website: tokenData.links?.homepage?.filter(Boolean)[0] || null,
                        explorer: tokenData.links?.blockchain_site?.filter(Boolean)[0] || null,
                        forum: tokenData.links?.official_forum_url?.filter(Boolean)[0] || null,
                        chat: tokenData.links?.chat_url?.filter(Boolean)[0] || null,
                        announcement: tokenData.links?.announcement_url?.filter(Boolean)[0] || null
                    };
                    
                    result.social = {
                        twitter: tokenData.links?.twitter_screen_name ? `https://twitter.com/${tokenData.links.twitter_screen_name}` : null,
                        telegram: tokenData.links?.telegram_channel_identifier ? `https://t.me/${tokenData.links.telegram_channel_identifier}` : null,
                        reddit: tokenData.links?.subreddit_url || null,
                        github: tokenData.links?.repos_url?.github?.length > 0 ? tokenData.links.repos_url.github[0] : null,
                        discord: tokenData.links?.chat_url?.find((url: string) => url.includes('discord')) || null
                    };
                    
                    // Clean up null values in links and social
                    Object.keys(result.links).forEach(key => {
                        if (!result.links[key]) delete result.links[key];
                    });
                    
                    Object.keys(result.social).forEach(key => {
                        if (!result.social[key]) delete result.social[key];
                    });
                }
            }
            
            // Add trading pairs if requested
            if (args.includePairs && pairsData.length > 0) {
                result.tradingPairs = {
                    count: pairsData.length,
                    topPairs: pairsData
                };
                
                // Generate trading insights
                const insights = [];
                
                // Check liquidity concentration
                const topPairLiquidity = pairsData[0]?.liquidity || 0;
                const totalLiquidity = pairsData.reduce((sum: number, pair: any) => sum + parseFloat(pair.liquidity || '0'), 0);
                
                if (topPairLiquidity / totalLiquidity > 0.7) {
                    insights.push("Liquidity is highly concentrated in the top trading pair");
                }
                
                // Check price divergence
                let priceValues = pairsData
                    .filter((pair: any) => pair.priceUsd)
                    .map((pair: any) => parseFloat(pair.priceUsd));
                
                if (priceValues.length > 1) {
                    const avgPrice = priceValues.reduce((sum: number, price: number) => sum + price, 0) / priceValues.length;
                    const maxDeviation = Math.max(...priceValues.map((price: number) => Math.abs(price - avgPrice) / avgPrice));
                    
                    if (maxDeviation > 0.05) {
                        insights.push(`Price varies by ${(maxDeviation * 100).toFixed(1)}% across exchanges - potential arbitrage opportunity`);
                    }
                }
                
                // Add other insights about volume, etc.
                if (insights.length > 0) {
                    result.tradingInsights = insights;
                }
            }
            
            // Add timestamp and data sources
            result.metaData = {
                timestamp: new Date().toISOString(),
                dataSources: []
            };
            
            if (tokenData) result.metaData.dataSources.push("CoinGecko");
            if (pairsData.length > 0) result.metaData.dataSources.push("DexScreener");
            
            return JSON.stringify(result, null, 2);
        }
        catch (error: any) {
            console.error('Token information search error:', error);
            return JSON.stringify({
                status: 'error',
                message: 'Error fetching token information',
                details: error.message,
                query: args.query,
                timestamp: new Date().toISOString()
            }, null, 2);
        }
    }
});

// Capability 1: Token Information by Address
blockchainAgent.addCapability({
    name: 'getTokenDetailsByAddress',
    description: 'Get detailed information about a token including price, market cap, and volume using its contract address',
    schema: z.object({
        tokenAddress: z.string().describe('The token contract address'),
        chain: z.enum(['ethereum', 'polygon', 'bsc', 'optimism', 'arbitrum']).default('ethereum').describe('Blockchain network where the token exists')
    }),
    async run({ args }) {
        try {
            // Part 1: Fetch token basic data from Chainbase
            const chainbaseResponse = await axios.get(
                `${API_ENDPOINTS.chainbase.base}/token/metadata`, {
                    params: {
                        chain_id: CHAIN_IDS.chainbase[args.chain],
                        contract_address: args.tokenAddress
                    },
                    headers: { 'x-api-key': process.env.CHAINBASE_API_KEY || '' }
                }
            );

            if (!chainbaseResponse.data || !chainbaseResponse.data.data) {
                return JSON.stringify({
                    status: 'error',
                    message: 'No token information found on Chainbase',
                    timestamp: new Date().toISOString()
                }, null, 2);
            }

            const tokenData = chainbaseResponse.data.data;
            let priceData = {};
            
            // Part 2: Fetch price data from DeFiLlama
            try {
                // Update endpoint to the correct DeFiLlama API for token prices
                const defillama_response = await axios.get(
                    `${API_ENDPOINTS.defillama.base}/v2/address/${args.tokenAddress}?chain=${args.chain}`
                );
                
                if (defillama_response.data && !defillama_response.data.error) {
                    if (defillama_response.data.coins && defillama_response.data.coins.length > 0) {
                        // Extract price information
                        const coin = defillama_response.data.coins[0];
                        priceData = {
                            price: coin.price ? `$${coin.price.toFixed(6)}` : 'Unknown',
                            price_24h_change: coin.price_24h_change ? `${coin.price_24h_change.toFixed(2)}%` : 'Unknown',
                            market_cap: coin.mcap ? `$${Number(coin.mcap).toLocaleString()}` : 'Unknown',
                            volume_24h: coin.volume_24h ? `$${Number(coin.volume_24h).toLocaleString()}` : 'Unknown'
                        };
                    }
                }
            } catch (error) {
                console.warn('Failed to fetch price data from DeFiLlama:', error);
                // Continue execution even if price data fetch fails
            }

            // Part 3: Fetch additional token data from DexScreener
            let dexData: {
                liquidity: string;
                pairs: Array<{
                    dex: string;
                    pair: string;
                    pairAddress: string;
                    priceUsd: string;
                    liquidity: string;
                    volume24h: string;
                    priceChange24h: string;
                }>;
                socialLinks: Array<{
                    type: string;
                    url?: string;
                    handle?: string;
                }>;
            } = {
                liquidity: 'Unknown',
                pairs: [],
                socialLinks: []
            };
            
            try {
                // Map chain name to DexScreener chain ID format
                const dexScreenerChainId = args.chain === 'ethereum' ? 'ethereum' : 
                                          args.chain === 'bsc' ? 'bsc' :
                                          args.chain === 'polygon' ? 'polygon' :
                                          args.chain === 'arbitrum' ? 'arbitrum' :
                                          args.chain === 'optimism' ? 'optimism' : 'ethereum';
                
                // Get token pairs data
                const dexScreenerResponse = await axios.get(
                    `${API_ENDPOINTS.dexscreener.base}${API_ENDPOINTS.dexscreener.tokenPairs}/${dexScreenerChainId}/${args.tokenAddress}`
                );

                if (dexScreenerResponse.data && Array.isArray(dexScreenerResponse.data) && dexScreenerResponse.data.length > 0) {
                    // Get total liquidity across all pairs
                    let totalLiquidity = 0;
                    const pairsData: Array<{
                        dex: string;
                        pair: string;
                        pairAddress: string;
                        priceUsd: string;
                        liquidity: string;
                        volume24h: string;
                        priceChange24h: string;
                    }> = [];
                    
                    // Extract relevant data from each pair
                    dexScreenerResponse.data.slice(0, 5).forEach((pair: any) => {
                        if (pair.liquidity && pair.liquidity.usd) {
                            totalLiquidity += parseFloat(pair.liquidity.usd);
                        }
                        
                        // Get data for top 5 trading pairs
                        pairsData.push({
                            dex: pair.dexId || 'Unknown',
                            pair: `${pair.baseToken.symbol}/${pair.quoteToken.symbol}`,
                            pairAddress: pair.pairAddress,
                            priceUsd: pair.priceUsd ? `$${parseFloat(pair.priceUsd).toFixed(6)}` : 'Unknown',
                            liquidity: pair.liquidity && pair.liquidity.usd ? `$${Number(pair.liquidity.usd).toLocaleString()}` : 'Unknown',
                            volume24h: pair.volume && pair.volume['24h'] ? `$${Number(pair.volume['24h']).toLocaleString()}` : 'Unknown',
                            priceChange24h: pair.priceChange && pair.priceChange['24h'] ? `${pair.priceChange['24h'].toFixed(2)}%` : 'Unknown'
                        });
                    });
                    
                    // Extract social links if available
                    const socialLinks: Array<{
                        type: string;
                        url?: string;
                        handle?: string;
                    }> = [];
                    const firstPair = dexScreenerResponse.data[0];
                    
                    if (firstPair.info) {
                        // Website
                        if (firstPair.info.websites && firstPair.info.websites.length > 0) {
                            socialLinks.push({
                                type: 'website',
                                url: firstPair.info.websites[0].url
                            });
                        }
                        
                        // Social media
                        if (firstPair.info.socials && firstPair.info.socials.length > 0) {
                            firstPair.info.socials.forEach((social: any) => {
                                socialLinks.push({
                                    type: social.platform,
                                    handle: social.handle
                                });
                            });
                        }
                    }
                    
                    dexData = {
                        liquidity: `$${Number(totalLiquidity).toLocaleString()}`,
                        pairs: pairsData,
                        socialLinks: socialLinks
                    };
                }
            } catch (error) {
                console.warn('Failed to fetch data from DexScreener:', error);
                // Continue execution even if DexScreener fails
            }

            // Block explorer URLs for different chains
            const explorerUrls = {
                ethereum: 'https://etherscan.io',
                polygon: 'https://polygonscan.com',
                bsc: 'https://bscscan.com',
                optimism: 'https://optimistic.etherscan.io',
                arbitrum: 'https://arbiscan.io'
            };

            // Construct the response
            const response = {
                status: 'success',
                timestamp: new Date().toISOString(),
                data: {
                    tokenAddress: args.tokenAddress,
                    chain: args.chain,
                    name: tokenData.name || 'Unknown',
                    symbol: tokenData.symbol || 'Unknown',
                    decimals: tokenData.decimals || 0,
                    totalSupply: tokenData.total_supply ? 
                        `${Number(tokenData.total_supply / Math.pow(10, tokenData.decimals || 18)).toLocaleString()} ${tokenData.symbol}` : 
                        'Unknown',
                    ...priceData,
                    dexData: {
                        liquidity: dexData.liquidity,
                        topPairs: dexData.pairs.length > 0 ? dexData.pairs : 'No trading pairs found'
                    },
                    links: {
                        explorer: `${explorerUrls[args.chain]}/token/${args.tokenAddress}`,
                        ...dexData.socialLinks.reduce((acc, link) => {
                            if (link.type === 'website' && link.url) {
                                acc.website = link.url;
                            } else if (link.type === 'twitter' && link.handle) {
                                acc.twitter = `https://twitter.com/${link.handle}`;
                            } else if (link.type === 'telegram' && link.handle) {
                                acc.telegram = `https://t.me/${link.handle}`;
                            } else if (link.type === 'discord' && link.url) {
                                acc.discord = link.url;
                            }
                            return acc;
                        }, {} as Record<string, string>)
                    }
                }
            };
            
            return JSON.stringify(response, null, 2);
        }
        catch (error) {
            console.error('Token information error:', error);
            return JSON.stringify({
                status: 'error',
                message: `Error fetching token information: ${error instanceof Error ? error.message : 'Unknown error'}`,
                timestamp: new Date().toISOString()
            }, null, 2);
        }
    }
});

// Capability: DEX Token Analytics
blockchainAgent.addCapability({
    name: 'getDexTokenAnalytics',
    description: 'Get comprehensive DEX trading data for a token including liquidity pools, trading volume, price charts, and social media information',
    schema: z.object({
        tokenAddress: z.string().describe('The token contract address'),
        chain: z.enum(['ethereum', 'polygon', 'bsc', 'optimism', 'arbitrum', 'solana', 'arbitrum_nova', 'avalanche', 'base', 'celo', 'cronos', 'fantom', 'gnosis', 'harmony', 'linea', 'moonbeam', 'moonriver', 'zksync']).default('ethereum').describe('Blockchain network where the token exists'),
        includeMarketMetrics: z.boolean().default(true).describe('Include market cap, FDV, and other market metrics')
    }),
    async run({ args }) {
        try {
            // Map chain name to DexScreener chain ID format
            // DexScreener uses different chain IDs than our internal mapping
            const dexScreenerChainMapping: Record<string, string> = {
                ethereum: 'ethereum',
                polygon: 'polygon',
                bsc: 'bsc',
                arbitrum: 'arbitrum',
                optimism: 'optimism',
                solana: 'solana',
                arbitrum_nova: 'arbitrumnova',
                avalanche: 'avalanche',
                base: 'base',
                celo: 'celo',
                cronos: 'cronos',
                fantom: 'fantom',
                gnosis: 'gnosis',
                harmony: 'harmony',
                linea: 'linea',
                moonbeam: 'moonbeam',
                moonriver: 'moonriver',
                zksync: 'zksync'
            };
            
            const chainId = dexScreenerChainMapping[args.chain] || args.chain;
            
            // Get token pairs data
            const pairsResponse = await axios.get(
                `${API_ENDPOINTS.dexscreener.base}${API_ENDPOINTS.dexscreener.tokenPairs}/${chainId}/${args.tokenAddress}`
            );
            
            if (!pairsResponse.data || !Array.isArray(pairsResponse.data) || pairsResponse.data.length === 0) {
                return JSON.stringify({
                    status: 'error',
                    message: 'No DEX trading data found for this token',
                    timestamp: new Date().toISOString()
                }, null, 2);
            }
            
            // Process the pairs data
            const pairs = pairsResponse.data;
            const tokenInfo = {
                name: '',
                symbol: '',
                logoUrl: ''
            };
            
            // Extract token info from the first pair
            if (pairs.length > 0) {
                const firstPair = pairs[0];
                // Check whether our token is the base or quote token
                if (firstPair.baseToken && firstPair.baseToken.address.toLowerCase() === args.tokenAddress.toLowerCase()) {
                    tokenInfo.name = firstPair.baseToken.name;
                    tokenInfo.symbol = firstPair.baseToken.symbol;
                } else if (firstPair.quoteToken && firstPair.quoteToken.address.toLowerCase() === args.tokenAddress.toLowerCase()) {
                    tokenInfo.name = firstPair.quoteToken.name;
                    tokenInfo.symbol = firstPair.quoteToken.symbol;
                }
                
                // Get logo if available
                if (firstPair.info && firstPair.info.imageUrl) {
                    tokenInfo.logoUrl = firstPair.info.imageUrl;
                }
            }
            
            // Calculate aggregated stats
            let totalLiquidity = 0;
            let totalVolume24h = 0;
            let totalVolume7d = 0;
            let weightedPriceUsd = 0;
            let weightedPriceChange24h = 0;
            let totalLiquidityWeight = 0;
            let fdv = 0;
            let marketCap = 0;
            
            // Process each pair for stats
            const pairsData = pairs.map((pair: any) => {
                // Calculate weighted price
                if (pair.liquidity && pair.liquidity.usd && pair.priceUsd) {
                    const liquidityUsd = parseFloat(pair.liquidity.usd);
                    totalLiquidity += liquidityUsd;
                    
                    if (liquidityUsd > 0 && pair.priceUsd) {
                        const priceUsd = parseFloat(pair.priceUsd);
                        weightedPriceUsd += priceUsd * liquidityUsd;
                        totalLiquidityWeight += liquidityUsd;
                        
                        if (pair.priceChange && pair.priceChange['24h']) {
                            weightedPriceChange24h += parseFloat(pair.priceChange['24h']) * liquidityUsd;
                        }
                    }
                }
                
                // Add up volumes
                if (pair.volume) {
                    if (pair.volume['24h']) {
                        totalVolume24h += parseFloat(pair.volume['24h']);
                    }
                    if (pair.volume['7d']) {
                        totalVolume7d += parseFloat(pair.volume['7d']);
                    }
                }
                
                // Set FDV and market cap from the highest liquidity pair
                if (args.includeMarketMetrics && pair.fdv && pair.fdv > fdv) {
                    fdv = pair.fdv;
                }
                if (args.includeMarketMetrics && pair.marketCap && pair.marketCap > marketCap) {
                    marketCap = pair.marketCap;
                }
                
                return {
                    dex: pair.dexId || 'Unknown',
                    pair: `${pair.baseToken.symbol}/${pair.quoteToken.symbol}`,
                    pairAddress: pair.pairAddress,
                    priceUsd: pair.priceUsd ? `$${parseFloat(pair.priceUsd).toFixed(6)}` : 'Unknown',
                    liquidity: pair.liquidity && pair.liquidity.usd ? `$${Number(pair.liquidity.usd).toLocaleString()}` : 'Unknown',
                    volume24h: pair.volume && pair.volume['24h'] ? `$${Number(pair.volume['24h']).toLocaleString()}` : 'Unknown',
                    priceChange24h: pair.priceChange && pair.priceChange['24h'] ? `${pair.priceChange['24h']}%` : 'Unknown'
                };
            });
            
            // Calculate final weighted price
            if (totalLiquidityWeight > 0) {
                weightedPriceUsd = weightedPriceUsd / totalLiquidityWeight;
                weightedPriceChange24h = weightedPriceChange24h / totalLiquidityWeight;
            }

            // Special handling for stablecoin prices
            // Check if token is a known stablecoin
            const isStablecoin = tokenInfo.symbol && [
                'USDT', 'USDC', 'DAI', 'BUSD', 'TUSD', 'USDP', 'GUSD', 'USDD', 'FRAX'
            ].includes(tokenInfo.symbol.toUpperCase());
            
            // If it's a stablecoin and the calculated price is between 0.5 and 1.5,
            // adjust it to be closer to 1.0 (but preserve small variations)
            if (isStablecoin && weightedPriceUsd > 0.5 && weightedPriceUsd < 1.5) {
                // Keep a small deviation but make it closer to 1.0
                weightedPriceUsd = 1.0 + (weightedPriceUsd - 1.0) * 0.05;
            }
            
            // Extract social and website links
            const links: Record<string, string> = {};
            const webLinks: Array<string> = [];
            const socialLinks: Array<{platform: string, handle: string}> = [];
            
            // Get links from the first pair with available info
            for (const pair of pairs) {
                if (pair.info) {
                    if (pair.info.websites && pair.info.websites.length > 0) {
                        pair.info.websites.forEach((website: any) => {
                            if (website.url) webLinks.push(website.url);
                        });
                        if (webLinks.length > 0) {
                            links.website = webLinks[0];
                        }
                    }
                    
                    if (pair.info.socials && pair.info.socials.length > 0) {
                        pair.info.socials.forEach((social: any) => {
                            if (social.platform && social.handle) {
                                socialLinks.push({
                                    platform: social.platform,
                                    handle: social.handle
                                });
                                
                                // Add formatted social links
                                if (social.platform === 'twitter') {
                                    links.twitter = `https://twitter.com/${social.handle}`;
                                } else if (social.platform === 'telegram') {
                                    links.telegram = `https://t.me/${social.handle}`;
                                } else if (social.platform === 'discord') {
                                    links.discord = social.handle;
                                }
                            }
                        });
                    }
                    
                    // Break once we've found links
                    if (Object.keys(links).length > 0) break;
                }
            }
            
            // Construct the response
            const response = {
                status: 'success',
                timestamp: new Date().toISOString(),
                data: {
                    token: {
                        address: args.tokenAddress,
                        chain: args.chain,
                        name: tokenInfo.name || 'Unknown',
                        symbol: tokenInfo.symbol || 'Unknown',
                        logoUrl: tokenInfo.logoUrl || ''
                    },
                    overview: {
                        priceUsd: weightedPriceUsd > 0 ? `$${weightedPriceUsd.toFixed(6)}` : 'Unknown',
                        priceChange24h: weightedPriceChange24h !== 0 ? `${weightedPriceChange24h.toFixed(2)}%` : 'Unknown',
                        totalLiquidity: `$${Number(totalLiquidity).toLocaleString()}`,
                        totalVolume24h: `$${Number(totalVolume24h).toLocaleString()}`,
                        totalVolume7d: `$${Number(totalVolume7d).toLocaleString()}`,
                        ...(args.includeMarketMetrics ? {
                            marketCap: marketCap > 0 ? `$${Number(marketCap).toLocaleString()}` : 'Unknown',
                            fullyDilutedValuation: fdv > 0 ? `$${Number(fdv).toLocaleString()}` : 'Unknown'
                        } : {})
                    },
                    tradingPairs: pairsData,
                    links
                }
            };
            
            return JSON.stringify(response, null, 2);
        }
        catch (error) {
            console.error('DEX analytics error:', error);
            return JSON.stringify({
                status: 'error',
                message: `Error fetching DEX analytics: ${error instanceof Error ? error.message : 'Unknown error'}`,
                timestamp: new Date().toISOString()
            }, null, 2);
        }
    }
});

// Capability: Get Transaction History
blockchainAgent.addCapability({
    name: 'getTransactionHistory',
    description: 'Fetch and analyze transaction history for an address',
    schema: z.object({
        address: z.string()
            .regex(/^0x[a-fA-F0-9]{40}$/, {
                message: "Address must be a valid Ethereum address starting with 0x followed by 40 hexadecimal characters"
            })
            .describe('The wallet or contract address to analyze'),
        chain: z.enum(['ethereum', 'polygon', 'bsc', 'optimism', 'arbitrum', 'avalanche', 'fantom'])
            .default('ethereum')
            .describe('The blockchain to query'),
        page: z.number().default(1).describe('Page number for pagination'),
        limit: z.number().min(1).max(100).default(20).describe('Number of transactions per page (max 100)'),
        includeTokenTransfers: z.boolean().default(true).describe('Include ERC20 token transfers in the analysis'),
        startBlock: z.number().optional().describe('Starting block number for the query (optional)'),
        endBlock: z.number().optional().describe('Ending block number for the query (optional)')
    }),
    async run({ args }) {
        try {
            console.log(`Fetching transaction history for ${args.address} on ${args.chain}...`);
            
            // Select the appropriate API endpoint for the chain
            const apiUrl = API_ENDPOINTS.etherscan[args.chain];
            
            // Get the API key for the chain's block explorer
            // Use ETHEREUM_SCAN_API_KEY as fallback for all chains to support free tier
            const apiKey = process.env[`${args.chain.toUpperCase()}_SCAN_API_KEY`] || 
                         process.env.ETHEREUM_SCAN_API_KEY || '';
            
            // Fetch normal transactions
            const txListResponse = await axiosWithRetry({
                method: 'get',
                url: apiUrl,
                params: {
                    module: 'account',
                    action: 'txlist',
                    address: args.address,
                    page: args.page,
                    offset: args.limit,
                    sort: 'desc',
                    startblock: args.startBlock || 0,
                    endblock: args.endBlock || 99999999,
                    apikey: apiKey,
                },
            });
            
            // Check if the API returned an error
            if (txListResponse.data.status === '0' && txListResponse.data.message !== 'No transactions found') {
                return JSON.stringify({
                    status: 'error',
                    message: `API Error: ${txListResponse.data.message}`,
                    address: args.address,
                    chain: args.chain
                }, null, 2);
            }
            
            // Get the transactions from the response
            const transactions = txListResponse.data.status === '1' ? txListResponse.data.result : [];
            
            // Format the transactions for better readability
            const formattedTxs = transactions.map((tx: Transaction) => {
                const nativeValue = parseFloat(tx.value) / 1e18;
                const timestamp = new Date(parseInt(tx.timeStamp) * 1000).toISOString();
                const isOutgoing = tx.from.toLowerCase() === args.address.toLowerCase();
                
                return {
                    hash: tx.hash,
                    timestamp,
                    timeAgo: getTimeAgo(timestamp),
                    from: tx.from,
                    to: tx.to || 'Contract Creation',
                    value: `${nativeValue.toFixed(6)} ${getCurrencySymbol(args.chain)}`,
                    isOutgoing,
                    direction: isOutgoing ? 'OUT' : 'IN',
                    gasUsed: tx.gasUsed,
                    gasPrice: `${(parseFloat(tx.gasPrice) / 1e9).toFixed(2)} Gwei`,
                    blockNumber: tx.blockNumber,
                    status: tx.txreceipt_status === '1' ? 'Success' : 'Failed',
                    methodId: tx.methodId || 'N/A',
                    functionName: tx.functionName || (tx.input === '0x' ? 'Simple Transfer' : 'Contract Interaction')
                };
            });
            
            // Fetch ERC20 token transfers if requested
            let tokenTransfers: any[] = [];
            
            if (args.includeTokenTransfers) {
                try {
                    const tokenTxListResponse = await axiosWithRetry({
                        method: 'get',
                        url: apiUrl,
                        params: {
                            module: 'account',
                            action: 'tokentx',
                            address: args.address,
                            page: args.page,
                            offset: args.limit,
                            sort: 'desc',
                            startblock: args.startBlock || 0,
                            endblock: args.endBlock || 99999999,
                            apikey: apiKey,
                        },
                    });
                    
                    if (tokenTxListResponse.data.status === '1') {
                        const rawTokenTransfers = tokenTxListResponse.data.result;
                        
                        tokenTransfers = rawTokenTransfers.map((transfer: TokenTransfer) => {
                            const tokenValue = parseFloat(transfer.value) / Math.pow(10, parseInt(transfer.tokenDecimal || '18'));
                            const timestamp = new Date(parseInt(transfer.timeStamp) * 1000).toISOString();
                            const isOutgoing = transfer.from.toLowerCase() === args.address.toLowerCase();
                            
                            return {
                                hash: transfer.hash,
                                timestamp,
                                timeAgo: getTimeAgo(timestamp),
                                from: transfer.from,
                                to: transfer.to,
                                tokenName: transfer.tokenName || 'Unknown Token',
                                tokenSymbol: transfer.tokenSymbol || 'UNKNOWN',
                                tokenAddress: transfer.contractAddress,
                                value: `${tokenValue.toFixed(6)} ${transfer.tokenSymbol || 'UNKNOWN'}`,
                                isOutgoing,
                                direction: isOutgoing ? 'OUT' : 'IN',
                                blockNumber: transfer.blockNumber
                            };
                        });
                    }
                } catch (error) {
                    console.warn("Error fetching token transfers: ", error);
                    // Continue with empty token transfers
                }
            }
            
            // Get account native token balance
            const balanceResponse = await axiosWithRetry({
                method: 'get',
                url: apiUrl,
                params: {
                    module: 'account',
                    action: 'balance',
                    address: args.address,
                    tag: 'latest',
                    apikey: apiKey,
                },
            });
            
            const balance = balanceResponse.data.status === '1' ? 
                parseFloat(balanceResponse.data.result) / 1e18 : 0;
            
            // Define types for transaction objects
            interface FormattedTransaction {
                status: string;
                isOutgoing: boolean;
                to: string;
                from: string;
            }
            
            interface TokenTransferFormatted {
                isOutgoing: boolean;
                to: string;
                from: string;
            }
            
            // Perform analysis on the transactions
            const analysis = {
                totalTransactions: formattedTxs.length,
                successfulTransactions: formattedTxs.filter((tx: FormattedTransaction) => tx.status === 'Success').length,
                failedTransactions: formattedTxs.filter((tx: FormattedTransaction) => tx.status !== 'Success').length,
                incomingTransactions: formattedTxs.filter((tx: FormattedTransaction) => !tx.isOutgoing).length,
                outgoingTransactions: formattedTxs.filter((tx: FormattedTransaction) => tx.isOutgoing).length,
                totalTokenTransfers: tokenTransfers.length,
                incomingTokenTransfers: tokenTransfers.filter((tx: TokenTransferFormatted) => !tx.isOutgoing).length,
                outgoingTokenTransfers: tokenTransfers.filter((tx: TokenTransferFormatted) => tx.isOutgoing).length,
                uniqueInteractions: new Set([
                    ...formattedTxs.map((tx: FormattedTransaction) => tx.isOutgoing ? tx.to : tx.from),
                    ...tokenTransfers.map((tx: TokenTransferFormatted) => tx.isOutgoing ? tx.to : tx.from)
                ]).size
            };
            
            // Format the result
            const result = {
                status: 'success',
                address: args.address,
                chain: args.chain,
                balance: `${balance.toFixed(6)} ${getCurrencySymbol(args.chain)}`,
                transactions: formattedTxs,
                tokenTransfers: tokenTransfers,
                analysis,
                pagination: {
                    page: args.page,
                    limit: args.limit,
                    hasMoreData: formattedTxs.length === args.limit
                },
                metaData: {
                    timestamp: new Date().toISOString(),
                    apiProvider: `${args.chain}scan.io`
                }
            };
            
            return JSON.stringify(result, null, 2);
        } catch (error: any) {
            console.error('Transaction history error:', error);
            return JSON.stringify({
                status: 'error',
                message: 'Error fetching transaction history',
                details: error.message,
                address: args.address,
                chain: args.chain,
                timestamp: new Date().toISOString()
            }, null, 2);
        }
    }
});

// Helper function to calculate relative time
function getTimeAgo(timestamp: string): string {
    const now = new Date().getTime();
    const txTime = new Date(timestamp).getTime();
    const diffSeconds = Math.floor((now - txTime) / 1000);
    
    if (diffSeconds < 60) return `${diffSeconds} seconds ago`;
    if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)} minutes ago`;
    if (diffSeconds < 86400) return `${Math.floor(diffSeconds / 3600)} hours ago`;
    return `${Math.floor(diffSeconds / 86400)} days ago`;
}


// Start the server with explicit configuration
console.log(`Starting server on port ${PORT}...`);
blockchainAgent.start().then(() => {
    console.log(`Server started successfully on port ${PORT}`);
}).catch(error => {
    console.error('Failed to start server:', error);
    process.exit(1);
});

