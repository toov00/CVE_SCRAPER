# CVE Fetcher

This is the first component of an AI-powered security monitoring system that tracks CVEs and checks their relevance to blockchain protocols.

## What This Does

The `CVEFetcher` class connects to the National Vulnerability Database (NVD) API and:
- Fetches recent CVEs from the last N days
- Searches for CVEs by keyword
- Extracts relevant information (severity, affected products, references)
- Handles rate limiting properly
- Saves data for further analysis

## Setup

1. Install dependencies:
```bash
pip3 install -r requirements.txt
```

2. (Optional) Get an NVD API key for higher rate limits:
   - Visit: https://nvd.nist.gov/developers/request-an-api-key
   - Without key: 5 requests per 30 seconds
   - With key: 50 requests per 30 seconds

## Usage

### Basic Example

Modify the variables within config.py:

```python
# NVD API key (optional! increases rate limit from 5 to 50 requests/30sec)
# Get one at: https://nvd.nist.gov/developers/request-an-api-key
API_KEY = None

# Recent CVE monitoring: Fetch all CVEs from the last N days
RECENT_CVE_DAYS = 3

# Keyword search: Find CVEs matching specific terms
KEYWORD_SEARCH_TERM = 'blockchain'
KEYWORD_SEARCH_DAYS = 90
```

### Run the Demo

```bash
python3 cve_fetcher.py
```

This will:
- Fetch CVEs from the last N days
- Show high severity ones
- Search for blockchain-related CVEs
- Save everything to `recent_cves.json`

## Data Structure

Each CVE object contains:

```python
{
    'id': 'CVE-2024-XXXXX',
    'description': 'Detailed vulnerability description',
    'severity': 'HIGH',  # LOW, MEDIUM, HIGH, CRITICAL
    'base_score': 7.5,   # CVSS score (0-10)
    'published': '2024-01-15T10:15:08.000',
    'last_modified': '2024-01-15T10:15:08.000',
    'references': ['https://...', 'https://...'],
    'affected_products': ['vendor/product:version', ...],
    'raw_data': {...}  # Full NVD API response
}
```

## Next Steps

To build the complete monitoring agent, you'll want to add:

1. **Protocol Knowledge Base** - Store info about the protocols you're tracking (dependencies, tech stack, contract addresses)

2. **Relevance Analysis** - Use LLMs/embeddings to determine if a CVE affects your tracked protocols

3. **Alert System** - Send notifications when relevant CVEs are found

4. **Database** - Store CVEs and analysis results persistently

5. **Scheduler** - Run this periodically (daily/hourly) to catch new CVEs

## Rate Limiting Notes

- Without API key: The code waits 6 seconds between requests
- With API key: Waits 0.6 seconds between requests
- Be respectful of NVD's infrastructure!

## Useful Keywords for Blockchain Security

When searching, try keywords like:
- `solidity`
- `smart contract`
- `ethereum`
- `web3`
- `blockchain`
- `defi`
- Specific library names (OpenZeppelin, etc.)

## Resources

- [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [CVSS Scoring Guide](https://www.first.org/cvss/v3.1/user-guide)
- [CPE Dictionary](https://nvd.nist.gov/products/cpe)
