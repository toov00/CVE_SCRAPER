# CVE Scraper

A Python tool that monitors the National Vulnerability Database (NVD) for Common Vulnerabilities and Exposures (CVEs) and filters them based on user-defined keywords to identify relevant security threats.

## What It Does

The CVE Scraper provides a clean interface to the NVD API v2.0, allowing you to:

**Features:**
- Fetch all CVEs published within a specified time window
- Search for CVEs matching specific keywords or technologies
- Extract structured information including severity scores, affected products, and references
- Automatically handle rate limiting based on whether you have an API key
- Export results to JSON for further analysis or integration with other tools

## Installation

**Requirements:** Python 3.7+

```bash
git clone <your-repo>
cd CVE_FETCHER
pip install -r requirements.txt
```

Optional: Get an [NVD API key ](https://nvd.nist.gov/developers/request-an-api-key) for higher rate limits (5 requests/30sec without key, 50 requests/30sec with key).

## Usage

### Quick Start

1. Configure settings in `config.py`:

```python
API_KEY = None  # Optional: your NVD API key
RECENT_CVE_DAYS = 3
KEYWORD_SEARCH_TERM = 'blockchain'
KEYWORD_SEARCH_DAYS = 90
```

2. Run the scraper:

```bash
python3 cve_fetcher.py
```

This fetches recent CVEs, displays high-severity ones, searches by keyword, and saves results to `recent_cves.json`.

### Programmatic Usage

```python
from cve_fetcher import CVEFetcher

fetcher = CVEFetcher(api_key="your-api-key-here")

# Fetch recent CVEs
recent_cves = fetcher.fetch_recent_cves(days=7)

# Search by keyword
blockchain_cves = fetcher.search_cves_by_keyword('solidity', days=30)
```

## CVE Data Structure

Each CVE object contains:

```python
{
    'id': 'CVE-2024-12345',
    'description': 'A detailed description of the vulnerability...',
    'severity': 'HIGH',  # LOW, MEDIUM, HIGH, CRITICAL
    'base_score': 7.5,   # CVSS score (0.0 to 10.0)
    'published': '2024-01-15T10:15:08.000',
    'last_modified': '2024-01-15T10:15:08.000',
    'references': ['https://example.com/advisory', ...],
    'affected_products': ['vendor/product:version', ...],
    'raw_data': {...}  # Complete NVD API response
}
```

**Key Fields:**
- `id`: CVE identifier (e.g., CVE-2024-12345)
- `severity`: Text severity level (LOW, MEDIUM, HIGH, CRITICAL)
- `base_score`: Numeric CVSS score where higher means more severe
- `affected_products`: Parsed vendor/product combinations from CPE data
- `references`: URLs to advisories, patches, or exploit details
- `raw_data`: Full API response for advanced analysis

## Output

Results are saved to `recent_cves.json` by default. The JSON file contains:
- Array of all fetched CVE objects
- Pretty-printed with 2-space indentation
- UTF-8 encoding preserving special characters

## Keyword Search Tips

Effective keywords for different use cases:

**Blockchain and Smart Contracts:**
- `solidity`, `smart contract`, `ethereum`, `web3`, `blockchain`, `defi`, `nft`

**Specific Libraries:**
- `openzeppelin`, `hardhat`, `truffle`, `web3.js`

**General Security:**
- `remote code execution`, `sql injection`, `authentication bypass`

Keyword search is case-insensitive and matches anywhere in the description. Use specific technology names or library identifiers for best results.

## Troubleshooting

**Rate limit errors even with API key?** Verify your API key is correctly set in `config.py` as a string (not None). Make sure you're not running multiple instances simultaneously.

**No CVEs returned for keyword search?** Try broadening your search terms or removing the date restriction. Some CVEs use different terminology.

**Timeout errors?** The default timeout is 30 seconds. Increase the `REQUEST_TIMEOUT` constant in the `CVEFetcher` class if needed.

**Missing CVSS scores?** Some older CVEs don't have CVSS v3 scores. The tool falls back to defaults (score 0.0, severity UNKNOWN). Check `raw_data` for CVSS v2 scores or other metrics.

## License

This project is provided as-is for security research and monitoring purposes. Make sure to comply with the NVD API terms of service when using this tool.

## Resources

- [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities): Official API reference
- [CVSS Scoring Guide](https://www.first.org/cvss/v3.1/user-guide): Understanding severity scores
- [CPE Dictionary](https://nvd.nist.gov/products/cpe): Common Platform Enumeration reference
