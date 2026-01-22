# CVE Fetcher

A Python tool that monitors the National Vulnerability Database (NVD) for Common Vulnerabilities and Exposures (CVEs) and filters them based on user-defined keywords to identify relevant security threats.

## What It Does

The CVE Fetcher provides a clean interface to the NVD API v2.0, allowing you to:

- Fetch all CVEs published within a specified time window
- Search for CVEs matching specific keywords or technologies
- Extract structured information including severity scores, affected products, and references
- Automatically handle rate limiting based on whether you have an API key
- Export results to JSON for further analysis or integration with other tools

## Installation

### Prerequisites

- Python 3.7 or higher
- pip package manager

### Setup Steps

1. Clone or download this repository

2. Install the required dependencies:

```bash
pip3 install -r requirements.txt
```

The main dependency is the `requests` library for HTTP calls to the NVD API.

3. (Optional) Obtain an NVD API key

While the tool works without an API key, having one significantly increases your rate limits:
- Without key: 5 requests per 30 seconds
- With key: 50 requests per 30 seconds

To get a free API key, visit the [NVD API key request page](https://nvd.nist.gov/developers/request-an-api-key). The process is straightforward and usually takes just a few minutes.

## Configuration

All configuration is done through the `config.py` file. Open it and adjust these settings:

```python
# NVD API key (optional but recommended)
# Leave as None if you don't have a key yet
API_KEY = None

# How many days back to fetch CVEs
# Set to 7 for a week, 30 for a month, etc.
RECENT_CVE_DAYS = 3

# Keyword to search for in CVE descriptions
# Useful for finding vulnerabilities in specific technologies
KEYWORD_SEARCH_TERM = 'blockchain'

# How many days back to search when using keyword search
KEYWORD_SEARCH_DAYS = 90
```

The configuration is straightforward. If you're just getting started, the defaults will work fine. Adjust `RECENT_CVE_DAYS` based on how frequently you want to run the fetcher. For daily monitoring, 1-3 days is usually sufficient. For weekly reports, 7 days makes sense.

## Basic Usage

### Running the Default Script

The simplest way to use the tool is to run the included script:

```bash
python3 cve_fetcher.py
```

This will:
1. Fetch all CVEs from the last N days (as specified in `config.py`)
2. Display high and critical severity CVEs in the console
3. Search for CVEs matching your keyword term
4. Save all fetched CVEs to `recent_cves.json`

The output includes severity scores, publication dates, descriptions, affected products, and reference counts for each CVE.

## Understanding the Output

### CVE Object Structure

Each CVE returned by the fetcher is a dictionary with the following structure:

```python
{
    'id': 'CVE-2024-12345',
    'description': 'A detailed description of the vulnerability...',
    'severity': 'HIGH',  # One of: LOW, MEDIUM, HIGH, CRITICAL
    'base_score': 7.5,   # CVSS base score from 0.0 to 10.0
    'published': '2024-01-15T10:15:08.000',
    'last_modified': '2024-01-15T10:15:08.000',
    'references': [
        'https://example.com/advisory',
        'https://github.com/...'
    ],
    'affected_products': [
        'vendor/product:version',
        'another-vendor/another-product:1.2.3'
    ],
    'raw_data': {
        # Complete NVD API response for advanced analysis
    }
}
```

### Key Fields Explained

- **id**: The CVE identifier (e.g., CVE-2024-12345)
- **description**: Human-readable description of the vulnerability
- **severity**: Text severity level based on CVSS scoring
- **base_score**: Numeric CVSS score where higher means more severe
- **published**: When the CVE was first published
- **last_modified**: When the CVE record was last updated
- **references**: URLs to advisories, patches, or exploit details
- **affected_products**: Parsed list of vendor/product combinations
- **raw_data**: Full API response if you need access to additional fields

The `affected_products` field is particularly useful. It extracts vendor and product names from the CPE (Common Platform Enumeration) data, making it easier to see what's actually vulnerable without parsing CPE strings yourself.

## Error Handling

The tool includes comprehensive error handling:

- **APIRequestError**: Raised when API calls fail (network issues, timeouts, HTTP errors)
- **InvalidInputError**: Raised when you provide invalid parameters (negative days, empty keywords, etc.)

All errors are logged with context, making it easier to debug issues. The tool also handles malformed API responses gracefully, skipping problematic CVEs and continuing with the rest.

## Keyword Search Tips

The keyword search function searches through CVE descriptions. Here are some effective keywords for different use cases:

**Blockchain and Smart Contracts:**
- `solidity`
- `smart contract`
- `ethereum`
- `web3`
- `blockchain`
- `defi`
- `nft`

**Specific Libraries:**
- `openzeppelin`
- `hardhat`
- `truffle`
- `web3.js`

**General Security:**
- `remote code execution`
- `sql injection`
- `authentication bypass`

Keep in mind that keyword search is case-insensitive and matches anywhere in the description. For best results, use specific technology names or library identifiers rather than generic terms.

## Troubleshooting

**Problem: Getting rate limit errors even with an API key**

Make sure your API key is correctly set in `config.py`. The key should be a string, not None. Also verify that you're not running multiple instances simultaneously.

**Problem: No CVEs returned for a keyword search**

Try broadening your search. Some CVEs might use different terminology. Also check that your date range isn't too restrictive. Try searching without a date limit first to see if any results exist.

**Problem: Timeout errors**

The default timeout is 30 seconds. If you're on a slow connection or the NVD API is experiencing issues, you might need to increase the `REQUEST_TIMEOUT` constant in the `CVEFetcher` class.

**Problem: Missing CVSS scores**

Some older CVEs might not have CVSS v3 scores. The tool falls back to defaults (score 0.0, severity UNKNOWN) when scores aren't available. Check the `raw_data` field if you need to extract CVSS v2 scores or other metrics.

## Resources

- [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities): Official API reference
- [CVSS Scoring Guide](https://www.first.org/cvss/v3.1/user-guide): Understanding severity scores
- [CPE Dictionary](https://nvd.nist.gov/products/cpe): Common Platform Enumeration reference

## License

This project is provided as-is for security research and monitoring purposes. Make sure to comply with the NVD API terms of service when using this tool.
