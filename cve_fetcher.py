"""
CVE Fetcher - Monitors new CVEs from the National Vulnerability Database (NVD)
"""

import logging
import requests
import time
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Any, Tuple
import json
import config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CVEFetcherError(Exception):
    """Base exception for CVE Fetcher errors."""
    pass


class APIRequestError(CVEFetcherError):
    """Exception raised when API request fails."""
    pass


class InvalidInputError(CVEFetcherError):
    """Exception raised when input validation fails."""
    pass


class CVEFetcher:
    """
    Fetches CVE data from the NVD API (v2.0)
    API Documentation: https://nvd.nist.gov/developers/vulnerabilities
    """
    
    # API Configuration
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    REQUEST_TIMEOUT = 30
    MAX_RESULTS_PER_PAGE = 2000
    
    # Rate limiting (seconds between requests)
    RATE_LIMIT_WITHOUT_KEY = 6.0
    RATE_LIMIT_WITH_KEY = 0.6
    
    # Date format for NVD API (ISO 8601)
    DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.000'
    
    # CVSS metric keys
    CVSS_V31_KEY = 'cvssMetricV31'
    CVSS_V30_KEY = 'cvssMetricV30'
    
    # Default values
    DEFAULT_DESCRIPTION = 'No description available'
    DEFAULT_CVE_ID = 'Unknown'
    DEFAULT_SEVERITY = 'UNKNOWN'
    DEFAULT_BASE_SCORE = 0.0
    
    # CPE format constants
    CPE_MIN_PARTS = 5
    CPE_VENDOR_INDEX = 3
    CPE_PRODUCT_INDEX = 4
    CPE_VERSION_INDEX = 5
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the CVE fetcher.
        
        Args:
            api_key: Optional NVD API key for higher rate limits
                    Without key: 5 requests per 30 seconds
                    With key: 50 requests per 30 seconds
                    
        Raises:
            InvalidInputError: If api_key is provided but empty string
        """
        if api_key is not None and not api_key.strip():
            raise InvalidInputError("API key cannot be an empty string")
        
        self.api_key = api_key
        self.headers: Dict[str, str] = {}
        if api_key:
            self.headers['apiKey'] = api_key
            logger.info("CVE Fetcher initialized with API key")
        else:
            logger.info("CVE Fetcher initialized without API key (lower rate limit)")
    
    def fetch_recent_cves(self, days: int = 7) -> List[Dict[str, Any]]:
        """
        Fetch CVEs published in the last N days.
        
        Args:
            days: Number of days to look back (must be positive)
            
        Returns:
            List of CVE objects with relevant information
            
        Raises:
            InvalidInputError: If days is not positive
            APIRequestError: If API request fails
        """
        if days <= 0:
            raise InvalidInputError(f"Days must be positive, got {days}")
        
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)
        
        # Format dates as required by NVD API (ISO 8601)
        params: Dict[str, Any] = {
            'pubStartDate': start_date.strftime(self.DATE_FORMAT),
            'pubEndDate': end_date.strftime(self.DATE_FORMAT),
        }
        
        logger.info(f"Fetching CVEs from {start_date.date()} to {end_date.date()}...")
        
        all_cves: List[Dict[str, Any]] = []
        start_index = 0
        rate_limit_delay = self.RATE_LIMIT_WITH_KEY if self.api_key else self.RATE_LIMIT_WITHOUT_KEY
        
        while True:
            params['startIndex'] = start_index
            params['resultsPerPage'] = self.MAX_RESULTS_PER_PAGE
            
            try:
                response = requests.get(
                    self.BASE_URL,
                    headers=self.headers,
                    params=params,
                    timeout=self.REQUEST_TIMEOUT
                )
                response.raise_for_status()
                
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                if not vulnerabilities:
                    logger.debug("No more vulnerabilities found")
                    break
                
                # Extract relevant information from each CVE
                for vuln in vulnerabilities:
                    try:
                        cve_data = self._extract_cve_info(vuln)
                        all_cves.append(cve_data)
                    except Exception as e:
                        logger.warning(f"Failed to extract CVE info: {e}")
                        continue
                
                logger.info(f"Fetched {len(vulnerabilities)} CVEs (total: {len(all_cves)})")
                
                # Check if there are more results
                total_results = data.get('totalResults', 0)
                if start_index + len(vulnerabilities) >= total_results:
                    logger.debug("All results fetched")
                    break
                
                start_index += self.MAX_RESULTS_PER_PAGE
                
                # Rate limiting - wait between requests
                if start_index < total_results:
                    time.sleep(rate_limit_delay)
                
            except requests.exceptions.Timeout as e:
                error_msg = f"Request timeout while fetching CVEs: {e}"
                logger.error(error_msg)
                raise APIRequestError(error_msg) from e
            except requests.exceptions.HTTPError as e:
                error_msg = f"HTTP error while fetching CVEs: {e}"
                logger.error(error_msg)
                raise APIRequestError(error_msg) from e
            except requests.exceptions.RequestException as e:
                error_msg = f"Request error while fetching CVEs: {e}"
                logger.error(error_msg)
                raise APIRequestError(error_msg) from e
            except (KeyError, ValueError, json.JSONDecodeError) as e:
                error_msg = f"Error parsing API response: {e}"
                logger.error(error_msg)
                raise APIRequestError(error_msg) from e
        
        logger.info(f"Total CVEs fetched: {len(all_cves)}")
        return all_cves
    
    def _extract_cve_info(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract relevant information from raw CVE data.
        
        Args:
            vuln_data: Raw vulnerability data from NVD API
            
        Returns:
            Simplified CVE information dictionary
            
        Raises:
            KeyError: If required CVE structure is missing
        """
        if not isinstance(vuln_data, dict):
            raise ValueError("vuln_data must be a dictionary")
        
        cve = vuln_data.get('cve', {})
        if not isinstance(cve, dict):
            logger.warning("Invalid CVE structure: 'cve' key is not a dictionary")
            cve = {}
        
        cve_id = cve.get('id', self.DEFAULT_CVE_ID)
        
        # Extract description
        descriptions = cve.get('descriptions', [])
        if not isinstance(descriptions, list):
            descriptions = []
        
        description = next(
            (d.get('value', '') for d in descriptions if isinstance(d, dict) and d.get('lang') == 'en'),
            self.DEFAULT_DESCRIPTION
        )
        
        # Extract CVSS scores with better error handling
        base_score, severity = self._extract_cvss_scores(cve.get('metrics', {}))
        
        # Extract references (useful for finding exploit details)
        references = cve.get('references', [])
        if not isinstance(references, list):
            references = []
        
        reference_urls = [
            ref.get('url') for ref in references 
            if isinstance(ref, dict) and ref.get('url')
        ]
        
        # Extract affected configurations/products
        configurations = cve.get('configurations', [])
        if not isinstance(configurations, list):
            configurations = []
        
        affected_products = self._extract_affected_products(configurations)
        
        # Dates
        published = cve.get('published', '')
        last_modified = cve.get('lastModified', '')
        
        return {
            'id': cve_id,
            'description': description,
            'severity': severity,
            'base_score': base_score,
            'published': published,
            'last_modified': last_modified,
            'references': reference_urls,
            'affected_products': affected_products,
            'raw_data': vuln_data  # Keep raw data for advanced analysis
        }
    
    def _extract_cvss_scores(self, metrics: Dict[str, Any]) -> Tuple[float, str]:
        """
        Extract CVSS base score and severity from metrics.
        
        Args:
            metrics: Metrics dictionary from CVE data
            
        Returns:
            Tuple of (base_score, severity)
        """
        if not isinstance(metrics, dict):
            return self.DEFAULT_BASE_SCORE, self.DEFAULT_SEVERITY
        
        # Try CVSS v3.1 first, then v3.0
        for cvss_key in [self.CVSS_V31_KEY, self.CVSS_V30_KEY]:
            cvss_metrics = metrics.get(cvss_key, [])
            if isinstance(cvss_metrics, list) and len(cvss_metrics) > 0:
                cvss_metric = cvss_metrics[0]
                if isinstance(cvss_metric, dict):
                    cvss_data = cvss_metric.get('cvssData', {})
                    if isinstance(cvss_data, dict):
                        base_score = cvss_data.get('baseScore', self.DEFAULT_BASE_SCORE)
                        severity = cvss_data.get('baseSeverity', self.DEFAULT_SEVERITY)
                        # Validate base_score is numeric
                        try:
                            base_score = float(base_score)
                        except (ValueError, TypeError):
                            base_score = self.DEFAULT_BASE_SCORE
                        return base_score, str(severity)
        
        return self.DEFAULT_BASE_SCORE, self.DEFAULT_SEVERITY
    
    def _extract_affected_products(self, configurations: List[Dict[str, Any]]) -> List[str]:
        """
        Extract list of affected products from CVE configurations.
        
        Args:
            configurations: Configuration data from CVE
            
        Returns:
            List of affected product strings
        """
        if not isinstance(configurations, list):
            return []
        
        products = set()
        
        for config in configurations:
            if not isinstance(config, dict):
                continue
            
            nodes = config.get('nodes', [])
            if not isinstance(nodes, list):
                continue
            
            for node in nodes:
                if not isinstance(node, dict):
                    continue
                
                cpe_matches = node.get('cpeMatch', [])
                if not isinstance(cpe_matches, list):
                    continue
                
                for match in cpe_matches:
                    if not isinstance(match, dict):
                        continue
                    
                    if match.get('vulnerable', False):
                        cpe_uri = match.get('criteria', '')
                        # CPE format: cpe:2.3:part:vendor:product:version:...
                        if cpe_uri and isinstance(cpe_uri, str):
                            parts = cpe_uri.split(':')
                            if len(parts) >= self.CPE_MIN_PARTS:
                                try:
                                    vendor = parts[self.CPE_VENDOR_INDEX]
                                    product = parts[self.CPE_PRODUCT_INDEX]
                                    version = parts[self.CPE_VERSION_INDEX] if len(parts) > self.CPE_VERSION_INDEX else '*'
                                    if vendor and product:
                                        products.add(f"{vendor}/{product}:{version}")
                                except IndexError:
                                    logger.debug(f"Invalid CPE format: {cpe_uri}")
                                    continue
        
        return sorted(list(products))
    
    def search_cves_by_keyword(self, keyword: str, days: Optional[int] = 30) -> List[Dict[str, Any]]:
        """
        Search for CVEs containing specific keywords in description.
        
        Args:
            keyword: Keyword to search for (e.g., 'solidity', 'smart contract')
            days: Number of days to look back (None to search all time)
            
        Returns:
            List of matching CVE objects
            
        Raises:
            InvalidInputError: If keyword is empty or days is negative
            APIRequestError: If API request fails
        """
        if not keyword or not keyword.strip():
            raise InvalidInputError("Keyword cannot be empty")
        
        if days is not None and days <= 0:
            raise InvalidInputError(f"Days must be positive, got {days}")
        
        params: Dict[str, Any] = {
            'keywordSearch': keyword.strip(),
        }
        
        # Add date range if specified
        if days:
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=days)
            params['pubStartDate'] = start_date.strftime(self.DATE_FORMAT)
            params['pubEndDate'] = end_date.strftime(self.DATE_FORMAT)
        
        logger.info(f"Searching for CVEs with keyword: '{keyword}'...")
        
        try:
            response = requests.get(
                self.BASE_URL,
                headers=self.headers,
                params=params,
                timeout=self.REQUEST_TIMEOUT
            )
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            
            if not isinstance(vulnerabilities, list):
                logger.warning("Invalid response format: vulnerabilities is not a list")
                return []
            
            cves: List[Dict[str, Any]] = []
            for vuln in vulnerabilities:
                try:
                    cve_data = self._extract_cve_info(vuln)
                    cves.append(cve_data)
                except Exception as e:
                    logger.warning(f"Failed to extract CVE info: {e}")
                    continue
            
            logger.info(f"Found {len(cves)} CVEs matching '{keyword}'")
            return cves
            
        except requests.exceptions.Timeout as e:
            error_msg = f"Request timeout while searching CVEs: {e}"
            logger.error(error_msg)
            raise APIRequestError(error_msg) from e
        except requests.exceptions.HTTPError as e:
            error_msg = f"HTTP error while searching CVEs: {e}"
            logger.error(error_msg)
            raise APIRequestError(error_msg) from e
        except requests.exceptions.RequestException as e:
            error_msg = f"Request error while searching CVEs: {e}"
            logger.error(error_msg)
            raise APIRequestError(error_msg) from e
        except (KeyError, ValueError, json.JSONDecodeError) as e:
            error_msg = f"Error parsing API response: {e}"
            logger.error(error_msg)
            raise APIRequestError(error_msg) from e


def main() -> None:
    """
    Example usage of the CVE fetcher
    """
    try:
        # Initialize fetcher
        fetcher = CVEFetcher(config.API_KEY)
        
        # Fetch recent CVEs from the last N days
        try:
            recent_cves = fetcher.fetch_recent_cves(config.RECENT_CVE_DAYS)
        except (APIRequestError, InvalidInputError) as e:
            logger.error(f"Failed to fetch recent CVEs: {e}")
            return
        
        # Display some results
        logger.info("\n" + "="*80)
        logger.info("RECENT HIGH SEVERITY CVEs")
        logger.info("="*80)
        
        HIGH_SEVERITY_THRESHOLD = 7.0
        high_severity = [
            cve for cve in recent_cves 
            if cve.get('severity') in ['HIGH', 'CRITICAL'] 
            and cve.get('base_score', 0.0) >= HIGH_SEVERITY_THRESHOLD
        ]
        
        MAX_DISPLAY = 5
        for cve in high_severity[:MAX_DISPLAY]:
            logger.info(f"\n{cve.get('id', 'Unknown')} - {cve.get('severity', 'UNKNOWN')} "
                       f"(Score: {cve.get('base_score', 0.0)})")
            logger.info(f"Published: {cve.get('published', 'N/A')}")
            description = cve.get('description', '')
            logger.info(f"Description: {description[:200]}...")
            affected_products = cve.get('affected_products', [])
            if affected_products:
                logger.info(f"Affected: {', '.join(affected_products[:3])}")
            logger.info(f"References: {len(cve.get('references', []))} available")
        
        # Save to file for later analysis
        output_file = 'recent_cves.json'
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(recent_cves, f, indent=2, ensure_ascii=False)
            logger.info(f"\n\nAll CVEs saved to {output_file}")
        except IOError as e:
            logger.error(f"Failed to save CVEs to file: {e}")
        
        # Example keyword search
        logger.info("\n" + "="*80)
        logger.info(f"SEARCHING FOR CVEs RELATED TO: {config.KEYWORD_SEARCH_TERM}")
        logger.info("="*80)
        
        # Rate limiting before next request
        rate_limit_delay = CVEFetcher.RATE_LIMIT_WITH_KEY if config.API_KEY else CVEFetcher.RATE_LIMIT_WITHOUT_KEY
        time.sleep(rate_limit_delay)
        
        try:
            blockchain_cves = fetcher.search_cves_by_keyword(
                config.KEYWORD_SEARCH_TERM, 
                config.KEYWORD_SEARCH_DAYS
            )
            
            MAX_KEYWORD_RESULTS = 3
            for cve in blockchain_cves[:MAX_KEYWORD_RESULTS]:
                logger.info(f"\n{cve.get('id', 'Unknown')} - {cve.get('severity', 'UNKNOWN')}")
                description = cve.get('description', '')
                logger.info(f"Description: {description[:150]}...")
        except (APIRequestError, InvalidInputError) as e:
            logger.error(f"Failed to search CVEs by keyword: {e}")
    
    except Exception as e:
        logger.exception(f"Unexpected error in main: {e}")
        raise


if __name__ == "__main__":
    main()
    