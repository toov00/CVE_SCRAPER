"""
CVE Fetcher - Monitors new CVEs from the National Vulnerability Database (NVD)
"""

import requests
import time
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional
import json
import config


class CVEFetcher:
    """
    Fetches CVE data from the NVD API (v2.0)
    API Documentation: https://nvd.nist.gov/developers/vulnerabilities
    """
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the CVE fetcher.
        
        Args:
            api_key: Optional NVD API key for higher rate limits
                    Without key: 5 requests per 30 seconds
                    With key: 50 requests per 30 seconds
        """
        self.api_key = api_key
        self.headers = {}
        if api_key:
            self.headers['apiKey'] = api_key
    
    def fetch_recent_cves(self, days: int = 7) -> List[Dict]:
        """
        Fetch CVEs published in the last N days.
        
        Args:
            days: Number of days to look back
            
        Returns:
            List of CVE objects with relevant information
        """
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)
        
        # Format dates as required by NVD API (ISO 8601)
        params = {
            'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
        }
        
        print(f"Fetching CVEs from {start_date.date()} to {end_date.date()}...")
        
        all_cves = []
        start_index = 0
        results_per_page = 2000  # Max allowed by API
        
        while True:
            params['startIndex'] = start_index
            params['resultsPerPage'] = results_per_page
            
            try:
                response = requests.get(
                    self.BASE_URL,
                    headers=self.headers,
                    params=params,
                    timeout=30
                )
                response.raise_for_status()
                
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                if not vulnerabilities:
                    break
                
                # Extract relevant information from each CVE
                for vuln in vulnerabilities:
                    cve_data = self._extract_cve_info(vuln)
                    all_cves.append(cve_data)
                
                print(f"Fetched {len(vulnerabilities)} CVEs (total: {len(all_cves)})")
                
                # Check if there are more results
                total_results = data.get('totalResults', 0)
                if start_index + len(vulnerabilities) >= total_results:
                    break
                
                start_index += results_per_page
                
                # Rate limiting - wait between requests
                time.sleep(6 if not self.api_key else 0.6)
                
            except requests.exceptions.RequestException as e:
                print(f"Error fetching CVEs: {e}")
                break
        
        print(f"Total CVEs fetched: {len(all_cves)}")
        return all_cves
    
    def _extract_cve_info(self, vuln_data: Dict) -> Dict:
        """
        Extract relevant information from raw CVE data.
        
        Args:
            vuln_data: Raw vulnerability data from NVD API
            
        Returns:
            Simplified CVE information dictionary
        """
        cve = vuln_data.get('cve', {})
        cve_id = cve.get('id', 'Unknown')
        
        # Extract description
        descriptions = cve.get('descriptions', [])
        description = next(
            (d['value'] for d in descriptions if d.get('lang') == 'en'),
            'No description available'
        )
        
        # Extract CVSS scores
        metrics = cve.get('metrics', {})
        cvss_v3 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}) or \
                  metrics.get('cvssMetricV30', [{}])[0].get('cvssData', {})
        
        base_score = cvss_v3.get('baseScore', 0.0)
        severity = cvss_v3.get('baseSeverity', 'UNKNOWN')
        
        # Extract references (useful for finding exploit details)
        references = cve.get('references', [])
        reference_urls = [ref.get('url') for ref in references]
        
        # Extract affected configurations/products
        configurations = cve.get('configurations', [])
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
    
    def _extract_affected_products(self, configurations: List[Dict]) -> List[str]:
        """
        Extract list of affected products from CVE configurations.
        
        Args:
            configurations: Configuration data from CVE
            
        Returns:
            List of affected product strings
        """
        products = set()
        
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for match in cpe_matches:
                    if match.get('vulnerable', False):
                        cpe_uri = match.get('criteria', '')
                        # CPE format: cpe:2.3:part:vendor:product:version:...
                        if cpe_uri:
                            parts = cpe_uri.split(':')
                            if len(parts) >= 5:
                                vendor = parts[3]
                                product = parts[4]
                                version = parts[5] if len(parts) > 5 else '*'
                                products.add(f"{vendor}/{product}:{version}")
        
        return sorted(list(products))
    
    def search_cves_by_keyword(self, keyword: str, days: int = 30) -> List[Dict]:
        """
        Search for CVEs containing specific keywords in description.
        
        Args:
            keyword: Keyword to search for (e.g., 'solidity', 'smart contract')
            days: Number of days to look back
            
        Returns:
            List of matching CVE objects
        """
        params = {
            'keywordSearch': keyword,
        }
        
        # Add date range if specified
        if days:
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=days)
            params['pubStartDate'] = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
            params['pubEndDate'] = end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
        
        print(f"Searching for CVEs with keyword: '{keyword}'...")
        
        try:
            response = requests.get(
                self.BASE_URL,
                headers=self.headers,
                params=params,
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            
            cves = [self._extract_cve_info(vuln) for vuln in vulnerabilities]
            print(f"Found {len(cves)} CVEs matching '{keyword}'")
            return cves
            
        except requests.exceptions.RequestException as e:
            print(f"Error searching CVEs: {e}")
            return []


def main():
    """
    Example usage of the CVE fetcher
    """
    # Initialize fetcher
    fetcher = CVEFetcher(config.API_KEY)
    
    # Fetch recent CVEs from the last N days
    recent_cves = fetcher.fetch_recent_cves(config.RECENT_CVE_DAYS)
    
    # Display some results
    print("\n" + "="*80)
    print("RECENT HIGH SEVERITY CVEs")
    print("="*80)
    
    high_severity = [
        cve for cve in recent_cves 
        if cve['severity'] in ['HIGH', 'CRITICAL'] and cve['base_score'] >= 7.0
    ]
    
    for cve in high_severity[:5]:  # Show top 5
        print(f"\n{cve['id']} - {cve['severity']} (Score: {cve['base_score']})")
        print(f"Published: {cve['published']}")
        print(f"Description: {cve['description'][:200]}...")
        if cve['affected_products']:
            print(f"Affected: {', '.join(cve['affected_products'][:3])}")
        print(f"References: {len(cve['references'])} available")
    
    # Save to file for later analysis
    output_file = 'recent_cves.json'
    with open(output_file, 'w') as f:
        json.dump(recent_cves, f, indent=2)
    print(f"\n\nAll CVEs saved to {output_file}")
    
    # Example
    print("\n" + "="*80)
    print("SEARCHING FOR CVEs RELATED TO: " + config.KEYWORD_SEARCH_TERM)
    print("="*80)
    time.sleep(6)  # Rate limiting
    blockchain_cves = fetcher.search_cves_by_keyword(config.KEYWORD_SEARCH_TERM, config.KEYWORD_SEARCH_DAYS)
    
    for cve in blockchain_cves[:3]:
        print(f"\n{cve['id']} - {cve['severity']}")
        print(f"Description: {cve['description'][:150]}...")


if __name__ == "__main__":
    main()
    