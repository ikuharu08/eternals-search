import requests
import json
from typing import List, Dict
import time
import os
from datetime import datetime, timedelta
import pycountry
import logging

class RIPEManager:
    def __init__(self):
        self.base_url = "https://stat.ripe.net/data"
        self.cache_dir = "cache"
        self.cache_duration = timedelta(hours=24)  # Cache valid for 24 hours
        
        # Create cache directory if not exists
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
    
    def _get_cache_path(self, key: str) -> str:
        return os.path.join(self.cache_dir, f"{key}.json")
    
    def _is_cache_valid(self, cache_path: str) -> bool:
        if not os.path.exists(cache_path):
            return False
            
        file_time = datetime.fromtimestamp(os.path.getmtime(cache_path))
        return datetime.now() - file_time < self.cache_duration
    
    def _read_cache(self, key: str) -> Dict:
        cache_path = self._get_cache_path(key)
        if self._is_cache_valid(cache_path):
            with open(cache_path, 'r') as f:
                return json.load(f)
        return None
    
    def _write_cache(self, key: str, data: Dict):
        cache_path = self._get_cache_path(key)
        with open(cache_path, 'w') as f:
            json.dump(data, f)

    def get_country_list(self) -> List[Dict]:
        """Get list of all countries with their codes"""
        cache_data = self._read_cache('countries')
        if cache_data:
            return cache_data
            
        try:
            countries = []
            # Get all countries from pycountry
            for country in pycountry.countries:
                countries.append({
                    'code': country.alpha_2,
                    'name': country.name
                })
            
            countries = sorted(countries, key=lambda x: x['name'])
            self._write_cache('countries', countries)
            return countries
            
        except Exception as e:
            print(f"Error fetching country list: {str(e)}")
            return []
    
    def get_country_ip_ranges(self, country_codes: List[str]) -> List[str]:
        """Get all IPv4 ranges for multiple countries"""
        all_ranges = []
        
        # Convert single string to list if needed
        if isinstance(country_codes, str):
            country_codes = [country_codes]
        
        for code in country_codes:
            try:
                url = f"https://stat.ripe.net/data/country-resource-list/data.json?resource={code}"
                response = requests.get(url)
                response.raise_for_status()
                
                data = response.json()
                
                # Extract IPv4 ranges from response
                if data and 'data' in data and 'resources' in data['data']:
                    ipv4_ranges = data['data']['resources'].get('ipv4', [])
                    all_ranges.extend(ipv4_ranges)
                    
                logging.debug(f"Found {len(ipv4_ranges)} IP ranges for {code}")
                    
            except Exception as e:
                logging.error(f"Error fetching IP ranges for {code}: {str(e)}")
                continue
        
        # Remove duplicates and empty strings
        return [r for r in list(set(all_ranges)) if r]
    
    def validate_ip_ranges(self, ranges: List[str], exclude_ranges: List[str] = None) -> List[str]:
        """Validate custom IP ranges and remove excluded ranges"""
        valid_ranges = []
        exclude_ranges = set(exclude_ranges or [])
        
        for ip_range in ranges:
            ip_range = ip_range.strip()
            if not ip_range:
                continue
                
            # Skip if in exclude list
            if ip_range in exclude_ranges:
                continue
                
            # Basic CIDR validation
            try:
                if '/' in ip_range:
                    ip, prefix = ip_range.split('/')
                    if 0 <= int(prefix) <= 32:
                        valid_ranges.append(ip_range)
            except:
                continue
                
        return valid_ranges
    
    def preview_ranges(self, ranges: List[str]) -> Dict:
        """Generate preview statistics for IP ranges"""
        total_ips = 0
        range_count = len(ranges)
        
        for ip_range in ranges:
            try:
                if '/' in ip_range:
                    _, prefix = ip_range.split('/')
                    total_ips += 2 ** (32 - int(prefix))
            except:
                continue
                
        return {
            'range_count': range_count,
            'total_ips': total_ips,
            'estimated_time': self._estimate_scan_time(total_ips)
        }
    
    def _estimate_scan_time(self, total_ips: int) -> str:
        """Estimate scan time based on number of IPs"""
        # Rough estimation: 1000 IPs per second
        seconds = total_ips / 1000
        if seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds/60)} minutes"
        else:
            return f"{round(seconds/3600, 1)} hours"
    
    def _get_country_name(self, code: str) -> str:
        """Get full country name from country code"""
        try:
            country = pycountry.countries.get(alpha_2=code)
            return country.name if country else code
        except:
            return code

    def get_country_resources(self, country_code: str) -> dict:
        """Get IP resources for a country"""
        url = f"{self.base_url}/country/{country_code}"
        response = self._make_request(url)
        
        if not response or 'data' not in response:
            return {'asn': [], 'ipv4': [], 'ipv6': []}
        
        resources = response.get('data', {}).get('resources', {})
        return {
            'asn': resources.get('asn', []),
            'ipv4': resources.get('ipv4', []),
            'ipv6': resources.get('ipv6', [])
        } 