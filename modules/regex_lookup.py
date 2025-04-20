#!/usr/bin/env python3
# Regex pattern loading and matching

import re
import os
import sys

class RegexLookup:
    """Handles regex pattern loading and matching for mXtract"""
    
    def __init__(self, options):
        """Initialize with options object"""
        self.options = options
        self.patterns = []
        self.pattern_names = []
        self.results = {}  # Dictionary to store unique results for each pattern
    
    def load_patterns(self):
        """Load regex patterns from specified file or default file"""
        regex_file = self.options.regex_file or self.options.default_regex_file
        
        # Create patterns directory if it doesn't exist
        if not os.path.exists(os.path.dirname(self.options.default_regex_file)):
            os.makedirs(os.path.dirname(self.options.default_regex_file))
            
            # If we just created the patterns directory and no regex file is specified,
            # we need to create the default patterns file
            if not self.options.regex_file:
                self._create_default_patterns()
        
        try:
            with open(regex_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Format should be: pattern_name:regex_pattern
                    if ':' in line:
                        name, pattern = line.split(':', 1)
                        try:
                            compiled_pattern = re.compile(pattern)
                            self.patterns.append(compiled_pattern)
                            self.pattern_names.append(name)
                            # Initialize results dictionary for this pattern
                            self.results[name] = set()
                        except re.error:
                            print(f"[!] Error compiling regex pattern: {pattern}")
        except FileNotFoundError:
            print(f"[!] Error: Regex file not found: {regex_file}")
            if not self.options.regex_file:
                self._create_default_patterns()
                # Try loading again
                self.load_patterns()
            else:
                sys.exit(1)
        
        print(f"[*] Loaded {len(self.patterns)} regex patterns")
    
    def _create_default_patterns(self):
        """Create default regex patterns file"""
        default_patterns = [
            "# Default regex patterns for MemSift",
            "# Format: pattern_name:regex_pattern",
            "",
            "# Passwords and authentication",
            "password:password\\s*[=:].{0,20}",
            "ssh_private_key:-----BEGIN.*PRIVATE KEY-----",
            "api_key:api[_-]?key.{0,20}['|\"][0-9a-zA-Z]{16,}['|\"]",
            "aws_key:AKIA[0-9A-Z]{16}",
            "aws_secret:[0-9a-zA-Z/+]{40}",
            "",
            "# Network",
            "ipv4:(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?![0-9])",
            "email:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
            "url:https?://(?:[-\\w.]|(?:%[\\da-fA-F]{2}))+[^\\s]*",
            "",
            "# Credit cards",
            "visa:4[0-9]{12}(?:[0-9]{3})?",
            "mastercard:5[1-5][0-9]{14}",
            "amex:3[47][0-9]{13}",
            "",
            "# Other sensitive information",
            "ssn:[0-9]{3}-[0-9]{2}-[0-9]{4}",
            "bitcoin_address:[13][a-km-zA-HJ-NP-Z1-9]{25,34}",
            "ethereum_address:0x[a-fA-F0-9]{40}",
        ]
        
        try:
            os.makedirs(os.path.dirname(self.options.default_regex_file), exist_ok=True)
            with open(self.options.default_regex_file, 'w') as f:
                f.write('\n'.join(default_patterns))
            print(f"[*] Created default regex patterns file: {self.options.default_regex_file}")
        except Exception as e:
            print(f"[!] Error creating default regex patterns file: {str(e)}")
            sys.exit(1)
    
    def search_regex(self, data, process_info=""):
        """Apply all loaded regex patterns to the given data"""
        if not data:
            return
        
        for i, pattern in enumerate(self.patterns):
            pattern_name = self.pattern_names[i]
            matches = pattern.findall(data)
            
            # Add unique matches to results
            for match in matches:
                if isinstance(match, tuple):  # If the pattern has groups
                    match = ''.join(match)
                
                # Only add non-empty matches
                if match and len(match) > 3:  # Minimum reasonable length
                    self.results[pattern_name].add((match, process_info))
    
    def search_regex_with_details(self, data, process_info=""):
        """Apply all loaded regex patterns and return detailed findings"""
        if not data:
            return []
        
        findings = []
        for i, pattern in enumerate(self.patterns):
            pattern_name = self.pattern_names[i]
            matches = pattern.findall(data)
            
            # Add unique matches to results and return findings
            for match in matches:
                if isinstance(match, tuple):  # If the pattern has groups
                    match = ''.join(match)
                
                # Only add non-empty matches
                if match and len(match) > 3:  # Minimum reasonable length
                    self.results[pattern_name].add((match, process_info))
                    
                    # Add to findings list
                    findings.append({
                        'pattern': pattern_name,
                        'match': match,
                        'process_info': process_info
                    })
        
        return findings
    
    def get_results(self):
        """Get all unique results"""
        all_results = []
        for pattern_name, matches in self.results.items():
            for match_data in matches:
                match, process_info = match_data
                all_results.append({
                    'pattern': pattern_name,
                    'match': match,
                    'process_info': process_info
                })
        return all_results
    
    def get_result_count(self):
        """Get total number of unique results"""
        return sum(len(matches) for matches in self.results.values())
