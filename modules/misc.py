#!/usr/bin/env python3
# Miscellaneous utility functions

import os
import re
import datetime
from colorama import init, Fore, Style

class Misc:
    """Utility functions for mXtract"""
    
    def __init__(self):
        # Initialize colorama for cross-platform colored terminal output
        init()
    
    def print_banner(self):
        """Display the MemSift banner"""
        banner = f"""{Fore.BLUE}
┌──────────────────────────────────────────────────┐
│                                                  │
│  ███╗   ███╗███████╗███╗   ███╗███████╗██╗███████╗████████╗  │
│  ████╗ ████║██╔════╝████╗ ████║██╔════╝██║██╔════╝╚══██╔══╝  │
│  ██╔████╔██║█████╗  ██╔████╔██║███████╗██║█████╗     ██║     │
│  ██║╚██╔╝██║██╔══╝  ██║╚██╔╝██║╚════██║██║██╔══╝     ██║     │
│  ██║ ╚═╝ ██║███████╗██║ ╚═╝ ██║███████║██║██║        ██║     │
│  ╚═╝     ╚═╝╚══════╝╚═╝     ╚═╝╚══════╝╚═╝╚═╝        ╚═╝     │
│                                                                  │
│  Memory Extraction and Analysis Tool                             │
│  By: Subhash Dasyam                                              │
└──────────────────────────────────────────────────────────────────┘
{Style.RESET_ALL}"""
        print(banner)
    
    def is_valid_ascii(self, char):
        """Check if a character is a valid printable ASCII character"""
        return 32 <= ord(char) <= 126
    
    def strip_non_ascii(self, data):
        """Strip non-ASCII characters from a string"""
        if isinstance(data, bytes):
            # Convert bytes to string if needed
            try:
                data = data.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                data = str(data)
        
        return ''.join(char for char in data if self.is_valid_ascii(char))
    
    def timestamp_to_readable(self, timestamp):
        """Convert Unix timestamp to human-readable format"""
        dt = datetime.datetime.fromtimestamp(timestamp)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    
    def get_current_time(self):
        """Get current time in human-readable format"""
        return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    def print_verbose(self, message, options):
        """Print message only if verbose mode is enabled"""
        if options.verbose:
            print(f"[*] {message}")
    
    def print_info(self, message):
        """Print informational message"""
        print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {message}")
    
    def print_warning(self, message):
        """Print warning message"""
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {message}")
    
    def print_error(self, message):
        """Print error message"""
        print(f"{Fore.RED}[!]{Style.RESET_ALL} {message}")
    
    def print_success(self, message):
        """Print success message"""
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {message}")
