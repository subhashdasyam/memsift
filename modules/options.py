#!/usr/bin/env python3
# Options class for storing global configuration

class Options:
    """Global configuration options for mXtract"""
    
    def __init__(self):
        # General options
        self.verbose = False
        self.no_banner = False
        
        # Target options
        self.pid_str = None  # Comma-separated process IDs string
        self.pid_list = []   # List of process IDs after parsing
        self.process_name = None  # Process name to target
        self.dump_all = False  # Dump all memory regions (not just heap/stack)
        
        # Regex options
        self.regex_file = None  # File containing regex patterns
        self.default_regex_file = "patterns/default.db"
        
        # Output options
        self.output_format = "plain"  # Default output format
        self.output_file = None  # Output file path
        self.show_process_info = False  # Show detailed process information

    def __str__(self):
        """String representation of current options"""
        return (
            f"Options:\n"
            f"  Verbose: {self.verbose}\n"
            f"  No Banner: {self.no_banner}\n"
            f"  PIDs: {', '.join(map(str, self.pid_list)) if self.pid_list else 'None'}\n"
            f"  Process Name: {self.process_name}\n"
            f"  Dump All: {self.dump_all}\n"
            f"  Regex File: {self.regex_file or self.default_regex_file}\n"
            f"  Output Format: {self.output_format}\n"
            f"  Output File: {self.output_file}\n"
            f"  Show Process Info: {self.show_process_info}"
        )
