#!/usr/bin/env python3
# Argument parser for MemSift

import argparse
import sys

class ArgParser:
    """Handles command-line argument parsing for MemSift"""
    
    def __init__(self, options):
        """Initialize with options object for storing results"""
        self.options = options
        self.parser = argparse.ArgumentParser(
            description="MemSift - Memory Extraction and Analysis Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        self._setup_arguments()
    
    def _setup_arguments(self):
        """Set up all command-line arguments"""
        # General options
        general = self.parser.add_argument_group("General Options")
        general.add_argument("-v", "--verbose", action="store_true", 
                          help="Enable verbose output")
        general.add_argument("-n", "--no-banner", action="store_true", 
                          help="Suppress banner display")
        
        # Target options
        target = self.parser.add_argument_group("Target Options")
        target.add_argument("-p", "--pid", type=int, 
                          help="Specific process ID to target")
        target.add_argument("-m", "--name", type=str,
                          help="Process name to target (can match multiple processes)")
        target.add_argument("-a", "--all-memory", action="store_true", 
                          help="Scan all memory regions (not just heap/stack)")
        
        # Regex options
        regex = self.parser.add_argument_group("Regex Options")
        regex.add_argument("-r", "--regex-file", type=str, 
                         help="File containing regex patterns")
        
        # Output options
        output = self.parser.add_argument_group("Output Options")
        output.add_argument("-o", "--output-format", type=str, 
                          choices=["plain", "xml", "html"], default="plain",
                          help="Output format (default: plain)")
        output.add_argument("-f", "--output-file", type=str, 
                          help="Write output to specified file")
        output.add_argument("-i", "--show-info", action="store_true", 
                          help="Show detailed process information")
    
    def parse_args(self):
        """Parse command-line arguments and update options"""
        args = self.parser.parse_args()
        
        # Update options based on parsed arguments
        self.options.verbose = args.verbose
        self.options.no_banner = args.no_banner
        self.options.pid = args.pid
        self.options.process_name = args.name
        self.options.dump_all = args.all_memory
        self.options.regex_file = args.regex_file
        self.options.output_format = args.output_format
        self.options.output_file = args.output_file
        self.options.show_process_info = args.show_info
        
        # Validate arguments
        self._validate_args()
        
        if self.options.verbose:
            print(f"[*] {self.options}")
    
    def _validate_args(self):
        """Validate argument combinations and values"""
        # If output file is specified but no output format, use file extension
        if self.options.output_file and not self.options.output_format:
            file_ext = self.options.output_file.split('.')[-1].lower()
            if file_ext in ['html', 'xml']:
                self.options.output_format = file_ext
                
        # Can't specify both pid and process name
        if self.options.pid and self.options.process_name:
            print("[!] Error: Cannot specify both PID and process name. Please use only one.")
            sys.exit(1)
