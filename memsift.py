#!/usr/bin/env python3
# MemSift - Memory Extraction and Analysis Tool

import os
import sys
import signal
from modules.arg_parser import ArgParser
from modules.misc import Misc
from modules.regex_lookup import RegexLookup
from modules.process_operations import ProcessOperations
from modules.controller import Controller
from modules.options import Options

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n[!] Keyboard interrupt detected, exiting...")
    sys.exit(0)

def main():
    # Configure signal handler for graceful exit
    signal.signal(signal.SIGINT, signal_handler)
    
    # Initialize options
    options = Options()
    
    # Parse command-line arguments
    arg_parser = ArgParser(options)
    arg_parser.parse_args()
    
    # Display banner if not suppressed
    misc = Misc()
    if not options.no_banner:
        misc.print_banner()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("[!] Error: This tool requires root privileges to access process memory")
        print("[!] Please run with sudo or as root")
        sys.exit(1)
    
    # Initialize regex lookup
    regex_lookup = RegexLookup(options)
    regex_lookup.load_patterns()
    
    # Initialize controller
    controller = Controller(options, regex_lookup, misc)
    
    # Start scanning
    if options.pid:
        # Scan specific process
        controller.scan_process(options.pid)
    elif options.process_name:
        # Scan processes by name
        controller.scan_processes_by_name(options.process_name)
    else:
        # Scan all processes
        controller.scan_all_processes()
    
    print(f"[*] Scan complete. Results: {controller.get_result_count()}")

if __name__ == "__main__":
    main()
