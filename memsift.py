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

# Update the main function to save timeline data at the end
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
    try:
        if options.pid_list:
            # Scan specific PIDs
            if len(options.pid_list) == 1:
                # Single PID
                controller.scan_process(options.pid_list[0])
            else:
                # Multiple PIDs
                controller.scan_multiple_pids(options.pid_list)
        elif options.process_name:
            # Scan processes by name
            controller.scan_processes_by_name(options.process_name)
        else:
            # Scan all processes
            controller.scan_all_processes()
        
        print(f"[*] Scan complete. Results: {controller.get_result_count()}")

        # Save timeline data if enabled
        if options.enable_timeline:
            controller.save_timeline_data()
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        # Still save any timeline data we've collected so far
        if options.enable_timeline:
            controller.save_timeline_data()
    except Exception as e:
        print(f"[!] Error during scan: {str(e)}")
        if options.verbose:
            import traceback
            traceback.print_exc()
        # Still save any timeline data we've collected so far
        if options.enable_timeline:
            controller.save_timeline_data()

if __name__ == "__main__":
    main()
