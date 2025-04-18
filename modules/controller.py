#!/usr/bin/env python3
# Controller class for orchestrating memory scanning

import os
import sys
import time
from modules.process_operations import ProcessOperations
from modules.output_formatter import OutputFormatter

class Controller:
    """Orchestrates the memory scanning process"""
    
    def __init__(self, options, regex_lookup, misc):
        """Initialize with options, regex lookup, and misc utilities"""
        self.options = options
        self.regex_lookup = regex_lookup
        self.misc = misc
        self.process_ops = ProcessOperations(options, misc)
        self.output = OutputFormatter(options, misc)
        self.scan_count = 0
        self.match_count = 0
        self.successful_processes = 0
    
    def scan_processes_by_name(self, process_name):
        """Scan processes matching the specified name"""
        matching_pids = self.process_ops.find_processes_by_name(process_name)
        
        if not matching_pids:
            self.misc.print_error(f"No processes found matching name: {process_name}")
            return
            
        self.misc.print_info(f"Found {len(matching_pids)} processes matching name: {process_name}")
        
        # Reset counter for successful processes
        self.successful_processes = 0
        
        # Scan each matching process
        for pid in matching_pids:
            # Skip our own process
            if pid == os.getpid():
                continue
                
            try:
                if self.scan_process(pid):
                    self.successful_processes += 1
            except KeyboardInterrupt:
                self.misc.print_info("Scan interrupted by user")
                raise
            except Exception as e:
                if self.options.verbose:
                    self.misc.print_error(f"Error scanning process {pid}: {str(e)}")
        
        self.misc.print_info(f"Successfully scanned {self.successful_processes} out of {len(matching_pids)} matching processes")
        
        # Display results
        results = self.regex_lookup.get_results()
        if results:
            self.output.print_results(results)
            
        # Write output to file if specified
        if self.options.output_file:
            self.output.write_to_file(results)
    
    def scan_all_processes(self):
        """Scan all processes on the system"""
        pids = self.process_ops.enum_processes()
        self.misc.print_info(f"Found {len(pids)} processes")
        
        self.successful_processes = 0
        attempted = 0
        skipped_kernel = 0
        permission_errors = 0
        
        # Skip kernel processes and ones without accessible memory maps
        for pid in pids:
            # Skip our own process
            if pid == os.getpid():
                continue
                
            # Skip very low PIDs (likely kernel processes)
            if pid < 10 and not self.options.verbose:
                skipped_kernel += 1
                continue
                
            attempted += 1
            try:
                if self.scan_process(pid):
                    self.successful_processes += 1
            except KeyboardInterrupt:
                self.misc.print_info("Scan interrupted by user")
                raise
            except PermissionError:
                permission_errors += 1
                if self.options.verbose:
                    self.misc.print_error(f"Permission denied scanning process {pid}")
            except Exception as e:
                if self.options.verbose:
                    self.misc.print_error(f"Error scanning process {pid}: {str(e)}")
        
        self.misc.print_info(f"Successfully scanned {self.successful_processes} out of {attempted} attempted processes")
        if skipped_kernel > 0:
            self.misc.print_verbose(f"Skipped {skipped_kernel} low PID (kernel) processes", self.options)
        if permission_errors > 0:
            self.misc.print_verbose(f"Encountered {permission_errors} permission errors", self.options)
        
        # Display results
        results = self.regex_lookup.get_results()
        if results:
            self.output.print_results(results)
            
        # Write output to file if specified
        if self.options.output_file:
            self.output.write_to_file(results)
    
    def scan_process(self, pid):
        """Scan a specific process for sensitive information"""
        try:
            # Get process information if requested
            proc_info = ""
            if self.options.show_process_info:
                info = self.process_ops.get_process_info(pid)
                proc_info = f"{pid} ({info['cmdline']})"
                self.misc.print_info(f"Scanning process {proc_info}")
                
                # Display detailed process info
                self.misc.print_info(f"Process: {info['cmdline']}")
                self.misc.print_info(f"Executable: {info['exe']}")
                self.misc.print_info(f"User: {info['username']} (UID: {info['uid']})")
                self.misc.print_info(f"Group: {info['groupname']} (GID: {info['gid']})")
                self.misc.print_info(f"Start time: {info['start_time']}")
            else:
                proc_info = str(pid)
                self.misc.print_verbose(f"Scanning process {pid}", self.options)
            
            # Get memory maps
            maps = self.process_ops.get_process_maps(pid)
            if not maps:
                if self.options.verbose:
                    self.misc.print_warning(f"No readable memory maps found for process {pid}")
                return False
            
            self.misc.print_verbose(f"Found {len(maps)} memory regions in process {pid}", self.options)
            
            # Filter regions we want to scan
            scannable_regions = [region for region in maps if self.is_scannable_region(region)]
            if not scannable_regions:
                self.misc.print_verbose(f"No scannable memory regions found in process {pid}", self.options)
                return False
                
            # Attach to the process
            if not self.process_ops.attach_pid(pid):
                return False
            
            try:
                # Scan memory regions
                regions_scanned = 0
                for region in scannable_regions:
                    # Scan this region
                    self.scan_memory_region(region, proc_info)
                    regions_scanned += 1
                    
                    # Check if we found matches and display progress occasionally
                    if regions_scanned % 5 == 0:
                        self.misc.print_verbose(f"Scanned {regions_scanned}/{len(scannable_regions)} regions in process {pid}", self.options)
                
                self.misc.print_verbose(f"Scanned {regions_scanned} memory regions in process {pid}", self.options)
                return regions_scanned > 0
                
            finally:
                # Always detach from process
                self.process_ops.detach_pid()
            
        except KeyboardInterrupt:
            # Make sure we detach on Ctrl+C
            if self.process_ops.attached_pid:
                self.process_ops.detach_pid()
            raise
        except Exception as e:
            self.misc.print_error(f"Error scanning process {pid}: {str(e)}")
            # Make sure we detach on error
            if self.process_ops.attached_pid:
                self.process_ops.detach_pid()
            return False
    
    def is_scannable_region(self, region):
        """Determine if a memory region should be scanned"""
        # Skip regions with no read permission
        if 'r' not in region['perms']:
            return False
            
        # Skip very small regions (not worth scanning)
        size = region['end'] - region['start']
        if size < 100:
            return False
            
        # Skip regions that are too large unless dump_all is set
        max_region_size = 50 * 1024 * 1024  # 50MB
        if size > max_region_size and not self.options.dump_all:
            self.misc.print_verbose(f"Skipping large region at 0x{region['start']:x} (size: {size} bytes)", self.options)
            return False
        
        # If dump_all is not set, only scan heap, stack and anonymous mappings
        if not self.options.dump_all:
            path = region['path'].lower()
            return 'heap' in path or 'stack' in path or '[anon' in path
        
        return True
    
    def scan_memory_region(self, region, proc_info):
        """Scan a memory region for sensitive information"""
        start_addr = region['start']
        end_addr = region['end']
        size = end_addr - start_addr
        
        # Region size has already been checked in is_scannable_region
        self.misc.print_verbose(
            f"Scanning region 0x{start_addr:x}-0x{end_addr:x} ({size} bytes) {region['perms']} {region['path']}",
            self.options
        )
        
        try:
            # Read memory with appropriate chunking for large regions
            chunk_size = 1 * 1024 * 1024  # 1MB chunks
            
            # For large regions, break into chunks
            if size > chunk_size:
                for chunk_start in range(start_addr, end_addr, chunk_size):
                    chunk_end = min(chunk_start + chunk_size, end_addr)
                    self.scan_memory_chunk(chunk_start, chunk_end, proc_info, region['path'])
            else:
                # Small enough to read in one go
                self.scan_memory_chunk(start_addr, end_addr, proc_info, region['path'])
                
            # Update counters
            self.scan_count += 1
            
            # Display results occasionally
            current_results = self.regex_lookup.get_result_count()
            if current_results > self.match_count:
                self.misc.print_info(f"Found {current_results} matches so far")
                self.match_count = current_results
                
        except Exception as e:
            self.misc.print_verbose(f"Error scanning memory region at 0x{start_addr:x}: {str(e)}", self.options)
    
    def scan_memory_chunk(self, start_addr, end_addr, proc_info, path_info):
        """Scan a chunk of memory for sensitive information"""
        # Read memory
        data = self.process_ops.read_memory_region(start_addr, end_addr)
        if not data or len(data) < 4:  # Need at least a few bytes to be worth scanning
            return
            
        # Convert to string
        try:
            memory_str = data.decode('utf-8', errors='ignore')
        except:
            memory_str = str(data)
        
        # Strip non-ASCII characters
        memory_str = self.misc.strip_non_ascii(memory_str)
        
        # Apply regex patterns
        self.regex_lookup.search_regex(memory_str, proc_info)
    
    def get_result_count(self):
        """Get the total number of results found"""
        return self.regex_lookup.get_result_count()
