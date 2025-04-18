#!/usr/bin/env python3
# Process memory operations using ptrace

import os
import ctypes
import time
import pwd
import grp
import struct
from ctypes import c_long, c_void_p, c_char_p, c_ulong

# Define ptrace constants
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_PEEKTEXT = 1
PTRACE_PEEKDATA = 2

# Load libc for ptrace calls
libc = ctypes.CDLL("libc.so.6")

# Set proper return and argument types for ptrace
libc.ptrace.argtypes = [c_ulong, c_ulong, c_void_p, c_void_p]
libc.ptrace.restype = c_long

class ProcessOperations:
    """Handles process memory operations using ptrace"""
    
    def __init__(self, options, misc):
        """Initialize with options object"""
        self.options = options
        self.misc = misc
        self.word_size = ctypes.sizeof(ctypes.c_void_p)  # Platform word size (4 or 8 bytes)
        self.attached_pid = None
    
    def __del__(self):
        """Destructor to automatically detach if needed"""
        if self.attached_pid:
            self.detach_pid()
    
    def attach_pid(self, pid):
        """Attach to a process using ptrace"""
        if not self._pid_exists(pid):
            self.misc.print_error(f"Process {pid} does not exist")
            return False
            
        try:
            # Check if we're already attached
            if self.attached_pid == pid:
                return True
            
            # Detach from any previously attached process
            if self.attached_pid:
                self.detach_pid()
            
            # All arguments need to be properly typed for ctypes
            c_pid = pid  # Don't convert to ctypes yet, pass as int
            c_null = ctypes.c_void_p(0)
            
            # Attach to the process
            res = libc.ptrace(PTRACE_ATTACH, c_pid, c_null, c_null)
            if res == -1:
                err = ctypes.get_errno()
                if err != 0:  # Real error occurred
                    error_msg = os.strerror(err)
                    self.misc.print_error(f"Failed to attach to process {pid}: {error_msg}")
                    return False
            
            # Wait for the process to stop
            try:
                status = os.waitpid(pid, 0)[1]
                if os.WIFSTOPPED(status):
                    self.attached_pid = pid
                    self.misc.print_verbose(f"Attached to process {pid}", self.options)
                    return True
                else:
                    self.misc.print_error(f"Process {pid} did not stop after attach")
                    return False
            except ChildProcessError:
                self.misc.print_error(f"Process {pid} not a child process or permission denied")
                return False
        except Exception as e:
            self.misc.print_error(f"Error attaching to process {pid}: {str(e)}")
            return False
    
    def detach_pid(self):
        """Detach from a process"""
        if not self.attached_pid:
            return True
        
        try:
            # All arguments need to be properly typed for ctypes
            c_pid = self.attached_pid  # Don't convert to ctypes yet, pass as int
            c_null = ctypes.c_void_p(0)
            
            # Detach from the process
            res = libc.ptrace(PTRACE_DETACH, c_pid, c_null, c_null)
            if res == -1:
                err = ctypes.get_errno()
                if err != 0:  # Real error occurred
                    error_msg = os.strerror(err)
                    self.misc.print_error(f"Failed to detach from process {self.attached_pid}: {error_msg}")
                    # Still mark as detached since we can't do much else
                    self.attached_pid = None
                    return False
            
            self.misc.print_verbose(f"Detached from process {self.attached_pid}", self.options)
            self.attached_pid = None
            return True
        except Exception as e:
            self.misc.print_error(f"Error detaching from process {self.attached_pid}: {str(e)}")
            self.attached_pid = None  # Still mark as detached
            return False
    
    def read_word(self, addr):
        """Read a single word from memory"""
        if not self.attached_pid:
            return None
        
        try:
            # All arguments need to be properly typed for ctypes
            c_addr = ctypes.c_void_p(addr)
            c_pid = self.attached_pid  # Pass as int
            c_null = ctypes.c_void_p(0)
            
            result = libc.ptrace(PTRACE_PEEKDATA, c_pid, c_addr, c_null)
            if result == -1:
                err = ctypes.get_errno()
                if err != 0:  # Real error occurred
                    return None
            return result
        except Exception as e:
            self.misc.print_verbose(f"Error reading memory at {hex(addr)}: {str(e)}", self.options)
            return None
    
    def read_bytes(self, addr, size):
        """Read a block of memory as bytes"""
        if not self.attached_pid:
            return None
        
        # Allocate buffer for the data
        data = bytearray()
        
        try:
            # Read memory word by word
            words_to_read = (size + self.word_size - 1) // self.word_size
            for i in range(words_to_read):
                try:
                    # Calculate current address
                    curr_addr = addr + i * self.word_size
                    
                    # Read word from memory
                    word = self.read_word(curr_addr)
                    if word is None:
                        break
                    
                    # Convert the word to bytes
                    try:
                        # Handle negative value correctly
                        if word < 0:
                            # Convert to unsigned representation (2's complement)
                            word = (1 << (self.word_size * 8)) + word
                        word_bytes = word.to_bytes(self.word_size, byteorder='little')
                        data.extend(word_bytes)
                    except (OverflowError, ValueError) as e:
                        self.misc.print_verbose(f"Error converting word to bytes at {hex(curr_addr)}: {str(e)}", self.options)
                        break
                except Exception as e:
                    self.misc.print_verbose(f"Error reading memory at {hex(addr + i * self.word_size)}: {str(e)}", self.options)
                    break
                    
            # If we got some data, return it, otherwise return None
            if data:
                # Truncate to requested size
                return bytes(data[:size])
            return None
        except Exception as e:
            self.misc.print_verbose(f"Error reading memory block at {hex(addr)}: {str(e)}", self.options)
            return None
    
    def read_memory_region(self, start_addr, end_addr):
        """Read a memory region"""
        size = end_addr - start_addr
        if size <= 0:
            return None
        
        # Limit very large regions (for safety)
        max_size = 10 * 1024 * 1024  # 10MB limit
        if size > max_size:
            self.misc.print_warning(f"Large memory region detected ({size} bytes). Limiting to {max_size} bytes.")
            size = max_size
        
        return self.read_bytes(start_addr, size)
    
    def get_process_maps(self, pid):
        """Get memory maps for a process"""
        try:
            maps = []
            maps_path = f"/proc/{pid}/maps"
            
            # Check if maps file exists and is readable
            if not os.path.isfile(maps_path):
                self.misc.print_verbose(f"Maps file does not exist for process {pid}", self.options)
                return []
                
            try:
                with open(maps_path, "r") as f:
                    for line in f:
                        try:
                            fields = line.split()
                            if len(fields) < 5:  # Need at least address, perms, offset, dev, inode
                                continue
                            
                            addr_range = fields[0].split("-")
                            start_addr = int(addr_range[0], 16)
                            end_addr = int(addr_range[1], 16)
                            
                            perms = fields[1]
                            offset = int(fields[2], 16)
                            dev = fields[3]
                            inode = int(fields[4])
                            path = " ".join(fields[5:]) if len(fields) >= 6 else ""
                            
                            # Only include readable regions
                            if 'r' in perms:
                                # Only add regions that are likely to contain data we care about
                                if self.options.dump_all or 'heap' in path.lower() or 'stack' in path.lower() or '[anon' in path.lower():
                                    maps.append({
                                        'start': start_addr,
                                        'end': end_addr,
                                        'perms': perms,
                                        'offset': offset,
                                        'dev': dev,
                                        'inode': inode,
                                        'path': path
                                    })
                        except (ValueError, IndexError) as e:
                            # Skip lines that can't be parsed
                            self.misc.print_verbose(f"Error parsing line in maps file for process {pid}: {str(e)}", self.options)
                            continue
            except PermissionError:
                self.misc.print_verbose(f"Permission denied reading maps for process {pid}", self.options)
                return []
                
            if not maps:
                self.misc.print_verbose(f"No valid memory regions found for process {pid}", self.options)
                
            return maps
        except Exception as e:
            self.misc.print_error(f"Failed to read memory maps for process {pid}: {str(e)}")
            return []
    
    def get_process_info(self, pid):
        """Get detailed information about a process"""
        info = {
            'pid': pid,
            'cmdline': '',
            'exe': '',
            'uid': -1,
            'gid': -1,
            'username': '',
            'groupname': '',
            'start_time': '',
        }
        
        try:
            # Get command line
            with open(f"/proc/{pid}/cmdline", "r") as f:
                info['cmdline'] = f.read().replace('\0', ' ').strip()
            
            # Get executable path
            info['exe'] = os.path.realpath(f"/proc/{pid}/exe")
            
            # Get user/group info
            stat_info = os.stat(f"/proc/{pid}")
            info['uid'] = stat_info.st_uid
            info['gid'] = stat_info.st_gid
            
            try:
                info['username'] = pwd.getpwuid(info['uid']).pw_name
            except:
                info['username'] = str(info['uid'])
                
            try:
                info['groupname'] = grp.getgrgid(info['gid']).gr_name
            except:
                info['groupname'] = str(info['gid'])
            
            # Get process start time
            with open(f"/proc/{pid}/stat", "r") as f:
                stat = f.read().strip().split()
                if len(stat) >= 22:
                    # Get starttime (in clock ticks since boot)
                    starttime = int(stat[21])
                    # Convert to seconds
                    with open("/proc/uptime", "r") as uptime_f:
                        uptime = float(uptime_f.read().split()[0])
                    
                    # Calculate start time
                    seconds_since_boot = starttime / os.sysconf(os.sysconf_names["SC_CLK_TCK"])
                    start_time = time.time() - uptime + seconds_since_boot
                    info['start_time'] = self.misc.timestamp_to_readable(start_time)
            
            return info
        except Exception as e:
            self.misc.print_warning(f"Failed to get some process info for {pid}: {str(e)}")
            return info
    
    def enum_processes(self):
        """Enumerate all processes on the system"""
        pids = []
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                pids.append(int(entry))
        return pids
    
    def find_processes_by_name(self, name):
        """Find processes by name (case insensitive)"""
        matching_pids = []
        name = name.lower()  # Convert to lowercase for case-insensitive comparison
        
        # Get all PIDs
        pids = self.enum_processes()
        
        for pid in pids:
            try:
                # Check against cmdline
                with open(f"/proc/{pid}/cmdline", "r") as f:
                    cmdline = f.read().replace('\0', ' ').strip().lower()
                    if name in cmdline:
                        matching_pids.append(pid)
                        continue
                
                # Check against comm (process name)
                with open(f"/proc/{pid}/comm", "r") as f:
                    comm = f.read().strip().lower()
                    if name in comm:
                        matching_pids.append(pid)
                        continue
                
                # Check against executable name (symlink target)
                try:
                    exe_path = os.path.realpath(f"/proc/{pid}/exe")
                    exe_name = os.path.basename(exe_path).lower()
                    if name in exe_name:
                        matching_pids.append(pid)
                except (FileNotFoundError, PermissionError):
                    pass
                    
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                # Process may have terminated or we don't have permission
                continue
        
        return matching_pids
    
    def _pid_exists(self, pid):
        """Check if a process exists"""
        return os.path.exists(f"/proc/{pid}")
