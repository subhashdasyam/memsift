#!/usr/bin/env python3
# Timeline tracking for process memory analysis

import time
import datetime
import json
import os
from collections import defaultdict

class TimelineTracker:
    """Tracks and visualizes the timeline of sensitive data in process memory"""
    
    def __init__(self, options, misc):
        """Initialize with options and misc utilities"""
        self.options = options
        self.misc = misc
        self.timeline_data = defaultdict(lambda: defaultdict(list))
        self.start_time = time.time()
        self.scan_intervals = []
    
    def record_finding(self, timestamp, pid, pattern_type, match_data, memory_region=None):
        """Record a sensitive data finding with timestamp"""
        process_key = str(pid)
        
        # Create the finding record
        finding = {
            'timestamp': timestamp,
            'relative_time': timestamp - self.start_time,
            'pattern_type': pattern_type,
            'match_data': match_data,
            'memory_region': memory_region
        }
        
        # Add to the timeline data
        self.timeline_data[process_key][pattern_type].append(finding)
    
    def record_scan_interval(self, start_time, end_time, process_id=None, scan_type=None):
        """Record when a scan occurred"""
        self.scan_intervals.append({
            'start_time': start_time,
            'end_time': end_time,
            'duration': end_time - start_time,
            'process_id': process_id,
            'scan_type': scan_type
        })
    
    def save_timeline_data(self, output_path):
        """Save timeline data to a JSON file"""
        try:
            output_dir = os.path.dirname(output_path)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            # Convert defaultdict to regular dict for JSON serialization
            serializable_data = {
                'timeline_data': {
                    pid: dict(pattern_dict) 
                    for pid, pattern_dict in self.timeline_data.items()
                },
                'start_time': self.start_time,
                'end_time': time.time(),
                'scan_intervals': self.scan_intervals,
                'metadata': {
                    'start_time_human': datetime.datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S'),
                    'pids_tracked': list(self.timeline_data.keys()),
                    'patterns_found': self._get_all_pattern_types()
                }
            }
            
            with open(output_path, 'w') as f:
                json.dump(serializable_data, f, indent=2)
                
            self.misc.print_success(f"Timeline data saved to {output_path}")
            return True
        except Exception as e:
            self.misc.print_error(f"Error saving timeline data: {str(e)}")
            return False
    
    def generate_html_timeline(self, output_path):
        """Generate an HTML visualization of the timeline"""
        try:
            from jinja2 import Template
            
            # Convert timestamps to human-readable format and add color information
            formatted_data, pattern_colors = self._format_timeline_for_display()
            
            # Create HTML using Jinja2 template
            template_str = self._get_html_template()
            template = Template(template_str)
            
            html_content = template.render(
                timeline_data=formatted_data,
                pattern_colors=pattern_colors,
                pids=list(self.timeline_data.keys()),
                pattern_types=self._get_all_pattern_types(),
                start_time=datetime.datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S'),
                end_time=datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'),
                scan_intervals=self._format_scan_intervals()
            )
            
            # Write HTML to file
            output_dir = os.path.dirname(output_path)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
                
            with open(output_path, 'w') as f:
                f.write(html_content)
                
            self.misc.print_success(f"HTML timeline visualization saved to {output_path}")
            return True
        except ImportError:
            self.misc.print_error("Jinja2 library required for HTML timeline generation. Install with: pip install jinja2")
            return False
        except Exception as e:
            self.misc.print_error(f"Error generating HTML timeline: {str(e)}")
            return False
    
    def _get_all_pattern_types(self):
        """Get a list of all pattern types found across all processes"""
        pattern_types = set()
        for pid_data in self.timeline_data.values():
            pattern_types.update(pid_data.keys())
        return sorted(list(pattern_types))
    
    
    
    def _format_scan_intervals(self):
        """Format scan intervals for display"""
        formatted_intervals = []
        
        for interval in self.scan_intervals:
            formatted = interval.copy()
            formatted['start_time_human'] = datetime.datetime.fromtimestamp(
                interval['start_time']
            ).strftime('%Y-%m-%d %H:%M:%S')
            formatted['end_time_human'] = datetime.datetime.fromtimestamp(
                interval['end_time']
            ).strftime('%Y-%m-%d %H:%M:%S')
            formatted['duration_human'] = f"{interval['duration']:.2f}s"
            
            formatted_intervals.append(formatted)
            
        return formatted_intervals
    
    def _format_timeline_for_display(self):
        """Format timeline data for visualization with color information"""
        formatted_data = {}
        pattern_colors = {}
        
        # Pre-defined color palette
        colors = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12', '#9b59b6', '#1abc9c', 
                '#e67e22', '#95a5a6', '#d35400', '#34495e', '#16a085', '#c0392b', 
                '#27ae60', '#2980b9']
        
        # Get all pattern types and assign colors
        pattern_types = self._get_all_pattern_types()
        for i, pattern_type in enumerate(pattern_types):
            pattern_colors[pattern_type] = colors[i % len(colors)]
        
        # Format the timeline data
        for pid, pid_data in self.timeline_data.items():
            formatted_data[pid] = {}
            
            for pattern_type, findings in pid_data.items():
                formatted_data[pid][pattern_type] = []
                
                for finding in findings:
                    # Create a copy with human-readable time
                    finding_copy = finding.copy()
                    finding_copy['time_human'] = datetime.datetime.fromtimestamp(
                        finding['timestamp']
                    ).strftime('%Y-%m-%d %H:%M:%S')
                    finding_copy['relative_time_human'] = f"{finding['relative_time']:.2f}s"
                    finding_copy['pattern_type'] = pattern_type  # Add pattern type to finding
                    finding_copy['color'] = pattern_colors[pattern_type]  # Add color to finding
                    
                    formatted_data[pid][pattern_type].append(finding_copy)
        
        return formatted_data, pattern_colors

    def _get_html_template(self):
        """Return HTML template for timeline visualization"""
        return '''<!DOCTYPE html>
    <html>
    <head>
        <title>MemSift Memory Timeline Visualization</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 20px;
                background-color: #f8f8f8;
                color: #333;
            }
            h1, h2, h3 {
                color: #2c3e50;
            }
            .info-box {
                background-color: #d5e9f6;
                border-left: 5px solid #3498db;
                padding: 10px;
                margin: 15px 0;
            }
            .timeline-container {
                margin: 20px 0;
                position: relative;
            }
            .timeline {
                position: relative;
                height: 80px;
                background-color: #f0f0f0;
                border-radius: 4px;
                margin-top: 5px;
            }
            .timeline-event {
                position: absolute;
                top: 5px;
                height: 70px;
                background-color: rgba(52, 152, 219, 0.7);
                border-radius: 4px;
                padding: 2px;
                font-size: 10px;
                color: white;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                cursor: pointer;
                transition: background-color 0.2s;
            }
            .timeline-event:hover {
                background-color: rgba(52, 152, 219, 1);
                z-index: 10;
            }
            .scan-marker {
                position: absolute;
                top: 0;
                width: 2px;
                height: 100%;
                background-color: rgba(231, 76, 60, 0.8);
            }
            .process-section {
                border-left: 3px solid #3498db;
                padding-left: 15px;
                margin-bottom: 30px;
            }
            .findings-table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
            }
            .findings-table th, .findings-table td {
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
            }
            .findings-table th {
                background-color: #2c3e50;
                color: white;
            }
            .findings-table tr:nth-child(even) {
                background-color: #f2f2f2;
            }
            .findings-table tr:hover {
                background-color: #e3e3e3;
            }
            .tooltip {
                position: absolute;
                background-color: #333;
                color: white;
                padding: 5px 10px;
                border-radius: 4px;
                font-size: 12px;
                z-index: 100;
                visibility: hidden;
                opacity: 0;
                transition: opacity 0.3s;
            }
            .pattern-badge {
                display: inline-block;
                padding: 2px 8px;
                border-radius: 10px;
                font-size: 12px;
                color: white;
                background-color: #3498db;
                margin-right: 5px;
            }
            .timeline-legend {
                display: flex;
                flex-wrap: wrap;
                margin-bottom: 10px;
            }
            .legend-item {
                display: flex;
                align-items: center;
                margin-right: 15px;
                margin-bottom: 5px;
            }
            .legend-color {
                width: 15px;
                height: 15px;
                border-radius: 3px;
                margin-right: 5px;
            }
        </style>
    </head>
    <body>
        <h1>MemSift Memory Timeline Visualization</h1>
        
        <div class="info-box">
            <p><strong>Scan Start:</strong> {{ start_time }}</p>
            <p><strong>Scan End:</strong> {{ end_time }}</p>
            <p><strong>Processes Tracked:</strong> {{ pids|length }}</p>
            <p><strong>Pattern Types Found:</strong> {{ pattern_types|length }}</p>
        </div>
        
        <h2>Scan Timeline Overview</h2>
        <p>Below shows when sensitive data was found in process memory, with each color representing a different pattern type.</p>
        
        {% for pid in pids %}
        <div class="process-section">
            <h3>Process: {{ pid }}</h3>
            
            <div class="timeline-legend">
                {% for pattern_type in pattern_types %}
                    {% if pattern_type in timeline_data[pid] %}
                    <div class="legend-item">
                        <div class="legend-color" style="background-color: {{ pattern_colors[pattern_type] }}"></div>
                        <span>{{ pattern_type }}</span>
                    </div>
                    {% endif %}
                {% endfor %}
            </div>
            
            <div class="timeline-container">
                <div class="timeline" id="timeline-{{ pid }}">
                    {% if scan_intervals %}
                        {% for pattern_type in pattern_types %}
                            {% if pattern_type in timeline_data[pid] %}
                                {% for finding in timeline_data[pid][pattern_type] %}
                                    <div class="timeline-event" 
                                        style="left: {{ (finding.relative_time / (scan_intervals[-1].end_time - scan_intervals[0].start_time)) * 100 }}%; 
                                                width: 10px;
                                                background-color: {{ finding.color }}"
                                        data-finding="{{ finding | tojson }}">
                                    </div>
                                {% endfor %}
                            {% endif %}
                        {% endfor %}
                        
                        {% for interval in scan_intervals %}
                            {% if interval.process_id == pid or interval.process_id is none %}
                                <div class="scan-marker" style="left: {{ (interval.start_time - scan_intervals[0].start_time) / (scan_intervals[-1].end_time - scan_intervals[0].start_time) * 100 }}%"
                                    title="Scan at {{ interval.start_time_human }}"></div>
                            {% endif %}
                        {% endfor %}
                    {% else %}
                        <p>No scan intervals recorded.</p>
                    {% endif %}
                </div>
            </div>
            
            <h4>Findings Details</h4>
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Pattern Type</th>
                        <th>Match Data</th>
                        <th>Memory Region</th>
                    </tr>
                </thead>
                <tbody>
                    {% for pattern_type in pattern_types %}
                        {% if pattern_type in timeline_data[pid] %}
                            {% for finding in timeline_data[pid][pattern_type] %}
                                <tr>
                                    <td>{{ finding.time_human }}<br><small>(+{{ finding.relative_time_human }})</small></td>
                                    <td><span class="pattern-badge" style="background-color: {{ finding.color }}">{{ pattern_type }}</span></td>
                                    <td>{{ finding.match_data }}</td>
                                    <td>{{ finding.memory_region or 'N/A' }}</td>
                                </tr>
                            {% endfor %}
                        {% endif %}
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endfor %}
        
        <div id="tooltip" class="tooltip"></div>
        
        <script>
            // Add interactive tooltip functionality
            document.addEventListener('DOMContentLoaded', function() {
                const tooltip = document.getElementById('tooltip');
                const events = document.querySelectorAll('.timeline-event');
                
                events.forEach(event => {
                    event.addEventListener('mouseover', function(e) {
                        const finding = JSON.parse(this.getAttribute('data-finding'));
                        
                        tooltip.innerHTML = `
                            <strong>${finding.pattern_type}</strong><br>
                            Time: ${finding.time_human}<br>
                            Match: ${finding.match_data}<br>
                            ${finding.memory_region ? `Region: ${finding.memory_region}` : ''}
                        `;
                        
                        tooltip.style.left = (e.pageX + 10) + 'px';
                        tooltip.style.top = (e.pageY + 10) + 'px';
                        tooltip.style.visibility = 'visible';
                        tooltip.style.opacity = '1';
                    });
                    
                    event.addEventListener('mouseout', function() {
                        tooltip.style.visibility = 'hidden';
                        tooltip.style.opacity = '0';
                    });
                    
                    event.addEventListener('mousemove', function(e) {
                        tooltip.style.left = (e.pageX + 10) + 'px';
                        tooltip.style.top = (e.pageY + 10) + 'px';
                    });
                });
            });
        </script>
    </body>
    </html>
    '''