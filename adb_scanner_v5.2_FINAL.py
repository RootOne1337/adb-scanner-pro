#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADB SCANNER v5.2.1 FIXED - Full featured ADB scanning with security fixes
VERSION: 5.2.1 SECURITY HOTFIX
FIXES:
  * Security: Removed shell=True from subprocess calls
  * Validation: Added IP address validation
  * DoS Prevention: Added thread limit enforcement
  * Stability: Fixed async event handling
"""

import flet as ft
import asyncio
import socket
import subprocess
import threading
import json
import csv
from datetime import datetime
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Tuple, Optional
from pathlib import Path
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import re
import platform
import sys

# ================================================================================
# LOGGING CONFIGURATION
# ================================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner_v5.2.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ================================================================================
# VALIDATION FUNCTIONS
# ================================================================================

def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(p) <= 255 for p in parts)

def validate_port(port: int) -> bool:
    """Validate port number"""
    return 1 <= port <= 65535

def validate_threads(threads: int) -> bool:
    """Validate thread count (prevent DoS)"""
    return 1 <= threads <= 200

# ================================================================================
# DATA CLASSES
# ================================================================================

@dataclass
class ScanSettings:
    """Settings for scanning"""
    # IP ranges
    ip_start: str = "192.168.1.1"
    ip_end: str = "192.168.1.255"
    
    # Ports
    port_start: int = 5037
    port_end: int = 5037
    custom_ports: str = "5037,5555,22,23"
    
    # Scan parameters
    timeout: float = 1.0
    threads: int = 50
    retry_count: int = 2
    
    # What to scan
    scan_adb: bool = True
    scan_ssh: bool = True
    scan_telnet: bool = True
    scan_custom: bool = False
    
    # Optimization
    skip_ping: bool = False
    use_async: bool = True
    
    # Profile
    profile: str = "balanced"  # lightning, quick, balanced, deep, paranoid
    
    def validate(self) -> Tuple[bool, str]:
        """Validate all settings"""
        if not validate_ip(self.ip_start):
            return False, f"Invalid IP start: {self.ip_start}"
        if not validate_ip(self.ip_end):
            return False, f"Invalid IP end: {self.ip_end}"
        if not validate_port(self.port_start):
            return False, f"Invalid port start: {self.port_start}"
        if not validate_port(self.port_end):
            return False, f"Invalid port end: {self.port_end}"
        if self.port_start > self.port_end:
            return False, "Port start cannot be greater than port end"
        if not validate_threads(self.threads):
            return False, f"Invalid threads (1-200): {self.threads}"
        if not (0.1 <= self.timeout <= 10.0):
            return False, f"Invalid timeout (0.1-10.0): {self.timeout}"
        return True, "OK"
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class DeviceInfo:
    """Device information"""
    ip: str
    port: int
    device_type: str  # "ADB", "SSH", "Telnet", "Unknown"
    status: str  # "online", "offline", "unknown"
    device_id: str = ""
    manufacturer: str = ""
    model: str = ""
    version: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self):
        return asdict(self)


@dataclass
class ScanResult:
    """Scan results"""
    devices: List[DeviceInfo] = field(default_factory=list)
    total_scanned: int = 0
    total_found: int = 0
    scan_time: float = 0.0
    settings: ScanSettings = field(default_factory=ScanSettings)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# ================================================================================
# IP ADDRESS GENERATOR
# ================================================================================

def ip_to_tuple(ip: str) -> Tuple[int, int, int, int]:
    """Convert IP to tuple of integers"""
    try:
        return tuple(map(int, ip.split('.')))
    except:
        return (0, 0, 0, 0)

def generate_ip_range(ip_start: str, ip_end: str) -> List[str]:
    """Generate list of IP addresses in range"""
    try:
        # Validate IPs
        if not validate_ip(ip_start) or not validate_ip(ip_end):
            logger.error(f"Invalid IP range: {ip_start} - {ip_end}")
            return []
        
        start = ip_to_tuple(ip_start)
        end = ip_to_tuple(ip_end)
        
        ips = []
        current = list(start)
        
        while tuple(current) <= end:
            ips.append('.'.join(map(str, current)))
            # Increment
            current[3] += 1
            if current[3] > 255:
                current[3] = 0
                current[2] += 1
                if current[2] > 255:
                    current[2] = 0
                    current[1] += 1
                    if current[1] > 255:
                        current[1] = 0
                        current[0] += 1
        
        return ips
    except Exception as e:
        logger.error(f"Error generating IP range: {e}")
        return []

def parse_ports(port_string: str, port_start: int, port_end: int) -> List[int]:
    """Parse ports from string and range"""
    ports = set()
    
    # Add port range
    if validate_port(port_start) and validate_port(port_end):
        for p in range(port_start, port_end + 1):
            ports.add(p)
    
    # Parse custom ports
    try:
        for p_str in port_string.split(','):
            p_str = p_str.strip()
            if '-' in p_str:
                parts = p_str.split('-')
                if len(parts) == 2:
                    p1, p2 = int(parts[0]), int(parts[1])
                    if validate_port(p1) and validate_port(p2) and p1 <= p2:
                        ports.update(range(p1, p2 + 1))
            else:
                p = int(p_str)
                if validate_port(p):
                    ports.add(p)
    except ValueError:
        logger.warning(f"Invalid port specification: {port_string}")
    
    return sorted(list(ports))

# ================================================================================
# ADB SCANNER CLASS
# ================================================================================

class ADBScanner:
    """Main scanner class"""
    
    def __init__(self):
        self.is_scanning = False
        self.devices_found: Dict[str, DeviceInfo] = {}
        self.callback = None
        self.scan_result = ScanResult()
    
    def set_callback(self, callback):
        """Set callback for updates"""
        self.callback = callback
    
    def _notify(self, message: str, progress: float = None, devices: int = None):
        """Send notification"""
        if self.callback:
            self.callback(message=message, progress=progress, devices=devices)
    
    def _check_port(self, ip: str, port: int, timeout: float = 1.0) -> bool:
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _ping_host(self, ip: str) -> bool:
        """Ping host (cross-platform, NO shell injection)"""
        try:
            # Windows: ping -n 1 -w 500
            # Unix: ping -c 1 -W 500
            if platform.system() == 'Windows':
                cmd = ['ping', '-n', '1', '-w', '500', ip]
            else:
                cmd = ['ping', '-c', '1', '-W', '500', ip]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=2,
                check=False
            )
            return result.returncode == 0
        except Exception as e:
            logger.debug(f"Ping failed for {ip}: {e}")
            return False
    
    def _identify_device(self, ip: str, port: int) -> Optional[DeviceInfo]:
        """Identify device type"""
        
        # Check ADB
        if port in [5037, 5555]:
            try:
                result = subprocess.run(
                    ['adb', 'connect', f'{ip}:{port}'],
                    capture_output=True,
                    timeout=2,
                    text=True,
                    check=False
                )
                if 'connected' in result.stdout.lower() or result.returncode == 0:
                    return DeviceInfo(
                        ip=ip,
                        port=port,
                        device_type="ADB",
                        status="online"
                    )
            except Exception as e:
                logger.debug(f"ADB check failed: {e}")
        
        # Check SSH
        if port == 22:
            if self._check_port(ip, port, timeout=0.5):
                return DeviceInfo(
                    ip=ip,
                    port=port,
                    device_type="SSH",
                    status="online"
                )
        
        # Check Telnet
        if port == 23:
            if self._check_port(ip, port, timeout=0.5):
                return DeviceInfo(
                    ip=ip,
                    port=port,
                    device_type="Telnet",
                    status="online"
                )
        
        # Unknown
        if self._check_port(ip, port, timeout=0.5):
            return DeviceInfo(
                ip=ip,
                port=port,
                device_type="Unknown",
                status="online"
            )
        
        return None
    
    def _scan_single_target(self, ip: str, port: int, settings: ScanSettings) -> Optional[DeviceInfo]:
        """Scan single target"""
        
        # Ping check (NO shell=True, secure)
        if not settings.skip_ping:
            if not self._ping_host(ip):
                return None
        
        # Check port
        if not self._check_port(ip, port, timeout=settings.timeout):
            return None
        
        # Identify
        return self._identify_device(ip, port)
    
    async def scan_async(self, settings: ScanSettings):
        """Async multi-threaded scanning"""
        
        # Validate settings FIRST
        is_valid, error_msg = settings.validate()
        if not is_valid:
            self._notify(f"[ERROR] {error_msg}")
            logger.error(f"Invalid settings: {error_msg}")
            return
        
        # Enforce thread limit
        if settings.threads > 200:
            settings.threads = 200
            logger.warning("Thread count capped at 200")
        
        self.is_scanning = True
        self.devices_found = {}
        start_time = time.time()
        
        try:
            # Generate targets
            ips = generate_ip_range(settings.ip_start, settings.ip_end)
            ports = parse_ports(settings.custom_ports, settings.port_start, settings.port_end)
            
            if not ips or not ports:
                self._notify("[ERROR] No valid IPs or ports to scan")
                return
            
            targets = [(ip, port) for ip in ips for port in ports]
            total_targets = len(targets)
            
            self._notify(f"[SCAN START] {total_targets} targets")
            logger.info(f"Scanning: {len(ips)} IPs * {len(ports)} ports = {total_targets} targets")
            
            # Multi-threaded scanning
            scanned = 0
            with ThreadPoolExecutor(max_workers=settings.threads) as executor:
                futures = {
                    executor.submit(self._scan_single_target, ip, port, settings): (ip, port)
                    for ip, port in targets
                }
                
                for future in as_completed(futures):
                    if not self.is_scanning:
                        break
                    
                    try:
                        device = future.result(timeout=settings.timeout + 2)
                        scanned += 1
                        
                        if device:
                            key = f"{device.ip}:{device.port}"
                            self.devices_found[key] = device
                            self._notify(
                                f"[FOUND] {device.ip}:{device.port} ({device.device_type})",
                                progress=scanned / total_targets * 100,
                                devices=len(self.devices_found)
                            )
                            logger.info(f"Device: {key} ({device.device_type})")
                        else:
                            if scanned % 10 == 0:
                                self._notify(
                                    f"[PROGRESS] {scanned}/{total_targets}",
                                    progress=scanned / total_targets * 100
                                )
                    
                    except Exception as e:
                        logger.error(f"Scan error: {e}")
                        scanned += 1
            
            scan_time = time.time() - start_time
            
            # Save results
            self.scan_result = ScanResult(
                devices=list(self.devices_found.values()),
                total_scanned=scanned,
                total_found=len(self.devices_found),
                scan_time=scan_time,
                settings=settings
            )
            
            self._notify(
                f"[COMPLETE] Found {len(self.devices_found)} devices in {scan_time:.1f}s",
                progress=100,
                devices=len(self.devices_found)
            )
            logger.info(f"Result: {len(self.devices_found)} devices, {scan_time:.1f}s")
        
        except Exception as e:
            self._notify(f"[ERROR] {str(e)}")
            logger.error(f"Critical error: {e}")
        
        finally:
            self.is_scanning = False
    
    def stop_scan(self):
        """Stop scanning"""
        self.is_scanning = False
        self._notify("[STOPPED] Scan stopped")
    
    def export_json(self, path: str):
        """Export to JSON"""
        try:
            data = {
                'devices': [d.to_dict() for d in self.scan_result.devices],
                'stats': {
                    'found': self.scan_result.total_found,
                    'scanned': self.scan_result.total_scanned,
                    'time': self.scan_result.scan_time,
                    'timestamp': self.scan_result.timestamp
                }
            }
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.info(f"Exported to JSON: {path}")
        except Exception as e:
            logger.error(f"JSON export error: {e}")
    
    def export_csv(self, path: str):
        """Export to CSV"""
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=['ip', 'port', 'device_type', 'status', 'device_id', 'timestamp']
                )
                writer.writeheader()
                for device in self.scan_result.devices:
                    row = device.to_dict()
                    writer.writerow(row)
            logger.info(f"Exported to CSV: {path}")
        except Exception as e:
            logger.error(f"CSV export error: {e}")


# ================================================================================
# FLET UI APPLICATION
# ================================================================================

class ScannerApp:
    """Main application"""
    
    def __init__(self):
        self.scanner = ADBScanner()
        self.settings = ScanSettings()
        self.scanner.set_callback(self._on_scan_update)
        self.scan_thread = None
    
    def _on_scan_update(self, message: str = "", progress: float = None, devices: int = None):
        """Callback from scanner"""
        if hasattr(self, 'log_text'):
            current = self.log_text.value
            ts = datetime.now().strftime('%H:%M:%S')
            new_line = f"[{ts}] {message}\n"
            self.log_text.value = current + new_line
            # Auto-scroll removed - TextField doesn't have scroll_to in this Flet version
        
        if progress is not None and hasattr(self, 'progress_bar'):
            self.progress_bar.value = progress / 100
        
        if devices is not None and hasattr(self, 'devices_count'):
            self.devices_count.value = f"Found: {devices} devices"
    
    def _build_settings_tab(self) -> ft.Control:
        """Settings tab"""
        
        ip_start_field = ft.TextField(
            label="IP Start",
            value=self.settings.ip_start,
            width=150,
            keyboard_type=ft.KeyboardType.URL
        )
        ip_end_field = ft.TextField(
            label="IP End",
            value=self.settings.ip_end,
            width=150,
            keyboard_type=ft.KeyboardType.URL
        )
        
        port_start_field = ft.TextField(
            label="Port From",
            value=str(self.settings.port_start),
            width=100,
            keyboard_type=ft.KeyboardType.NUMBER
        )
        port_end_field = ft.TextField(
            label="Port To",
            value=str(self.settings.port_end),
            width=100,
            keyboard_type=ft.KeyboardType.NUMBER
        )
        
        custom_ports_field = ft.TextField(
            label="Custom ports (comma separated)",
            value=self.settings.custom_ports,
            width=300,
            multiline=False
        )
        
        timeout_field = ft.TextField(
            label="Timeout (sec)",
            value=str(self.settings.timeout),
            width=100,
            keyboard_type=ft.KeyboardType.NUMBER
        )
        
        threads_slider = ft.Slider(
            min=1,
            max=200,
            value=self.settings.threads,
            label="Threads: {value}",
            width=300
        )
        
        scan_adb_check = ft.Checkbox(label="Scan ADB", value=self.settings.scan_adb)
        scan_ssh_check = ft.Checkbox(label="Scan SSH", value=self.settings.scan_ssh)
        scan_telnet_check = ft.Checkbox(label="Scan Telnet", value=self.settings.scan_telnet)
        skip_ping_check = ft.Checkbox(label="Skip Ping check", value=self.settings.skip_ping)
        
        profile_dropdown = ft.Dropdown(
            label="Scan Profile",
            options=[
                ft.dropdown.Option("lightning", "Lightning (fast)"),
                ft.dropdown.Option("quick", "Quick"),
                ft.dropdown.Option("balanced", "Balanced"),
                ft.dropdown.Option("deep", "Deep"),
                ft.dropdown.Option("paranoid", "Paranoid")
            ],
            value=self.settings.profile,
            width=250
        )
        
        def apply_profile(name: str):
            """Apply preset profile"""
            profiles = {
                "lightning": ScanSettings(threads=200, timeout=0.3, port_end=5555),
                "quick": ScanSettings(threads=100, timeout=0.5, port_end=5555),
                "balanced": ScanSettings(threads=50, timeout=1.0, port_end=5555),
                "deep": ScanSettings(threads=30, timeout=2.0, port_end=65535),
                "paranoid": ScanSettings(threads=10, timeout=5.0, port_end=65535, retry_count=3)
            }
            if name in profiles:
                prof = profiles[name]
                timeout_field.value = str(prof.timeout)
                threads_slider.value = prof.threads
                port_end_field.value = str(prof.port_end)
                self.page.update()
        
        profile_dropdown.on_change = lambda e: apply_profile(profile_dropdown.value)
        
        def save_settings():
            """Save settings"""
            try:
                self.settings.ip_start = ip_start_field.value
                self.settings.ip_end = ip_end_field.value
                self.settings.port_start = int(port_start_field.value)
                self.settings.port_end = int(port_end_field.value)
                self.settings.custom_ports = custom_ports_field.value
                self.settings.timeout = float(timeout_field.value)
                self.settings.threads = int(threads_slider.value)
                self.settings.scan_adb = scan_adb_check.value
                self.settings.scan_ssh = scan_ssh_check.value
                self.settings.scan_telnet = scan_telnet_check.value
                self.settings.skip_ping = skip_ping_check.value
                self.settings.profile = profile_dropdown.value
                
                # Validate
                is_valid, error_msg = self.settings.validate()
                if is_valid:
                    self._on_scan_update("[OK] Settings saved")
                else:
                    self._on_scan_update(f"[ERROR] {error_msg}")
            except Exception as e:
                self._on_scan_update(f"[ERROR] {e}")
        
        save_btn = ft.ElevatedButton(
            text="Save",
            on_click=lambda e: save_settings(),
            bgcolor=ft.Colors.BLUE_600,
            color=ft.Colors.WHITE,
            width=200
        )
        
        settings_col = ft.Column(
            scroll=ft.ScrollMode.AUTO,
            controls=[
                ft.Text("SETTINGS", size=20, weight="bold", color=ft.Colors.BLUE_600),
                
                ft.Divider(height=20),
                ft.Text("IP ADDRESSES", size=16, weight="bold"),
                ft.Row([
                    ft.Column([ip_start_field, ip_end_field], spacing=10),
                ]),
                
                ft.Divider(height=20),
                ft.Text("PORTS", size=16, weight="bold"),
                ft.Row([
                    port_start_field,
                    ft.Text("-", size=16),
                    port_end_field,
                ]),
                custom_ports_field,
                
                ft.Divider(height=20),
                ft.Text("PARAMETERS", size=16, weight="bold"),
                ft.Row([timeout_field, ft.Text("sec")]),
                ft.Text("Concurrent threads:"),
                threads_slider,
                
                ft.Divider(height=20),
                ft.Text("WHAT TO SCAN", size=16, weight="bold"),
                scan_adb_check,
                scan_ssh_check,
                scan_telnet_check,
                skip_ping_check,
                
                ft.Divider(height=20),
                ft.Text("PROFILES", size=16, weight="bold"),
                profile_dropdown,
                
                ft.Divider(height=20),
                save_btn,
            ],
            spacing=10
        )
        
        # Wrap in Container for padding
        return ft.Container(
            content=settings_col,
            padding=20
        )
    
    def _build_scan_tab(self) -> ft.Control:
        """Scan tab"""
        
        self.log_text = ft.TextField(
            multiline=True,
            min_lines=15,
            read_only=True,
            value="[WAITING FOR SCAN]\n",
            text_size=10
        )
        
        self.progress_bar = ft.ProgressBar(value=0, width=500)
        self.devices_count = ft.Text("Found: 0 devices", size=16, weight="bold")
        
        def start_scan():
            """Start scan"""
            if not self.scanner.is_scanning:
                self.log_text.value = "[SCAN STARTED]\n"
                self.progress_bar.value = 0
                self.devices_count.value = "Found: 0 devices"
                self.page.update()
                
                def run_scan():
                    try:
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        loop.run_until_complete(self.scanner.scan_async(self.settings))
                    except Exception as e:
                        logger.error(f"Scan thread error: {e}")
                        self._on_scan_update(f"[ERROR] {str(e)}")
                
                self.scan_thread = threading.Thread(target=run_scan, daemon=True)
                self.scan_thread.start()
        
        def stop_scan():
            """Stop scan"""
            self.scanner.stop_scan()
        
        def export_results():
            """Export results"""
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.scanner.export_json(f'scan_result_{ts}.json')
            self.scanner.export_csv(f'scan_result_{ts}.csv')
            self._on_scan_update(f"[OK] Exported to scan_result_{ts}.*")
        
        start_btn = ft.ElevatedButton(
            text="START",
            on_click=lambda e: start_scan(),
            bgcolor=ft.Colors.GREEN_600,
            color=ft.Colors.WHITE,
            width=200
        )
        
        stop_btn = ft.ElevatedButton(
            text="STOP",
            on_click=lambda e: stop_scan(),
            bgcolor=ft.Colors.RED_600,
            color=ft.Colors.WHITE,
            width=200
        )
        
        export_btn = ft.ElevatedButton(
            text="EXPORT",
            on_click=lambda e: export_results(),
            bgcolor=ft.Colors.BLUE_600,
            color=ft.Colors.WHITE,
            width=200
        )
        
        scan_col = ft.Column(
            scroll=ft.ScrollMode.AUTO,
            controls=[
                ft.Text("SCANNING", size=20, weight="bold", color=ft.Colors.BLUE_600),
                
                ft.Row([start_btn, stop_btn, export_btn], spacing=10),
                
                ft.Divider(height=20),
                self.devices_count,
                self.progress_bar,
                
                ft.Divider(height=20),
                ft.Text("SCAN LOG:", size=14, weight="bold"),
                self.log_text,
            ],
            spacing=10
        )
        
        # Wrap in Container for padding
        return ft.Container(
            content=scan_col,
            padding=20,
            expand=True
        )
    
    def _build_results_tab(self) -> ft.Control:
        """Results tab"""
        
        results_list = ft.ListView(
            expand=True,
            spacing=5,
            auto_scroll=True
        )
        
        def update_results():
            """Update results list"""
            results_list.controls.clear()
            
            if not self.scanner.scan_result.devices:
                results_list.controls.append(
                    ft.Text("No results. Run scan first.", color=ft.Colors.GREY_600)
                )
            else:
                for device in self.scanner.scan_result.devices:
                    results_list.controls.append(
                        ft.Card(
                            content=ft.Container(
                                content=ft.Column([
                                    ft.Text(f"PC: {device.ip}:{device.port}", weight="bold", size=12),
                                    ft.Text(f"Type: {device.device_type}", size=10, color=ft.Colors.BLUE_600),
                                    ft.Text(f"Status: {device.status}", size=10),
                                    ft.Text(device.timestamp, size=9, color=ft.Colors.GREY_600)
                                ]),
                                padding=10
                            )
                        )
                    )
            
            self.page.update()
        
        self._update_results = update_results
        
        results_col = ft.Column(
            controls=[
                ft.Text("RESULTS", size=20, weight="bold", color=ft.Colors.BLUE_600),
                ft.Divider(height=20),
                results_list
            ],
            spacing=10,
            expand=True
        )
        
        # Wrap in Container for padding
        return ft.Container(
            content=results_col,
            padding=20,
            expand=True
        )
    
    def build(self, page: ft.Page):
        """Build UI"""
        self.page = page
        page.title = "ADB SCANNER v5.2.1 FIXED"
        page.window_width = 1000
        page.window_height = 700
        
        page.theme_mode = ft.ThemeMode.LIGHT
        page.theme = ft.Theme(
            color_scheme=ft.ColorScheme(
                primary=ft.Colors.BLUE_600,
                secondary=ft.Colors.BLUE_700,
                surface=ft.Colors.GREY_100,
                background=ft.Colors.WHITE
            )
        )
        
        tabs = ft.Tabs(
            selected_index=0,
            tabs=[
                ft.Tab(
                    text="SCANNING",
                    content=self._build_scan_tab()
                ),
                ft.Tab(
                    text="SETTINGS",
                    content=self._build_settings_tab()
                ),
                ft.Tab(
                    text="RESULTS",
                    content=self._build_results_tab()
                ),
            ]
        )
        
        page.add(
            ft.Column([
                ft.Row([
                    ft.Icon(name=ft.Icons.LANGUAGE, size=30, color=ft.Colors.BLUE_600),
                    ft.Text("ADB SCANNER v5.2.1 FIXED", size=24, weight="bold", color=ft.Colors.BLUE_600),
                ]),
                ft.Divider(height=10),
                tabs
            ], expand=True)
        )


# ================================================================================
# MAIN
# ================================================================================

def main():
    """Main function"""
    try:
        app = ScannerApp()
        ft.app(target=app.build)
    except Exception as e:
        logger.error(f"Application error: {e}")
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
