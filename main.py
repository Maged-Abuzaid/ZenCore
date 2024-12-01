import ctypes
import logging
import math
import os
import string
import subprocess
import sys
import winreg
from datetime import datetime

import PyQt5
from PyQt5.QtCore import (QThread, pyqtSignal, QObject, Qt, QFile, QTextStream)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QPushButton, QVBoxLayout, QHBoxLayout, QProgressBar,
    QTextEdit, QLabel, QGroupBox, QMessageBox, QDialog, QScrollArea, QCheckBox, QFrame,
    QTabWidget, QSizePolicy, QListWidget, QSplitter, QListWidgetItem
)

LOG_BASE_PATH = os.path.join(os.path.expanduser("~"), "Documents", "ZenCore", "Logs")

LOG_SECTIONS = {
    "disk_cleanup": os.path.join(LOG_BASE_PATH, "Disk Cleanup"),
    "defragment_and_optimize_drives": os.path.join(LOG_BASE_PATH, "Defragment & Optimize Drives"),
    "system_health_check": os.path.join(LOG_BASE_PATH, "System Integrity Scan & Repair")
}

SECTION_NAME_MAPPING = {
    "disk_cleanup": "Disk Cleanup",
    "defragment_and_optimize_drives": "Defragment && Optimize Drives",
    "system_health_check": "System Integrity Scan && Repair"
}

CUSTOM_CLEANUP_PATHS = {
    "System Temporary Files": [
        r"C:\Windows\Temp",
        os.path.expandvars(r"%TEMP%")
    ],
    "Browser Cache Files": [
        # Will be populated dynamically
    ],
    "Windows Update Files": [
        os.path.expandvars(r"%WINDIR%\SoftwareDistribution\Download")
    ],
    "Windows Thumbnail Cache": [
        os.path.expandvars(r"%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer")
    ],
    "Windows Prefetch Data": [
        r"C:\Windows\Prefetch"
    ]
}

def get_browser_cache_paths():
    """Scan for browser cache paths on the system."""
    cache_paths = []
    username = os.path.expandvars("%USERNAME%")

    # Chrome paths (including profiles)
    chrome_base = os.path.expandvars(r"%USERPROFILE%\AppData\Local\Google\Chrome\User Data")
    if os.path.exists(chrome_base):
        # Check default profile
        default_cache = os.path.join(chrome_base, "Default", "Cache")
        if os.path.exists(default_cache):
            cache_paths.append(default_cache)

        # Check numbered profiles
        for item in os.listdir(chrome_base):
            if item.startswith("Profile "):
                profile_cache = os.path.join(chrome_base, item, "Cache")
                if os.path.exists(profile_cache):
                    cache_paths.append(profile_cache)

    # Firefox paths
    firefox_base = os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles")
    if os.path.exists(firefox_base):
        for item in os.listdir(firefox_base):
            if item.endswith(".default") or item.endswith(".default-release"):
                cache_path = os.path.join(firefox_base, item, "cache2")
                if os.path.exists(cache_path):
                    cache_paths.append(cache_path)

    # Opera paths
    opera_cache = os.path.expandvars(r"%APPDATA%\Opera Software\Opera Stable\Cache")
    if os.path.exists(opera_cache):
        cache_paths.append(opera_cache)

    # Edge paths
    edge_base = os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data")
    if os.path.exists(edge_base):
        # Check default profile
        default_cache = os.path.join(edge_base, "Default", "Cache")
        if os.path.exists(default_cache):
            cache_paths.append(default_cache)

        # Check numbered profiles
        for item in os.listdir(edge_base):
            if item.startswith("Profile "):
                profile_cache = os.path.join(edge_base, item, "Cache")
                if os.path.exists(profile_cache):
                    cache_paths.append(profile_cache)

    # Internet Explorer cache
    ie_cache = os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\INetCache")
    if os.path.exists(ie_cache):
        cache_paths.append(ie_cache)

    return cache_paths


# Update the browser cache paths at program startup
CUSTOM_CLEANUP_PATHS["Browser Cache Files"] = get_browser_cache_paths()

def main():
    """Main entry point of the application."""
    # Check for admin rights at startup
    if not is_admin():
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            " ".join(sys.argv),
            None,
            1  # SW_SHOWNORMAL
        )
        return

    # Create application
    app = QApplication(sys.argv)

    # Set application style
    app.setStyle('Fusion')

    # Set a global font with a slightly larger size
    global_font = QFont("MonoLisa", 10)  # You can choose any font and size
    app.setFont(global_font)

    # Create and show main window
    window = ZenCore()
    window.setWindowIcon(QIcon(resource_path('assets/icon.ico')))  # Set the icon
    window.show()

    # Start event loop
    sys.exit(app.exec_())


def get_available_drives():
    """
    Get all available drives suitable for optimization.
    Returns a list of drive letters that are fixed (local) drives.
    """
    import win32api
    import win32file
    import wmi

    suitable_drives = []
    try:
        # Initialize WMI
        c = wmi.WMI()

        # Get all drives from WMI
        wmi_drives = c.Win32_LogicalDisk()

        for drive in wmi_drives:
            # Check if it's a local fixed drive (Type 3)
            # Skip CD-ROM (Type 5) and Network Drives (Type 4)
            if drive.DriveType == 3:  # Fixed drive
                drive_letter = drive.DeviceID
                try:
                    # Additional checks
                    drive_type = win32file.GetDriveType(drive_letter)
                    if drive_type == win32file.DRIVE_FIXED:
                        # Check if drive is ready and accessible
                        volume_info = win32api.GetVolumeInformation(drive_letter + "\\")
                        suitable_drives.append(drive_letter)
                except Exception:
                    continue

    except Exception as e:
        print(f"Error detecting drives: {e}")
        # Fallback to basic detection if WMI fails
        drives = win32api.GetLogicalDriveStrings()
        drives = drives.split('\000')[:-1]
        for drive in drives:
            try:
                if win32file.GetDriveType(drive) == win32file.DRIVE_FIXED:
                    suitable_drives.append(drive[:2])  # Get only the drive letter with colon
            except:
                continue

    return suitable_drives


def resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller."""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(os.path.dirname(os.path.abspath(__file__)))

    abs_path = os.path.join(base_path, relative_path)

    # Debug logging
    if not os.path.exists(abs_path):
        print(f"Warning: Resource not found at {abs_path}")
        # Try current directory as fallback
        alt_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)
        if os.path.exists(alt_path):
            print(f"Found resource at alternate path: {alt_path}")
            return alt_path
        print(f"Resource not found in alternate path: {alt_path}")

    return abs_path


def load_stylesheet(file_path):
    """Load a QSS stylesheet from the given file path."""
    try:
        # Use resource_path to get the correct path
        full_path = resource_path(file_path)
        if not os.path.exists(full_path):
            print(f"Stylesheet file not found: {full_path}")
            return ""

        with open(full_path, 'r', encoding='utf-8') as file:
            return file.read()
    except Exception as e:
        print(f"Error loading stylesheet {file_path}: {str(e)}")
        return ""


def is_admin():
    """Check if the program is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def get_cleanup_categories():
    """Scan Windows Registry for available cleanup categories and add custom categories."""
    categories = []

    # Get built-in Windows cleanup categories
    try:
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            num_subkeys = winreg.QueryInfoKey(key)[0]

            for i in range(num_subkeys):
                try:
                    subkey_name = winreg.EnumKey(key, i)

                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{key_path}\\{subkey_name}") as subkey:
                        try:
                            display_name = winreg.QueryValueEx(subkey, 'DisplayName')[0]
                        except:
                            display_name = subkey_name

                        try:
                            description = winreg.QueryValueEx(subkey, 'Description')[0]
                        except:
                            description = ""

                        category = {
                            'key_name': subkey_name,
                            'display_name': display_name,
                            'description': description,
                            'registry_path': f"{key_path}\\{subkey_name}",
                            'is_custom': False
                        }

                        if isinstance(category['display_name'], str):
                            category['display_name'] = os.path.expandvars(category['display_name'])
                        if isinstance(category['description'], str):
                            category['description'] = os.path.expandvars(category['description'])

                        categories.append(category)
                except Exception as e:
                    print(f"Error processing subkey {i}: {str(e)}")
                    continue
    except Exception as e:
        print(f"Error accessing registry: {str(e)}")

    # Add custom cleanup categories
    for display_name, paths in CUSTOM_CLEANUP_PATHS.items():
        category = {
            'key_name': display_name,  # Use display name as key_name for custom categories
            'display_name': display_name,
            'description': f"Clean files in: {', '.join(paths)}",
            'paths': paths,
            'is_custom': True
        }
        categories.append(category)

    return categories


def get_log_filename():
    """Generate timestamp-based log filename."""
    return datetime.now().strftime("%Y-%m-%d_%H-%M.log")


def create_hyperlink(url, text, icon_path=None):
    """
    Helper function to create an HTML hyperlink.
    - If icon_path is provided, it includes the icon in the link.
    - Otherwise, it creates a simple text link with specified styles.
    """
    if icon_path:
        return (
            f'<a href="{url}" style="text-decoration:none; color:#4ea8f2;">'
            f'<img src="file://{icon_path}" width="16" height="16" style="vertical-align: middle; margin-right: 5px;"> {text}</a>'
        )
    else:
        return f'<a href="{url}" style="text-decoration:none; color:#4ea8f2;">{text}</a>'

class WorkerSignals(QObject):
    update_text = pyqtSignal(str)
    update_progress = pyqtSignal(int)
    error = pyqtSignal(str)
    finished = pyqtSignal()


class Worker(QThread):
    """Worker thread for running system maintenance tasks."""

    def __init__(self, task, logger, options=None, drives=None, commands=None):
        super().__init__()
        self.task = task
        self.logger = logger  # Specific logger for the task
        self.options = options or set()  # For Disk Cleanup
        self.drives = drives or []  # For Defragmentation
        self.commands = commands or []  # For Health Check
        self.signals = WorkerSignals()
        self.is_running = True
        self.current_process = None

    def run(self):
        """Executes the assigned task."""
        try:
            if self.task == "defrag":
                self._run_defrag()
            elif self.task == "cleanup":
                self._run_cleanup()
            elif self.task == "health_check":
                self._run_health_check()
            else:
                self.logger.error(f"Unknown task: {self.task}")
                self.signals.error.emit(f"Unknown task: {self.task}")
        except Exception as e:
            self.logger.error(f"Unexpected error: {str(e)}")
            self.signals.error.emit(str(e))
        finally:
            self.signals.finished.emit()

    def _run_cleanup(self):
        """Performs disk cleanup with accurate space tracking."""
        try:
            self.logger.info("Starting Disk Cleanup...")
            self.signals.update_text.emit("=== Selected Cleanup Options ===")

            if not self.options:
                self.logger.error("No cleanup options selected.")
                self.signals.update_text.emit("No cleanup options selected.")
                self.signals.update_progress.emit(100)
                return

            # Split selected options into built-in and custom categories
            builtin_options = {opt for opt in self.options if not opt.startswith("Custom - ")}
            custom_options = {opt for opt in self.options if opt.startswith("Custom - ")}

            # Track space for each drive separately
            drives_space_before = {}
            for drive_letter in range(ord('A'), ord('Z') + 1):
                drive = f"{chr(drive_letter)}:"
                if os.path.exists(drive):
                    space = self.get_drive_free_space(drive)
                    if space > 0:
                        drives_space_before[drive] = space
                        self.logger.info(f"Drive {drive} free space before cleanup: {self._format_size(space)}")

            total_space_freed = 0

            # Handle built-in Windows cleanup if any selected
            if builtin_options:
                # First validate which cleanup options are available
                key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
                available_options = {}

                # Get all available cleanup categories from the registry
                all_cleanup_categories = set()
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ) as key:
                        num_subkeys = winreg.QueryInfoKey(key)[0]
                        for i in range(num_subkeys):
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                all_cleanup_categories.add(subkey_name)
                            except WindowsError:
                                continue
                except Exception as e:
                    self.logger.error(f"Error enumerating cleanup categories: {str(e)}")

                # Check each selected option's availability
                for category in builtin_options:
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{key_path}\\{category}") as subkey:
                            try:
                                display_name = winreg.QueryValueEx(subkey, 'DisplayName')[0]
                                if isinstance(display_name, str):
                                    display_name = os.path.expandvars(display_name)
                            except Exception:
                                display_name = category

                            available_options[category] = {
                                'display_name': display_name,
                                'available': True,
                                'reason': 'Available for cleanup'
                            }
                    except WindowsError:
                        available_options[category] = {
                            'display_name': category,
                            'available': False,
                            'reason': 'Category not found in system'
                        }

                # Display initial status for each option
                for category, info in available_options.items():
                    status = "✓ Will clean" if info['available'] else "✗ Skipped"
                    self.signals.update_text.emit(f"{info['display_name']}: {status} - {info['reason']}")

                # Count available options
                active_options = sum(1 for info in available_options.values() if info['available'])
                if active_options > 0:
                    self.signals.update_text.emit("\n=== Starting Windows Cleanup Process ===")

                    # Use SAGESET/SAGERUN method
                    sage_number = 123

                    # Reset all StateFlags for this SAGE number
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ) as key:
                            num_subkeys = winreg.QueryInfoKey(key)[0]
                            for i in range(num_subkeys):
                                try:
                                    subkey_name = winreg.EnumKey(key, i)
                                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                                        f"{key_path}\\{subkey_name}",
                                                        0,
                                                        winreg.KEY_WRITE) as subkey:
                                        value_name = f"StateFlags{sage_number:04d}"
                                        try:
                                            winreg.DeleteValue(subkey, value_name)
                                        except FileNotFoundError:
                                            pass
                                except Exception:
                                    continue
                    except Exception as e:
                        self.logger.error(f"Error resetting StateFlags: {str(e)}")

                    # Set StateFlags for ALL categories (explicitly enable or disable each one)
                    for category in all_cleanup_categories:
                        try:
                            with winreg.OpenKey(
                                    winreg.HKEY_LOCAL_MACHINE,
                                    f"{key_path}\\{category}",
                                    0,
                                    winreg.KEY_WRITE) as subkey:
                                value_name = f"StateFlags{sage_number:04d}"
                                state_value = 2 if (category in builtin_options and
                                                    category in available_options and
                                                    available_options[category]['available']) else 0
                                winreg.SetValueEx(subkey, value_name, 0, winreg.REG_DWORD, state_value)
                        except Exception as e:
                            self.logger.error(f"Error setting StateFlags for {category}: {str(e)}")

                    # Run cleanmgr
                    try:
                        cmd = f"cleanmgr.exe /sagerun:{sage_number}"
                        process = subprocess.Popen(
                            cmd,
                            shell=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
                        )

                        self.current_process = process

                        while process.poll() is None:
                            if not self.is_running:
                                process.terminate()
                                break
                            self.msleep(500)

                        stdout, stderr = process.communicate()
                        if process.returncode != 0:
                            self.logger.error(f"Windows Cleanup failed with return code {process.returncode}")
                            if stderr:
                                self.logger.error(f"Error output: {stderr.strip()}")
                                self.signals.update_text.emit(f"Error output: {stderr.strip()}")
                        else:
                            self.logger.info("Windows Cleanup completed successfully.")
                            self.signals.update_text.emit("Windows Cleanup completed successfully.")

                    finally:
                        # Cleanup: Remove StateFlags from ALL categories
                        for category in all_cleanup_categories:
                            try:
                                with winreg.OpenKey(
                                        winreg.HKEY_LOCAL_MACHINE,
                                        f"{key_path}\\{category}",
                                        0,
                                        winreg.KEY_WRITE) as subkey:
                                    value_name = f"StateFlags{sage_number:04d}"
                                    try:
                                        winreg.DeleteValue(subkey, value_name)
                                    except FileNotFoundError:
                                        pass
                            except Exception:
                                pass

            # Handle custom cleanup options
            if custom_options:
                self.signals.update_text.emit("\n=== Processing Custom Cleanup Options ===")

                for option in custom_options:
                    if not self.is_running:
                        break

                    paths = CUSTOM_CLEANUP_PATHS.get(option, [])
                    if not paths:
                        continue

                    self.signals.update_text.emit(f"\nCleaning {option}...")
                    space_freed, files_removed = self.clean_custom_paths(paths)

                    if space_freed > 0:
                        self.signals.update_text.emit(
                            f"Cleaned {files_removed} files, freed {self._format_size(space_freed)}")
                        total_space_freed += space_freed
                    else:
                        self.signals.update_text.emit("No files needed cleaning")

            # Ensure progress bar reaches 100%
            self.signals.update_progress.emit(100)

            # Calculate final space freed per drive
            self.signals.update_text.emit("\n=== Cleanup Results ===")

            for drive, space_before in drives_space_before.items():
                space_after = self.get_drive_free_space(drive)
                space_difference = space_after - space_before

                if space_difference != 0:
                    if space_difference > 0:
                        self.signals.update_text.emit(
                            f"Drive {drive} space freed: {self._format_size(space_difference)}")
                    else:
                        self.signals.update_text.emit(
                            f"Drive {drive} space used: {self._format_size(-space_difference)}")
                    total_space_freed += space_difference

            # Show total results
            if total_space_freed > 0:
                self.signals.update_text.emit(
                    f"\nTotal space freed across all drives: {self._format_size(total_space_freed)}")
                self.logger.info(f"Total space freed: {self._format_size(total_space_freed)}")
            elif total_space_freed < 0:
                self.signals.update_text.emit(f"\nTotal disk usage increased: {self._format_size(-total_space_freed)}")
                self.logger.info(f"Total disk usage increased: {self._format_size(-total_space_freed)}")
            else:
                self.signals.update_text.emit("\nNo significant disk space change detected")
                self.logger.info("No significant disk space change detected")

        except Exception as e:
            # Handle any exceptions that were not caught by inner try-except blocks
            self.logger.error(f"Error during cleanup: {str(e)}")
            self.signals.update_text.emit(f"Error during cleanup: {str(e)}")
            self.signals.error.emit(str(e))
        finally:
            # Any cleanup actions that need to be performed regardless of success or failure
            self.logger.info("Disk cleanup process finalized.")
            self.signals.update_text.emit("Disk cleanup process finalized.")
            # Optionally, ensure the progress bar is set to 100%
            self.signals.update_progress.emit(100)

    def _run_defrag(self):
        """Handles drive defragmentation with automatic drive detection and optimization decision based on analysis."""
        if not self.drives:
            self.logger.info("No drives selected for optimization.")
            self.signals.update_text.emit("No drives selected for optimization.")
            self.signals.update_progress.emit(100)
            return

        self.logger.info(f"Selected drives: {', '.join(self.drives)}")
        self.signals.update_text.emit(f"Selected drives: {', '.join(self.drives)}")

        # First analyze all drives
        drives_to_optimize = []
        for drive in self.drives:
            if not self.is_running:
                break

            self.logger.info(f"Analyzing drive {drive}...")
            self.signals.update_text.emit(f"Analyzing drive {drive}...")
            needs_optimization, frag_level = self.analyze_drive(drive)

            if needs_optimization:
                drives_to_optimize.append((drive, frag_level))
                self.logger.info(
                    f"Drive {drive} needs optimization (Fragmentation: {frag_level if frag_level >= 0 else 'Unknown'}%)"
                )
                self.signals.update_text.emit(
                    f"Drive {drive} needs optimization (Fragmentation: {frag_level if frag_level >= 0 else 'Unknown'}%)"
                )
            else:
                self.logger.info(f"Drive {drive} does not need optimization")
                self.signals.update_text.emit(f"Drive {drive} does not need optimization")

        if not drives_to_optimize:
            self.logger.info("No drives require optimization.")
            self.signals.update_text.emit("No drives require optimization.")
            self.signals.update_progress.emit(100)
            return

        # Sort drives by fragmentation level (highest first)
        drives_to_optimize.sort(key=lambda x: x[1] if x[1] >= 0 else 999, reverse=True)

        # Now optimize the drives that need it
        progress_per_drive = 100 // len(drives_to_optimize)

        for i, (drive, frag_level) in enumerate(drives_to_optimize):
            if not self.is_running:
                break

            try:
                self.logger.info(f"Starting optimization of drive {drive}")
                self.signals.update_text.emit(f"Starting optimization of drive {drive}")

                optimize_cmd = f"defrag {drive} /O"
                process = subprocess.Popen(
                    optimize_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )

                steps = 100
                base_progress = i * progress_per_drive

                for step in range(steps):
                    if not self.is_running or process.poll() is not None:
                        break

                    drive_progress = (step + 1) * progress_per_drive // steps
                    total_progress = min(base_progress + drive_progress, 99)

                    self.signals.update_progress.emit(total_progress)
                    self.logger.info(f"Optimizing drive {drive}: {step + 1}% complete")
                    self.signals.update_text.emit(f"Optimizing drive {drive}: {step + 1}% complete")

                    self.msleep(100)

                stdout, stderr = process.communicate(timeout=3600)  # 1 hour timeout per drive

                if process.returncode == 0:
                    self.logger.info(f"Successfully optimized drive: {drive}")
                    self.signals.update_text.emit(f"Successfully optimized drive: {drive}")
                else:
                    self.logger.error(f"Error optimizing drive {drive}: {stderr}")
                    self.signals.update_text.emit(f"Error optimizing drive {drive}: {stderr}")

            except subprocess.TimeoutExpired:
                process.kill()
                self.logger.error(f"Timeout while optimizing drive {drive}.")
                self.signals.update_text.emit(f"Timeout while optimizing drive {drive}.")
                continue
            except Exception as e:
                self.logger.error(f"Error processing drive {drive}: {str(e)}")
                self.signals.update_text.emit(f"Error processing drive {drive}: {str(e)}")
                continue

        # Final update
        if self.is_running:
            self.logger.info("Defragmentation and optimization completed.")
            self.signals.update_text.emit("Defragmentation and optimization completed.")
            self.signals.update_progress.emit(100)
        else:
            self.logger.info("Operation stopped by user.")
            self.signals.update_text.emit("Operation stopped by user.")

    def _run_health_check(self):
        """Handles system health check using user-selected commands."""
        try:
            if not self.commands:
                self.logger.info("No commands selected for system health check.")
                self.signals.update_text.emit("No commands selected for system health check.")
                self.signals.update_progress.emit(100)
                return

            # Dictionary to store progress of each command
            command_progress = {name: 0 for name, _ in self.commands}
            total_commands = len(self.commands)

            for idx, (name, command) in enumerate(self.commands):
                if not self.is_running:
                    break

                try:
                    self.logger.info(f"Running {name}...")
                    self.signals.update_text.emit(f"Running {name}...")

                    process = subprocess.Popen(
                        command,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        universal_newlines=True
                    )

                    while True:
                        if not self.is_running:
                            process.terminate()
                            self.logger.info(f"{name} terminated by user.")
                            self.signals.update_text.emit(f"{name} terminated by user.")
                            break

                        line = process.stdout.readline()
                        if not line and process.poll() is not None:
                            break
                        if line:
                            line = line.strip()
                            if line:
                                self.logger.info(line)
                                self.signals.update_text.emit(line)

                                # Look for percentage in the output
                                if '%' in line:
                                    try:
                                        # Extract percentage value using regex
                                        import re
                                        percentage_match = re.search(r'(\d+\.?\d*)%', line)
                                        if percentage_match:
                                            current_command_progress = float(percentage_match.group(1))
                                            command_progress[name] = current_command_progress

                                            # Calculate total progress
                                            total_progress = sum(command_progress.values()) / total_commands

                                            # Emit the total progress
                                            self.signals.update_progress.emit(math.floor(total_progress))
                                    except ValueError:
                                        continue

                except Exception as e:
                    self.logger.error(f"Error running {name}: {str(e)}")
                    self.signals.update_text.emit(f"Error running {name}: {str(e)}")
                    self.signals.error.emit(str(e))
                    continue

                # Get final status of the command
                try:
                    returncode = process.wait()
                    if returncode == 0:
                        self.logger.info(f"{name} completed successfully")
                        self.signals.update_text.emit(f"{name} completed successfully")
                        # Set command progress to 100% when successfully completed
                        command_progress[name] = 100
                    else:
                        stderr = process.stderr.read().strip()
                        self.logger.error(f"{name} failed with error code: {returncode}")
                        self.signals.update_text.emit(f"{name} failed with error code: {returncode}")
                        if stderr:
                            self.logger.error(f"Error details: {stderr}")
                            self.signals.update_text.emit(f"Error details: {stderr}")
                except Exception as e:
                    self.logger.error(f"Error waiting for {name} to finish: {str(e)}")
                    self.signals.update_text.emit(f"Error waiting for {name} to finish: {str(e)}")
                    self.signals.error.emit(str(e))
                    continue

                # Update total progress after each command
                total_progress = sum(command_progress.values()) / total_commands
                self.signals.update_progress.emit(math.floor(total_progress))

            # Finalize progress bar
            if self.is_running:
                self.signals.update_progress.emit(100)
                self.logger.info("System health check completed.")
                self.signals.update_text.emit("System health check completed.")
            else:
                self.logger.info("System health check stopped by user.")
                self.signals.update_text.emit("System health check stopped by user.")

        except Exception as e:
            self.logger.error(f"Error during health check: {str(e)}")
            self.signals.update_text.emit(f"Error during health check: {str(e)}")
            self.signals.error.emit(str(e))

    def analyze_drive(self, drive):
        """Analyze a drive and return if it needs optimization."""
        try:
            analyze_cmd = f"defrag {drive} /A"
            process = subprocess.Popen(
                analyze_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            stdout, stderr = process.communicate(timeout=300)  # 5 minute timeout

            if process.returncode == 0:
                output_lower = stdout.lower()
                if "ok" in output_lower and "not required" in output_lower:
                    self.logger.info(f"Drive {drive} does not require optimization.")
                    return False, 0

                import re
                frag_match = re.search(r'(\d+)% fragmented', output_lower)
                if frag_match:
                    frag_level = int(frag_match.group(1))
                    self.logger.info(f"Drive {drive} fragmentation level: {frag_level}%")
                    return frag_level > 5, frag_level  # Only optimize if fragmentation > 5%

                self.logger.info(f"Drive {drive} fragmentation level unknown. Assuming optimization needed.")
                return True, -1

            self.logger.error(f"Defrag analysis failed for drive {drive} with return code {process.returncode}.")
            return False, 0

        except subprocess.TimeoutExpired:
            process.kill()
            self.logger.error(f"Defrag analysis timed out for drive {drive}.")
            return False, 0
        except Exception as e:
            self.logger.error(f"Error during defrag analysis for drive {drive}: {str(e)}")
            return False, 0

    def get_drive_free_space(self, drive_letter):
        """Get free space for a specific drive."""
        try:
            free_bytes = ctypes.c_ulonglong(0)
            total_bytes = ctypes.c_ulonglong(0)
            total_free_bytes = ctypes.c_ulonglong(0)

            ret = ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                ctypes.c_wchar_p(f"{drive_letter}\\"),
                ctypes.pointer(free_bytes),
                ctypes.pointer(total_bytes),
                ctypes.pointer(total_free_bytes)
            )

            if ret == 0:
                return 0
            return free_bytes.value
        except Exception as e:
            self.logger.error(f"Error retrieving free space for drive {drive_letter}: {str(e)}")
            return 0

    def get_total_free_space(self):
        """Calculate the total free space across all fixed drives."""
        try:
            total_free = 0
            for drive_letter in string.ascii_uppercase:
                drive = f"{drive_letter}:\\"
                if os.path.exists(drive):
                    drive_type = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(drive))
                    if drive_type == 3:  # Local Disk
                        free_bytes = ctypes.c_ulonglong(0)
                        total_bytes = ctypes.c_ulonglong(0)
                        total_free_bytes = ctypes.c_ulonglong(0)
                        ret = ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                            ctypes.c_wchar_p(drive),
                            ctypes.pointer(free_bytes),
                            ctypes.pointer(total_bytes),
                            ctypes.pointer(total_free_bytes)
                        )
                        if ret == 0:
                            continue
                        total_free += free_bytes.value
            return total_free
        except Exception as e:
            self.logger.error(f"Error calculating total free space: {str(e)}")
            return 0

    def _format_size(self, size_in_bytes):
        """
        Convert bytes to human-readable format with appropriate units.
        Only displays positive values in KB, MB, or GB with proper decimal formatting.
        """
        try:
            if size_in_bytes <= 0:
                return "0 KB"

            KB = 1024
            MB = KB * 1024
            GB = MB * 1024

            if size_in_bytes < MB:  # Less than 1 MB
                kb_value = size_in_bytes / KB
                if kb_value < 10:
                    return f"{kb_value:.2f} KB"  # Show decimals for small values
                else:
                    return f"{int(kb_value)} KB"  # Show whole numbers for larger values
            elif size_in_bytes < GB:  # Less than 1 GB
                mb_value = size_in_bytes / MB
                if mb_value < 10:
                    return f"{mb_value:.2f} MB"  # Show decimals for small values
                else:
                    return f"{int(mb_value)} MB"  # Show whole numbers for larger values
            else:  # GB or larger
                gb_value = size_in_bytes / GB
                if gb_value < 10:
                    return f"{gb_value:.2f} GB"
                else:
                    return f"{int(gb_value)} GB"
        except Exception as e:
            self.logger.error(f"Error formatting size: {str(e)}")
            return "N/A"

    def clean_custom_paths(self, paths):
        """Clean files from custom paths safely."""
        total_size_freed = 0
        files_removed = 0

        for path in paths:
            if not os.path.exists(path):
                continue

            try:
                if os.path.isfile(path):
                    # If path is a file, remove it
                    try:
                        size = os.path.getsize(path)
                        os.remove(path)
                        total_size_freed += size
                        files_removed += 1
                    except (OSError, PermissionError):
                        continue
                else:
                    # If path is a directory, clean its contents
                    for root, dirs, files in os.walk(path, topdown=False):
                        # Remove files
                        for name in files:
                            try:
                                file_path = os.path.join(root, name)
                                size = os.path.getsize(file_path)
                                os.remove(file_path)
                                total_size_freed += size
                                files_removed += 1
                            except (OSError, PermissionError):
                                continue

                        # Remove empty directories
                        for name in dirs:
                            try:
                                dir_path = os.path.join(root, name)
                                if not os.listdir(dir_path):  # Only remove if empty
                                    os.rmdir(dir_path)
                            except (OSError, PermissionError):
                                continue

            except Exception as e:
                self.logger.error(f"Error cleaning path {path}: {str(e)}")
                continue

        return total_size_freed, files_removed


class LazyFileHandler(logging.FileHandler):
    """A file handler that only creates its file on first write."""
    def __init__(self, filename, mode='a', encoding=None, delay=True):
        super().__init__(filename, mode, encoding, delay=True)
        self._file_created = False

    def emit(self, record):
        """Create the log file only when the first record is emitted."""
        if not self._file_created:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.baseFilename), exist_ok=True)
            self._file_created = True
        super().emit(record)


def load_stylesheet_from_resource(resource_path):
    """Load a QSS stylesheet from the Qt resource system."""
    file = QFile(resource_path)
    if not file.exists():
        print(f"Resource stylesheet not found: {resource_path}")
        return ""

    if not file.open(QFile.ReadOnly | QFile.Text):
        print(f"Cannot open resource stylesheet: {resource_path}")
        return ""

    stream = QTextStream(file)
    stylesheet = stream.readAll()
    file.close()
    return stylesheet


def apply_stylesheet(app, stylesheet_path):
    """Apply the stylesheet to the entire application."""
    stylesheet = load_stylesheet(stylesheet_path)
    app.setStyleSheet(stylesheet)


class ZenCore(QMainWindow):
    def __init__(self):
        super().__init__()
        self.disk_cleanup_started = False
        self.defrag_started = False
        self.health_check_started = False
        self.run_all_in_progress = False
        self.maintenance_tasks = []
        self.current_task_index = 0
        self.setWindowTitle("ZenCore")
        self.setMinimumSize(800, 800)
        self.setWindowIcon(QIcon('assets/icon.ico'))  # Ensure the path is correct

        # Create menu bar
        self.create_menu_bar()

        # Initialize worker thread references
        self.defrag_worker = None
        self.disk_cleanup_worker = None
        self.health_check_worker = None

        # Initialize settings
        self.settings = PyQt5.QtCore.QSettings("ZenCore", "ZenCoreApp")

        # Initialize logging
        self.loggers = {}
        self.logger = logging.getLogger('ZenCore')
        self.logger.setLevel(logging.INFO)

        # Setup main logger with lazy file handler
        os.makedirs(LOG_BASE_PATH, exist_ok=True)
        main_log_file = os.path.join(LOG_BASE_PATH, 'zencore.log')
        handler = LazyFileHandler(main_log_file, encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(handler)

        # Initialize configuration attributes with default values
        self.cleanup_options = set()
        self.defrag_drives = []
        self.health_check_commands = []

        # Load user configurations
        self.load_configurations()

        # Create main widget that will contain everything
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # Create sections directly in main layout
        self.create_section("Disk Cleanup", self.start_disk_cleanup, "Clean", main_layout, "disk_cleanup")
        self.create_section("Defragment & Optimize Drives", self.start_defrag, "Optimize", main_layout,
                            "defragment_and_optimize_drives")
        self.create_section("System Integrity Scan & Repair", self.start_health_check, "Start", main_layout,
                            "system_health_check")

        # Add stretch to push content to top and footer to bottom
        main_layout.addStretch()

        # Add footer
        footer = QWidget()
        footer_layout = QHBoxLayout(footer)

        # Create copyright
        copyright_label = QLabel('© 2024. All rights reserved.')
        copyright_label.setObjectName("footerLabel")
        copyright_label.setAlignment(Qt.AlignRight)

        # Add a stretch to push the label to the right
        footer_layout.addStretch(1)
        footer_layout.addWidget(copyright_label)

        main_layout.addWidget(footer)

        # Apply global styles from external .qss file
        apply_stylesheet(app=QApplication.instance(), stylesheet_path='styles/main_window.qss')

    def create_section(self, label, command, button_label, parent_layout, section_key):
        section = QFrame()
        section.setObjectName("section")
        layout = QVBoxLayout(section)

        # Header with title and buttons
        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)

        title = QLabel(label)
        title.setObjectName("sectionTitle")
        title.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        header_layout.addWidget(title)

        header_layout.addStretch(1)

        buttons = QWidget()
        buttons_layout = QHBoxLayout(buttons)
        buttons_layout.setSpacing(10)

        start_btn = QPushButton(button_label)
        start_btn.setObjectName("primaryButton")
        start_btn.clicked.connect(command)

        configure_btn = QPushButton("Configure")
        configure_btn.setObjectName("secondaryButton")
        configure_btn.clicked.connect(lambda: self.open_configuration_dialog(section_key))

        buttons_layout.addWidget(start_btn)
        buttons_layout.addWidget(configure_btn)
        header_layout.addWidget(buttons)

        layout.addWidget(header)

        # Progress bar
        progress = QProgressBar()
        progress.setObjectName("progressBar")
        progress.setTextVisible(False)
        layout.addWidget(progress)

        # Info panel
        info = QTextEdit()
        info.setObjectName("infoPanel")
        info.setReadOnly(True)
        layout.addWidget(info)

        parent_layout.addWidget(section)

        # Store references
        setattr(self, f"{section_key}_progress", progress)
        setattr(self, f"{section_key}_info", info)
        setattr(self, f"{section_key}_start_btn", start_btn)
        setattr(self, f"{section_key}_configure_btn", configure_btn)

    def create_menu_bar(self):
        menubar = self.menuBar()

        # File Menu
        file_menu = menubar.addMenu('File')

        logs_action = file_menu.addAction('Logs')
        logs_action.triggered.connect(self.open_logs_dialog)

        reset_action = file_menu.addAction('Reset')
        reset_action.triggered.connect(self.reset_application)

        exit_action = file_menu.addAction('Exit')
        exit_action.triggered.connect(self.close)

        # Info Menu
        help_menu = menubar.addMenu('Info')

        about_action = help_menu.addAction('About')
        about_action.triggered.connect(self.show_about_dialog)

        help_action = help_menu.addAction('Help')
        help_action.triggered.connect(self.show_help_dialog)

        # Run All Action
        self.run_all_action = menubar.addAction('▶ Run')  # Changed to instance variable
        self.run_all_action.triggered.connect(self.run_all_maintenance)

    def reset_application(self):
        try:
            # Reset progress bars and info panels
            for section in ["disk_cleanup", "defragment_and_optimize_drives", "system_health_check"]:
                progress_bar = getattr(self, f"{section}_progress", None)
                info_panel = getattr(self, f"{section}_info", None)
                if progress_bar:
                    progress_bar.setValue(0)
                    progress_bar.setRange(0, 100)
                    progress_bar.setFormat("")
                if info_panel:
                    info_panel.clear()

            # Log the reset action
            self.logger.info("Application has been reset by the user.")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to reset the application: {str(e)}")
            self.logger.error(f"Failed to reset the application: {str(e)}")

    def set_all_task_buttons_enabled(self, enabled: bool):
        """Enable or disable all Start and Configure buttons."""
        for section in ["disk_cleanup", "defragment_and_optimize_drives", "system_health_check"]:
            start_btn = getattr(self, f"{section}_start_btn", None)
            configure_btn = getattr(self, f"{section}_configure_btn", None)
            if start_btn:
                start_btn.setEnabled(enabled)
            if configure_btn:
                configure_btn.setEnabled(enabled)

    def set_run_all_action_enabled(self, enabled: bool):
        """Enable or disable the Run All action."""
        if hasattr(self, 'run_all_action') and self.run_all_action:
            self.run_all_action.setEnabled(enabled)

    def run_all_maintenance(self):
        try:
            self.logger.info("Initiating 'Run All' maintenance tasks.")
            if not self.check_admin():
                return

            # Define the sequence of maintenance tasks
            self.maintenance_tasks = ["health_check", "cleanup", "defrag"]
            self.current_task_index = 0
            self.run_all_in_progress = True

            # Disable the Run All action to prevent re-clicking
            self.set_run_all_action_enabled(False)

            # Disable all Start and Configure buttons
            self.set_all_task_buttons_enabled(False)

            # Start the first maintenance task
            self.run_next_maintenance_task()
        except Exception as e:
            self.logger.error(f"Unexpected error in run_all_maintenance: {str(e)}")
            # Re-enable the Run All action and Start/Configure buttons in case of error
            self.set_run_all_action_enabled(True)
            self.set_all_task_buttons_enabled(True)
            self.run_all_in_progress = False

    def run_next_maintenance_task(self):
        try:
            # Check if all tasks in the sequence are complete
            if self.current_task_index >= len(self.maintenance_tasks):
                # Mark the "Run All" process as complete
                self.run_all_in_progress = False

                # Re-enable buttons and update the UI
                self.set_run_all_action_enabled(True)
                self.set_all_task_buttons_enabled(True)
                return

            # Get the current task from the sequence
            task = self.maintenance_tasks[self.current_task_index]
            self.logger.info(f"Starting task: {task}")

            # Execute the appropriate task based on the sequence
            if task == "health_check":
                if not self.health_check_commands:
                    # Skip this task and proceed to the next
                    self.current_task_index += 1
                    self.run_next_maintenance_task()
                    return
                self.start_health_check(run_all=True)

            elif task == "cleanup":
                if not self.cleanup_options:
                    # Skip this task and proceed to the next
                    self.current_task_index += 1
                    self.run_next_maintenance_task()
                    return
                self.start_disk_cleanup(run_all=True)

            elif task == "defrag":
                if not self.defrag_drives:
                    # Skip this task and proceed to the next
                    self.current_task_index += 1
                    self.run_next_maintenance_task()
                    return
                self.start_defrag(run_all=True)

        except Exception as e:
            self.logger.error(f"Error in run_next_maintenance_task: {str(e)}")

            # Re-enable buttons and mark "Run All" as complete in case of errors
            self.run_all_in_progress = False
            self.set_run_all_action_enabled(True)
            self.set_all_task_buttons_enabled(True)

    def handle_task_completion(self, section_name, run_all):
        """Handle completion of a task."""
        self.logger.info(f"Handling completion of '{section_name}' task.")

        # Update progress bar to indicate task completion
        progress_bar = getattr(self, f"{section_name}_progress")
        progress_bar.setRange(0, 100)
        progress_bar.setValue(100)
        progress_bar.setFormat('Process Completed Successfully')

        if run_all and self.run_all_in_progress:
            self.logger.info(f"'{section_name}' task completed during 'Run All'. Proceeding to the next task.")

            # Proceed to the next task in sequence
            self.current_task_index += 1
            self.run_next_maintenance_task()
        elif not run_all:
            # Re-enable buttons and update the status for individual tasks
            self.update_ui_state(section_name, False)

    def handle_error(self, error_message, section_name, run_all):
        """Handle errors from worker threads."""
        self.logger.error(f"Error in {section_name}: {error_message}")
        info_panel = getattr(self, f"{section_name}_info")
        self.update_info_panel(info_panel, f"Error: {error_message}")

        # Update progress bar and re-enable buttons only if not running 'Run All'
        progress_bar = getattr(self, f"{section_name}_progress")
        progress_bar.setRange(0, 100)
        progress_bar.setValue(100)
        progress_bar.setFormat('Process Completed with Errors')

        if not run_all or not self.run_all_in_progress:
            self.update_ui_state(section_name, False)  # Re-enable individual buttons

        if run_all and self.run_all_in_progress:
            self.current_task_index += 1
            self.run_next_maintenance_task()
        else:
            # Re-enable the Run All action and individual buttons if not running all
            self.set_run_all_action_enabled(True)
            self.set_all_task_buttons_enabled(True)
            # Update status bar

    def update_ui_state(self, section, is_running):
        """
        Enable or disable the Start and Configure buttons for a given section.

        :param section: The key identifier for the section (e.g., 'disk_cleanup')
        :param is_running: Boolean indicating if the task is running
        """
        start_btn = getattr(self, f"{section}_start_btn", None)
        configure_btn = getattr(self, f"{section}_configure_btn", None)
        if start_btn:
            start_btn.setEnabled(not is_running)
            self.logger.info(f"Start button for '{section}' set to {'enabled' if not is_running else 'disabled'}.")
        if configure_btn:
            configure_btn.setEnabled(not is_running)
            self.logger.info(f"Configure button for '{section}' set to {'enabled' if not is_running else 'disabled'}.")

    def start_disk_cleanup(self, run_all=False):
        """Start disk cleanup process."""
        # Prevent starting individual tasks during 'Run All'
        if self.run_all_in_progress and not run_all:
            QMessageBox.warning(self, "Run All in Progress",
                                "Cannot start Disk Cleanup while 'Run All' is in progress.")
            return

        self.disk_cleanup_started = True
        self.setup_logger_for_section("disk_cleanup")

        if not self.check_admin():
            if run_all:
                self.run_all_action.setEnabled(True)
            return
        if not self.cleanup_options:
            QMessageBox.warning(self, "No Options Selected", "Please configure Disk Cleanup options before running.")
            if run_all:
                self.run_all_action.setEnabled(True)
            return

        # Clear the info panel to reset the dialog box
        info_panel = getattr(self, "disk_cleanup_info")
        info_panel.clear()

        # Inform the user of the selected configurations
        self.update_info_panel(info_panel, "Disk Cleanup will run on all selected options.")
        self.update_info_panel(info_panel, "Disk Cleanup is in progress. This may take several minutes.")

        # Reset progress bar
        progress_bar = getattr(self, "disk_cleanup_progress")
        progress_bar.resetFormat()
        progress_bar.setValue(0)
        progress_bar.setRange(0, 0)  # Indeterminate state

        # Get the specific logger for Disk Cleanup
        section_name = "Disk Cleanup"
        cleanup_logger = self.loggers.get(section_name)
        if not cleanup_logger:
            QMessageBox.critical(self, "Logging Error", f"Logger for '{section_name}' is not initialized.")
            self.logger.error(f"Logger for '{section_name}' is not initialized.")
            if run_all:
                self.run_all_action.setEnabled(True)
            return

        # Create and start the worker
        self.disk_cleanup_worker = Worker(
            task="cleanup",
            logger=cleanup_logger,
            options=self.cleanup_options
        )
        self.setup_worker_connections(self.disk_cleanup_worker, "disk_cleanup", run_all=run_all)
        self.disk_cleanup_worker.start()
        self.update_ui_state("disk_cleanup", True)  # Disable buttons for this section

    def start_defrag(self, run_all=False):
        """Start defragmentation process."""
        if self.run_all_in_progress and not run_all:
            QMessageBox.warning(self, "Run All in Progress",
                                "Cannot start Defragmentation while 'Run All' is in progress.")
            return

        self.defrag_started = True
        self.setup_logger_for_section("defragment_and_optimize_drives")

        if not self.check_admin():
            if run_all:
                self.run_all_action.setEnabled(True)
            return
        if not self.defrag_drives:
            QMessageBox.warning(self, "No Drives Selected", "Please configure defragmentation drives before running.")
            if run_all:
                self.run_all_action.setEnabled(True)
            return

        # Clear the info panel
        info_panel = getattr(self, "defragment_and_optimize_drives_info")
        info_panel.clear()

        # Inform user
        self.update_info_panel(info_panel, "Note: This task cannot be stopped once started.")

        # Reset progress bar
        progress_bar = getattr(self, "defragment_and_optimize_drives_progress")
        progress_bar.resetFormat()
        progress_bar.setValue(0)

        # Get the specific logger
        section_name = "Defragment && Optimize Drives"
        defrag_logger = self.loggers.get(section_name)
        if not defrag_logger:
            QMessageBox.critical(self, "Logging Error", f"Logger for '{section_name}' is not initialized.")
            self.logger.error(f"Logger for '{section_name}' is not initialized.")
            if run_all:
                self.run_all_action.setEnabled(True)
            return

        # Create and start the worker
        self.defrag_worker = Worker("defrag", defrag_logger, drives=self.defrag_drives.copy())
        self.setup_worker_connections(self.defrag_worker, "defragment_and_optimize_drives", run_all=run_all)
        self.defrag_worker.start()
        self.update_ui_state("defragment_and_optimize_drives", True)  # Disable buttons for this section

    def start_health_check(self, run_all=False):
        """Start system health check process."""
        if self.run_all_in_progress and not run_all:
            QMessageBox.warning(self, "Run All in Progress",
                                "Cannot start System Health Check while 'Run All' is in progress.")
            return

        self.health_check_started = True
        self.setup_logger_for_section("system_health_check")

        if not self.check_admin():
            if run_all:
                self.run_all_action.setEnabled(True)
            return
        if not self.health_check_commands:
            QMessageBox.warning(self, "No Commands Selected",
                                "Please configure System Health Check commands before running.")
            if run_all:
                self.run_all_action.setEnabled(True)
            return

        # Clear the info panel
        info_panel = getattr(self, "system_health_check_info")
        info_panel.clear()

        # Reset progress bar
        progress_bar = getattr(self, "system_health_check_progress")
        progress_bar.resetFormat()
        progress_bar.setValue(0)

        # Inform user
        self.update_info_panel(info_panel, "Note: This task cannot be stopped once started.")

        # Get the specific logger
        section_name = "System Integrity Scan && Repair"
        health_check_logger = self.loggers.get(section_name)
        if not health_check_logger:
            QMessageBox.critical(self, "Logging Error", f"Logger for '{section_name}' is not initialized.")
            self.logger.error(f"Logger for '{section_name}' is not initialized.")
            if run_all:
                self.run_all_action.setEnabled(True)
            return

        # Create and start the worker
        self.health_check_worker = Worker("health_check", health_check_logger, commands=self.health_check_commands)
        self.setup_worker_connections(self.health_check_worker, "system_health_check", run_all=run_all)
        self.health_check_worker.start()
        self.update_ui_state("system_health_check", True)  # Disable buttons for this section

    def setup_worker_connections(self, worker, section_name, run_all=False):
        """Set up signal connections for a worker thread."""
        progress_bar = getattr(self, f"{section_name}_progress")
        info_panel = getattr(self, f"{section_name}_info")

        # Connect signals to appropriate slots
        worker.signals.update_text.connect(lambda text: self.update_info_panel(info_panel, text))
        worker.signals.update_progress.connect(progress_bar.setValue)
        worker.signals.finished.connect(lambda: self.handle_task_completion(section_name, run_all))
        worker.signals.error.connect(lambda msg: self.handle_error(msg, section_name, run_all))

    def show_about_dialog(self):
        dialog = AboutDialog(self)
        dialog.exec_()

    def show_help_dialog(self):
        dialog = HelpDialog(self)
        dialog.exec_()

    def open_logs_dialog(self):
        dialog = LogsDialog(self)
        dialog.exec_()

    def open_configuration_dialog(self, section_key):
        if section_key == "disk_cleanup":
            self.open_disk_cleanup_config_dialog()
        elif section_key == "defragment_and_optimize_drives":
            self.open_defrag_config_dialog()
        elif section_key == "system_health_check":
            self.open_health_check_config_dialog()

    def open_disk_cleanup_config_dialog(self):
        dialog = DiskCleanupConfigDialog(
            self,
            selected_options=self.cleanup_options
        )
        if dialog.exec_() == QDialog.Accepted:
            self.cleanup_options = dialog.get_selected_options()
            self.logger.info(f"Disk Cleanup options updated: {self.cleanup_options}")
            self.save_configurations()

    def open_defrag_config_dialog(self):
        dialog = DefragConfigDialog(self, selected_drives=self.defrag_drives)
        if dialog.exec_() == QDialog.Accepted:
            self.defrag_drives = dialog.get_selected_drives()
            self.logger.info(f"Defragmentation drives updated: {self.defrag_drives}")
            self.save_configurations()

    def open_health_check_config_dialog(self):
        dialog = HealthCheckConfigDialog(self, selected_commands=[name for name, _ in self.health_check_commands])
        if dialog.exec_() == QDialog.Accepted:
            self.health_check_commands = dialog.get_selected_commands()
            self.logger.info(f"Health Check commands updated: {[name for name, _ in self.health_check_commands]}")
            self.save_configurations()

    def update_info_panel(self, panel, text):
        """Update the info panel with new text."""
        panel.append(text)
        panel.verticalScrollBar().setValue(panel.verticalScrollBar().maximum())

    def check_admin(self):
        """Check for administrator privileges."""
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                QMessageBox.warning(self, "Admin Rights Required",
                                    "This operation requires administrator privileges.\n"
                                    "Please run the program as administrator.")
            return is_admin
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to check admin rights: {e}")
            return False

    def setup_logger_for_section(self, section_key):
        """Initialize the logger for a specific section."""
        section_name = SECTION_NAME_MAPPING.get(section_key)
        if not section_name:
            self.logger.error(f"No section name mapping found for key: {section_key}")
            return

        # Correctly use section_key to get the path
        section_path = LOG_SECTIONS.get(section_key)
        if not section_path:
            section_path = os.path.join(LOG_BASE_PATH, "General")

        # Ensure the log directory exists
        os.makedirs(section_path, exist_ok=True)

        # Set up the logger
        logger = logging.getLogger(section_name)
        logger.setLevel(logging.INFO)

        # Clear existing handlers to prevent duplicate logs
        if logger.hasHandlers():
            logger.handlers.clear()

        # Create a new lazy file handler
        log_file = os.path.join(section_path, self.get_log_filename())
        handler = LazyFileHandler(log_file, encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(handler)
        self.loggers[section_name] = logger

    def get_log_filename(self):
        """Generate a log filename based on the current date and time."""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d_%H-%M-%S.log")

    def close_log_handlers_for_section(self, section_name):
        """Close log handlers for a specific section and stop any running tasks."""
        worker_attr = f"{section_name.lower().replace(' ', '_')}_worker"
        worker = getattr(self, worker_attr, None)
        if worker and worker.isRunning():
            worker.is_running = False
            if worker.current_process:
                worker.current_process.terminate()  # Consider replacing with graceful shutdown
            worker.wait()

        logger = self.loggers.get(section_name)
        if logger:
            handlers = logger.handlers[:]
            for handler in handlers:
                handler.close()
                logger.removeHandler(handler)
            del self.loggers[section_name]

    def save_configurations(self):
        """Save user configurations using QSettings."""
        self.settings.setValue("DiskCleanupOptions", list(self.cleanup_options))
        self.settings.setValue("DefragDrives", self.defrag_drives)
        self.settings.setValue("HealthCheckCommands", [name for name, _ in self.health_check_commands])

    def load_configurations(self):
        """Load user configurations using QSettings."""
        self.cleanup_options = set(self.settings.value("DiskCleanupOptions", []))
        self.defrag_drives = self.settings.value("DefragDrives", [])
        command_names = self.settings.value("HealthCheckCommands", [])

        commands_dict = {
            "Check Health": "DISM.exe /Online /Cleanup-Image /CheckHealth",
            "Scan Health": "DISM.exe /Online /Cleanup-Image /ScanHealth",
            "Restore Health": "DISM.exe /Online /Cleanup-Image /RestoreHealth",
            "SFC Scan": "sfc /scannow",
            "Analyze Component Store": "DISM.exe /Online /Cleanup-Image /AnalyzeComponentStore",
            "Component Cleanup": "DISM.exe /Online /Cleanup-Image /StartComponentCleanup"
        }
        self.health_check_commands = [(name, commands_dict[name]) for name in command_names if name in commands_dict]

    def closeEvent(self, event):
        """Handle application close event."""
        # Stop any running tasks
        for section in ["defragment_and_optimize_drives", "disk_cleanup", "system_health_check"]:
            worker = getattr(self, f"{section}_worker", None)
            if worker and worker.isRunning():
                worker.is_running = False
                if worker.current_process:
                    worker.current_process.terminate()
                worker.wait()

        # Close logging handlers
        for section_name in list(self.loggers.keys()):
            self.close_log_handlers_for_section(section_name)

        # Close main logger
        if self.logger and self.logger.handlers:
            for handler in self.logger.handlers:
                handler.close()
                self.logger.removeHandler(handler)

        # Save configurations
        self.save_configurations()

        event.accept()


class BaseConfigDialog(QDialog):
    def __init__(self, parent=None, title="Configuration"):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setWindowFlags(Qt.Dialog | Qt.MSWindowsFixedSizeDialogHint)
        self.setObjectName("baseConfigDialog")  # Add object name for styling if needed
        self.load_external_stylesheet()

    def load_external_stylesheet(self):
        """Load the Help Dialog stylesheet."""
        stylesheet_path = 'styles/base_config_dialog.qss'
        stylesheet = load_stylesheet(stylesheet_path)
        self.setStyleSheet(stylesheet)


class DiskCleanupConfigDialog(BaseConfigDialog):
    def __init__(self, parent=None, selected_options=None):
        super().__init__(parent, "Disk Cleanup Configuration")
        self.setFixedSize(710, 750)
        self.selected_options = selected_options or set()
        self.cleanup_categories = get_cleanup_categories()
        self.load_external_stylesheet()
        self.init_ui()

    def load_external_stylesheet(self):
        """Load the Help Dialog stylesheet."""
        stylesheet_path = 'styles/disk_cleanup_dialog.qss'
        stylesheet = load_stylesheet(stylesheet_path)
        self.setStyleSheet(stylesheet)

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)

        # Drives Information Group
        drives_group = QGroupBox("Drives")
        drives_group.setObjectName("configGroupBox")
        drives_layout = QVBoxLayout(drives_group)
        drives_layout.setAlignment(Qt.AlignCenter)

        # Detected Drives Label
        detected_drives_label = QLabel("Detected Drives:")
        detected_drives_label.setAlignment(Qt.AlignCenter)
        detected_drives_label.setObjectName("configHeaderLabel")
        drives_layout.addWidget(detected_drives_label)

        # Show available drives in specified format
        drives = get_available_drives()
        drives_formatted = " | ".join(drives)
        drives_text = f"[ {drives_formatted} ]"
        drives_label = QLabel(drives_text)
        drives_label.setAlignment(Qt.AlignCenter)
        drives_layout.addWidget(drives_label)

        main_layout.addWidget(drives_group)

        # Cleanup Options Group
        options_group = QGroupBox("Cleanup Options")
        options_group.setObjectName("configGroupBox")
        options_layout = QVBoxLayout(options_group)

        # Select All Options Button - centered
        select_all_container = QHBoxLayout()
        self.options_select_all_btn = QPushButton("Select All")
        self.options_select_all_btn.setObjectName("selectAllButton")
        self.options_select_all_btn.setFixedWidth(200)
        self.options_select_all_btn.clicked.connect(lambda: self.toggle_select_all('options'))
        select_all_container.addStretch()
        select_all_container.addWidget(self.options_select_all_btn)
        select_all_container.addStretch()
        options_layout.addLayout(select_all_container)

        # Create scroll area for options
        scroll_area = QScrollArea()
        scroll_area.setObjectName("configScrollArea")
        scroll_area.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)

        # Add cleanup options
        self.option_checkboxes = []
        for category in self.cleanup_categories:
            # Create frame for each option
            frame = QFrame()
            frame.setObjectName("configOptionFrame")
            frame_layout = QVBoxLayout(frame)
            frame_layout.setContentsMargins(5, 2, 5, 2)
            frame_layout.setSpacing(2)

            # Add checkbox
            checkbox = QCheckBox(category['display_name'])
            checkbox.setObjectName("configCheckBox")
            if category['key_name'] in self.selected_options:
                checkbox.setChecked(True)
            checkbox.stateChanged.connect(self.on_checkbox_changed)
            frame_layout.addWidget(checkbox)

            # Add path label
            if 'is_custom' in category and category['is_custom']:
                paths = CUSTOM_CLEANUP_PATHS[category['key_name']]
                path_text = ", ".join(paths)
            else:
                path_text = category.get('registry_path', '')

            # In the path_label setup
            path_label = QLabel(path_text)
            path_label.setObjectName("pathLabel")
            path_label.setWordWrap(True)  # Ensure word wrap is enabled
            path_label.setMaximumWidth(500)  # Limit the maximum width
            path_label.setContentsMargins(20, 0, 0, 0)
            frame_layout.addWidget(path_label)

            scroll_layout.addWidget(frame)
            self.option_checkboxes.append((checkbox, category['key_name']))

        scroll_widget.setLayout(scroll_layout)
        scroll_area.setWidget(scroll_widget)
        options_layout.addWidget(scroll_area)
        main_layout.addWidget(options_group)

        # Buttons layout
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        ok_btn = QPushButton("OK")
        ok_btn.setObjectName("primaryButton")
        ok_btn.clicked.connect(self.accept)
        button_layout.addWidget(ok_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("secondaryButton")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)

        main_layout.addLayout(button_layout)

    def toggle_select_all(self, target):
        if target == 'options':
            checkboxes = [cb for cb, _ in self.option_checkboxes]
            all_selected = all(cb.isChecked() for cb in checkboxes)
            for checkbox in checkboxes:
                checkbox.setChecked(not all_selected)
            self.update_select_all_button_text(self.options_select_all_btn, checkboxes)

    def on_checkbox_changed(self):
        self.update_select_all_button_text(
            self.options_select_all_btn,
            [cb for cb, _ in self.option_checkboxes]
        )

    def get_selected_options(self):
        return {
            key_name for checkbox, key_name in self.option_checkboxes
            if checkbox.isChecked()
        }

    def update_select_all_button_text(self, button, checkboxes):
        all_selected = all(cb.isChecked() for cb in checkboxes)
        button.setText("Deselect All" if all_selected else "Select All")


class DefragConfigDialog(BaseConfigDialog):
    def __init__(self, parent=None, selected_drives=None):
        super().__init__(parent, "Defragmentation Configuration")
        self.setFixedSize(400, 250)
        self.load_external_stylesheet()
        self.selected_drives = selected_drives or []
        self.init_ui()

    def load_external_stylesheet(self):
        """Load the Help Dialog stylesheet."""
        stylesheet_path = 'styles/base_config_dialog.qss'
        stylesheet = load_stylesheet(stylesheet_path)
        self.setStyleSheet(stylesheet)

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)

        # Drives Selection Group
        drives_group = QGroupBox("Select Drives")
        drives_layout = QVBoxLayout(drives_group)
        drives_layout.setAlignment(Qt.AlignTop)

        # Get the list of available drives
        drives = get_available_drives()

        # If selected_drives is None, select all by default
        if not self.selected_drives:
            self.selected_drives = drives.copy()

        self.checkboxes = []
        for drive in drives:
            # Create a horizontal layout for each checkbox and drive label
            drive_frame = QFrame()
            drive_layout = QHBoxLayout(drive_frame)
            drive_layout.setContentsMargins(5, 2, 5, 2)
            drive_layout.setSpacing(10)

            checkbox = QCheckBox(drive)
            checkbox.setChecked(drive in self.selected_drives)
            self.checkboxes.append(checkbox)
            drive_layout.addWidget(checkbox, alignment=Qt.AlignVCenter)

            # Optionally, add additional labels or information here

            drives_layout.addWidget(drive_frame)

        drives_group.setLayout(drives_layout)
        main_layout.addWidget(drives_group)

        # Buttons layout
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        ok_btn = QPushButton("OK")
        ok_btn.setObjectName("primaryButton")
        ok_btn.clicked.connect(self.accept)
        button_layout.addWidget(ok_btn)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("secondaryButton")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        main_layout.addLayout(button_layout)

    def get_selected_drives(self):
        return [checkbox.text() for checkbox in self.checkboxes if checkbox.isChecked()]


class HealthCheckConfigDialog(BaseConfigDialog):
    def __init__(self, parent=None, selected_commands=None):
        super().__init__(parent, "System Integrity Configuration")
        self.load_external_stylesheet()
        self.setFixedSize(500, 450)
        self.selected_commands = selected_commands or []
        self.init_ui()

    def load_external_stylesheet(self):
        """Load the Help Dialog stylesheet."""
        stylesheet_path = 'styles/base_config_dialog.qss'
        stylesheet = load_stylesheet(stylesheet_path)
        self.setStyleSheet(stylesheet)

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)

        # Commands Selection Group
        commands_group = QGroupBox("Select Commands")
        commands_layout = QVBoxLayout(commands_group)

        # Select All Button - centered
        select_all_container = QHBoxLayout()
        self.select_all_btn = QPushButton("Select All")
        self.select_all_btn.setObjectName("selectAllButton")
        self.select_all_btn.setFixedWidth(200)
        self.select_all_btn.clicked.connect(self.toggle_select_all)
        select_all_container.addStretch()
        select_all_container.addWidget(self.select_all_btn)
        select_all_container.addStretch()
        commands_layout.addLayout(select_all_container)

        # Define the list of available commands
        self.commands = [
            ("Check Health", "DISM.exe /Online /Cleanup-Image /CheckHealth"),
            ("Scan Health", "DISM.exe /Online /Cleanup-Image /ScanHealth"),
            ("Restore Health", "DISM.exe /Online /Cleanup-Image /RestoreHealth"),
            ("SFC Scan", "sfc /scannow"),
            ("Analyze Component Store", "DISM.exe /Online /Cleanup-Image /AnalyzeComponentStore"),
            ("Component Cleanup", "DISM.exe /Online /Cleanup-Image /StartComponentCleanup")
        ]

        self.checkboxes = []
        for name, command in self.commands:
            # Create a horizontal layout for each checkbox and command label
            command_frame = QFrame()
            command_layout = QHBoxLayout(command_frame)
            command_layout.setContentsMargins(5, 2, 5, 2)
            command_layout.setSpacing(10)

            checkbox = QCheckBox(name)
            checkbox.setChecked(name in self.selected_commands)
            checkbox.stateChanged.connect(self.on_checkbox_changed)
            self.checkboxes.append((checkbox, command))
            command_layout.addWidget(checkbox, alignment=Qt.AlignVCenter)

            # Optionally, add additional labels or information here

            commands_layout.addWidget(command_frame)

        commands_group.setLayout(commands_layout)
        main_layout.addWidget(commands_group)

        # Buttons layout
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        ok_btn = QPushButton("OK")
        ok_btn.setObjectName("primaryButton")
        ok_btn.clicked.connect(self.accept)
        button_layout.addWidget(ok_btn)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("secondaryButton")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        main_layout.addLayout(button_layout)

    def toggle_select_all(self):
        all_selected = all(checkbox.isChecked() for checkbox, _ in self.checkboxes)
        for checkbox, _ in self.checkboxes:
            checkbox.setChecked(not all_selected)
        self.update_select_all_button_text()

    def on_checkbox_changed(self):
        self.update_select_all_button_text()

    def get_selected_commands(self):
        return [(checkbox.text(), command) for checkbox, command in self.checkboxes if checkbox.isChecked()]

    def update_select_all_button_text(self):
        all_selected = all(cb.isChecked() for cb, _ in self.checkboxes)
        self.select_all_btn.setText("Deselect All" if all_selected else "Select All")


class LogsDialog(BaseConfigDialog):
    def __init__(self, parent=None):
        super().__init__(parent, "Logs")
        self.setFixedSize(1000, 1000)
        self.load_external_stylesheet()
        self.init_ui()

        logs_icon_path = resource_path('assets/logs.ico')
        if os.path.exists(logs_icon_path):
            self.setWindowIcon(QIcon(logs_icon_path))
        else:
            return

    def load_external_stylesheet(self):
        stylesheet_path = 'styles/logs_dialog.qss'
        stylesheet = load_stylesheet(stylesheet_path)
        self.setStyleSheet(stylesheet)

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)

        # Top level container to help with vertical centering
        content_container = QWidget()
        content_layout = QVBoxLayout(content_container)
        content_layout.setContentsMargins(0, 0, 0, 0)

        # Splitter for left and right panes
        splitter = QSplitter(Qt.Horizontal)

        # Left Pane
        left_pane = QWidget()
        left_pane.setObjectName("leftPane")
        left_layout = QVBoxLayout(left_pane)
        left_layout.setContentsMargins(10, 10, 10, 10)
        left_layout.setSpacing(10)

        self.section_widgets = {}
        for section_key, path in LOG_SECTIONS.items():
            section_name = SECTION_NAME_MAPPING.get(section_key, section_key)
            group_box = QGroupBox(section_name)
            group_box.setObjectName("logGroupBox")
            layout = QVBoxLayout(group_box)

            list_widget = QListWidget()
            list_widget.setObjectName("logListWidget")
            list_widget.itemClicked.connect(self.display_log_content)
            layout.addWidget(list_widget)

            group_box.setLayout(layout)
            left_layout.addWidget(group_box)
            self.section_widgets[section_key] = (list_widget, path)

        splitter.addWidget(left_pane)

        # Set fixed width for left pane
        fixed_left_width = 225
        left_pane.setFixedWidth(fixed_left_width)
        left_pane.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)

        # Right Container
        right_container = QWidget()
        right_container.setObjectName("rightContainer")
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(10, 10, 10, 10)

        # Centered Action Buttons Container
        buttons_container = QWidget()
        buttons_container.setObjectName("actionButtonsContainer")
        buttons_layout = QHBoxLayout(buttons_container)
        buttons_layout.setContentsMargins(0, 0, 0, 10)

        # Add stretch to push buttons to center
        buttons_layout.addStretch()

        open_explorer_btn = QPushButton("Open Logs in Explorer")
        open_explorer_btn.setObjectName("primaryButton")
        open_explorer_btn.clicked.connect(self.open_logs_in_explorer)
        buttons_layout.addWidget(open_explorer_btn)

        clear_logs_btn = QPushButton("Clear All Logs")
        clear_logs_btn.setObjectName("secondaryButton")
        clear_logs_btn.clicked.connect(self.clear_all_logs)
        buttons_layout.addWidget(clear_logs_btn)

        # Add stretch to push buttons to center
        buttons_layout.addStretch()

        # Add buttons container to right layout
        right_layout.addWidget(buttons_container)

        # Log Content Viewer in a container
        log_viewer_container = QWidget()
        log_viewer_container.setObjectName("logViewerContainer")
        viewer_layout = QVBoxLayout(log_viewer_container)
        viewer_layout.setContentsMargins(0, 0, 0, 0)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setObjectName("logTextViewer")
        viewer_layout.addWidget(self.log_view)

        right_layout.addWidget(log_viewer_container)
        splitter.addWidget(right_container)

        # Set splitter sizes
        splitter.setSizes([fixed_left_width, self.width() - fixed_left_width - 10])

        main_layout.addWidget(splitter)

        # Dialog buttons at bottom
        dialog_buttons_layout = QHBoxLayout()
        dialog_buttons_layout.addStretch()

        ok_button = QPushButton("OK")
        ok_button.setObjectName("primaryButton")
        ok_button.clicked.connect(self.accept)
        dialog_buttons_layout.addWidget(ok_button)

        cancel_button = QPushButton("Cancel")
        cancel_button.setObjectName("secondaryButton")
        cancel_button.clicked.connect(self.reject)
        dialog_buttons_layout.addWidget(cancel_button)

        main_layout.addLayout(dialog_buttons_layout)

        # Populate Logs
        self.populate_logs()

    def populate_logs(self):
        """Populate each QListWidget with logs from the respective directory, sorted by modification time."""
        for section_key, (list_widget, path) in self.section_widgets.items():
            list_widget.clear()
            list_widget.clearSelection()  # Clear any existing selection

            section_name = SECTION_NAME_MAPPING.get(section_key, section_key)
            if os.path.exists(path):
                # Gather all log files and their modification times
                log_files = [
                    (f, os.path.getmtime(os.path.join(path, f)))
                    for f in os.listdir(path) if f.endswith(".log")
                ]
                # Sort log files by modification time (most recent first)
                log_files.sort(key=lambda x: x[1], reverse=True)

                if log_files:
                    for log_file, _ in log_files:
                        item = QListWidgetItem(log_file)
                        item.setData(Qt.UserRole, os.path.join(path, log_file))
                        item.setSelected(False)  # Ensure item is not selected
                        list_widget.addItem(item)
                    list_widget.setCurrentItem(None)  # Clear current item
                else:
                    list_widget.addItem("No logs available")
            else:
                list_widget.addItem("Logs directory not found")

    def display_log_content(self, item):
        """Display the content of the selected log file."""
        file_path = item.data(Qt.UserRole)
        if file_path and os.path.isfile(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.log_view.setPlainText(content)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to read log file:\n{e}")
        else:
            self.log_view.clear()

    def open_logs_in_explorer(self):
        """Open the logs directory in the file explorer."""
        if os.path.exists(LOG_BASE_PATH):
            try:
                subprocess.Popen(["explorer", LOG_BASE_PATH])
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to open Explorer:\n{e}")
        else:
            QMessageBox.warning(self, "Error", "Logs directory does not exist.")

    def clear_all_logs(self):
        """Clear all log files after user confirmation."""
        reply = QMessageBox.question(
            self,
            "Clear All Logs",
            "Are you sure you want to delete all log files?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            errors = []
            for _, (_, path) in self.section_widgets.items():
                if os.path.exists(path):
                    for log_file in os.listdir(path):
                        if log_file.endswith(".log"):
                            try:
                                os.remove(os.path.join(path, log_file))
                            except Exception as e:
                                errors.append(f"Failed to delete {log_file}: {e}")
            if errors:
                QMessageBox.warning(self, "Error", "\n".join(errors))
            else:
                QMessageBox.information(self, "Success", "All logs cleared.")
            self.populate_logs()
            self.log_view.clear()


class AboutDialog(BaseConfigDialog):
    def __init__(self, parent=None):
        super().__init__(parent, "About ZenCore")
        self.setFixedSize(370, 320)
        self.load_external_stylesheet()
        self.init_ui()

    def load_external_stylesheet(self):
        stylesheet_path = 'styles/about_dialog.qss'
        stylesheet = load_stylesheet(stylesheet_path)
        self.setStyleSheet(stylesheet)

    def init_ui(self):
        self.setWindowTitle("About ZenCore")
        self.setFixedSize(370, 320)
        self.setWindowFlags(Qt.Window | Qt.WindowTitleHint | Qt.WindowCloseButtonHint)

        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setAlignment(Qt.AlignCenter)

        # App Title and Version
        title_layout = QHBoxLayout()
        title_layout.setAlignment(Qt.AlignCenter)

        # App Icon using resource_path function
        icon_label = QLabel()
        icon_path = resource_path('assets/icon.ico')
        icon_label.setPixmap(QIcon(icon_path).pixmap(48, 48))
        title_layout.addWidget(icon_label, alignment=Qt.AlignCenter)

        # Title and Version
        title_version = QVBoxLayout()
        title_version.setAlignment(Qt.AlignCenter)

        app_title = QLabel("ZenCore")
        app_title.setStyleSheet("font-size: 20px; font-weight: bold; color: #2c3e50;")
        app_title.setAlignment(Qt.AlignCenter)

        version = QLabel("Version 1.0.0")
        version.setStyleSheet("font-size: 11px; color: #7f8c8d;")
        version.setAlignment(Qt.AlignCenter)

        title_version.addWidget(app_title)
        title_version.addWidget(version)
        title_layout.addLayout(title_version)

        layout.addLayout(title_layout)

        # Description
        description = QLabel(
            "ZenCore is a comprehensive Windows system maintenance utility designed "
            "to optimize performance and maintain system health using official "
            "Microsoft Windows tools and commands."
        )
        description.setWordWrap(True)
        description.setStyleSheet("font-size: 11px; color: #2c3e50; margin: 5px 0;")
        description.setAlignment(Qt.AlignCenter)
        layout.addWidget(description)

        # Developer Info
        dev_info = QGroupBox("Developer Information")
        dev_info.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                margin-top: 1ex;
                padding: 10px;
                font-size: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 3px;
                font-size: 12px;
            }
        """)

        dev_layout = QVBoxLayout()
        dev_layout.setSpacing(15)
        dev_layout.setAlignment(Qt.AlignCenter)

        # Developer name
        name_label = QLabel("Maged Abuzaid")
        name_label.setStyleSheet("color: #2c3e50; font-weight: bold; font-size: 12px;")
        name_label.setAlignment(Qt.AlignCenter)
        dev_layout.addWidget(name_label)

        # Contact and social links
        links_layout = QHBoxLayout()
        links_layout.setSpacing(20)
        links_layout.setAlignment(Qt.AlignCenter)

        # Use resource_path for icons
        github_icon_path = resource_path('assets/github.ico')
        linkedin_icon_path = resource_path('assets/linkedin.ico')

        # Email link
        email_link = QLabel(
            '<a href="mailto:MagedM.Abuzaid@gmail.com" style="text-decoration:none; color:#1373b7;">'
            '<span style="font-size:12px;">MagedM.Abuzaid@gmail.com</span></a>'
        )
        email_link.setOpenExternalLinks(True)
        email_link.setStyleSheet("font-size: 12px;")
        email_link.setAlignment(Qt.AlignCenter)

        # GitHub Link with icon
        github_link = QLabel()
        github_icon_pixmap = QIcon(github_icon_path).pixmap(24, 24)
        github_link.setPixmap(github_icon_pixmap)
        github_link_container = QWidget()
        github_layout = QHBoxLayout(github_link_container)
        github_layout.addWidget(github_link)
        github_layout.setContentsMargins(0, 0, 0, 0)

        github_link_clickable = QLabel(
            '<a href="https://github.com/Maged-Abuzaid" style="text-decoration:none;"></a>'
        )
        github_link_clickable.setOpenExternalLinks(True)
        github_layout.addWidget(github_link_clickable)

        # LinkedIn Link with icon
        linkedin_link = QLabel()
        linkedin_icon_pixmap = QIcon(linkedin_icon_path).pixmap(24, 24)
        linkedin_link.setPixmap(linkedin_icon_pixmap)
        linkedin_link_container = QWidget()
        linkedin_layout = QHBoxLayout(linkedin_link_container)
        linkedin_layout.addWidget(linkedin_link)
        linkedin_layout.setContentsMargins(0, 0, 0, 0)

        linkedin_link_clickable = QLabel(
            '<a href="https://www.linkedin.com/in/maged-abuzaid/" style="text-decoration:none;"></a>'
        )
        linkedin_link_clickable.setOpenExternalLinks(True)
        linkedin_layout.addWidget(linkedin_link_clickable)

        # Add links to the horizontal layout
        links_layout.addWidget(email_link)
        links_layout.addWidget(github_link_container)
        links_layout.addWidget(linkedin_link_container)

        dev_layout.addLayout(links_layout)
        dev_info.setLayout(dev_layout)
        layout.addWidget(dev_info)

        # Copyright
        copyright_label = QLabel("© 2024. All rights reserved.")
        copyright_label.setAlignment(Qt.AlignCenter)
        copyright_label.setStyleSheet("color: #7f8c8d; padding: 5px; font-size: 10px;")
        layout.addWidget(copyright_label)

        self.setLayout(layout)


class HelpDialog(BaseConfigDialog):
    def __init__(self, parent=None):
        super().__init__(parent, "ZenCore Help")
        self.setMaximumSize(800, 700)
        self.load_external_stylesheet()
        self.init_ui()

    def load_external_stylesheet(self):
        """Load the Help Dialog stylesheet."""
        stylesheet_path = 'styles/help_dialog.qss'
        stylesheet = load_stylesheet(stylesheet_path)
        self.setStyleSheet(stylesheet)

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # Add title section
        title_container = self._create_title_section()
        main_layout.addWidget(title_container)

        # Create and add tab widget
        tab_widget = self._create_tab_widget()
        main_layout.addWidget(tab_widget)

        # Add support section
        support_label = self._create_support_section()
        main_layout.addWidget(support_label)

        # Add OK button at the bottom
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        ok_button = QPushButton("OK")
        ok_button.setObjectName("primaryButton")
        ok_button.clicked.connect(self.accept)
        button_layout.addWidget(ok_button)
        main_layout.addLayout(button_layout)

    def _create_title_section(self):
        container = QFrame()
        container.setObjectName("titleContainer")
        layout = QVBoxLayout(container)  # Changed to QVBoxLayout
        layout.setContentsMargins(10, 10, 10, 10)  # Even margins all around
        layout.setSpacing(10)  # Space between elements
        layout.setAlignment(Qt.AlignCenter)  # Center alignment for the layout

        # Title and subtitle directly in main layout
        title = QLabel("ZenCore Help Center")
        title.setObjectName("helpTitle")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel("Your guide to system maintenance and optimization")
        subtitle.setObjectName("helpSubtitle")
        subtitle.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle)

        return container

    def _create_tab_widget(self):
        tab_widget = QTabWidget()
        tab_widget.setObjectName("helpTabWidget")

        # Overview Tab
        overview_widget = self._create_overview_tab()
        tab_widget.addTab(overview_widget, "Overview")

        # Features Tab
        features_widget = self._create_features_tab()
        tab_widget.addTab(features_widget, "Features")

        # Usage Tab
        usage_widget = self._create_usage_tab()
        tab_widget.addTab(usage_widget, "Usage Guide")

        # Maintenance Tab
        maintenance_widget = self._create_maintenance_tab()
        tab_widget.addTab(maintenance_widget, "Maintenance")

        # Troubleshooting Tab
        troubleshooting_widget = self._create_troubleshooting_tab()
        tab_widget.addTab(troubleshooting_widget, "Troubleshooting")

        return tab_widget

    def _create_overview_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        overview_html = """
            <div class="help-content">
                <h2>Welcome to ZenCore</h2>
                <p class="centered">
                    ZenCore is your comprehensive system maintenance solution, designed to keep your Windows system 
                    running smoothly and efficiently. Using only official Microsoft Windows utilities, ZenCore 
                    provides a safe and reliable way to maintain your system.
                </p>

                <h3>Why Choose ZenCore?</h3>
                <ul>
                    <li><strong>Safety First:</strong> All operations use built-in Windows tools</li>
                    <li><strong>User-Friendly:</strong> Simple interface for complex maintenance tasks</li>
                    <li><strong>Comprehensive:</strong> Complete suite of maintenance tools</li>
                    <li><strong>Efficient:</strong> Optimized performance with minimal system impact</li>
                </ul>

                <h3>Core Features</h3>
                <ul>
                    <li><strong>Disk Cleanup:</strong> Remove unnecessary files and free up space</li>
                    <li><strong>Drive Optimization:</strong> Defragment and optimize drive performance</li>
                    <li><strong>System Integrity:</strong> Verify and repair system files</li>
                    <li><strong>Detailed Logging:</strong> Track all maintenance activities</li>
                </ul>
            </div>
        """

        content = QLabel(overview_html)
        content.setObjectName("helpContent")
        content.setWordWrap(True)
        content.setTextFormat(Qt.RichText)
        layout.addWidget(content)
        layout.addStretch()

        return widget

    def _create_features_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        features_html = """
            <div class="help-content">
                <h3>Disk Cleanup</h3>
                <ul>
                    <li>Automatic system file cleanup</li>
                    <li>Browser cache management</li>
                    <li>Windows update cleanup</li>
                    <li>Temporary file removal</li>
                    <li>Custom cleanup paths</li>
                </ul>

                <h3>Drive Optimization</h3>
                <ul>
                    <li>Smart drive analysis</li>
                    <li>Selective optimization</li>
                    <li>Multiple drive support</li>
                    <li>Progress tracking</li>
                </ul>

                <h3>System Integrity</h3>
                <ul>
                    <li>System file verification</li>
                    <li>Automatic repair capabilities</li>
                    <li>Component store management</li>
                    <li>Health status reporting</li>
                </ul>

                <h3>Additional Features</h3>
                <ul>
                    <li>Detailed logging system</li>
                    <li>Real-time progress monitoring</li>
                    <li>Configuration management</li>
                    <li>Multiple task execution</li>
                </ul>
            </div>
        """

        content = QLabel(features_html)
        content.setObjectName("helpContent")
        content.setWordWrap(True)
        content.setTextFormat(Qt.RichText)
        layout.addWidget(content)
        layout.addStretch()

        return widget

    def _create_usage_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        usage_html = """
            <div class="help-content">
                <h3>Getting Started</h3>
                <ol>
                    <li>Launch ZenCore with administrator privileges</li>
                    <li>Select the desired maintenance task</li>
                    <li>Configure task-specific options</li>
                    <li>Click Start to begin the process</li>
                </ol>

                <h3>Configuration Options</h3>
                <ul>
                    <li><strong>Disk Cleanup:</strong> Select file categories to remove</li>
                    <li><strong>Drive Optimization:</strong> Choose drives to optimize</li>
                    <li><strong>System Integrity:</strong> Select scan and repair options</li>
                </ul>

                <h3>Using the Interface</h3>
                <ul>
                    <li>Monitor progress through the progress bar</li>
                    <li>View detailed status in the info panel</li>
                    <li>Access logs through the File menu</li>
                    <li>Configure options using the Configure button</li>
                </ul>

                <h3>Best Practices</h3>
                <ul>
                    <li>Run maintenance tasks during system idle time</li>
                    <li>Save and close other applications first</li>
                    <li>Review logs after task completion</li>
                    <li>Maintain regular maintenance schedule</li>
                </ul>
            </div>
        """

        content = QLabel(usage_html)
        content.setObjectName("helpContent")
        content.setWordWrap(True)
        content.setTextFormat(Qt.RichText)
        layout.addWidget(content)
        layout.addStretch()

        return widget

    def _create_maintenance_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        maintenance_html = """
            <div class="help-content">
                <h3>Maintenance Schedule</h3>
                <ul>
                    <li><strong>Weekly:</strong> Run Disk Cleanup</li>
                    <li><strong>Monthly:</strong> Run Drive Optimization</li>
                    <li><strong>Quarterly:</strong> Run System Integrity Scan</li>
                </ul>

                <h3>Disk Cleanup Guidelines</h3>
                <ul>
                    <li>Review selected cleanup categories carefully</li>
                    <li>Ensure sufficient free space before starting</li>
                    <li>Monitor system performance during cleanup</li>
                    <li>Verify results after completion</li>
                </ul>

                <h3>Drive Optimization Tips</h3>
                <ul>
                    <li>Run analysis before optimization</li>
                    <li>Optimize during system idle time</li>
                    <li>Allow full completion without interruption</li>
                    <li>Verify drive health beforehand</li>
                </ul>

                <h3>System Integrity Maintenance</h3>
                <ul>
                    <li>Start with basic health check</li>
                    <li>Progress to detailed scans if needed</li>
                    <li>Allow Windows Update access</li>
                    <li>Monitor repair progress</li>
                </ul>
            </div>
        """

        content = QLabel(maintenance_html)
        content.setObjectName("helpContent")
        content.setWordWrap(True)
        content.setTextFormat(Qt.RichText)
        layout.addWidget(content)
        layout.addStretch()

        return widget

    def _create_troubleshooting_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        troubleshooting_html = """
            <div class="help-content">
                <h3>Common Issues</h3>
                <ul>
                    <li><strong>Administrator Rights:</strong> Ensure ZenCore runs with admin privileges</li>
                    <li><strong>Windows Services:</strong> Verify required services are running</li>
                    <li><strong>Disk Space:</strong> Maintain adequate free space</li>
                    <li><strong>Internet Connection:</strong> Required for some repair operations</li>
                </ul>

                <h3>Error Messages</h3>
                <ul>
                    <li><strong>Access Denied:</strong> Run as administrator</li>
                    <li><strong>Insufficient Space:</strong> Free up disk space</li>
                    <li><strong>Service Not Running:</strong> Start Windows Update service</li>
                    <li><strong>Operation Failed:</strong> Check logs for details</li>
                </ul>

                <h3>Performance Issues</h3>
                <ul>
                    <li>Close resource-intensive applications</li>
                    <li>Run one maintenance task at a time</li>
                    <li>Allow tasks to complete fully</li>
                    <li>Monitor system resources</li>
                </ul>

                <h3>Getting Help</h3>
                <ul>
                    <li>Review detailed logs</li>
                    <li>Check documentation</li>
                    <li>Contact support</li>
                    <li>Visit the GitHub repository</li>
                </ul>
            </div>
        """

        content = QLabel(troubleshooting_html)
        content.setObjectName("helpContent")
        content.setWordWrap(True)
        content.setTextFormat(Qt.RichText)
        layout.addWidget(content)
        layout.addStretch()

        return widget

    def _create_support_section(self):
        support_html = """
            <div class="support-section">
                <p>
                    Need additional assistance? Visit our 
                    <a href="https://github.com/Maged-Abuzaid/ZenCore" style="color: #1373b7; text-decoration: none;">GitHub repository</a> 
                    or contact our support team at 
                    <a href="mailto:contact@zencore.support" style="color: #1373b7; text-decoration: none;">support@zencore.com</a>
                </p>
            </div>
        """
        label = QLabel(support_html)
        label.setObjectName("supportLabel")
        label.setOpenExternalLinks(True)
        label.setAlignment(Qt.AlignCenter)
        return label

if __name__ == "__main__":
    main()
