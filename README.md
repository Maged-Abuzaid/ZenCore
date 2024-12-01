# ZenCore

ZenCore is a comprehensive Windows system maintenance utility built with PyQt5 that optimizes system performance using native Windows tools. The application provides a modern, user-friendly interface for performing essential system maintenance tasks.

![ZenCore Screenshot](assets/icon.ico)

## Features

- **Disk Cleanup**
  - System file cleanup
  - Browser cache management
  - Windows update cleanup
  - Temporary file removal
  - Custom cleanup paths

- **Drive Optimization**
  - Smart drive analysis
  - Selective optimization
  - Multiple drive support
  - Progress tracking

- **System Integrity**
  - System file verification
  - Automatic repair capabilities
  - Component store management
  - Health status reporting

- **Additional Features**
  - Detailed logging system
  - Real-time progress monitoring
  - Configuration management
  - Multiple task execution
  - Modern, intuitive interface

## Prerequisites

- Windows 10/11
- Python 3.8 or higher
- Administrator privileges

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Maged-Abuzaid/ZenCore.git
```

2. Navigate to the project directory:
```bash
cd ZenCore
```

3. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Run ZenCore with administrator privileges:
```bash
python main.py
```

2. Select desired maintenance task:
   - Disk Cleanup
   - Drive Optimization
   - System Integrity Scan

3. Configure task-specific options using the "Configure" button

4. Click "Start" to begin the selected maintenance task

## Configuration

### Disk Cleanup
- Select file categories to remove
- Choose custom cleanup paths
- Configure browser cache cleanup options

### Drive Optimization
- Select drives for optimization
- Choose optimization level
- Set scheduling options

### System Integrity
- Select scan types
- Configure repair options
- Set component store management options

## Logging

- Logs are stored in `%UserProfile%\Documents\ZenCore\Logs`
- Separate log files for each maintenance task
- Timestamp-based log naming
- Detailed operation tracking

## Building from Source

1. Install PyInstaller:
```bash
pip install pyinstaller
```

2. Build the executable:
```bash
pyinstaller --onefile --windowed --icon=assets/icon.ico main.py
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Maged Abuzaid**
- Email: MagedM.Abuzaid@gmail.com
- GitHub: [Maged-Abuzaid](https://github.com/Maged-Abuzaid)
- LinkedIn: [Maged Abuzaid](https://www.linkedin.com/in/maged-abuzaid/)

## Acknowledgments

- PyQt5 for the GUI framework
- Microsoft Windows for system maintenance utilities
- All contributors and testers

---
© 2024 ZenCore. All rights reserved.
