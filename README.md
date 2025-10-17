# 🌐 ADB Scanner Pro v5.2 FINAL

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Flet](https://img.shields.io/badge/Flet-0.28.3+-purple.svg)](https://flet.dev/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)]()

> **Professional ADB Device Scanner with Modern Material Design 3 UI**

Powerful network scanner for Android Debug Bridge (ADB) devices with advanced features, beautiful interface, and enterprise-grade security.

---

## ✨ Features

### 🎨 **Beautiful Material Design 3 Interface**
- Modern clean interface with responsive design
- Three intuitive tabs: Scanning, Settings, Results
- Real-time progress indicators
- Responsive card-based results display

### 🔍 **Advanced Scanning Capabilities**
- **IP Range Scanning**: Configure custom IP ranges (Start IP → End IP)
- **Flexible Port Configuration**: 
  - Single port mode
  - Port range (e.g., 5555-5585)
  - Custom port list (e.g., 5555,5556,5557)
- **Multi-threaded Scanning**: 1-200 concurrent threads
- **Scan Profiles**: Lightning, Quick, Balanced, Deep, Paranoid
- **Ping Check**: Optional network reachability test

### 🔒 **Enterprise Security**
- ✅ **No Shell Injection**: Safe subprocess execution without `shell=True`
- ✅ **IP Validation**: Regex pattern + octet range checking (0-255)
- ✅ **Port Validation**: Enforced 1-65535 range
- ✅ **Thread Limits**: Hard cap at 200 threads (DoS prevention)
- ✅ **Timeout Bounds**: Validated 0.1-10.0 second range
- ✅ **Input Sanitization**: All user inputs validated before execution

### 📊 **Professional Features**
- Real-time scan progress with percentage
- Live device counter
- Detailed scan logs with timestamps
- Export results (JSON, CSV)
- Cross-platform support (Windows, Linux, macOS)
- Configuration persistence

---

## 📦 Installation

### Prerequisites
- Python 3.10 or higher
- ADB tools installed and in PATH (optional, for ADB scanning)

### Quick Setup

```bash
# Clone repository
git clone https://github.com/RootOne1337/adb-scanner-pro.git
cd adb-scanner-pro

# Install dependencies
pip install -r requirements.txt

# Run application
python adb_scanner_v5.2_FINAL.py
```

---

## 🚀 Usage

### Basic Scanning

1. **Configure Settings Tab**:
   - Set IP range (e.g., 192.168.1.1 → 192.168.1.255)
   - Choose ports (5555 for ADB)
   - Adjust threads (50 recommended)
   - Select scan profile

2. **Start Scan Tab**:
   - Click "START"
   - Monitor real-time progress
   - View live logs

3. **View Results Tab**:
   - See discovered devices as cards
   - Export to JSON/CSV

### Scan Profiles

| Profile | Threads | Timeout | Best For |
|---------|---------|---------|----------|
| ⚡ Lightning | 200 | 0.5s | Fast LAN scans |
| 🔍 Quick | 100 | 1.0s | Standard home networks |
| ⚖️ Balanced | 50 | 2.0s | Reliable results |
| 🔬 Deep | 30 | 3.0s | Thorough scanning |
| 🛡️ Paranoid | 10 | 5.0s | Maximum accuracy |

### Advanced Configuration

```
Scan specific subnet:
  IP Start: 192.168.1.1
  IP End:   192.168.1.255

Multiple ports:
  Custom Ports: 5555,5556,5557,5585

Port range:
  Custom Ports: 5555-5585

Performance tuning:
  Threads: 100
  Timeout: 2.0 seconds
```

---

## 🔧 Configuration

### Settings

- **IP Range**: Start and end IP addresses for scanning
- **Ports**: 
  - Single port (e.g., 5555)
  - Range (e.g., 5555-5585)
  - Custom list (e.g., 5555,5556,5557)
- **Threads**: Concurrent scanning threads (1-200)
- **Timeout**: Connection timeout in seconds (0.1-10.0)
- **Scan Profiles**: Pre-configured scanning modes
- **Options**:
  - Scan ADB (port 5555)
  - Scan SSH (port 22)
  - Scan Telnet (port 23)
  - Skip ping check

---

## 🔒 Security

This project takes security seriously. See [SECURITY.md](SECURITY.md) for:
- Security features
- Vulnerability reporting
- Security audit results

### Security Highlights

- **v5.2.1 Security Hotfix**: Fixed 5 critical vulnerabilities
- No shell injection risks
- All inputs validated and sanitized
- DoS prevention (thread limiting)
- Safe subprocess execution

---

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md) for complete version history.

### v5.2 FINAL (Latest)

**🎉 Features:**
- IP range configuration (Start → End)
- Flexible port configuration (single/range/custom)
- 5 scan profiles (Lightning to Paranoid)
- Real-time progress tracking
- Material Design 3 UI
- Export results (JSON/CSV)

**🔒 Security Fixes:**
- Removed shell=True (prevents shell injection)
- Added IP validation (regex + range check)
- Added port validation (1-65535)
- Thread limits enforced (1-200)
- Timeout bounds checking (0.1-10.0)

**🐛 Bug Fixes:**
- Fixed padding parameter compatibility with Flet 0.28.3
- Removed unsupported scroll_to() method
- Fixed async event handling

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## 👤 Author

**RootOne1337**
- GitHub: [@RootOne1337](https://github.com/RootOne1337)
- Project: [ADB Scanner Pro](https://github.com/RootOne1337/adb-scanner-pro)

---

## 🙏 Acknowledgments

- [Flet](https://flet.dev/) - Beautiful UI framework
- [Python](https://www.python.org/) - Programming language
- [ADB](https://developer.android.com/studio/command-line/adb) - Android Debug Bridge

---

## 📞 Support

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/RootOne1337/adb-scanner-pro/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/RootOne1337/adb-scanner-pro/discussions)

---

## ⭐ Star History

If you find this project useful, please consider giving it a star! ⭐

---

**Made with ❤️ by RootOne1337**
