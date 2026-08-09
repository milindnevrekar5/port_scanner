# Advanced Python Port Scanner

A fast, multithreaded TCP port scanner built in Python. This reconnaissance tool checks for open ports and utilizes intelligent banner grabbing to identify running services and software versions.

## 🚀 Features

* **Multithreading:** Scans hundreds of ports concurrently using Python's `ThreadPoolExecutor` for rapid execution, drastically reducing scan times.
* **Smart Banner Grabbing:** Automatically detects how to interact with services. It listens for SSH/FTP greetings and sends proper `HTTP HEAD` requests to web servers (ports 80, 443, 8080) to accurately extract the `Server` header.
* **CLI Interface:** Fully configurable via the command line using `argparse`. Customize the target IP, port ranges, timeout durations, and thread counts.
* **Graceful Exit:** Safely handles `Ctrl+C` (KeyboardInterrupt) to cancel massive scans without flooding the terminal with tracebacks.
* **Zero Dependencies:** Built entirely using Python's standard library (`socket`, `argparse`, `concurrent.futures`). No `pip install` required!

## 📋 Prerequisites

* Python 3.6 or higher installed on your system.

## 🛠️ Installation

1. Clone the repository to your local machine:
   ```bash
   git clone https://github.com/YOUR-USERNAME/python-port-scanner.git
   ```
2. Navigate to the project directory:
   ```bash
   cd python-port-scanner
   ```

## 💻 Usage

Run the script directly from your terminal. The only required argument is the target hostname or IP address.

### Basic Scan
Scans the default list of common ports (21, 22, 23, 25, 53, 80, 443, etc.) on the target.
```bash
python port_scanner.py scanme.nmap.org
```

### Custom Ports
Use the `--ports` flag to specify a comma-separated list of ports or port ranges.
```bash
python port_scanner.py 192.168.1.1 --ports 22,80,443,1000-2000
```

### Advanced Scan (Custom Threads & Timeout)
Speed up or slow down the scan by adjusting the thread count and socket timeout.
```bash
python port_scanner.py 127.0.0.1 --threads 200 --timeout 0.5
```

## 📊 Example Output

```text
Scanning scanme.nmap.org [45.33.32.156] with 22 ports using 100 threads...

Port 22/tcp OPEN   service=ssh | Banner: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.3
Port 80/tcp OPEN   service=http | Banner: Server: Apache/2.4.7 (Ubuntu)

Open ports summary:
------------------------------------------------------------
  22/tcp open  (service: ssh) | SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.3
  80/tcp open  (service: http) | Server: Apache/2.4.7 (Ubuntu)
```

## ⚠️ Disclaimer

**Educational Purposes Only.** This tool was created for educational purposes and ethical hacking only. You must have explicit, written permission to scan any network, application, or device that you do not own. The creator of this tool is not responsible for any misuse or damage caused by this program.

## 📜 License

Distributed under the MIT License.
