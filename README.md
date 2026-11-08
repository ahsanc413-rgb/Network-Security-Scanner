# Network Security Scanner & Firewall Visualizer

**Student:** Muhammad Ahsan Ashfaq  
**Roll No:** 03-134231-036

A web-based tool built with Python (Flask) and HTML/CSS/JavaScript. It does three things:
- Scans an IP address, hostname or small local network for **open ports, services and possible vulnerabilities**.
- Lets you create **firewall rules** (allow/deny) and simulates which traffic gets through, checking rules in priority order.
- Shows a **visual flow diagram** and a chart of allowed and blocked traffic.

---

## How to Run (Step by Step)

### Step 1: Install Python
- Download Python 3.9 or newer from https://www.python.org/downloads/
- During installation, **tick "Add Python to PATH"**.
- To check that it worked, open Command Prompt and run:
  ```
  python --version
  ```

### Step 2: Download / extract the project
- Extract the ZIP file (for example to the Desktop).
- You should see a folder named `Network-Security-Scanner` containing `app.py`.

### Step 3: Run the project

**Option A – Easiest (Windows)**
- Double-click **`run.bat`**.
- It installs the required libraries, starts the server and opens the browser automatically.

**Option B – Manual (any OS)**
1. Open Command Prompt / Terminal **inside the project folder**.
   On Windows: open the folder, type `cmd` in the address bar and press Enter.
2. Install the libraries (needed only the first time):
   ```
   pip install -r requirements.txt
   ```
3. Start the server:
   ```
   python app.py
   ```
4. Open this link in your browser:
   ```
   http://127.0.0.1:5000
   ```

### Step 4: Stop the server
Go to the Command Prompt window and press **Ctrl + C**, or just close the window.

---

## How to Use (Demo)

1. **Scan**
   - In *Target* enter `127.0.0.1` (your own computer).
   - Choose a *Scan Type* (TCP Full Connect / TCP SYN / UDP) and a port range.
   - Click **▶ Start Scan**. The table shows the IP, port, service, status and possible vulnerability.
2. **Firewall rules**
   - Fill in the rule form and click **＋ Add Rule**, or click **Load sample rules**.
   - A lower priority number means the rule is checked first. Use ▲/▼ to change the order.
3. **Traffic**
   - Add packets yourself, click **Load sample traffic**, or click **Use open ports from last scan**.
4. Click **⚡ Simulate Firewall**. You will see:
   - a flow diagram (green = allowed, red ✖ = blocked)
   - a decision table showing which rule matched (e.g. `R1✗ → R2✓`)
   - a matplotlib chart of allowed vs blocked traffic

---

## Optional Setup
| Feature | What to install |
|---|---|
| Real Nmap scanning with service versions | Nmap from https://nmap.org/download.html (add it to PATH) |
| True TCP SYN (half-open) scan on Windows | Npcap from https://npcap.com, then run Command Prompt **as Administrator** |

Without these, the tool **automatically** uses its built-in Python socket scanner, so everything still works.

---

## Troubleshooting
| Problem | Solution |
|---|---|
| `python` is not recognized | Reinstall Python and tick **"Add Python to PATH"**, or try `py app.py` |
| `pip` is not recognized | Use `python -m pip install -r requirements.txt` |
| `ModuleNotFoundError: flask` | Run `pip install -r requirements.txt` again |
| Port 5000 already in use | Close the other program, or change `port=5000` at the bottom of `app.py` |
| SYN scan shows a "fell back" note | Normal without Npcap/admin rights. The scan still works as Full Connect. |
| Scan takes long | Use a smaller port range or lower the timeout |

---

## Project Structure
```
Network-Security-Scanner/
├── app.py              # Flask backend + REST API
├── scanner.py          # Scanning engine (Nmap → Scapy → socket fallback)
├── firewall.py         # Firewall rule matching & priority-based simulation
├── requirements.txt    # Python libraries
├── run.bat             # One-click start (Windows)
├── templates/
│   └── index.html      # User interface
├── static/
│   ├── app.js          # Frontend logic + SVG flow diagram
│   └── style.css       # Styling
├── screenshots/        # Screenshots of the working app
└── Project_Report.docx # Assignment report
```

## API Endpoints
| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | User interface |
| GET | `/api/status` | Shows which scan engines are available |
| POST | `/api/scan` | Runs a scan `{target, ports, scan_type, timeout}` |
| POST | `/api/firewall/simulate` | Checks packets against the rules |
| POST | `/api/firewall/chart` | Returns a PNG chart (matplotlib) |

## Tech Stack
- **Frontend:** HTML, CSS, JavaScript (SVG)
- **Backend:** Python, Flask
- **Libraries:** python-nmap, scapy, matplotlib, socket, ipaddress

---

> ⚠️ **For educational use only.** Only scan computers or networks that you own or have permission to test.
