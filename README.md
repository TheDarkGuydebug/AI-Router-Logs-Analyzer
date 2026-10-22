PCAP Insight Workbench v1.5
PCAP Insight Workbench is a local Python-based packet capture analysis tool designed for broadband, CPE, ONT/AP, and network troubleshooting.

The tool analyzes .pcap and .pcapng captures using TShark and presents protocol information through structured summaries, timelines, ladder diagrams, alarms, host information, and optional local AI-assisted analysis using Ollama.

Key Features
PPPoE Discovery
PADI
PADO
PADR
PADS
PADT
PPP analysis
LCP
PAP
IPCP
IPv6CP
DHCPv4 / DHCPv6
DNS / mDNS
TCP flow analysis
TCP retransmissions
TCP MSS analysis
Out-of-order packet detection
HTTP / TLS visibility
TR-069 / CWMP traffic visibility
Protocol ladder diagrams
End-to-end timeline
Alarm / issue indicators
Host and client summaries
Optional local AI Q&A using Ollama
Architecture
              PCAP / PCAPNG
                    │
                    ▼
                  TShark
                    │
                    ▼
          PCAP Insight Workbench
                    │
        ┌───────────┼────────────┐
        ▼           ▼            ▼
      PPPoE        DHCP          DNS
        │           │            │
   LCP/PAP/IPCP   DHCPv6        mDNS
        │           │            │
        └───────────┼────────────┘
                    ▼
             TCP / HTTP / TLS
                    │
                    ▼
             Analysis Dashboard
                    │
                    ▼
              Optional AI
                    │
                    ▼
                 Ollama
                    │
                    ▼
               qwen2.5:7b
Prerequisites
Install the following before running the application:

Python 3
Git
Wireshark / TShark
Modern web browser
Ollama - optional, required for AI functionality
Verify the basic requirements:

python3 --version
git --version
tshark --version
Installation
1. Clone the Repository
git clone https://github.com/TheDarkGuydebug/AI-Router-Logs-Analyzer.git
Enter the project:

cd AI-Router-Logs-Analyzer
2. Create a Python Virtual Environment
python3 -m venv .venv
Activate it:

source .venv/bin/activate
After activation, the Terminal should display:

(.venv)
3. Install Python Dependencies
Upgrade pip:

python3 -m pip install --upgrade pip
Install the project dependencies:

pip install -r requirements.txt
TShark Setup
PCAP Insight Workbench uses TShark for packet decoding.

Verify TShark:

tshark --version
If TShark is not installed on macOS, install Wireshark or install through Homebrew:

brew install wireshark
Run PCAP Insight Workbench
Activate the virtual environment:

source .venv/bin/activate
Start the application:

python3 pcap_insight.py
Or start it on a specific port:

python3 pcap_insight.py --port 8091
Open the URL displayed in the Terminal using a web browser.

Upload a .pcap or .pcapng file and start the analysis.

Optional Local AI Setup
PCAP Insight Workbench can use Ollama for locally running AI-assisted analysis.

1. Install Ollama
Install Ollama for macOS from the official Ollama website.

After installation, verify:

ollama --version
2. Start Ollama
Normally, the Ollama macOS application starts the local Ollama service.

Verify that the service is running:

curl http://localhost:11434/api/tags
If required, Ollama can also be started manually:

ollama serve
3. Download the AI Model
PCAP Insight Workbench v1.5 can use:

qwen2.5:7b
Download the model:

ollama pull qwen2.5:7b
Check installed models:

ollama list
Expected example:

NAME
qwen2.5:7b
4. Test the AI Model
ollama run qwen2.5:7b
Example question:

Explain the PPPoE PADI, PADO, PADR and PADS sequence.
Exit the Ollama interactive session:

/bye
Running PCAP Insight with AI
Terminal 1 - Verify Ollama
curl http://localhost:11434/api/tags
If required:

ollama serve
Terminal 2 - Start PCAP Insight
cd AI-Router-Logs-Analyzer
Activate the environment:

source .venv/bin/activate
Start PCAP Insight:

python3 pcap_insight.py --port 8091
Open the displayed local URL in your browser.

AI Q&A Examples
After analyzing a PCAP, example questions can include:

Did PPPoE discovery complete successfully?
Did LCP negotiation complete?
Was PAP authentication successful?
What IPv4 address was negotiated?
Were TCP retransmissions observed?
Summarize the connection establishment flow.
Important AI Note
The AI assistant is intended to help interpret analyzer results.

The primary source of truth remains the packet capture.

PCAP
  │
  ▼
Packet Evidence
  │
  ▼
PCAP Insight Analysis
  │
  ▼
AI Interpretation
Important conclusions should always be validated against the actual packet evidence.

Starting the Tool Next Time
After completing the initial setup, there is no need to reinstall the dependencies.

Run:

cd AI-Router-Logs-Analyzer
Activate the environment:

source .venv/bin/activate
Check Ollama if AI functionality is required:

curl http://localhost:11434/api/tags
Start PCAP Insight:

python3 pcap_insight.py --port 8091
Troubleshooting
tshark: command not found
Verify:

which tshark
Install Wireshark/TShark if required.

ollama: command not found
Verify:

which ollama
Install Ollama and reopen the Terminal.

AI model is missing
Check installed models:

ollama list
If required:

ollama pull qwen2.5:7b
Ollama API is not responding
Test:

curl http://localhost:11434/api/tags
If required:

ollama serve
Python module is missing
Activate the virtual environment:

source .venv/bin/activate
Reinstall dependencies:

pip install -r requirements.txt
Port is already in use
Start PCAP Insight on another port:

python3 pcap_insight.py --port 8092
Useful Commands
Check Python:

python3 --version
Check TShark:

tshark --version
Check Ollama:

ollama --version
Check installed Ollama models:

ollama list
Check Ollama API:

curl http://localhost:11434/api/tags
Check application syntax:

python3 -m py_compile pcap_insight.py
Privacy
PCAP files can contain sensitive networking information, including:

IP addresses
MAC addresses
DNS queries
Hostnames
URLs
Device identifiers
Authentication exchanges
Review packet captures and analyzer output before sharing them publicly.

Project Structure
AI-Router-Logs-Analyzer/
│
├── pcap_insight.py
├── README.md
├── CHANGELOG.md
├── LICENSE.txt
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
│
├── tests/
│
└── validation/
    ├── VALIDATION_REPORT.md
    ├── synthetic_analysis_fixture.json
    ├── generate_synthetic_pcap.py
    └── screenshots/
Version
PCAP Insight Workbench v1.5

License
Refer to LICENSE.txt for the license applicable to this project.
