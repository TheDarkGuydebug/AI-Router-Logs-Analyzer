# PCAP Insight Workbench v1.5

PCAP Insight Workbench is a local Python-based packet capture analysis tool designed for broadband, CPE, ONT/AP, and network troubleshooting.

The tool analyzes `.pcap` and `.pcapng` captures using TShark and presents protocol information through structured summaries, timelines, ladder diagrams, alarms, host information, and optional local AI-assisted analysis using Ollama.

## Key Features

- PPPoE Discovery: PADI, PADO, PADR, PADS, and PADT
- PPP analysis: LCP, PAP, IPCP, and IPv6CP
- DHCPv4 and DHCPv6 analysis
- DNS and mDNS analysis
- TCP flow, MSS, retransmission, and out-of-order analysis
- HTTP and TLS visibility
- TR-069 and CWMP traffic visibility
- Protocol ladder diagrams
- End-to-end timeline
- Alarm and issue indicators
- Host and client summaries
- Optional local AI Q&A using Ollama

## Architecture

```text
              PCAP / PCAPNG
                    |
                    v
                  TShark
                    |
                    v
          PCAP Insight Workbench
                    |
        +-----------+------------+
        |           |            |
        v           v            v
      PPPoE        DHCP          DNS
        |           |            |
   LCP/PAP/IPCP   DHCPv6        mDNS
        |           |            |
        +-----------+------------+
                    |
                    v
             TCP / HTTP / TLS
                    |
                    v
             Analysis Dashboard
                    |
                    v
              Optional AI
                    |
                    v
                 Ollama
                    |
                    v
               qwen2.5:7b
```

## Prerequisites

Install the following before running the application:

- Python 3
- Git
- Wireshark / TShark
- A modern web browser
- Ollama, optional and required only for AI functionality

Verify the basic requirements:

```bash
python3 --version
git --version
tshark --version
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/TheDarkGuydebug/AI-Router-Logs-Analyzer.git
cd AI-Router-Logs-Analyzer
```

### 2. Create a Python virtual environment

```bash
python3 -m venv .venv
```

Activate it on macOS or Linux:

```bash
source .venv/bin/activate
```

After activation, the Terminal prompt should include:

```text
(.venv)
```

### 3. Install Python dependencies

```bash
python3 -m pip install --upgrade pip
pip install -r requirements.txt
```

## TShark Setup

PCAP Insight Workbench uses TShark for packet decoding.

Verify TShark:

```bash
tshark --version
```

If TShark is not installed on macOS, install Wireshark or use Homebrew:

```bash
brew install wireshark
```

## Run PCAP Insight Workbench

Activate the virtual environment:

```bash
source .venv/bin/activate
```

Start the application:

```bash
python3 pcap_insight.py
```

Or start it on a specific port:

```bash
python3 pcap_insight.py --port 8091
```

Open the URL displayed in Terminal, upload a `.pcap` or `.pcapng` file, and start the analysis.

## Optional Local AI Setup

PCAP Insight Workbench can use Ollama for local AI-assisted analysis.

### 1. Install Ollama

Install Ollama for macOS from the official Ollama website.

Verify the installation:

```bash
ollama --version
```

### 2. Start or verify Ollama

The Ollama macOS application normally starts the local service automatically.

Verify the service:

```bash
curl http://localhost:11434/api/tags
```

If required, start Ollama manually:

```bash
ollama serve
```

### 3. Download the AI model

```bash
ollama pull qwen2.5:7b
```

Check installed models:

```bash
ollama list
```

### 4. Test the AI model

```bash
ollama run qwen2.5:7b
```

Example question:

```text
Explain the PPPoE PADI, PADO, PADR and PADS sequence.
```

Exit the interactive Ollama session with:

```text
/bye
```

## Running PCAP Insight with AI

### Terminal 1: Verify Ollama

```bash
curl http://localhost:11434/api/tags
```

If required:

```bash
ollama serve
```

### Terminal 2: Start PCAP Insight

```bash
cd AI-Router-Logs-Analyzer
source .venv/bin/activate
python3 pcap_insight.py --port 8091
```

Open the displayed local URL in a browser.

## AI Q&A Examples

After analyzing a capture, example questions include:

- Did PPPoE discovery complete successfully?
- Did LCP negotiation complete?
- Was PAP authentication successful?
- What IPv4 address was negotiated?
- Were TCP retransmissions observed?
- Summarize the connection-establishment flow.

## Important AI Note

The AI assistant is an interpretation layer. The packet capture remains the primary source of truth.

```text
PCAP
  |
  v
Packet Evidence
  |
  v
PCAP Insight Analysis
  |
  v
AI Interpretation
```

Important conclusions should always be validated against the actual packet evidence.

## Starting the Tool Next Time

After the first installation, there is no need to reinstall dependencies.

```bash
cd AI-Router-Logs-Analyzer
source .venv/bin/activate
curl http://localhost:11434/api/tags
python3 pcap_insight.py --port 8091
```

The Ollama check is only required when using AI functionality.

## Troubleshooting

### `tshark: command not found`

```bash
which tshark
tshark --version
```

Install Wireshark or TShark if required.

### `ollama: command not found`

```bash
which ollama
```

Install Ollama and reopen Terminal.

### AI model is missing

```bash
ollama list
ollama pull qwen2.5:7b
```

### Ollama API is not responding

```bash
curl http://localhost:11434/api/tags
```

If required:

```bash
ollama serve
```

### Python module is missing

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

### Port is already in use

```bash
python3 pcap_insight.py --port 8092
```

## Useful Commands

```bash
python3 --version
tshark --version
ollama --version
ollama list
curl http://localhost:11434/api/tags
python3 -m py_compile pcap_insight.py
```

## Privacy

PCAP files can contain sensitive networking information, including:

- IP addresses
- MAC addresses
- DNS queries
- Hostnames
- URLs
- Device identifiers
- Authentication exchanges

Review packet captures and analyzer output before sharing them publicly.

## Project Structure

```text
AI-Router-Logs-Analyzer/
|
+-- pcap_insight.py
+-- README.md
+-- CHANGELOG.md
+-- LICENSE.txt
+-- requirements.txt
+-- Dockerfile
+-- docker-compose.yml
+-- tests/
+-- validation/
    +-- VALIDATION_REPORT.md
    +-- synthetic_analysis_fixture.json
    +-- generate_synthetic_pcap.py
    +-- screenshots/
```

## Version

**PCAP Insight Workbench v1.5**

## License

Refer to `LICENSE.txt` for the license applicable to this project.
