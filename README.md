# PCAP Insight Workbench

A local Python/Flask web application for dissecting `.pcap` and `.pcapng` files with TShark and presenting the evidence in an interactive browser dashboard.

## What it analyzes

- **TCP:** SYN-advertised MSS distribution, retransmissions, fast/spurious retransmissions, out-of-order segments, and previous-segment-not-captured indications.
- **DNS:** query/response frame numbers, A/AAAA type, IPv4/IPv6 source and destination, domain, A/AAAA/CNAME answers, response codes, unanswered queries, and domain-level dual-stack outcomes.
- **HTTP:** URLs, hosts, methods (including GET/POST), user agents, response status, content type, request/response linkage, and captured cleartext request/response bodies where TShark exposes them. Encrypted application bodies are not decrypted or claimed.
- **Large-body resilience:** TShark CSV fields can exceed 128 KiB. The application raises Python's CSV limit safely, parses complete cleartext bodies for CWMP semantics, and shows at most 64 KiB per packet with an exact total-byte truncation note.
- **DHCPv4 clients:** client MAC, inferred lease status, offered/requested address, server identifier, Option 12 hostname, Option 60 vendor class, Option 55 parameter request list, and transaction history.
- **Airtel management plane:** DNS, HTTP, TLS SNI, and subsequent IP traffic associated with `tms.airtelbroadband.in`, plus cleartext body-derived CWMP/TR-069 operations, Inform event codes, command keys, parameter/value evidence, and boot/reboot/reset-related indications when present in the capture.
- **mDNS:** LAN-side query/client details and an evidence-based success/failure/unanswered outcome using matching responses visible within five seconds.
- **WAN control plane:** PPPoE discovery/session, LCP control and Echo Request/Reply, PAP request/ack/failure, IPCP IPv4 and DNS negotiation, IPv6CP interface identifiers, and DHCPv6 IA address/prefix/DNS allocation.
- **Packet-evidence WAN diagnostics:** marks each PPPoE/LCP/PAP/IPCP/IPv6CP/DHCPv6 stage as complete, advanced, incomplete, failed, or not observed; reports the last successful stage and first evidenced break/incomplete point without manufacturing missing packets.
- **Alarms and events:** dedicated alarm/event view plus alarm markers on the corresponding ladder rows. DNS resolution alarms are emitted per domain only when neither A nor AAAA produced an address; success in either family suppresses the resolution alarm.
- **Reference-style UI:** persistent left navigation with counts for Overview, End-to-End Flows, Clients/Hosts, DHCPv4, DHCPv6, PPPoE/PPP, DNS, mDNS, TCP/MSS, HTTP/TLS, Management, Alarms, and Timeline.
- **Modal ladders:** packet-derived sequence diagrams per PPP session, DHCPv4 client, DHCPv6 exchange, DNS/mDNS transaction, and HTTP/management conversation. Each has labelled lifelines, directional arrows, always-visible frame/IST/message/details, a searchable message table, row count, and CSV export.
- **Time standard:** every displayed/exported event time is calculated in Python from `frame.time_epoch` and formatted as `DD-MMM-YYYY HH:MM:SS.mmm IST` using Asia/Kolkata's fixed UTC+05:30 offset. Relative seconds and UTC timestamps are not used in the UI or CSV exports.
- **Failure isolation:** each protocol and derived module is guarded independently. If one dissector/module fails, its error is logged and shown as a warning while other protocol results remain usable.
- **PCAP-grounded Q&A agent:** local Ollama is the default model backend at `http://127.0.0.1:11434`, using `qwen2.5:7b` by default. The backend supplies only credential-masked normalized evidence cached for the current PCAP, requires valid frame citations, and rejects unsupported model output. The original deterministic browser-side agent and all local guided templates remain available as an explicit mode and automatic fallback.
- **Issue-aligned guided templates:** the Q&A view automatically surfaces pre-created guides for the evidence actually present, including generated alarms, WAN establishment breaks, DNS failures, non-Bound DHCP clients, TCP retransmission/out-of-order findings, management/TR-069 activity, and incomplete mDNS discovery.

## Quick start with Docker (recommended)

Docker supplies the required TShark runtime.

```bash
cd pcap_insight
docker compose up --build
```

Open <http://127.0.0.1:8080>.

For a macOS-hosted Ollama with the analyzer in Docker, the container must address the
host explicitly. Because this is not a loopback URL from the container's perspective,
the remote-endpoint opt-in is intentionally required:

```bash
PCAP_AI_BASE_URL=http://host.docker.internal:11434 \
PCAP_AI_ALLOW_REMOTE=true docker compose up --build
```

For the strongest local-only boundary, run the analyzer natively so both processes use
`127.0.0.1`.

The former generic packet ladder has been removed. Open focused modal ladders from
the relevant client, session, transaction, or conversation record.

### Ask the capture agent

After analysis, open **Local Q&A Agent** in the left navigation. You can either type
a question or choose an issue guide selected for the current PCAP. If Ollama and the
configured model are ready, select **Local Ollama (PCAP-only context)** for model-assisted answers or
**Local deterministic rules** for the original browser-side behavior. Examples:

- `Summarize this capture and the issues found.`
- `Where did WAN establishment stop, and which frames prove it?`
- `Which DNS names failed, and what responses were observed?`
- `Which DHCP clients did not reach Bound state?`
- `Summarize retransmissions and out-of-order packets.`
- `What happened at frame 23?`
- `What management or TR-069 activity is visible?`

The local agent supports evidence questions for capture health/alarms, investigation order,
WAN/PPPoE/PPP, DNS, DHCPv4, TCP/MSS, HTTP/TLS, management/TR-069, mDNS,
clients/hosts, specific normalized frames, named DNS domains, and visible IP/MAC
endpoints. Responses include interpretation boundaries so that missing or encrypted
traffic is not presented as proof.

### Local Ollama backend (default)

The application checks Ollama at startup and through `GET /api/health`. It verifies
both that the service is reachable and that the configured model is pulled. If either
check fails, the Q&A panel shows **OLLAMA OFFLINE** or **MODEL MISSING** and automatically
uses the preserved deterministic rule engine.

Both Ollama APIs are supported:

- native `POST /api/chat` (preferred in `auto` mode);
- OpenAI-compatible `POST /v1/chat/completions`.

Each model call sends the question plus a bounded normalized-evidence JSON projection
for exactly one in-memory analysis session. PAP passwords, authorization values,
cookies, API keys, tokens, passphrases, URI credentials, and similar values are masked
before prompt construction. The raw `.pcap/.pcapng` file is not sent. Cleartext
HTTP/CWMP bodies are excluded by default; enable them only for an approved local model.

The endpoint is localhost-only by default. A non-localhost URL is blocked unless the
operator explicitly sets `PCAP_AI_ALLOW_REMOTE=true` or starts with `--allow-remote-ai`.
This opt-in is required even when a remote URL is otherwise correctly configured.

Stop the service with:

```bash
docker compose down
```

The Compose profile binds only to loopback, drops Linux capabilities, uses a read-only container filesystem, and places temporary uploads in a RAM-backed `/tmp`. Uploaded captures are deleted when each request completes.

## Native installation

### 1. Install TShark

Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y tshark
```

macOS with Homebrew:

```bash
brew install wireshark
```

Windows: install Wireshark and ensure `tshark.exe` is on `PATH`, or set `TSHARK_BIN` to its full path.

### 2. Install and start Ollama on macOS (optional but recommended)

For an Apple M1 with 16 GB RAM, the default `qwen2.5:7b` model provides a practical
quality/memory balance. In separate Terminal windows:

```bash
brew install ollama
ollama serve
```

Then pull the model once:

```bash
ollama pull qwen2.5:7b
```

Ollama listens on `http://127.0.0.1:11434` by default. The analyzer detects it at
startup. To use another installed model, pass `--ai-model <model>` or set
`PCAP_AI_MODEL=<model>`; for example:

```bash
python pcap_insight.py --ai-model llama3.1:8b
```

### 3. Create a Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python pcap_insight.py
```

The native default is <http://127.0.0.1:8765>. If 8765 is occupied, the app
automatically selects the next available port and prints the chosen URL.

Choose a specific port when required:

```bash
python pcap_insight.py --port 8899
```

Other native options:

```bash
python pcap_insight.py --host 127.0.0.1 --port 8899
python pcap_insight.py --no-auto-port
python pcap_insight.py --ai-model qwen2.5:7b --ai-api-style native
python pcap_insight.py --ai-api-style openai
```

## Configuration

| Environment variable | Default | Purpose |
|---|---:|---|
| `PCAP_HOST` | `127.0.0.1` | Listening address |
| `PCAP_PORT` | native `8765`; Docker `8080` | Listening port; an environment value is treated as explicit |
| `PCAP_MAX_UPLOAD_MB` | `512` | Upload size limit |
| `PCAP_MAX_TABLE_ROWS` | `20000` | Per-table extraction safety limit |
| `PCAP_MAX_BODY_BYTES` | `65536` | Maximum cleartext HTTP/body bytes shown per packet; complete cleartext is still parsed for CWMP semantics |
| `TSHARK_TIMEOUT` | `300` | Maximum seconds for each TShark pass |
| `TSHARK_BIN` | `tshark` | TShark executable/path |
| `PCAP_AI_BASE_URL` | `http://127.0.0.1:11434` | Ollama server root |
| `PCAP_AI_CHAT_URL` | unset | Optional full `/api/chat` or `/v1/chat/completions` URL; overrides the base URL |
| `PCAP_AI_MODEL` | `qwen2.5:7b` | Pulled Ollama model name; also configurable with `--ai-model` |
| `PCAP_AI_API_STYLE` | `auto` | `auto` tries native then OpenAI-compatible; or force `native`/`openai` |
| `PCAP_AI_ALLOW_REMOTE` | `false` | Explicit opt-in for non-localhost model endpoints; CLI equivalent `--allow-remote-ai` |
| `PCAP_AI_API_KEY` | unset | Optional bearer token kept only in the Flask backend |
| `PCAP_AI_TIMEOUT` | `60` | Backend AI request timeout in seconds |
| `PCAP_AI_HEALTH_CACHE_SECONDS` | `10` | Ollama/model health-result cache duration |
| `PCAP_AI_MAX_CONTEXT_BYTES` | `120000` | Maximum normalized PCAP evidence context per model call (sized for the default local model) |
| `PCAP_AI_MAX_OUTPUT_TOKENS` | `1400` | Requested maximum model answer length |
| `PCAP_AI_INCLUDE_BODIES` | `false` | Include bounded cleartext captured bodies in model context |
| `PCAP_AI_MAX_BODY_CHARS` | `4096` | Per-body character cap when body inclusion is enabled |
| `PCAP_QA_SESSION_TTL` | `3600` | In-memory PCAP analysis session lifetime in seconds |
| `PCAP_QA_MAX_SESSIONS` | `8` | Maximum remembered analyses per process |

Example:

```bash
PCAP_MAX_UPLOAD_MB=1024 TSHARK_TIMEOUT=600 python pcap_insight.py --port 8899
```

## API

- `GET /api/health` — reports application and TShark readiness.
- `POST /api/analyze` — multipart upload with the file field named `file`; returns the normalized analysis as JSON.
- `POST /api/qa` — asks the ready local Ollama model about one server-cached analysis using `analysis_id` and `question`; returns a clear error and leaves local rule fallback active when Ollama/model health fails.

Example:

```bash
curl -F "file=@capture.pcapng" http://127.0.0.1:8765/api/analyze > report.json
```

## Logic tests

The included tests validate the exact absolute IST timestamp format, CLI port
selection, dual-stack DNS alarm suppression, DNS failure alarms, packet-evidence
PPPoE/WAN break detection, the reference sidebar, modal ladder rendering, and local
Q&A template selection/evidence citations without requiring TShark or Flask to be
installed:

```bash
python -m unittest discover -s tests -v
```

## Interpretation and capture-point limitations

1. **Visible evidence only.** The application does not probe devices, query DNS externally, or infer packets that are not in the capture.
2. **DHCP vs. association.** DHCP ACK is evidence that a client completed a lease transaction on the captured Layer-2 segment; it does not prove that the client is still associated with a Wi-Fi access point.
3. **Encrypted traffic.** HTTPS request URLs and methods are not visible without decryption keys. The dashboard can still map TLS SNI when the ClientHello is visible and not protected by ECH.
4. **mDNS outcomes.** “No response seen” may mean failure, capture loss, a response outside the five-second correlation window, or that the capture point did not observe the response.
5. **TCP expert flags.** Retransmission/out-of-order findings are TShark analyses of the observed trace and can be affected by capture loss, NIC offload, asymmetric routing, and snap length.
6. **WAN protocols.** PPP control-protocol field names vary slightly by Wireshark version. The backend resolves known aliases dynamically and returns a warning when a dissector is unavailable.
7. **PAP sensitivity.** PAP is clear text on the wire. This application reports peer ID/message evidence but deliberately does not extract or display PAP passwords.
8. **Browser assets.** The reference-style dashboard, tables, exports, and SVG modal ladders are embedded in the Python application and do not require external chart libraries.
9. **DNS alarm scope.** DNS resolution alarms evaluate A and AAAA attempts grouped by normalized domain within the capture. An observed address in either family suppresses the domain alarm even if the other family times out or returns an error.
10. **WAN break scope.** “Incomplete” means the next success packet is not visible after the observed stage; it does not prove the network failed outside the capture. “Not observed” is never presented as a packet that occurred.
11. **HTTP/management bodies.** A body is shown only when TShark exposes packet or reassembled cleartext bytes that pass a printable-text check. TLS/SSL/QUIC application data is labelled encrypted and is not decoded by the application.
12. **CWMP semantics.** TR-069 operation, event, command-key, parameter, and reboot/reset labels are derived from literal XML tags and values present in the captured cleartext body. Absence of a label is not proof that an operation did not occur outside the visible capture.
13. **Local Q&A scope.** The preserved local mode is a deterministic evidence router, not a general-purpose language model. It maps supported question intents to the normalized analysis and will ask for a narrower protocol, entity, or frame when a question is outside that scope.
14. **Q&A evidence.** Frame citations point to normalized protocol timeline entries. A raw packet may exist without appearing in the normalized timeline if it was outside the selected protocol evidence or row limits.
15. **Backend AI scope.** Model answers are constrained by prompt and context to the current normalized PCAP evidence, but model output should still be verified against the cited frames and protocol tables. A context-bounded answer may require a narrower follow-up.

## Security notes

- Use only on captures you are authorized to inspect.
- The server uses `tshark -n` to disable network name resolution.
- Filenames are sanitized, extensions are allow-listed, and uploads are held in a per-request temporary directory.
- Local Q&A mode runs in the delivered HTML/JavaScript against the in-memory analysis object and makes no model request. Backend mode calls only the local Flask `/api/qa` route; Flask then contacts the explicitly configured AI URL with a bounded normalized evidence view for the current in-memory session.
- Backend AI credentials are read from server environment variables and are never exposed in HTML, analysis JSON, health details, or browser requests.
- Do not expose the development Flask server directly to an untrusted network. Keep the default loopback binding or place it behind an authenticated production reverse proxy.
- Large captures can consume CPU and memory. Adjust size/row/time limits to match the host.

## File layout

```text
pcap_insight.py      Flask backend and embedded HTML/JavaScript UI
tests/test_logic.py  Offline logic regression tests
tests/test_ui_smoke.py Embedded JavaScript ladder smoke test (uses Node.js when available)
validation/            Synthetic PCAP, validation fixture/scripts, report, and headless-browser screenshots
CHANGELOG.md         Versioned change summary
requirements.txt     Python dependencies
Dockerfile           Reproducible Python + TShark image
docker-compose.yml   Hardened local deployment profile
README.md            Setup, use, and interpretation guidance
LICENSE.txt          MIT license
```
