# Changelog

## 1.5.0 — 2026-10-12

- Added local Ollama as the default backend Q&A provider at `http://127.0.0.1:11434`, with `qwen2.5:7b` as the Apple-M1-friendly default model and environment/CLI model selection.
- Added support for both Ollama native `/api/chat` and OpenAI-compatible `/v1/chat/completions` APIs.
- Added startup and health checks for Ollama reachability and pulled-model availability; the UI shows model/status and automatically falls back to local deterministic Q&A.
- Blocked non-localhost AI endpoints by default unless `PCAP_AI_ALLOW_REMOTE=true` or `--allow-remote-ai` explicitly opts in.
- Bound every model question to an opaque, expiring, in-memory analysis session for one uploaded PCAP; the browser sends only the question and analysis ID to `/api/qa`.
- Added a strict evidence-only system prompt, bounded normalized context, credential/PAP-secret masking, frame-reference validation, and prompt-injection handling for untrusted packet strings.
- Excluded captured HTTP/CWMP bodies from model context by default, with explicit opt-in and per-body limits.
- Preserved the complete deterministic browser-side Q&A engine and all issue-triggered templates as an explicit Local mode and automatic fallback when the backend model fails.
- Kept the analyzer, upload API, protocol views, ladders, tables, exports, alarms, Docker/native behavior, and all v1.4.0 evidence rules intact.

## 1.4.0 — 2026-10-12

- Added a local, browser-side Q&A agent for asking evidence questions about the currently analyzed PCAP without a cloud model, external lookup, or new runtime dependency.
- Added issue-triggered guided templates for alarms, WAN establishment breaks, DNS failures, non-Bound DHCP clients, TCP retransmission/out-of-order findings, management/TR-069 activity, incomplete mDNS discovery, investigation planning, and capture limitations.
- Added deterministic answers for capture health, WAN/PPPoE/PPP, DNS, DHCPv4, TCP/MSS, HTTP/TLS, management/TR-069, mDNS, clients/hosts, protocol coverage, named visible entities, and normalized frame numbers.
- Q&A evidence cards cite frames and open the existing focused frame ladder; answers preserve capture-point, encryption, offload, and correlation-window limitations.
- Added Node.js UI regressions proving issue-template selection, WAN/DNS/frame evidence answers, and the no-external-model privacy boundary.
- Preserved the existing upload API, protocol extraction, tables, exports, ladders, alarms, CLI, Docker deployment, and failure-isolation behavior.

## 1.3.1 — 2026-10-12

- Raised Python's CSV field-size limit at module load using a `sys.maxsize` fallback loop, preventing `_csv.Error: field larger than field limit (131072)` for large TShark HTTP/CWMP fields.
- Full cleartext bodies remain available to the semantic parser, while UI/API display bodies are bounded to 64 KiB and carry a `[truncated, N bytes total; showing first 65,536 bytes]` note.
- Isolated Core, TCP, DNS, HTTP/TLS, DHCPv4, mDNS, management, PPPoE/WAN, alarm, timeline, host, and correlation modules. A module exception is logged and returned as a visible warning while unaffected modules continue.
- Added a regression with a cleartext HTTP/CWMP body over 200 KiB whose `Inform` element appears beyond the display boundary, proving full semantic parsing and bounded presentation.
- Added a module-isolation regression reproducing an HTTP CSV error while preserving the rest of the analysis response.

## 1.3.0 — 2026-10-12

- Reworked the dashboard to match the supplied PCAP Flow Analyzer reference: sticky header, file/capture metadata, Open PCAP and Export JSON controls, and a left sidebar with counts for all requested views.
- Added full DHCPv4 client cards with state, Option 12/60 badges, address/server/network/DNS/domain/lease/client/user/FQDN/relay/PRL/VLAN evidence, message chips, and per-client DORA ladder.
- Replaced the remaining general call-flow page with focused reference-style modal ladders per PPP session, DHCPv4 client, DHCPv6 exchange, DNS/mDNS transaction, and HTTP/management conversation.
- Modal ladders now show labelled endpoint boxes, dashed lifelines, true-direction arrows, protocol-coloured message labels, details, and frame plus absolute IST time at the left of every arrow.
- Added searchable modal message tables with exact Frame, IST time, Dir, Proto, Code, Id, Details columns, row counts, and CSV export.
- Added a combined searchable/exportable DNS table for DNS, mDNS, and LLMNR evidence with RCODE, latency, and separately coloured CNAME/IPv4/IPv6 answers.
- Expanded DHCPv4 option extraction and added aggregated host, DHCPv6 client/exchange, PPP session, and end-to-end journey models.
- Changed the universal timestamp format to `DD-MMM-YYYY HH:MM:SS.mmm IST`, calculated in Python from `frame.time_epoch` using the fixed Asia/Kolkata UTC+05:30 offset.
- Added native `--host`, `--port`, and `--no-auto-port` CLI options. Native default port is 8765 and automatically advances when occupied; Docker remains on 8080.

## 1.2.0 — 2026-10-12

- Replaced the combined packet ladder with separate readable protocol call-flow/sequence diagrams for DNS, DHCP, PPPoE discovery, LCP, PAP, IPCP, IPv6CP, DHCPv6, mDNS, HTTP, management, and TCP.
- Added endpoint lifelines, directional arrows, and always-visible per-arrow cards carrying IST date-time, frame, message type, source/destination, and key packet evidence.
- Added transaction/session grouping and pagination (20 messages by default) so dense captures do not become an overlapping generic line plot.
- Suppressed generic PPPoE “Session data” rows from the PPPoE discovery call flow while retaining explicit LCP/PAP/IPCP/IPv6CP protocol messages.
- Added bounded extraction and display of HTTP cleartext request/response payloads when visible, with explicit encrypted/binary/not-visible evidence states.
- Added body-derived CWMP/TR-069 operation, Inform event-code, command-key, parameter/value, and boot/reboot/reset evidence for `tms.airtelbroadband.in` management traffic.
- Preserved DNS alarms, flow alarm markers, and packet-evidence WAN break-point diagnostics in the protocol call flows.
- Converted remaining TCP and management timeline axes to absolute India date-time.
- Expanded regression coverage for cleartext/binary payload handling, CWMP semantics, PPP protocol separation, and protocol call-flow rendering.

## 1.1.0 — 2026-10-12

- Replaced the hover-dependent Plotly ladder with a scalable SVG sequence view whose packet cards are always visible on/above the flow arrows.
- Added India Standard Time packet timestamps (`DD-MM-YYYY HH:MM:SS.mmm IST`) throughout protocol tables, alarms, events, WAN diagnostics, and the ladder.
- Added ladder category, text/exact-frame, alarm-only, row-limit, and density controls; packet selection opens full captured details.
- Expanded DNS transaction evidence with query/response frames, A/AAAA type, separate IPv4/IPv6 endpoints, A/AAAA/CNAME answers, response status, and packet summaries.
- Added domain-level dual-stack DNS outcomes. A DNS resolution alarm is raised only if no observed A or AAAA attempt for the domain returned an address.
- Added a dedicated Alarms / Events view and visible alarm markers on affected ladder flows.
- Added packet-evidence PPPoE/WAN stage diagnostics for PPPoE discovery, LCP, PAP, IPCP, IPv6CP, and DHCPv6, including last successful/advanced stage and the first failed/incomplete stage.
- Added explicit handling for PPPoE error tags and non-zero/absent session assignment.
- Preserved the existing TCP, HTTP, DHCPv4, mDNS, Airtel management, WAN protocol tables, flow graph, upload API, and container deployment.
- Added offline backend logic tests and an embedded-JavaScript ladder smoke test.
