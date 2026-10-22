# PCAP Insight Workbench 1.5.0 — Validation Report

Validation date: 12-Oct-2026

## Outcome

The base analyzer UI was rendered in headless Chromium using the deterministic synthetic PCAP fixture. All analyzer views and focused modal ladders rendered, and the deterministic local Q&A agent was exercised with an evidence question. The v1.5.0 Ollama extension was then covered by the offline Python/Node regression suite described below. The old top-tab/Plotly ladder UI remains absent from the embedded `pcap_insight.py`.

## v1.5.0 Ollama extension validation

- `python -m unittest discover -s tests -v`: **26 tests passed** on 12-Oct-2026.
- Verified both Ollama native `/api/chat` and OpenAI-compatible `/v1/chat/completions` request/response handling with deterministic mock endpoints.
- Verified startup/health model discovery logic, default `qwen2.5:7b` selection, non-local endpoint blocking without explicit opt-in, and local-rule fallback UI wiring.
- Verified PCAP-only analysis-session context, frame-citation extraction/validation, and PAP/password/token/cookie/authorization masking before prompt construction.
- Re-ran the embedded Node.js Q&A and sequence-ladder smoke tests, preserving all v1.4.0 local templates and evidence answers.

The build environment did not provide a live Ollama daemon, Flask package source, or TShark binary, so live model generation and a fresh end-to-end PCAP upload were not executed in this extension pass. Those runtime dependencies are checked by the application and surface clear degraded/offline status without disabling deterministic local Q&A.

## Synthetic capture

`synthetic_all_protocols.pcap` contains 42 deterministic Ethernet frames covering:

- PPPoE discovery: PADI, PADO, PADR, PADS and PADT.
- PPP session protocols: LCP Configure, Echo Request/Reply and Terminate; PAP Request/Ack; IPCP with IPv4 and DNS; IPv6CP.
- DHCPv4 DORA with Options 12, 55 and 60 plus address, router, DNS, domain and lease timers.
- DHCPv6 Solicit, Advertise, Request and Reply with IA address, delegated prefix and DNS.
- DNS A/AAAA success for `tms.airtelbroadband.in`, A/AAAA failures for `broken.example`, and LLMNR.
- mDNS query/response.
- TCP/HTTP CWMP Inform and InformResponse with cleartext XML bodies.
- An intentional retransmitted HTTP segment for TCP anomaly evidence.

The capture was decoded by the supplied reference browser analyzer. Its saved protocol summary (`reference_decoder_summary.json`) reported:

- 1 DHCPv4 client and 4 DHCPv4 messages.
- 1 DHCPv6 client and 4 DHCPv6 messages.
- 1 PPPoE/PPP session with discovery, LCP, PAP, IPCP and IPv6CP phases.
- 6 DNS-family transactions, including LLMNR.
- 2 mDNS packets.
- 2 HTTP requests (one retransmission) and 1 HTTP response.
- Protocol counts for PPPoE Discovery/Session, PPP-LCP, PPP-PAP, PPP-IPCP, PPP-IPv6CP, DHCPv4, DHCPv6, DNS, LLMNR, mDNS and HTTP.

## Headless browser validation

Browser: Google Chrome for Testing 145.0.7632.6, launched by Python Playwright.
Viewport: 1600 × 1000.

The exact HTML embedded in `pcap_insight.py` was served by `fixture_server.py`; upload of `synthetic_all_protocols.pcap` returned the deterministic fixture mirroring that capture. This exercised the production HTML, navigation, rendering, search/table code, modal code and browser exports.

### Every sidebar view rendered

Screenshots under `screenshots/actual/`:

1. Overview
2. Local Q&A Agent
3. End-to-End Flows
4. Clients / Hosts
5. DHCPv4
6. DHCPv6
7. PPPoE / PPP
8. DNS
9. mDNS
10. TCP / MSS
11. HTTP / TLS
12. Management
13. Alarms
14. Timeline

### Every requested modal rendered

14. DHCPv4 DORA ladder
15. DHCPv6 Solicit/Advertise/Request/Reply ladder
16. PPPoE/PPP session ladder
17. DNS transaction ladder
18. HTTP conversation ladder with cleartext bodies
19. Management conversation ladder with CWMP Inform/InformResponse bodies

`actual_views_contact_sheet.png` and `modal_ladders_contact_sheet.png` provide compact inspection sheets.

## Local Q&A validation

The production embedded JavaScript was validated in two independent ways:

- A Node.js smoke test supplied deterministic WAN, DNS, TCP, alarm, frame, and capture metadata. It verified that issue-aligned templates were selected, the WAN answer named the IPCP break and cited frame 23, the DNS answer named `broken.test` and cited frame 2, a frame-specific question returned the normalized timeline evidence, and the fallback preserved the local/no-external-model boundary.
- Headless Chromium loaded `synthetic_all_protocols.pcap` through the fixture server, opened the Local Q&A Agent, and asked: `Which DNS names failed, and which frames support the finding?` The rendered answer identified `broken.example`, reported the visible NXDOMAIN/SERVFAIL outcomes, and displayed frame evidence buttons for frames 29–32. No browser page error was emitted.

For the synthetic fixture, the agent displayed eight applicable guides: TCP reliability, DNS failures, the generated alarm, capture health, investigation planning, capture limits, management/TR-069 activity, and the first alarm frame. The guide set is computed from the loaded analysis and therefore changes with each PCAP.

## Visual comparison with reference

The same synthetic PCAP was loaded into the supplied reference HTML. Reference screenshots and side-by-side comparison montages are included for:

- Overview
- DHCPv4
- PPPoE / PPP
- DNS
- DHCPv4 DORA modal
- PPPoE / PPP modal

Verified visually:

- Fixed left sidebar with counts and matching dark panel/card styling.
- Header file metadata plus Open PCAP and Export JSON controls.
- DHCPv4 card hierarchy, Bound/hostname/vendor badges, requested option fields, message chips, All clients table and DORA button.
- Modal lifeline header boxes, dashed lifelines and true-direction arrowheads.
- Frame plus absolute IST time at the left of every arrow.
- Bold protocol-coloured labels and visible detail text, without hover dependency.
- Searchable ladder message table, row count and CSV button below the diagram.
- DNS RCODE badges, latency and distinct CNAME/IPv4/IPv6 chips.
- HTTP/management cleartext bodies shown below their modal tables.

## Timestamp verification

Python regression tests verify the exact format:

`DD-MMM-YYYY HH:MM:SS.mmm IST`

Example from the deterministic capture:

`12-Oct-2025 11:50:00.123 IST`

The embedded UI and modal/CSV column definitions use the Python-produced `timestamp_india`/`capture_start_india` values. Relative capture seconds are not used as displayed event timestamps.

## Large HTTP/CWMP body fix

Regression coverage includes a cleartext HTTP/CWMP field over 200 KiB:

- Python's CSV field limit is raised at module import using a `sys.maxsize` loop that backs down on `OverflowError`.
- The complete body is decoded and parsed; a CWMP `Inform` located beyond the 64 KiB display boundary is still detected.
- The displayed body is limited to 64 KiB and ends with an exact total-size truncation note.
- A simulated HTTP `_csv.Error` proves HTTP/TLS can fail while core, DNS, DHCP, WAN and other results still return with a visible warning.

All 21 Python/UI regression tests passed when this report was prepared.

## Important environment limitation

A genuine TShark executable was not present in this Azure Linux sandbox. Package repositories and external binary downloads were blocked with HTTP 403 by sandbox policy, so **a production `TSharkAnalyzer` pass could not be executed here**. This report does not claim otherwise.

To compensate without hiding the limitation:

- The PCAP itself was decoded successfully by the supplied reference analyzer in headless Chromium.
- The production embedded UI was exercised through HTTP upload with a deterministic analysis fixture matching the PCAP.
- The CSV and >200 KiB HTTP regression runs through the actual Python extraction/body-processing code.
- Production/native and Docker deployments still require/use real TShark as documented.

For a complete local TShark acceptance run, execute after installing Wireshark/TShark:

```bash
python pcap_insight.py --port 8899
curl -F "file=@validation/synthetic_all_protocols.pcap" http://127.0.0.1:8899/api/analyze > validation/tshark_analysis.json
```

Then run `validation/render_validation_screenshots.py` against that result/server if the validation host provides Playwright and Chromium.
