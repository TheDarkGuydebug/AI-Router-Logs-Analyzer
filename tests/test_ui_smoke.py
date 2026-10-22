import ast
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class UiSmokeTests(unittest.TestCase):
    def embedded_html(self):
        source = (Path(__file__).resolve().parents[1] / "pcap_insight.py").read_text()
        module = ast.parse(source)
        assignment = next(
            node for node in module.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "HTML" for target in node.targets)
        )
        return ast.literal_eval(assignment.value)

    def test_reference_sidebar_and_header_controls_exist(self):
        html = self.embedded_html()
        for label in (
            "Overview", "End-to-End Flows", "Clients / Hosts", "DHCPv4", "DHCPv6",
            "PPPoE / PPP", "DNS", "mDNS", "TCP / MSS", "HTTP / TLS",
            "Management (tms.airtelbroadband.in)", "Alarms", "Timeline",
            "Local Q&A Agent",
        ):
            self.assertIn(label, html)
        self.assertIn('id="openbtn"', html)
        self.assertIn('id="exportJson"', html)
        self.assertIn('<title>PCAP Insight Workbench v{{ version }}</title>', html)
        self.assertGreaterEqual(html.count('v{{ version }}'), 3)  # title, header and footer
        self.assertIn('warnings=(D.warnings||[])', html)
        self.assertIn('function answerQuestion', html)
        self.assertIn('function qaTemplates', html)
        self.assertIn('function askCaptureAgent', html)
        self.assertIn("fetch('/api/qa'", html)
        self.assertIn('OLLAMA READY', html)
        self.assertIn('LOCAL · NO EXTERNAL MODEL', html)
        for field in (
            "Assigned IP", "Requested IP (50)", "Server ID (54)", "Subnet / Router",
            "DNS (6)", "Domain (15)", "Lease / T1 / T2", "Client ID (61)",
            "User class (77)", "FQDN (81)", "Relay agent (82)",
            "PRL (55) fingerprint", "VLAN", "DORA ladder &amp; options",
        ):
            self.assertIn(field, html)
        for column in ("Frame", "IST time", "Dir", "Proto", "Code", "Id", "Details"):
            self.assertIn(column, html)
        self.assertNotIn("Interactive packet ladder", html)
        self.assertNotIn("ladderViewport", html)
        self.assertNotIn("Plotly", html)
        source = (Path(__file__).resolve().parents[1] / "pcap_insight.py").read_text()
        self.assertIn('print(f"PCAP Insight Workbench {APP_VERSION}:', source)

    @unittest.skipUnless(shutil.which("node"), "Node.js is required for the embedded UI smoke test")
    def test_modal_sequence_has_visible_lifelines_arrows_and_ist_labels(self):
        html = self.embedded_html()
        script = re.findall(r"<script>(.*?)</script>", html, re.S)[-1]
        harness = r'''
class FakeElement {
  constructor(id){this.id=id;this._html='';this.value='';this.checked=false;this.files=[];this.style={};this.className='';this.disabled=false;this.textContent='';this.dataset={};this.classList={add(){},remove(){},toggle(){}}}
  set innerHTML(v){this._html=String(v)} get innerHTML(){return this._html}
  addEventListener(){} querySelectorAll(){return []} querySelector(){return null}
  closest(){return null} scrollIntoView(){} click(){}
}
const ids=new Map();
const get=id=>{if(!ids.has(id))ids.set(id,new FakeElement(id));return ids.get(id)};
global.document={querySelector:s=>s.startsWith('#')?get(s.slice(1)):get(s),querySelectorAll:s=>[],createElement:s=>new FakeElement(s)};
global.window={scrollTo(){}};global.URL={createObjectURL(){return 'blob:test'},revokeObjectURL(){}};global.Blob=class{};
'''
        assertions = r'''
const lanes=[{name:'PPPoE Client (CPE/ONT)',sub:'00:11:22:33:44:55'},{name:'BNG / BRAS (AC)',sub:'Airtel-AC 66:77:88:99:aa:bb'}];
const messages=[{frame:'42',time:'01-Jan-1970 05:30:01.000 IST',from:0,to:1,src:'00:11',dst:'66:77',proto:'LCP',code:'Echo-Request',id:'244',details:'magic=0x1234 · session=0x0010',raw:{}}];
const out=sequenceSvg(lanes,messages);
for(const expected of ['PPPoE Client (CPE/ONT)','BNG / BRAS (AC)','Frame 42','01-Jan-1970 05:30:01.000 IST','LCP Echo-Request id=244','magic=0x1234','marker-end','class="lane"']){
  if(!out.includes(expected)){console.error('missing',expected);process.exit(2)}
}
if(out.includes('hover')){console.error('hover-only sequence information detected');process.exit(3)}
console.log('reference modal sequence smoke test OK');
'''
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "ui-smoke.js"
            path.write_text(harness + "\n" + script + "\n" + assertions)
            result = subprocess.run(["node", str(path)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("smoke test OK", result.stdout)

    @unittest.skipUnless(shutil.which("node"), "Node.js is required for the local Q&A smoke test")
    def test_local_qa_agent_selects_issue_templates_and_cites_evidence(self):
        html = self.embedded_html()
        script = re.findall(r"<script>(.*?)</script>", html, re.S)[-1]
        harness = r'''
class FakeElement {
  constructor(id){this.id=id;this._html='';this.value='';this.checked=false;this.files=[];this.style={};this.className='';this.disabled=false;this.textContent='';this.dataset={};this.classList={add(){},remove(){},toggle(){}}}
  set innerHTML(v){this._html=String(v)} get innerHTML(){return this._html}
  addEventListener(){} querySelectorAll(){return []} querySelector(){return null}
  closest(){return null} scrollIntoView(){} click(){}
}
const ids=new Map();
const get=id=>{if(!ids.has(id))ids.set(id,new FakeElement(id));return ids.get(id)};
global.document={querySelector:s=>s.startsWith('#')?get(s.slice(1)):get(s),querySelectorAll:s=>[],createElement:s=>new FakeElement(s)};
global.window={scrollTo(){}};global.URL={createObjectURL(){return 'blob:test'},revokeObjectURL(){}};global.Blob=class{};
'''
        assertions = r'''
const fixture={
 metadata:{filename:'fixture.pcap',packets:20,duration_seconds:4,capture_start_india:'01-Jan-1970 05:30:00.000 IST',capture_end_india:'01-Jan-1970 05:30:04.000 IST',analysis_scope:'visible packets only',tshark:'TShark test'},
 alarms:[{id:'ALM-0001',severity:'high',category:'WAN',type:'wan_establishment_break',title:'WAN establishment incomplete: IPCP',detail:'IPCP Configure-Request is visible but no completion is visible.',frame:'23',timestamp_india:'01-Jan-1970 05:30:03.000 IST',related_frames:['23']}],
 dns:{domain_outcomes:[{domain:'broken.test',resolved:false,attempt_statuses:['NXDOMAIN'],frames:['2'],frame:'2',timestamp_india:'01-Jan-1970 05:30:01.000 IST',ipv4_addresses:[],ipv6_addresses:[]}],transactions:[]},
 wan:{diagnostics:{statement:'WAN establishment is incomplete at IPCP.',visibility_note:'Visible evidence only.',last_successful_stage:'PAP',break_stage:{stage:'IPCP',status:'incomplete',reason:'IPCP Configure-Request is visible but no completion is visible.',frames:['23'],last_frame:'23',timestamp_india:'01-Jan-1970 05:30:03.000 IST'}}},
 dhcp:{clients:[]},tcp:{packet_count:10,retransmissions:2,out_of_order:1,anomalies:[{frame:'18',timestamp_india:'01-Jan-1970 05:30:02.000 IST',kind:'Retransmission',src:'192.0.2.1',dst:'192.0.2.2',stream:'4'}]},
 management:{target:'tms.airtelbroadband.in',events:[]},mdns:{transactions:[],events:[]},warnings:[],hosts:[],http:{requests:[],responses:[],tls:[],messages:[]},
 timeline:[{frame:'23',timestamp_india:'01-Jan-1970 05:30:03.000 IST',category:'IPCP',message_type:'Configure-Request',summary:'IPCP Configure-Request',details:['session 0x10'],src:'cpe',dst:'bng',src_host:'cpe',dst_host:'bng'}]
};
const idsFound=qaTemplates(fixture).map(x=>x.id);
for(const id of ['wan','dns','tcp','alarms','summary','next','coverage'])if(!idsFound.includes(id)){console.error('missing template',id,idsFound);process.exit(2)}
const wan=answerQuestion('Where did WAN establishment stop, and which frames prove it?',fixture);
if(!wan.title.includes('IPCP')||wan.evidence[0].frame!=='23'||!wan.findings.join(' ').includes('PAP')){console.error('bad WAN answer',wan);process.exit(3)}
const dns=answerQuestion('Which DNS names failed?',fixture);
if(!dns.findings.join(' ').includes('broken.test')||dns.evidence[0].frame!=='2'){console.error('bad DNS answer',dns);process.exit(4)}
const frame=answerQuestion('Explain frame 23',fixture);
if(!frame.summary.includes('timeline item')||!frame.findings.join(' ').includes('Configure-Request')){console.error('bad frame answer',frame);process.exit(5)}
const fallback=answerQuestion('Tell me something unrelated',fixture);
if(!fallback.note.includes('does not send')){console.error('missing local privacy boundary',fallback);process.exit(6)}
console.log('local Q&A smoke test OK');
'''
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "qa-smoke.js"
            path.write_text(harness + "\n" + script + "\n" + assertions)
            result = subprocess.run(["node", str(path)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("local Q&A smoke test OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
