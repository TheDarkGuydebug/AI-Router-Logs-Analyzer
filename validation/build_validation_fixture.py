#!/usr/bin/env python3
"""Build deterministic analyzer JSON matching synthetic_all_protocols.pcap.

This fixture exists only to drive repeatable headless visual validation in
restricted environments where TShark cannot be installed. Production analysis
continues to use TShark through TSharkAnalyzer.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_app():
    flask = types.ModuleType("flask")
    class DummyFlask:
        def __init__(self,*a,**k): self.config={}; self.logger=types.SimpleNamespace(exception=lambda *a,**k:None)
        def get(self,*a,**k): return lambda fn: fn
        post=get; errorhandler=get
        def run(self,*a,**k): pass
    flask.Flask=DummyFlask; flask.jsonify=lambda x=None,**k:x if x is not None else k
    flask.render_template_string=lambda text,**k:text; flask.request=types.SimpleNamespace(files={})
    werkzeug=types.ModuleType("werkzeug"); utils=types.ModuleType("werkzeug.utils"); utils.secure_filename=lambda x:x; werkzeug.utils=utils
    sys.modules.update({"flask":flask,"werkzeug":werkzeug,"werkzeug.utils":utils})
    spec=importlib.util.spec_from_file_location("pcap_validation_app",ROOT/"pcap_insight.py")
    mod=importlib.util.module_from_spec(spec);sys.modules[spec.name]=mod;spec.loader.exec_module(mod);return mod


def main():
    m=load_app(); base=1760250000.123
    def row(frame,proto,src,dst,**kw):
        epoch=base+(frame-1)*.075
        ip_src=src if "." in src else ""; ip_dst=dst if "." in dst else ""
        ipv6_src=src if ":" in src and "." not in src else ""; ipv6_dst=dst if ":" in dst and "." not in dst else ""
        return {"frame":str(frame),"epoch":str(epoch),"relative":str((frame-1)*.075),"timestamp_india":m.india_timestamp(epoch),"protocol":proto,"src":src,"dst":dst,"ip_src":ip_src,"ip_dst":ip_dst,"ipv6_src":ipv6_src,"ipv6_dst":ipv6_dst,"eth_src":"","eth_dst":"","length":"100","info":kw.pop("info",proto),**kw}
    # PPP/WAN evidence.
    pppoe=[
      row(1,"PPPoED","00:11:22:33:44:55","ff:ff:ff:ff:ff:ff",event="PADI",code="0x09",session_id="0x0000",host_uniq="aa:bb:cc:dd",service_name="internet"),
      row(2,"PPPoED","66:77:88:99:aa:bb","00:11:22:33:44:55",event="PADO",code="0x07",session_id="0x0000",host_uniq="aa:bb:cc:dd",service_name="internet",ac_name="Airtel-BNG-01"),
      row(3,"PPPoED","00:11:22:33:44:55","66:77:88:99:aa:bb",event="PADR",code="0x19",session_id="0x0000",host_uniq="aa:bb:cc:dd",service_name="internet"),
      row(4,"PPPoED","66:77:88:99:aa:bb","00:11:22:33:44:55",event="PADS",code="0x65",session_id="0x0010",host_uniq="aa:bb:cc:dd",service_name="internet",ac_name="Airtel-BNG-01"),
      row(16,"PPPoED","00:11:22:33:44:55","66:77:88:99:aa:bb",event="PADT",code="0xa7",session_id="0x0010",host_uniq="aa:bb:cc:dd"),
    ]
    lcp=[row(5,"LCP","00:11:22:33:44:55","66:77:88:99:aa:bb",event="Configure-Request",identifier="10",mru="1492",magic="0x12345678",pppoe_session_id="0x0010"),row(6,"LCP","66:77:88:99:aa:bb","00:11:22:33:44:55",event="Configure-Ack",identifier="10",mru="1492",magic="0x12345678",pppoe_session_id="0x0010"),row(13,"LCP","00:11:22:33:44:55","66:77:88:99:aa:bb",event="Echo-Request",identifier="244",magic="0x12345678",pppoe_session_id="0x0010"),row(14,"LCP","66:77:88:99:aa:bb","00:11:22:33:44:55",event="Echo-Reply",identifier="244",magic="0x12345678",pppoe_session_id="0x0010"),row(15,"LCP","00:11:22:33:44:55","66:77:88:99:aa:bb",event="Terminate-Request",identifier="55",pppoe_session_id="0x0010",info="admin reset")]
    pap=[row(7,"PAP","00:11:22:33:44:55","66:77:88:99:aa:bb",event="Authenticate-Request",identifier="20",peer_id="user@airtel",pppoe_session_id="0x0010"),row(8,"PAP","66:77:88:99:aa:bb","00:11:22:33:44:55",event="Authenticate-Ack",identifier="20",message="Welcome",pppoe_session_id="0x0010")]
    ipcp=[row(9,"IPCP","00:11:22:33:44:55","66:77:88:99:aa:bb",event="Configure-Request",identifier="30",ipv4="0.0.0.0",primary_dns="0.0.0.0",pppoe_session_id="0x0010"),row(10,"IPCP","66:77:88:99:aa:bb","00:11:22:33:44:55",event="Configure-Ack",identifier="30",ipv4="100.64.1.10",primary_dns="1.1.1.1",secondary_dns="8.8.8.8",pppoe_session_id="0x0010")]
    ipv6cp=[row(11,"IPv6CP","00:11:22:33:44:55","66:77:88:99:aa:bb",event="Configure-Request",identifier="40",interface_id="021122fffe334455",pppoe_session_id="0x0010"),row(12,"IPv6CP","66:77:88:99:aa:bb","00:11:22:33:44:55",event="Configure-Ack",identifier="40",interface_id="021122fffe334455",pppoe_session_id="0x0010")]
    dhcpv6=[row(21,"DHCPv6","fe80::10","ff02::1:2",event="Solicit",transaction_id="0x010203",duid="000100010001e240020000000010"),row(22,"DHCPv6","fe80::1","fe80::10",event="Advertise",transaction_id="0x010203",duid="000100010001e240020000000010",iaaddr="2001:db8:100::10",iaprefix="2001:db8:200::/56"),row(23,"DHCPv6","fe80::10","fe80::1",event="Request",transaction_id="0x010203",duid="000100010001e240020000000010"),row(24,"DHCPv6","fe80::1","fe80::10",event="Reply",transaction_id="0x010203",duid="000100010001e240020000000010",iaaddr="2001:db8:100::10",iaprefix="2001:db8:200::/56",dns_servers="2001:4860:4860::8888",status_code="0")]
    wan={"pppoe":pppoe,"lcp":lcp,"pap":pap,"ipcp":ipcp,"ipv6cp":ipv6cp,"dhcpv6":dhcpv6}
    wan["diagnostics"]=m.TSharkAnalyzer._build_wan_diagnostics(pppoe,lcp,pap,ipcp,ipv6cp,dhcpv6)
    wan["summary"]={"pppoe_sessions":["0x0010"],"lcp_echo_requests":1,"lcp_echo_replies":1,"pap_success":1,"pap_failure":0,"ipv4_allocations":["100.64.1.10"],"ipcp_dns_servers":["1.1.1.1","8.8.8.8"],"ipv6_interface_ids":["021122fffe334455"],"dhcpv6_addresses":["2001:db8:100::10"],"dhcpv6_prefixes":["2001:db8:200::/56"],"dhcpv6_dns_servers":["2001:4860:4860::8888"]}
    # DHCPv4 client/event model.
    d4=[]
    for frame,msg,src,dst,ip in [(17,"Discover","0.0.0.0","255.255.255.255","192.168.1.100"),(18,"Offer","192.168.1.1","255.255.255.255","192.168.1.100"),(19,"Request","0.0.0.0","255.255.255.255","192.168.1.100"),(20,"ACK","192.168.1.1","255.255.255.255","192.168.1.100")]:
        d4.append(row(frame,"DHCP",src,dst,xid="0x12345678",mac="02:00:00:00:00:10",message=msg,ip=ip,option_12_hostname="CPE-VALIDATION",option_60_vendor_class="Airtel-CPE",option_55_parameter_request_list=["1","3","6","15","51","54","58","59"],subnet="255.255.255.0",router=["192.168.1.1"],dns_servers=["1.1.1.1","8.8.8.8"],domain="home.airtel",lease_time="86400",renewal_time="43200",rebinding_time="75600",client_id_value="01:02:00:00:00:00:10",user_class="home",fqdn="cpe.home.airtel",relay_agent=["circuit-1"],giaddr="198.51.100.1",vlans=["200"]))
    d4client={"mac":"02:00:00:00:00:10","hostnames":["CPE-VALIDATION"],"vendor_classes":["Airtel-CPE"],"parameter_request_list":["1","3","6","15","51","54","58","59"],"ipv4_addresses":["192.168.1.100"],"server_ids":["192.168.1.1"],"messages":["Discover","Offer","Request","ACK"],"first_frame":"17","last_frame":"20","status":"Bound","requested_ips":["192.168.1.100"],"offered_ips":["192.168.1.100"],"subnets":["255.255.255.0"],"routers":["192.168.1.1"],"dns_servers":["1.1.1.1","8.8.8.8"],"domains":["home.airtel"],"lease_times":["86400"],"renewal_times":["43200"],"rebinding_times":["75600"],"client_ids":["01:02:00:00:00:00:10"],"user_classes":["home"],"fqdns":["cpe.home.airtel"],"relay_agents":["circuit-1"],"giaddrs":["198.51.100.1"],"vlans":["200"],"transactions":d4}
    dhcp={"packet_count":4,"clients":[d4client],"events":d4}
    # DNS/mDNS model.
    dns_tx=[]
    def dns_pair(qf,rf,txid,name,qtype,answer=None,rcode="NOERROR",proto="DNS"):
        q=row(qf,proto,"192.168.1.100:53000","192.168.1.1:53"); r=row(rf,proto,"192.168.1.1:53","192.168.1.100:53000")
        ipv4=[answer] if answer and "." in answer else []; ipv6=[answer] if answer and ":" in answer else []
        return {"frame":str(qf),"epoch":q["epoch"],"relative":q["relative"],"timestamp_india":q["timestamp_india"],"dns_id":txid,"proto":proto,"client":q["src"],"server":q["dst"],"name":name,"query_type":qtype,"type":qtype,"query_type_number":1 if qtype=="A" else 28,"query_src_ipv4":"192.168.1.100","query_dst_ipv4":"192.168.1.1","query_src_ipv6":"","query_dst_ipv6":"","query_details":f"{qtype} query {name}","status":f"Resolved ({qtype})" if answer else rcode,"resolved":bool(answer),"answers":[answer] if answer else [],"ipv4_answers":ipv4,"ipv6_answers":ipv6,"cnames":[],"response_frame":str(rf),"response_epoch":r["epoch"],"response_timestamp_india":r["timestamp_india"],"response_relative":r["relative"],"response_src_ipv4":"192.168.1.1","response_dst_ipv4":"192.168.1.100","response_src_ipv6":"","response_dst_ipv6":"","response_client":q["src"],"response_server":q["dst"],"response_details":f"{rcode} answer {answer or 'none'}","rcode":0 if rcode=="NOERROR" else (3 if rcode=="NXDOMAIN" else 2),"rcode_name":rcode,"latency_ms":75.0}
    dns_tx += [dns_pair(25,26,"0x1001","tms.airtelbroadband.in","A","203.0.113.80"),dns_pair(27,28,"0x1002","tms.airtelbroadband.in","AAAA","2001:db8::80"),dns_pair(29,30,"0x1003","broken.example","A",None,"NXDOMAIN"),dns_pair(31,32,"0x1004","broken.example","AAAA",None,"SERVFAIL"),dns_pair(33,34,"0x2001","gateway","A","192.168.1.1","NOERROR","LLMNR")]
    outcomes=[{"domain":"tms.airtelbroadband.in","status":"Resolved","resolved":True,"ipv4_addresses":["203.0.113.80"],"ipv6_addresses":["2001:db8::80"],"query_types":["A","AAAA"],"attempt_count":2,"frames":["25","26","27","28"],"frame":"28","timestamp_india":row(28,"DNS","","")["timestamp_india"],"client":"192.168.1.100:53000","server":"192.168.1.1:53","attempt_statuses":["Resolved (A)","Resolved (AAAA)"]},{"domain":"broken.example","status":"Resolution failed","resolved":False,"ipv4_addresses":[],"ipv6_addresses":[],"query_types":["A","AAAA"],"attempt_count":2,"frames":["29","30","31","32"],"frame":"32","timestamp_india":row(32,"DNS","","")["timestamp_india"],"client":"192.168.1.100:53000","server":"192.168.1.1:53","attempt_statuses":["NXDOMAIN","SERVFAIL"]}]
    dns={"packet_count":10,"transactions":dns_tx,"domain_outcomes":outcomes,"rows":[]}
    mdq=row(35,"mDNS","192.168.1.100:5353","224.0.0.251:5353",name="cpe.local",answers=[],kind="Query",dns_id="0")
    mdr=row(36,"mDNS","192.168.1.100:5353","224.0.0.251:5353",name="cpe.local",answers=["192.168.1.100"],kind="Response",dns_id="0")
    mdns={"packet_count":2,"transactions":[{"frame":"35","relative":mdq["relative"],"epoch":mdq["epoch"],"timestamp_india":mdq["timestamp_india"],"client_mac":"02:00:00:00:00:10","client":mdq["src"],"query":"cpe.local","type":"A","status":"Succeeded","answers":["192.168.1.100"],"response_frames":["36"]}],"events":[mdq,mdr]}
    # HTTP + management.
    xml='<?xml version="1.0"?><soap:Envelope><soap:Body><cwmp:Inform><EventCode>1 BOOT</EventCode><CommandKey>validation-reboot</CommandKey><ParameterValueStruct><Name>Device.DeviceInfo.SoftwareVersion</Name><Value>1.2.3</Value></ParameterValueStruct></cwmp:Inform></soap:Body></soap:Envelope>'
    sem=m.cwmp_semantics(xml)
    req=row(40,"HTTP","192.168.1.100:40000","203.0.113.80:7547",stream="0",method="POST",url="http://tms.airtelbroadband.in/acs",message_type="HTTP POST",content_type="text/xml",body=xml,body_state="visible_cleartext",cwmp=sem)
    resp_xml='<soap:Body><cwmp:InformResponse><MaxEnvelopes>1</MaxEnvelopes></cwmp:InformResponse></soap:Body>'
    resp=row(41,"HTTP","203.0.113.80:7547","192.168.1.100:40000",stream="0",response_code="200",response_phrase="OK",message_type="HTTP 200 response",content_type="text/xml",body=resp_xml,body_state="visible_cleartext",cwmp=m.cwmp_semantics(resp_xml))
    http={"packet_count":2,"requests":[req],"responses":[resp],"tls":[],"messages":[req,resp]}
    mgreq={**req,"http_host":"tms.airtelbroadband.in","tcp_stream":"0","host_evidence":"tms.airtelbroadband.in","action":"CWMP/TR-069 Inform","message_type":"Inform","management_details":[sem["summary"]],"encrypted":False}
    mgresp={**resp,"http_host":"tms.airtelbroadband.in","tcp_stream":"0","host_evidence":"tms.airtelbroadband.in","action":"CWMP/TR-069 InformResponse","message_type":"InformResponse","management_details":[resp["cwmp"]["summary"]],"encrypted":False}
    management={"target":"tms.airtelbroadband.in","resolved_ips":["203.0.113.80","2001:db8::80"],"events":[mgreq,mgresp],"packet_count":2}
    tcp={"packet_count":5,"mss_distribution":[{"mss":1460,"count":1}],"mss_events":[row(37,"TCP","192.168.1.100:40000","203.0.113.80:7547",stream="0",mss_value=1460)],"anomalies":[row(42,"TCP","192.168.1.100:40000","203.0.113.80:7547",stream="0",kind="Retransmission",seq="1001",ackno="5001")],"retransmissions":1,"out_of_order":0}
    alarms=m.TSharkAnalyzer._build_alarms(tcp,dns,dhcp,wan)
    events=m.TSharkAnalyzer._build_event_stream(tcp,dns,wan,alarms)
    ladder=m.TSharkAnalyzer._build_ladder(tcp,dns,http,dhcp,mdns,management,wan,alarms)
    # Ensure management and HTTP stream groups are present for modal validation.
    hosts=[{"mac":"02:00:00:00:00:10","ips":["192.168.1.100","fe80::10"],"packet_appearances":28,"bytes":4200,"first_frame":"17","last_frame":"42","first_timestamp_india":row(17,"",'', '')["timestamp_india"],"last_timestamp_india":row(42,"",'', '')["timestamp_india"],"hostname":"CPE-VALIDATION","vendor_class":"Airtel-CPE","dhcp_ip":"192.168.1.100","dhcp_state":"Bound","mdns_names":["cpe.local"],"dns_queries":6,"tcp_findings":1},{"mac":"00:11:22:33:44:55","ips":[],"packet_appearances":16,"bytes":1800,"first_frame":"1","last_frame":"16","first_timestamp_india":row(1,"",'', '')["timestamp_india"],"last_timestamp_india":row(16,"",'', '')["timestamp_india"],"hostname":"","vendor_class":"","dhcp_ip":"","dhcp_state":"","mdns_names":[],"dns_queries":0,"tcp_findings":0}]
    dhcpv6_clients=m.TSharkAnalyzer._build_dhcpv6_clients(dhcpv6); ppp_sessions=m.TSharkAnalyzer._build_ppp_sessions(wan); end_to_end=m.TSharkAnalyzer._build_end_to_end(dns,http,management)
    meta={"filename":"synthetic_all_protocols.pcap","packets":42,"duration_seconds":3.075,"capture_start_india":m.india_timestamp(base),"capture_end_india":m.india_timestamp(base+41*.075),"analyzed_seconds":0.5,"tshark":"Validation fixture (TShark unavailable in sandbox)","analysis_scope":"Deterministic visual-validation fixture mirroring synthetic_all_protocols.pcap.","version":m.APP_VERSION}
    data={"metadata":meta,"summary":{"tcp_packets":5,"tcp_retransmissions":1,"tcp_out_of_order":0,"dns_transactions":len(dns_tx),"http_requests":1,"dhcp_clients":1,"mdns_queries":1,"management_packets":2,"wan_control_events":sum(len(wan[k]) for k in ("pppoe","lcp","pap","ipcp","ipv6cp","dhcpv6")),"alarms":len(alarms)},"tcp":tcp,"dns":dns,"http":http,"dhcp":dhcp,"mdns":mdns,"management":management,"wan":wan,"alarms":alarms,"events":events,"ladder":ladder,"timeline":ladder,"flow_graph":{"nodes":[],"edges":[]},"hosts":hosts,"dhcpv6_clients":dhcpv6_clients,"ppp_sessions":ppp_sessions,"end_to_end":end_to_end,"warnings":[]}
    output=ROOT/"validation"/"synthetic_analysis_fixture.json";output.write_text(json.dumps(data,indent=2));print(output)

if __name__=="__main__":main()
