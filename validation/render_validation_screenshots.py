#!/usr/bin/env python3
"""Headless Chromium visual validation for every sidebar view and modal flow."""
from __future__ import annotations

import subprocess
import time
from pathlib import Path
from urllib.request import urlopen

from PIL import Image, ImageDraw
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
VAL = ROOT / "validation"
ACTUAL = VAL / "screenshots" / "actual"
REFERENCE = VAL / "screenshots" / "reference"
COMPARE = VAL / "screenshots" / "comparisons"
PCAP = VAL / "synthetic_all_protocols.pcap"
REFERENCE_HTML = Path("/home/oai/share/PCAP_Flow_Analyzer_latest.html")
CHROME = "/opt/pw-browsers/chromium-1208/chrome-linux64/chrome"
PORT = 8877

VIEWS = [
    ("overview", "01-overview"), ("agent", "02-local-qa-agent"), ("e2e", "02-end-to-end"), ("hosts", "03-clients-hosts"),
    ("dhcp4", "04-dhcpv4"), ("dhcp6", "05-dhcpv6"), ("ppp", "06-pppoe-ppp"),
    ("dns", "07-dns"), ("mdns", "08-mdns"), ("tcp", "09-tcp-mss"),
    ("http", "10-http-tls"), ("management", "11-management"),
    ("alarms", "12-alarms"), ("timeline", "13-timeline"),
]


def wait_server():
    for _ in range(50):
        try:
            urlopen(f"http://127.0.0.1:{PORT}/api/health", timeout=1).read(); return
        except Exception: time.sleep(.1)
    raise RuntimeError("fixture server did not start")


def screenshot_page(page, path: Path):
    page.screenshot(path=str(path), full_page=True, animations="disabled")


def render_actual(browser):
    ACTUAL.mkdir(parents=True, exist_ok=True)
    page = browser.new_page(viewport={"width": 1600, "height": 1000}, device_scale_factor=1)
    page.goto(f"http://127.0.0.1:{PORT}/", wait_until="load")
    page.set_input_files("#file", str(PCAP))
    page.wait_for_function("document.querySelector('#app') && getComputedStyle(document.querySelector('#app')).display !== 'none'", timeout=30000)
    page.wait_for_timeout(250)
    assert page.title() == "PCAP Insight Workbench v1.5.0"
    for view, name in VIEWS:
        page.locator(f'nav button[data-view="{view}"]').click(); page.wait_for_timeout(100)
        if view == "agent":
            page.locator("#qaTemplates .qatemplate").first.click(); page.wait_for_timeout(100)
            assert page.locator("#qaHistory .qapair").count() == 1
        screenshot_page(page, ACTUAL / f"{name}.png")
    # Modal ladders.
    page.locator('nav button[data-view="dhcp4"]').click(); page.get_by_role("button", name="DORA ladder & options").click(); page.wait_for_timeout(100); page.locator("#modal .mbox").screenshot(path=str(ACTUAL / "14-modal-dhcpv4-dora.png")); page.locator("#modalClose").click()
    page.locator('nav button[data-view="dhcp6"]').click(); page.get_by_role("button", name="Solicit / Advertise / Request / Reply").click(); page.wait_for_timeout(100); page.locator("#modal .mbox").screenshot(path=str(ACTUAL / "15-modal-dhcpv6.png")); page.locator("#modalClose").click()
    page.locator('nav button[data-view="ppp"]').click(); page.get_by_role("button", name="Session ladder").click(); page.wait_for_timeout(100); page.locator("#modal .mbox").screenshot(path=str(ACTUAL / "16-modal-pppoe-ppp.png")); page.locator("#modalClose").click()
    page.locator('nav button[data-view="dns"]').click(); page.locator("#dnsTable tbody tr").first.click(); page.wait_for_timeout(100); page.locator("#modal .mbox").screenshot(path=str(ACTUAL / "17-modal-dns.png")); page.locator("#modalClose").click()
    page.locator('nav button[data-view="http"]').click(); page.locator("#httpTable tbody tr").first.click(); page.wait_for_timeout(100); page.locator("#modal .mbox").screenshot(path=str(ACTUAL / "18-modal-http.png")); page.locator("#modalClose").click()
    page.locator('nav button[data-view="management"]').click(); page.locator("#mgmtTable tbody tr").first.click(); page.wait_for_timeout(100); page.locator("#modal .mbox").screenshot(path=str(ACTUAL / "19-modal-management.png")); page.locator("#modalClose").click()
    # Assertions that directly reflect user feedback.
    body = page.locator("body").inner_text()
    assert "Interactive packet ladder" not in body and "Analyze capture" not in body
    assert page.locator("nav button").count() == 14
    page.close()


def reference_click(page, name: str):
    page.get_by_role("button", name=name, exact=False).first.click(); page.wait_for_timeout(100)


def render_reference(browser):
    REFERENCE.mkdir(parents=True, exist_ok=True)
    page = browser.new_page(viewport={"width": 1600, "height": 1000}, device_scale_factor=1)
    page.goto(REFERENCE_HTML.as_uri(), wait_until="load"); page.set_input_files("#fin", str(PCAP))
    page.wait_for_function("document.querySelector('.wrap') && getComputedStyle(document.querySelector('.wrap')).display !== 'none'", timeout=30000); page.wait_for_timeout(300)
    for label, name in [("Overview","01-overview"),("DHCPv4","04-dhcpv4"),("PPPoE / PPP","06-pppoe-ppp"),("DNS","07-dns")]:
        reference_click(page,label); screenshot_page(page,REFERENCE/f"{name}.png")
    reference_click(page,"DHCPv4"); page.get_by_role("button", name="DORA ladder & options").click(); page.wait_for_timeout(100); page.locator("#modal .mbox").screenshot(path=str(REFERENCE/"14-modal-dhcpv4-dora.png")); page.get_by_role("button", name="Close").click()
    reference_click(page,"PPPoE / PPP"); page.get_by_role("button", name="Session ladder").click(); page.wait_for_timeout(100); page.locator("#modal .mbox").screenshot(path=str(REFERENCE/"16-modal-pppoe-ppp.png")); page.get_by_role("button", name="Close").click()
    page.close()


def montage(reference: Path, actual: Path, output: Path):
    r=Image.open(reference).convert("RGB"); a=Image.open(actual).convert("RGB")
    max_h=1100
    def fit(img):
        if img.height<=max_h:return img
        w=int(img.width*max_h/img.height);return img.resize((w,max_h))
    r,a=fit(r),fit(a); header=48; canvas=Image.new("RGB",(r.width+a.width, max(r.height,a.height)+header),(11,16,32)); draw=ImageDraw.Draw(canvas); draw.text((15,14),"REFERENCE",fill=(79,195,247)); draw.text((r.width+15,14),"PCAP INSIGHT v1.5.0",fill=(52,211,153)); canvas.paste(r,(0,header));canvas.paste(a,(r.width,header));output.parent.mkdir(parents=True,exist_ok=True);canvas.save(output,optimize=True)


def build_comparisons():
    for name in ["01-overview","04-dhcpv4","06-pppoe-ppp","07-dns","14-modal-dhcpv4-dora","16-modal-pppoe-ppp"]:
        montage(REFERENCE/f"{name}.png",ACTUAL/f"{name}.png",COMPARE/f"compare-{name}.png")


def main():
    for directory in (ACTUAL,REFERENCE,COMPARE): directory.mkdir(parents=True,exist_ok=True)
    server=subprocess.Popen(["python3",str(VAL/"fixture_server.py"),"--port",str(PORT)],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    try:
        wait_server()
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path=CHROME,headless=True,args=["--no-sandbox","--disable-dev-shm-usage"])
            render_actual(browser);render_reference(browser);browser.close()
        build_comparisons()
    finally:
        server.terminate(); server.wait(timeout=10)
    print(f"Actual screenshots: {len(list(ACTUAL.glob('*.png')))}")
    print(f"Reference screenshots: {len(list(REFERENCE.glob('*.png')))}")
    print(f"Comparison montages: {len(list(COMPARE.glob('*.png')))}")


if __name__ == "__main__": main()
