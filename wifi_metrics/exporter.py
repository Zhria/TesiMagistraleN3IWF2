#!/usr/bin/env python3
import os, time, json, subprocess, re, socket, tempfile

HOSTAPD_CTRL = os.environ.get("HOSTAPD_CTRL_PATH", "/var/run/hostapd")
IFACES = [x.strip() for x in os.environ.get("HOSTAPD_IFACES", "wlp6s0").replace(",", " ").split() if x.strip()]
SCRAPE_INTERVAL = float(os.environ.get("SCRAPE_INTERVAL", "5"))
OUTDIR = os.environ.get("OUTPUT_DIR", "/var/run/wifi-metrics")

os.makedirs(OUTDIR, exist_ok=True)

def run(cmd, timeout=3):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode("utf-8", "replace")
    except subprocess.CalledProcessError as e:
        return e.output.decode("utf-8", "replace")
    except Exception as e:
        return f"__ERR__ {e}"

def parse_keyvals(txt):
    d = {}
    for line in txt.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip()
    return d

def hostapd_status(iface):
    return parse_keyvals(run(f"hostapd_cli -p {HOSTAPD_CTRL} -i {iface} status"))

def hostapd_all_sta(iface):
    txt = run(f"hostapd_cli -p {HOSTAPD_CTRL} -i {iface} all_sta")
    stas, cur = {}, None
    for line in txt.splitlines():
        line=line.strip()
        if re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", line):
            cur=line
            stas[cur]={}
        elif cur and "=" in line:
            k,v=line.split("=",1)
            stas[cur][k]=v
    return stas

def iw_station_dump(iface):
    txt = run(f"iw dev {iface} station dump", timeout=5)
    blocks = re.split(r"\n(?=Station\s)", txt)
    res = {}
    for b in blocks:
        m = re.search(r"Station\s([0-9a-f:]{17})", b)
        if not m: continue
        mac = m.group(1)
        data={}
        for line in b.splitlines():
            line=line.strip()
            if not line: continue
            kv = line.split(":",1)
            if len(kv)==2:
                k = kv[0].strip().lower().replace(" ", "_").replace("(","").replace(")","")
                v = kv[1].strip()
                data[k]=v
        res[mac]=data
    return res

def iw_survey_dump(iface):
    txt = run(f"iw dev {iface} survey dump", timeout=5)
    surveys=[]
    cur={}
    for line in txt.splitlines():
        l=line.strip()
        if l.startswith("Survey data from"):
            if cur: surveys.append(cur); cur={}
            cur["phy"]=l.split()[-1]
        elif l.startswith("frequency:"):
            cur["frequency"]=l.split(":",1)[1].strip()
        elif ":" in l:
            k,v=l.split(":",1)
            cur[k.strip().lower().replace(" ","_")]=v.strip()
    if cur: surveys.append(cur)
    return surveys

def ethtool_stats(iface):
    txt = run(f"ethtool -S {iface}", timeout=5)
    stats={}
    for line in txt.splitlines():
        if ":" in line:
            k,v=line.strip().split(":",1)
            k=k.strip(); v=v.strip()
            try: stats[k]=int(v)
            except: stats[k]=v
    return stats

def write_atomic(path, content_bytes):
    tmp = path + ".tmp"
    with open(tmp,"wb") as f: f.write(content_bytes)
    os.replace(tmp, path)

def to_prom(metrics):
    lines=[]
    def esc(lbl): return lbl.replace("\\","\\\\").replace("\"","\\\"")
    ts=int(time.time())
    # Esempi chiave
    for iface, m in metrics.items():
        if "hostapd" in m and "status" in m["hostapd"]:
            st=m["hostapd"]["status"]
            if "num_sta" in st:
                lines.append(f'hostapd_stations{{iface="{esc(iface)}"}} {st.get("num_sta",0)} {ts}000')
        if "survey" in m:
            for s in m["survey"]:
                if "frequency" in s and "channel_time_busy" in s:
                    lines.append(f'wifi_survey_channel_time_busy_ms{{iface="{esc(iface)}",freq="{esc(str(s.get("frequency","")))}"}} {s.get("channel_time_busy","0").split()[0]} {ts}000')
        if "ethtool" in m:
            et=m["ethtool"]
            for k,v in et.items():
                if isinstance(v, int):
                    lines.append(f'ethtool_{k}{{iface="{esc(iface)}"}} {v} {ts}000')
    return ("\n".join(lines)+"\n").encode()

def main():
    while True:
        payload={}
        for iface in IFACES:
            entry={"ts":int(time.time())}
            entry["hostapd"]={
                "status": hostapd_status(iface),
                "stations": hostapd_all_sta(iface)
            }
            entry["station_dump"]=iw_station_dump(iface)
            entry["survey"]=iw_survey_dump(iface)
            entry["ethtool"]=ethtool_stats(iface)
            payload[iface]=entry
        # Scrive JSON e Prometheus textfile nel volume condiviso
        write_atomic(os.path.join(OUTDIR,"metrics.json"), json.dumps(payload, indent=2).encode())
        write_atomic(os.path.join(OUTDIR,"metrics.prom"), to_prom(payload))
        time.sleep(SCRAPE_INTERVAL)

if __name__=="__main__":
    main()