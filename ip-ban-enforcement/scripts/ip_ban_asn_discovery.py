#!/usr/bin/env python3
"""ip_ban_asn_discovery.py — 通用 ASN 动态发现
auth.log → WHOIS → ≥3次同ASN → RIPE拉取前缀 → 拦截 /24
"""
import subprocess, re, os, json
from datetime import datetime, timezone, timedelta
from collections import Counter
UTC+8 = timezone(timedelta(hours=8))
MIN_ASN_HITS, WHOIS_MAX_IPS, SKIP_ASNS = 3, 50, {"AS132839"}
def run(cmd,t=30):
    try: r=subprocess.run(cmd,capture_output=True,text=True,timeout=t); return r.stdout.strip()
    except: return ""
def get_attacker_ips():
    ips=set()
    for f in ["/var/log/auth.log","/var/log/auth.log.1"]:
        if not os.path.exists(f): continue
        r=subprocess.run(["zgrep","-h","Failed password\\|Invalid user",f],capture_output=True,text=True,timeout=30)
        for l in r.stdout.splitlines():
            m=re.search(r"(\d+\.\d+\.\d+\.\d+)",l)
            if m: ips.add(m.group(1))
    return ips
def get_asn(ip):
    out=run(["whois","-B",ip],t=15)
    m=re.search(r"origin:\s*(AS\d+)",out,re.IGNORECASE)
    return m.group(1) if m else None
def get_ripe_prefixes(asn):
    out=run(["whois","-h","whois.ripe.net","-T","route","-i","origin",asn],t=30)
    p=set()
    for l in out.splitlines():
        m=re.match(r"^route:\s*(\S+)",l,re.IGNORECASE)
        if m: p.add(m.group(1))
    return p
def main():
    now=datetime.now(UTC+8)
    print(f"🔍 ASN 动态发现 — {now.strftime('%Y-%m-%d %H:%M:%S')} UTC+8\n{'='*55}")
    attackers=get_attacker_ips()
    print(f"\n📡 攻击来源: {len(attackers)} 个")
    if not attackers: print("  无，退出"); return
    out=run(["iptables","-L","PERMA-BAN","-n"])
    blocked=set()
    for l in out.splitlines():
        p=l.split()
        if len(p)>=5 and p[0]=="DROP" and "/" not in p[3] and p[3]!="0.0.0.0/0": blocked.add(p[3])
    print(f"🔒 已封禁: {len(blocked)}")
    new=attackers-blocked
    print(f"🆕 待查: {len(new)}")
    if not new: print("\n✨ 无新 IP"); return
    print(f"\n🌐 WHOIS (最多{WHOIS_MAX_IPS}):")
    cnt,ip_asn=Counter(),{}
    for i,ip in enumerate(sorted(new)):
        if i>=WHOIS_MAX_IPS: print(f"   (上限{WHOIS_MAX_IPS},跳过{len(new)-WHOIS_MAX_IPS})"); break
        asn=get_asn(ip)
        if asn and asn not in SKIP_ASNS: cnt[asn]+=1; ip_asn[ip]=asn; print(f"   {ip:18s} → {asn}")
    if not cnt: print("  无 ASN"); return
    susp={a:c for a,c in cnt.items() if c>=MIN_ASN_HITS}
    if not susp: print(f"\n✅ 无可疑 ASN (≥{MIN_ASN_HITS})"); return
    print(f"\n🚨 {len(susp)} 可疑 ASN:")
    total=0
    for asn,c in sorted(susp.items(),key=lambda x:-x[1]):
        print(f"\n   {asn}: {c} IP → RIPE...")
        prefixes=get_ripe_prefixes(asn)
        print(f"   RIPE: {len(prefixes)} 前缀")
        affected=[ip for ip,a in ip_asn.items() if a==asn]
        sn=set()
        for ip in affected:
            parts=ip.split("."); sub=f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            if sub in prefixes: sn.add(sub)
            else:
                for pr in prefixes:
                    if pr.startswith(f"{parts[0]}.{parts[1]}.{parts[2]}"): sn.add(sub); break
        print(f"   匹配: {len(sn)} 子网")
        existing=set()
        for l in out.splitlines():
            p=l.split()
            if len(p)>=5 and p[0]=="DROP" and "/" in p[3]: existing.add(p[3])
        nb=0
        for s in sorted(sn):
            if s in existing: print(f"      ✅ {s}")
            else:
                subprocess.run(["iptables","-A","PERMA-BAN","-s",s,"-m","comment","--comment",f"{asn} auto-discovery {now.strftime('%Y-%m-%d')}","-j","DROP"],capture_output=True,timeout=10)
                print(f"      🆕 {s} 已封禁"); nb+=1
        total+=nb
    if total>0: subprocess.run(["netfilter-persistent","save"],timeout=30); print(f"\n💾 新增 {total}")
    else: print("\n无新增 ✅")
if __name__=="__main__": main()
