#!/usr/bin/env python3
"""
setup_cron.py — ip-ban-enforcement 全自动 cron 部署（可移植）
用法: python3 setup_cron.py [--dry-run]

做什么:
  1. 把本 skill scripts/ 下的脚本同步到 ~/.hermes/scripts/（cron 的 script 字段相对该目录解析）
  2. 幂等创建 6 个 cron job（已存在则跳过，不会重复）
  3. 验证创建结果

可移植: 解压 skill 到任意 Hermes 环境 → python3 scripts/setup_cron.py → 全部就位。
依赖: hermes CLI（cron create 官方入口，不用手写 jobs.json）。
"""

import subprocess, sys, shutil, os
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent          # skill 根目录
HERMES_SCRIPTS = Path.home() / ".hermes" / "scripts"

DRY_RUN = "--dry-run" in sys.argv

# ─── 需要部署的脚本（源 → cron script 字段名） ───
# (skill 内相对路径, cron 用文件名)
SCRIPTS_TO_DEPLOY = [
    "ip_ban_sync.py",
    "ip_ban_asn_discovery.py",
    "intent_analysis.py",
    "intent_lib.py",
    "ip_ban_sync_daily.sh",
    "ip_ban_sync_ips.sh",
    "ip_ban_cleanup.sh",
    "intent_analysis_cron.sh",
]

# ─── cron job 定义（name, schedule, script, prompt） ───
# no_agent=True：script stdout 原样投递；空 stdout = 静默
JOBS = [
    {
        "name": "Weekly IP Ban Sync",
        "schedule": "0 3 * * 0",
        "script": "ip_ban_sync.py",
        "prompt": "[no_agent] ip_ban_sync.py sync — 每周全量同步 + 意图打标",
    },
    {
        "name": "Daily Web Attack Sync",
        "schedule": "30 3 * * *",
        "script": "ip_ban_sync_daily.sh",
        "prompt": "[no_agent] 每日攻击日志增量同步 (wrapper)",
    },
    {
        "name": "IPS Signature Detect",
        "schedule": "45 3 * * *",
        "script": "ip_ban_sync_ips.sh",
        "prompt": "[no_agent] IPS 签名检测 access.log (wrapper)",
    },
    {
        "name": "ASN Dynamic Discovery (daily)",
        "schedule": "0 4 * * *",
        "script": "ip_ban_asn_discovery.py",
        "prompt": "[no_agent] ASN 动态发现",
        "deliver": "local",  # 静默存档，不打扰用户（与现有 job 保持一致）
    },
    {
        "name": "网络威胁意图分析 (daily intent)",
        "schedule": "0 4 * * *",
        "script": "intent_analysis_cron.sh",
        "prompt": "[no_agent] 每日意图分析画像报告 (wrapper: --cron --save)",
        "deliver": "origin",
    },
    {
        "name": "PERMA-BAN 自动维护 (cleanup)",
        "schedule": "0 5 * * *",
        "script": "ip_ban_cleanup.sh",
        "prompt": "[no_agent] 每日 PERMA-BAN 去重 + 老化清理",
    },
]

def run(cmd, timeout=60):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.stdout, r.stderr, r.returncode

def hermes_available():
    out, _, rc = run(["hermes", "cron", "list"])
    return rc == 0

def list_existing_jobs():
    """返回 {job_name: job_id} — 直接读 jobs.json（权威数据源，不解析 CLI 文本）。"""
    jobs = {}
    jp = Path.home() / ".hermes" / "cron" / "jobs.json"
    try:
        import json
        data = json.loads(jp.read_text())
        for j in data.get("jobs", []):
            if isinstance(j, dict) and j.get("name"):
                jobs[j["name"]] = j.get("id", "")
    except Exception:
        pass
    return jobs

def deploy_scripts():
    """同步脚本到 ~/.hermes/scripts/。已部署过（同文件）自动跳过。"""
    HERMES_SCRIPTS.mkdir(parents=True, exist_ok=True)
    done = []
    for fname in SCRIPTS_TO_DEPLOY:
        src = SKILL_DIR / "scripts" / fname
        if not src.exists():
            print(f"  ⚠️ 缺失 {fname}（跳过）")
            continue
        dst = HERMES_SCRIPTS / fname
        # 已部署：源和目标同文件 → 跳过（防止从 ~/.hermes/scripts/ 复跑时 SameFileError）
        if dst.exists() and src.resolve() == dst.resolve():
            done.append(fname)
            continue
        if DRY_RUN:
            print(f"  [dry-run] cp {src.name} → {dst.name}")
        else:
            shutil.copy2(src, dst)
            dst.chmod(0o755 if fname.endswith(".sh") else 0o644)
        done.append(fname)
    return done

def create_job(job):
    """幂等创建单个 job，返回 (created|exists|error, msg)。"""
    existing = list_existing_jobs()
    if job["name"] in existing:
        return "exists", f"已存在 (id={existing[job['name']]})"
    cmd = ["hermes", "cron", "create", job["schedule"], job["prompt"],
           "--name", job["name"], "--script", job["script"],
           "--deliver", job.get("deliver", "origin")]
    if not job.get("agent"):
        cmd.append("--no-agent")
    if DRY_RUN:
        print(f"  [dry-run] {' '.join(cmd)}")
        return "dry-run", "仅预览"
    out, err, rc = run(cmd, timeout=90)
    if rc == 0:
        return "created", "✅ 创建成功"
    return "error", f"❌ {err.strip()[:120]}"

def main():
    print("🛡️ ip-ban-enforcement cron 部署" + (" (DRY-RUN)" if DRY_RUN else ""))
    print("=" * 50)

    if not hermes_available():
        print("❌ hermes CLI 不可用，无法创建 cron")
        sys.exit(1)

    print(f"\n[1/3] 同步脚本 → {HERMES_SCRIPTS}/")
    deploy_scripts()

    print(f"\n[2/3] 创建 {len(JOBS)} 个 cron job（幂等）")
    results = []
    for job in JOBS:
        status, msg = create_job(job)
        results.append((job["name"], status))
        print(f"  {'✅' if status in ('created','exists') else '⚠️'} {job['name']:35s} {msg}")

    print(f"\n[3/3] 验证")
    out, _, _ = run(["hermes", "cron", "list"])
    n = out.count("[active]")
    print(f"  当前活跃 job 总数: {n}")

    created = [r for r in results if r[1] == "created"]
    print(f"\n{'✅ 部署完成' if not DRY_RUN else '（dry-run 未实际创建）'}"
          f" — 新增 {len(created)} 个，其余已存在")

if __name__ == "__main__":
    main()
