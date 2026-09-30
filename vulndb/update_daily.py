#!/usr/bin/env python3
"""SecForge 漏洞库每日增量更新

思路: 不用 NVD 的 API(限速), 用 NVD 每天重新发布的「今日变动」feed:
  nvdcve-2.0-modified.json.gz  约 4MB, 每天中午更新一次
再顺带刷三个小源:
  · CISA KEV(1.7MB)          —— 新的「已被真实利用」条目
  · MSRC 当月文档(几 MB)      —— 新的 Windows 补丁日漏洞
  · 已下过的年度 feed          —— 不重下, 直接用增量

用法:
  python3 update_daily.py             # 增量更新
  python3 update_daily.py --full      # 连年度 feed 也重扫(慢)
  python3 update_daily.py --sync-image  # 顺便把新库同步进容器

装成定时任务(cron 里每天 09:00 跑):
  hermes cronjob / 或直接 crontab -e
"""
import argparse
import gzip
import json
import os
import shutil
import sqlite3
import subprocess
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "vulndb.sqlite")
RAW = os.path.join(HERE, "raw")
UA = {"User-Agent": "Mozilla/5.0 SecForge/1.0"}
SEV = {"CRITICAL": "Critical", "HIGH": "Important", "MEDIUM": "Moderate", "LOW": "Low"}


def log(*a):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}]", *a, flush=True)


def fetch(url, timeout=600, accept=None):
    h = dict(UA)
    if accept:
        h["Accept"] = accept
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def pick(cve):
    m = cve.get("metrics", {})
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(k):
            d = m[k][0].get("cvssData", {})
            if d.get("baseScore") is not None:
                sev = (d.get("baseSeverity") or m[k][0].get("baseSeverity") or "").upper()
                return float(d["baseScore"]), d.get("vectorString", ""), SEV.get(sev, "")
    return None, "", ""


def cwe_of(cve):
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if (d.get("value") or "").startswith("CWE-"):
                return d["value"]
    return ""


def update_from_nvd(con, year_files=()):
    """增量: modified feed;  可选: 年度 feed 补漏"""
    urls = ["https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz"]
    if year_files:
        urls += [f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{y}.json.gz" for y in year_files]
    added = updated = 0
    for u in urls:
        name = u.split("/")[-1]
        try:
            log(f"拉 {name} ...")
            raw = gzip.decompress(fetch(u))
            data = json.loads(raw)
        except Exception as e:
            log(f"  ! {name} 失败: {e}")
            continue
        items = data.get("vulnerabilities", [])
        for it in items:
            cve = it.get("cve", {})
            cid = cve.get("id")
            if not cid:
                continue
            exists = con.execute("SELECT 1 FROM cve WHERE cve_id=?", (cid,)).fetchone()
            score, vec, sev = pick(cve)
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:4000]
                    break
            pub = (cve.get("published") or "")[:10]
            if exists:
                sets, args = [], []
                if score is not None:
                    sets += ["cvss=?", "cvss_vector=?"] + (["severity=?"] if sev else [])
                    args += [score, vec] + ([sev] if sev else [])
                c = cwe_of(cve)
                if c:
                    sets.append("cwe=?"); args.append(c)
                if desc:
                    sets.append("description=?")
                    args.append(desc)
                if pub:
                    sets.append("published=?")
                    args.append(pub)
                if sets:
                    con.execute(f"UPDATE cve SET {','.join(sets)} WHERE cve_id=?", args + [cid])
                    updated += 1
            else:
                # 库里没有的(多半是非微软新漏洞): 收进来, 标 nvd 来源
                con.execute("""INSERT OR IGNORE INTO cve
                    (cve_id,title,description,severity,cvss,cvss_vector,cwe,published,updated,sources)
                    VALUES(?,?,?,?,?,?,?,?,?,?)""",
                            (cid, desc[:300], desc, sev, score, vec, cwe_of(cve), pub, pub, "nvd"))
                added += 1
        con.commit()
        log(f"  {name}: 更新 {updated} 条, 新增 {added} 条")
    return added, updated


def update_kev(con):
    try:
        d = json.loads(fetch("https://raw.githubusercontent.com/cisagov/kev-data/develop/"
                             "known_exploited_vulnerabilities.json", timeout=120))
    except Exception as e:
        log(f"! KEV 失败: {e}")
        return 0
    n = 0
    for v in d.get("vulnerabilities", []):
        cid = v.get("cveID")
        if not cid:
            continue
        row = con.execute("SELECT kev FROM cve WHERE cve_id=?", (cid,)).fetchone()
        if row and row[0] == 1:
            continue
        kw = dict(kev=1,
                  kev_ransomware=1 if v.get("knownRansomwareCampaignUse") == "Known" else 0,
                  kev_due=v.get("dueDate", ""),
                  exploit_status="已被真实利用 (CISA KEV)")
        exists = con.execute("SELECT published FROM cve WHERE cve_id=?", (cid,)).fetchone()
        if not exists:
            kw.update(title=v.get("vulnerabilityName", "")[:400],
                      description=v.get("shortDescription", "")[:2000],
                      affected=f"{v.get('product','')} {v.get('vendorProject','')}",
                      published=(v.get("dateAdded") or "")[:10],
                      sources="kev")
            con.execute(f"INSERT OR IGNORE INTO cve(cve_id,{','.join(kw)}) "
                        f"VALUES(?{',?' * len(kw)})", [cid] + list(kw.values()))
        else:
            con.execute(f"UPDATE cve SET {','.join(k + '=?' for k in kw)} WHERE cve_id=?",
                        list(kw.values()) + [cid])
        n += 1
    con.commit()
    log(f"KEV: 新增/更新 {n} 条已被真实利用的漏洞")
    return n


def update_msrc_latest(con):
    """只拉当月+上月 MSRC 文档, 拿新的补丁日漏洞"""
    try:
        # 注意: MSRC 不带 Accept: application/json 会返回 XML, 这里必须带上
        up = json.loads(fetch("https://api.msrc.microsoft.com/cvrf/v3.0/updates",
                              timeout=120, accept="application/json"))
    except Exception as e:
        log(f"! MSRC 列表失败: {e}")
        return 0
    ids = [u["ID"] for u in up["value"] if u["ID"].count("-") == 1]
    ids.sort()
    todo = ids[-2:]
    import build_vulndb as BV          # 复用解析逻辑
    total = 0
    for did in todo:
        p = os.path.join(RAW, f"msrc_{did}.json")
        try:
            raw = fetch(f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{did}",
                        timeout=300, accept="application/json").decode("utf-8", "ignore")
            doc = json.loads(raw)
            json.dump(doc, open(p, "w"))
            n = BV.parse_msrc_doc(con, doc, did)
            total += n
            log(f"MSRC {did}: 解析 {n} 条")
        except Exception as e:
            log(f"  ! MSRC {did} 失败: {e}")
    con.commit()
    return total


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", action="store_true", help="连年度 feed 也重扫")
    ap.add_argument("--sync-image", action="store_true", help="更新后同步进容器")
    a = ap.parse_args()

    if not os.path.exists(DB):
        raise SystemExit("! 还没有 vulndb.sqlite, 先跑 build_vulndb.py")

    t0 = time.time()
    before = sqlite3.connect(DB).execute("SELECT COUNT(*) FROM cve").fetchone()[0]
    con = sqlite3.connect(DB)

    years = ()
    if a.full:
        years = tuple(str(y) for y in range(2016, time.localtime().tm_year + 1))
    added, updated = update_from_nvd(con, years)
    update_kev(con)
    try:
        update_msrc_latest(con)
    except Exception as e:
        log(f"! MSRC 更新跳过: {e}")

    # 收尾: 从 CVSS 补 severity
    n = con.execute("UPDATE cve SET severity=CASE WHEN cvss>=9 THEN 'Critical' WHEN cvss>=7 THEN "
                    "'Important' WHEN cvss>=4 THEN 'Moderate' ELSE 'Low' END "
                    "WHERE (severity IS NULL OR severity='') AND cvss IS NOT NULL").rowcount
    con.commit()
    after = con.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
    kb = con.execute("SELECT COUNT(*) FROM cve WHERE kbs<>''").fetchone()[0]
    log(f"完成: CVE {before} → {after} (+{after-before}), 更新 {updated} 条, "
        f"补 severity {n} 条, 有补丁KB {kb} 条, 耗时 {time.time()-t0:.0f}s")
    # 写一份状态给图形界面显示
    try:
        json.dump({"ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "before": before, "after": after,
                   "updated": updated, "added": after - before,
                   "with_cvss": con.execute("SELECT COUNT(*) FROM cve WHERE cvss IS NOT NULL").fetchone()[0],
                   "kev": con.execute("SELECT COUNT(*) FROM cve WHERE kev=1").fetchone()[0],
                   "with_kb": kb, "seconds": round(time.time() - t0)},
                  open(os.path.join(HERE, "last_update.json"), "w"), ensure_ascii=False)
    except Exception as e:
        log(f"! 写状态失败: {e}")
    con.close()
    con = None

    if a.sync_image:
        r = subprocess.run(["docker", "ps", "--filter", "name=^secforge$", "-q"],
                           capture_output=True, text=True).stdout.strip()
        if r:
            subprocess.run(["docker", "cp", DB, "secforge:/opt/secforge/vulndb.sqlite"],
                           capture_output=True)
            log("已同步进容器 /opt/secforge/vulndb.sqlite")
        else:
            log("容器没跑, 跳过同步")
