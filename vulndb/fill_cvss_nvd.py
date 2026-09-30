#!/usr/bin/env python3
"""SecForge 漏洞库补全 —— 用 NVD 官方年度 feed 批量补 CVSS / 严重性 / CWE。

为什么不用 NVD 的 per-CVE API: 无 key 限速 5 req/30s, 补 2.5 万条要 40+ 小时。
年度 feed 一次几十 MB 就覆盖一整年所有 CVE, 几分钟搞定。

用法:
  python3 fill_cvss_nvd.py            # 自动只下缺 CVSS 的那些年份
  python3 fill_cvss_nvd.py --years 2024,2025,2026
"""
import argparse
import gzip
import json
import os
import sqlite3
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "vulndb.sqlite")
RAW = os.path.join(HERE, "raw", "nvd")
UA = {"User-Agent": "Mozilla/5.0 SecForge/1.0"}

SEV = {"CRITICAL": "Critical", "HIGH": "Important", "MEDIUM": "Moderate", "LOW": "Low"}


def download(year):
    os.makedirs(RAW, exist_ok=True)
    p = os.path.join(RAW, f"nvd-{year}.json.gz")
    if os.path.exists(p) and os.path.getsize(p) > 100000:
        return p
    url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
    print(f"  下载 {url} ...", flush=True)
    t0 = time.time()
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=600) as r, open(p, "wb") as f:
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
    except Exception as e:
        print(f"  ! {year} 下载失败: {e}")
        return None
    print(f"  完成 {os.path.getsize(p)//1024//1024} MB, {time.time()-t0:.0f}s")
    return p


def pick_cvss(cve):
    m = cve.get("metrics", {})
    for k, sev_key in (("cvssMetricV31", "baseSeverity"), ("cvssMetricV30", "baseSeverity"),
                       ("cvssMetricV2", "baseSeverity")):
        if m.get(k):
            d = m[k][0].get("cvssData", {})
            score = d.get("baseScore")
            if score is None:
                continue
            sev = (d.get("baseSeverity") or m[k][0].get(sev_key) or "").upper()
            return (float(score), d.get("vectorString", ""), SEV.get(sev, ""))
    return (None, "", "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--years", default="")
    a = ap.parse_args()

    con = sqlite3.connect(DB)
    # 只关心库里还缺分数的, 按年份统计
    missing = {}
    for cid, in con.execute("SELECT cve_id FROM cve WHERE cvss IS NULL"):
        y = cid.split("-")[1] if cid.count("-") >= 2 else "0"
        missing.setdefault(y, set()).add(cid)
    print(f"缺 CVSS 的 CVE: {sum(len(v) for v in missing.values())} 个")
    print("  按年份:", ", ".join(f"{y}:{len(v)}" for y, v in sorted(missing.items())))

    if a.years:
        years = [y.strip() for y in a.years.split(",") if y.strip()]
    else:
        years = sorted(y for y in missing if y.isdigit() and len(y) == 4)
    print(f"需要下载的年份: {years}")

    filled = sev_filled = cwe_filled = 0
    for y in years:
        need = missing.get(y, set())
        if not need:
            continue
        p = download(y)
        if not p:
            continue
        t0 = time.time()
        with gzip.open(p, "rt", encoding="utf-8") as f:
            data = json.load(f)
        items = data.get("vulnerabilities", [])
        print(f"  {y}: feed 内 {len(items)} 个 CVE, 需补 {len(need)} 个, 解析 {time.time()-t0:.0f}s")
        for it in items:
            cve = it.get("cve", {})
            cid = cve.get("id")
            if not cid or cid not in need:
                continue
            score, vec, sev = pick_cvss(cve)
            sets, args = [], []
            if score:
                sets += ["cvss=?", "cvss_vector=?"]
                args += [score, vec]
                if sev:
                    sets.append("severity=?")
                    args.append(sev)
            cwe = ""
            for w in cve.get("weaknesses", []):
                for d in w.get("description", []):
                    if d.get("value", "").startswith("CWE-"):
                        cwe = d["value"]
                        break
                if cwe:
                    break
            if cwe:
                sets.append("cwe=?")
                args.append(cwe)
            pub = (cve.get("published") or "")[:10]
            sets.append("published=COALESCE(NULLIF(published,''),?)")
            args.append(pub)
            if sets:
                con.execute(f"UPDATE cve SET {','.join(sets)} WHERE cve_id=?", args + [cid])
                filled += 1 if score else 0
                sev_filled += 1 if sev else 0
                cwe_filled += 1 if cwe else 0
        con.commit()
        os.remove(p)   # 删掉压缩包省空间
    con.commit()

    # 剩余: 用 CVSS 推 severity (空白的)
    n = con.execute("UPDATE cve SET severity = CASE WHEN cvss>=9 THEN 'Critical' "
                    "WHEN cvss>=7 THEN 'Important' WHEN cvss>=4 THEN 'Moderate' "
                    "ELSE 'Low' END WHERE (severity IS NULL OR severity='') AND cvss IS NOT NULL"
                    ).rowcount
    con.commit()
    print(f"\n补了 CVSS {filled} 条, severity {sev_filled} 条, CWE {cwe_filled} 条")
    print(f"再从 CVSS 推 severity: {n} 条")
    ncvss = con.execute("SELECT COUNT(*) FROM cve WHERE cvss IS NULL").fetchone()[0]
    nsev = con.execute("SELECT COUNT(*) FROM cve WHERE severity IS NULL OR severity=''").fetchone()[0]
    print(f"剩余无 CVSS: {ncvss}    剩余无 severity: {nsev}")
    con.close()


if __name__ == "__main__":
    main()
