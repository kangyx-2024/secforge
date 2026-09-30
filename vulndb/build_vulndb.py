#!/usr/bin/env python3
"""SecForge - 独立漏洞库构建器

数据源(全部免费无需 key):
  1. MSRC CVRF  —— 微软官方漏洞库, 每月一份, 含 Windows/Office/Exchange/Edge/AD 等
                   CVE / CVSS / 受影响产品(CPE) / 补丁KB / 可利用性评估
  2. CISA KEV   —— 已被真实利用的漏洞清单
  3. ExploitDB  —— 公开 PoC/Exploit 对应关系
  4. NVD(可选)  —— 补充非微软 CVE 的 CVSS

用法:
  python3 build_vulndb.py                  # 全量(2016 至今)
  python3 build_vulndb.py --from 2020-Jan
  python3 build_vulndb.py --kev-only
"""
import argparse
import gzip
import io
import json
import os
import re
import sqlite3
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "vulndb.sqlite")
RAW = os.path.join(HERE, "raw")
UA = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) SecForge/1.0",
      "Accept": "application/json"}

# Windows 版本表: (显示名, 内部版本号, 产品匹配串)
#   第 3 列是关键 —— 必须是 affected.product 里真实存在的子串, 否则查出来是 0 条。
#   坑: 之前拿标签当匹配串, "11-22H2"/"WIN7SP1" 这种根本不是产品串的子串 → 永远 0 命中。
#   真实写法: "Windows 11 Version 22H2 for x64-based Systems" / "Windows 7 for x64-based Systems Service Pack 1"
WIN_VERSIONS = [
    ("Windows 11 26H1",         "",      "Windows 11 version 26H1"),
    ("Windows 11 25H2",         "26200", "Windows 11 Version 25H2"),
    ("Windows 11 24H2",         "26100", "Windows 11 Version 24H2"),
    ("Windows 11 23H2",         "22631", "Windows 11 Version 23H2"),
    ("Windows 11 22H2",         "22621", "Windows 11 Version 22H2"),
    ("Windows 11 21H2",         "22000", "Windows 11 version 21H2"),
    ("Windows Server 2025",     "26100", "Windows Server 2025"),
    ("Windows Server 2022",     "20348", "Windows Server 2022"),
    ("Windows Server 2019",     "17763", "Windows Server 2019"),
    ("Windows Server 2016",     "14393", "Windows Server 2016"),
    ("Windows 10 22H2",         "19045", "Windows 10 Version 22H2"),
    ("Windows 10 21H2",         "19044", "Windows 10 Version 21H2"),
    ("Windows 10 21H1",         "19043", "Windows 10 Version 21H1"),
    ("Windows 10 20H2",         "19042", "Windows 10 Version 20H2"),
    ("Windows 10 2004",         "19041", "Windows 10 Version 2004"),
    ("Windows 10 1909",         "18363", "Windows 10 Version 1909"),
    ("Windows 10 1903",         "18362", "Windows 10 Version 1903"),
    ("Windows 10 1809",         "17763", "Windows 10 Version 1809"),
    ("Windows 10 1803",         "17134", "Windows 10 Version 1803"),
    ("Windows 10 1709",         "16299", "Windows 10 Version 1709"),
    ("Windows 10 1703",         "15063", "Windows 10 Version 1703"),
    ("Windows 10 1607",         "14393", "Windows 10 Version 1607"),
    ("Windows 10 1511",         "10586", "Windows 10 Version 1511"),
    ("Windows 10 1507",         "10240", "Windows 10 for"),
    ("Windows 8.1",             "9600",  "Windows 8.1"),
    ("Windows Server 2012 R2",  "9600",  "Windows Server 2012 R2"),
    ("Windows 7 SP1",           "7601",  "Windows 7"),
]

# 兼容旧代码引用
WIN_BUILDS = {label: build for label, build, _ in WIN_VERSIONS}


def fetch(url, timeout=120, hdr=None):
    req = urllib.request.Request(url, headers=hdr or UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def fetch_json(url, timeout=120):
    return json.loads(fetch(url, timeout))


def cache(name, url, timeout=180):
    os.makedirs(RAW, exist_ok=True)
    p = os.path.join(RAW, name)
    if os.path.exists(p) and os.path.getsize(p) > 1000:
        return json.load(open(p))
    raw = fetch(url, timeout=timeout)
    if name.endswith(".gz"):
        raw = gzip.decompress(raw)
    d = json.loads(raw)
    json.dump(d, open(p, "w"))
    return d


# ---------------------------------------------------------------- 建表
SCHEMA = """
CREATE TABLE IF NOT EXISTS cve(
  cve_id TEXT PRIMARY KEY,
  title TEXT, description TEXT,
  severity TEXT, cvss REAL, cvss_vector TEXT, cwe TEXT,
  published TEXT, updated TEXT,
  exploit_status TEXT, impact TEXT,
  kev INTEGER DEFAULT 0, kev_ransomware INTEGER DEFAULT 0, kev_due TEXT,
  poc INTEGER DEFAULT 0, poc_refs TEXT,
  affected TEXT, kbs TEXT, patch_url TEXT, sources TEXT
);
CREATE TABLE IF NOT EXISTS affected(
  cve_id TEXT, product TEXT, cpe TEXT, product_id TEXT, kb TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_aff_uniq
  ON affected(cve_id, product, cpe, product_id, kb);
CREATE TABLE IF NOT EXISTS win_versions(
  label TEXT PRIMARY KEY, build TEXT, match TEXT
);
CREATE INDEX IF NOT EXISTS idx_cve_sev ON cve(severity);
CREATE INDEX IF NOT EXISTS idx_cve_cvss ON cve(cvss);
CREATE INDEX IF NOT EXISTS idx_cve_kev ON cve(kev);
CREATE INDEX IF NOT EXISTS idx_cve_poc ON cve(poc);
CREATE INDEX IF NOT EXISTS idx_cve_pub ON cve(published);
CREATE INDEX IF NOT EXISTS idx_aff ON affected(cve_id);
CREATE INDEX IF NOT EXISTS idx_aff_cpe ON affected(cpe);
"""


def init_db():
    con = sqlite3.connect(DB)
    con.executescript(SCHEMA)
    # 老库迁移
    cols = [r[1] for r in con.execute("PRAGMA table_info(cve)")]
    if "impact" not in cols:
        con.execute("ALTER TABLE cve ADD COLUMN impact TEXT")
    wcols = [r[1] for r in con.execute("PRAGMA table_info(win_versions)")]
    if "match" not in wcols:
        con.execute("ALTER TABLE win_versions ADD COLUMN match TEXT")
    con.execute("DELETE FROM win_versions")
    con.executemany("INSERT OR REPLACE INTO win_versions(label,build,match) VALUES(?,?,?)",
                    WIN_VERSIONS)
    con.commit()
    return con


# 攻击类型 (从标题里抽, 用来按危害类型筛漏洞)
IMPACTS = [
    ("Remote Code Execution", ["remote code execution", "rce", "arbitrary code execution",
                               "code execution", "command injection", "execute arbitrary"]),
    ("Elevation of Privilege", ["elevation of privilege", "privilege escalation",
                                "escalate privileges", "privilege elevation"]),
    ("Information Disclosure", ["information disclosure", "info disclosure",
                                "information leak", "memory disclosure",
                                "sensitive information", "spoofing of"]),
    ("Denial of Service", ["denial of service", "dos ", "out-of-bounds read",
                           "null pointer dereference", "infinite loop"]),
    ("Security Feature Bypass", ["security feature bypass", "bypass", "sandbox escape"]),
    ("Spoofing", ["spoofing", "spoof"]),
    ("Tampering", ["tampering", "tamper"]),
    ("Cross-site Scripting", ["cross-site scripting", "xss"]),
    ("Memory Corruption", ["memory corruption", "use after free", "use-after-free",
                           "type confusion", "buffer overflow", "heap overflow",
                           "stack overflow", "integer overflow", "out-of-bounds write",
                           "double free", "uninitialized", "wild pointer"]),
    ("SQL Injection", ["sql injection", "sqli"]),
    ("Path Traversal", ["path traversal", "directory traversal"]),
    ("SSRF", ["server-side request forgery", "ssrf"]),
    ("XXE", ["xml external entity", "xxe"]),
    ("Deserialization", ["deserialization", "deserialize"]),
    ("Authentication Bypass", ["authentication bypass", "auth bypass",
                               "improper authentication", "bypass authentication"]),
    ("Cryptographic Issue", ["cryptographic", "certificate validation", "encryption weakness",
                             "signature validation"]),
    ("Race Condition", ["race condition", "toctou", "time-of-check"]),
    ("Protection Mechanism Failure", ["protection mechanism"]),
]


def guess_impact(title: str) -> str:
    t = (title or "").lower()
    for name, keys in IMPACTS:
        if any(k in t for k in keys):
            return name
    return ""


def sev_from_cvss(score):
    if score is None:
        return ""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "Important"
    if score >= 4.0:
        return "Moderate"
    return "Low"


def postprocess(con):
    """补齐: 攻击类型 / 从 CVSS 推严重性 / 时间戳"""
    n_imp = n_sev = 0
    for cid, title, sev, cvss, pub in con.execute(
            "SELECT cve_id,title,severity,cvss,published FROM cve"):
        sets, args = [], []
        imp = guess_impact(title)
        if imp:
            sets.append("impact=?"); args.append(imp); n_imp += 1
        if (not sev) and cvss:
            sets.append("severity=?"); args.append(sev_from_cvss(cvss)); n_sev += 1
        if not pub or pub < "1990":
            sets.append("published=?"); args.append("2020-01")
        if pub and pub < "1990":
            sets.append("updated=?"); args.append("2020-01")
        if sets:
            con.execute(f"UPDATE cve SET {','.join(sets)} WHERE cve_id=?", args + [cid])
    con.commit()
    print(f"[补全] 攻击类型 {n_imp} 条, 严重性(按CVSS推) {n_sev} 条")


def upsert(con, cve_id, **kw):
    row = con.execute("SELECT cve_id FROM cve WHERE cve_id=?", (cve_id,)).fetchone()
    if not row:
        cols = ["cve_id"] + list(kw.keys())
        con.execute(f"INSERT INTO cve({','.join(cols)}) VALUES({','.join('?' * len(cols))})",
                    [cve_id] + list(kw.values()))
    else:
        sets = ",".join(f"{k}=COALESCE(?,{k})" for k in kw)
        con.execute(f"UPDATE cve SET {sets} WHERE cve_id=?", list(kw.values()) + [cve_id])


# ---------------------------------------------------------------- 1. MSRC
SEV_MAP = {0: "None", 1: "Low", 2: "Moderate", 3: "Important", 4: "Critical"}
THREAT_TYPE = {0: "Impact", 1: "Exploitability Assessment", 2: "Latest Software Release",
               3: "Older Software Release", 4: "Exploit Status",
               5: "Exploitation Assessment", 6: "Vulnerability Severity"}
EXPLOIT_DESC = {
    0: "Exploitation Unlikely", 1: "Exploitation Less Likely", 2: "Exploitation More Likely",
    3: "Exploitation Detected", 4: "Exploitation Unlikely",
}


MONTHS = {"Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04", "May": "05", "Jun": "06",
          "Jul": "07", "Aug": "08", "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12"}


def parse_msrc_doc(con, doc, docid):
    """解析一份 MSRC CVRF"""
    m = re.match(r"(\d{4})-(\w{3})", docid or "")
    docdate = f"{m.group(1)}-{MONTHS.get(m.group(2), '01')}" if m else ""
    prod = {}
    pt = doc.get("ProductTree", {})
    for p in pt.get("FullProductName", []):
        prod[p.get("ProductID")] = (p.get("Value"), p.get("CPE", ""))
    # 分支里也有
    for br in pt.get("Branch", []):
        for p in br.get("FullProductName", []):
            prod[p.get("ProductID")] = (p.get("Value"), p.get("CPE", ""))

    n = 0
    for v in doc.get("Vulnerability", []):
        cid = v.get("CVE")
        if not cid:
            continue
        title = str((v.get("Title") or {}).get("Value", ""))[:500]
        desc = ""
        for nt in v.get("Notes", []):
            if nt.get("Title") in ("Description",) and nt.get("Value"):
                d = re.sub(r"<[^>]+>", " ", nt["Value"])
                d = re.sub(r"\s+", " ", d).strip()
                if len(d) > len(desc):
                    desc = d
        # CVSS
        cvss, vec = None, ""
        for s in v.get("CVSSScoreSets", []):
            if s.get("BaseScore"):
                cvss = max(cvss or 0, float(s["BaseScore"]))
                vec = s.get("Vector", vec)
        # 严重性 + 可利用性
        sev, exploit = "", ""
        for t in v.get("Threats", []):
            tt = t.get("Type")
            val = (t.get("Description") or {}).get("Value", "")
            if tt in (6, 2) and val:
                vv = str(val)
                if vv in SEV_MAP.values():
                    order = ["None", "Low", "Moderate", "Important", "Critical"]
                    if not sev or order.index(vv) > order.index(sev):
                        sev = vv
            if tt in (1, 4, 5):
                if val:
                    exploit = str(val)
                else:
                    ds = (t.get("Description") or {})
                    if isinstance(ds, dict) and ds.get("Value") is None:
                        pass
        # 补丁 KB
        kbs, patch_url, prods, fixed = [], "", [], []
        rem_urls = []
        for rem in v.get("Remediations", []):
            dv = (rem.get("Description") or {}).get("Value", "") or ""
            u = rem.get("URL", "") or ""
            for pid in rem.get("ProductID", [])[:20]:
                pn, pc = prod.get(pid, ("", ""))
                if pn:
                    prods.append(pn)
                    con.execute("INSERT OR IGNORE INTO affected VALUES(?,?,?,?,?)",
                                (cid, pn, pc, pid, dv if dv.startswith("KB") else ""))
            if u:
                rem_urls.append(u)
            # KB 号在描述里 或 在 URL 里(catalog.update.microsoft.com/...?q=KBxxxxxxx)
            for m2 in re.finditer(r"KB(\d{6,8})|/help/(\d{6,8})", dv + " " + u, re.I):
                kb = "KB" + (m2.group(1) or m2.group(2))
                if kb not in kbs:
                    kbs.append(kb)
            if rem.get("FixedBuild"):
                fixed.append(str(rem["FixedBuild"])[:40])
        # patch_url 优先用能直接定位补丁的那个
        for u in rem_urls:
            if "catalog.update.microsoft.com" in u and "KB" in u.upper():
                patch_url = u
                break
        if not patch_url:
            patch_url = next((u for u in rem_urls if "microsoft.com" in u), rem_urls[0] if rem_urls else "")
        pub = (v.get("ReleaseDate") or "")[:10]
        if not pub or pub < "1990":
            pub = docdate
        redate = (v.get("ReleaseDate") or "")[:10]
        upsert(con, cid, title=title, description=desc, severity=sev,
               cvss=cvss, cvss_vector=vec, cwe=json.dumps(v.get("CWE"))[:300] if v.get("CWE") else "",
               published=pub,
               updated=redate if redate >= "1990" else docdate,
               exploit_status=exploit,
               affected=", ".join(sorted(set(prods))[:12]),
               kbs=", ".join(sorted(set(kbs))[:8]),
               patch_url=patch_url,
               sources=f"msrc:{docid}")
        n += 1
    return n


def build_msrc(con, start="2016-Jan"):
    up = fetch_json("https://api.msrc.microsoft.com/cvrf/v3.0/updates")
    docs = [u for u in up["value"] if u["ID"] >= start and re.match(r"^\d{4}-[A-Za-z]{3}$", u["ID"])]
    docs.sort(key=lambda x: x["ID"])
    print(f"[MSRC] 待抓 {len(docs)} 份月度文档 ({docs[0]['ID']} → {docs[-1]['ID']})")
    total = 0
    for i, u in enumerate(docs, 1):
        did = u["ID"]
        try:
            d = cache(f"msrc_{did}.json",
                      f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{did}", timeout=300)
        except Exception as e:
            print(f"  [{i}/{len(docs)}] {did} 下载失败: {e}")
            continue
        try:
            n = parse_msrc_doc(con, d, did)
        except Exception as e:
            print(f"  [{i}/{len(docs)}] {did} 解析失败: {e}")
            continue
        total += n
        if i % 5 == 0 or i == len(docs):
            con.commit()
            print(f"  [{i}/{len(docs)}] {did}: +{n} (累计 {total})", flush=True)
    con.commit()
    print(f"[MSRC] 完成, {total} 条")
    return total


# ---------------------------------------------------------------- 2. KEV
def build_kev(con):
    try:
        d = cache("kev.json", "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
                              "known_exploited_vulnerabilities.json", timeout=120)
    except Exception as e:
        print(f"[KEV] 失败: {e}")
        return 0
    n = 0
    for v in d.get("vulnerabilities", []):
        cid = v.get("cveID")
        if not cid:
            continue
        kw = dict(
            title=v.get("vulnerabilityName", "")[:400],
            description=v.get("shortDescription", "")[:2000],
            kev=1,
            kev_ransomware=1 if v.get("knownRansomwareCampaignUse") == "Known" else 0,
            kev_due=v.get("dueDate", ""),
            affected=v.get("product", "") + " " + v.get("vendorProject", ""),
            exploit_status="已被真实利用 (CISA KEV)",
            sources="kev")
        # 库里没有或日期是坏的, 才用 KEV 收录日期
        row = con.execute("SELECT published FROM cve WHERE cve_id=?", (cid,)).fetchone()
        if not row or not row[0] or row[0] < "1990":
            kw["published"] = (v.get("dateAdded") or "")[:10]
        upsert(con, cid, **kw)
        n += 1
    con.commit()
    print(f"[KEV] 完成, {n} 条已利用漏洞")
    return n


# ---------------------------------------------------------------- 3. ExploitDB
def build_edb(con):
    try:
        req = urllib.request.Request(
            "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
            headers=UA)
        raw = urllib.request.urlopen(req, timeout=180).read().decode("utf-8", "ignore")
    except Exception as e:
        print(f"[EDB] 失败: {e}")
        return 0
    import csv
    lines = raw.splitlines()
    rd = csv.DictReader(io.StringIO("\n".join(lines)))
    per_cve, per_cve_date, n = {}, {}, 0
    for r in rd:
        codes = r.get("codes", "") or ""
        d0 = (r.get("date_published") or r.get("date_added") or "")[:10]
        for cid in re.findall(r"CVE-\d{4}-\d{4,7}", codes):
            per_cve.setdefault(cid, []).append(
                f"EDB-{r.get('id')} {r.get('description','')[:70]} ({r.get('type')}/{r.get('platform')})")
            per_cve_date.setdefault(cid, d0)
            n += 1
    for cid, refs in per_cve.items():
        row = con.execute("SELECT published FROM cve WHERE cve_id=?", (cid,)).fetchone()
        kw = dict(poc=1, poc_refs=" | ".join(refs[:6]))
        if not row or not row[0] or row[0] < "1990":
            kw["published"] = per_cve_date.get(cid, "")
        upsert(con, cid, **kw)
    con.commit()
    print(f"[EDB] 完成, {len(per_cve)} 个 CVE 有公开 PoC ({n} 条映射)")
    return len(per_cve)


# ---------------------------------------------------------------- 4. NVD (可选)
def build_nvd_for_windows_missing(con, limit=3000):
    """给库里还缺 CVSS 的 CVE 从 NVD 补(限速 5req/30s, 慢, 用 limit 控制)"""
    rows = con.execute("""SELECT cve_id FROM cve WHERE cvss IS NULL AND kev=0
                          ORDER BY published DESC LIMIT ?""", (limit,)).fetchall()
    print(f"[NVD] 待补 {len(rows)} 条 (约 {len(rows)*6/60:.0f} 分钟)")
    done = 0
    for i, (cid,) in enumerate(rows, 1):
        try:
            d = fetch_json(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cid}", timeout=40)
            v = d["vulnerabilities"][0]["cve"]
            m = v.get("metrics", {})
            score, vec, sev = None, "", ""
            for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if k in m:
                    md = m[k][0]["cvssData"]
                    score = md.get("baseScore")
                    vec = md.get("vectorString", "")
                    sev = md.get("baseSeverity") or m[k][0].get("baseSeverity", "")
                    break
            if score:
                upsert(con, cid, cvss=score, cvss_vector=vec, severity=sev or None)
                done += 1
        except Exception:
            pass
        if i % 25 == 0:
            con.commit()
            print(f"  [{i}/{len(rows)}] 补了 {done}", flush=True)
        time.sleep(6)
    con.commit()
    print(f"[NVD] 补了 {done} 条")
    return done


def stats(con):
    print("\n" + "=" * 62)
    print("漏洞库统计")
    print("=" * 62)
    q = con.execute
    print(f"  总 CVE      : {q('SELECT COUNT(*) FROM cve').fetchone()[0]}")
    print(f"  有 CVSS     : {q('SELECT COUNT(*) FROM cve WHERE cvss IS NOT NULL').fetchone()[0]}")
    print(f"  被真实利用  : {q('SELECT COUNT(*) FROM cve WHERE kev=1').fetchone()[0]}")
    print(f"  有公开 PoC  : {q('SELECT COUNT(*) FROM cve WHERE poc=1').fetchone()[0]}")
    print(f"  受影响记录  : {q('SELECT COUNT(*) FROM affected').fetchone()[0]}")
    print("\n  按年份:")
    for y, c in q("""SELECT substr(published,1,4) y, COUNT(*) FROM cve
                     WHERE published<>'' GROUP BY y ORDER BY y DESC LIMIT 12"""):
        print(f"    {y}  {c:>6}")
    print("\n  严重性分布:")
    for s, c in q("SELECT COALESCE(severity,'未知'), COUNT(*) FROM cve GROUP BY 1 ORDER BY 2 DESC"):
        print(f"    {s:<12} {c:>6}")
    print("\n  CVSS>=9 的数量:", q("SELECT COUNT(*) FROM cve WHERE cvss>=9").fetchone()[0])
    print("\n  攻击类型分布:")
    for i, c in q("SELECT COALESCE(NULLIF(impact,''),'未分类'), COUNT(*) FROM cve GROUP BY 1 ORDER BY 2 DESC LIMIT 12"):
        print(f"    {i[:34]:<34} {c:>6}")
    print("\n  Top 受影响产品:")
    for p, c in q("SELECT product, COUNT(*) FROM affected GROUP BY 1 ORDER BY 2 DESC LIMIT 12"):
        print(f"    {p[:52]:<52} {c:>5}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="start", default="2016-Jan")
    ap.add_argument("--kev-only", action="store_true")
    ap.add_argument("--skip-msrc", action="store_true")
    ap.add_argument("--nvd", type=int, default=0, help="从 NVD 补 N 条缺 CVSS 的记录")
    a = ap.parse_args()

    con = init_db()
    if not a.kev_only:
        if not a.skip_msrc:
            build_msrc(con, a.start)
        build_edb(con)
    build_kev(con)          # KEV 放最后, 覆盖 exploit_status
    postprocess(con)        # 补攻击类型 / 严重性 / 时间戳
    if a.nvd:
        build_nvd_for_windows_missing(con, a.nvd)
    stats(con)
    con.close()
    print(f"\n→ {DB}")
