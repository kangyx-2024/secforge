#!/usr/bin/env python3
"""注入测试 —— 证明「参数不会被当成 shell 命令执行」。

背景：sec_run 的参数来自 AI，早期版本把它直接拼进 `bash -lc`，
于是 `args="127.0.0.1; touch /loot/x"` 里的 `; touch /loot/x` 会被真的执行。
现在参数切成 argv 后以 argv 形式交给容器，不经过 shell。

跑法: .venv/bin/python mcp/test_injection.py
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("srv", os.path.join(HERE, "server.py"))
srv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(srv)

MARK = "/loot/INJECT_PROOF"          # 哨兵：出现在容器里 = 注入成功


def clean():
    srv.dex(f"rm -f {MARK}", 30)


def exists():
    return "YES" in srv.dex(f"test -f {MARK} && echo YES || echo NO", 30)


print("— 对照组：老写法（拼进 bash -lc）确实能注入 —")
clean()
srv.dex(f"nmap 127.0.0.1; touch {MARK}", 60)
ctrl = exists()
print(f"  dex(\"nmap 127.0.0.1; touch {MARK}\") → 哨兵出现: {ctrl}")
if not ctrl:
    print("  ❌ 测法本身有问题（哨兵机制没生效），后面的结论不可信")
    sys.exit(1)
print("  ✓ 哨兵机制有效 —— 老写法真的能注入\n")

print("— 实验组：新写法（argv，不经过 shell）—")
cases = [
    ("args 带分号",    lambda: srv.sec_run(tool="nmap", args=f"127.0.0.1; touch {MARK}")),
    ("args 带 &&",     lambda: srv.sec_run(tool="nmap", args=f"127.0.0.1 && touch {MARK}")),
    ("args 带 $(...)", lambda: srv.sec_run(tool="nmap", args=f"$(touch {MARK})")),
    ("args 带反引号",   lambda: srv.sec_run(tool="nmap", args=f"`touch {MARK}`")),
    ("args 带管道",     lambda: srv.sec_run(tool="nmap", args=f"127.0.0.1 | touch {MARK}")),
    ("tool 里塞命令",   lambda: srv.sec_run(tool=f"nmap; touch {MARK}", args="--version")),
    ("job_output jid", lambda: srv.sec_job_output(jid=f"x; touch {MARK}")),
    ("job_status jid", lambda: srv.sec_job_status(jid=f"x; touch {MARK}")),
    ("job_start name", lambda: srv.sec_job_start(name=f"a; touch {MARK}", command="sleep 1")),
]
bad = 0
for name, fn in cases:
    clean()
    try:
        fn()
    except Exception:
        pass
    got = exists()
    if got:
        bad += 1
    print(f"  {name:<16} 哨兵出现: {got}   {'❌ 还是能注入' if got else '✓ 挡住了'}")
clean()

print("\n— 功能性：正常调用还好使吗 —")
out = srv.sec_run(tool="nmap", args="--version")
print("  sec_run(nmap --version) →", "OK" if "Nmap version" in out else out[:120])
out2 = srv.sec_run(tool="nmap", args="-sV -T4 -Pn -p 8787 127.0.0.1", timeout=90)
print("  真扫一个端口 →", "OK" if ("open" in out2 or "closed" in out2) else out2[:150])
out3 = srv.sec_run(tool="nmap", args='-p "80,443" 127.0.0.1', timeout=60)
print("  带引号的参数 →", "OK" if "解析失败" not in out3 else "❌ 引号解析失败")

print(f"\n注入成功次数: {bad}  ({'全部挡住 ✓' if bad == 0 else '有漏网 ❌'})")
sys.exit(1 if bad else 0)
