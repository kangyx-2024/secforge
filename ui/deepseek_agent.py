#!/usr/bin/env python3
# ⚠️ 使用声明：仅供合法的网络安全工作 —— 你自己的资产，或你持有书面授权的目标。
#    严禁用于任何未授权的系统。相关行为由《刑法》第 285 / 286 条规制。详见 USAGE-POLICY.md
"""SecForge 的第二个大脑 —— DeepSeek 直连（不经过 Hermes）

设计要点:
  · 工具就是 mcp/server.py 里那 21 个 sec_* 函数, 直接当普通 Python 函数调,
    不走 MCP 协议(少一层进程, 快)。
  · 工具 schema 从函数签名 + docstring 自动生成, 所以以后给 server.py 加工具,
    这里不用改任何代码。
  · 安全护栏在工具自己身上(sec_run/sec_job_start 里的 guard()), 所以这个大脑
    自动继承同一套红线 —— 政府/教育/军方域名照样会被拒。
  · 它只能动容器(docker exec 进 secforge), 碰不到宿主机的文件。
  · 任意 shell(sec_shell) 故意**不暴露**给 AI —— 那是人类用的通道(secforge sh)。
"""
import inspect
import json
import os
import re
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API = "https://api.deepseek.com/v1/chat/completions"
MODEL = os.environ.get("SECFORGE_DS_MODEL", "deepseek-chat")
MAX_STEPS = 15
MAX_HISTORY = 40          # 保留最近多少条消息(含工具结果), 防止无限涨

SYS = """你是 SecForge 工具盒的 AI 操作员（DeepSeek 直连大脑）。

你有 21 个工具，运行在一个隔离的 Kali Linux 容器里，包括：
跑安全工具（sec_run/sec_job_start）、查 GitHub 安全工具库
（sec_catalog/sec_tool_info）、查 5 万条漏洞库（sec_vuln_search/sec_vuln_detail/
sec_vuln_for_windows/sec_vuln_auto）、管理容器和镜像（sec_image_status/
sec_start_container/sec_build_image）、装新工具（sec_install_tool）。

规矩：
1. 用中文，简洁直接，不废话。
2. 要干活就真调工具，别只描述你想干什么。拿到结果再下结论。
3. 只报告工具真实返回的内容，不许编造数字、CVE 号或补丁号。
4. 目标只允许自有设备、内网靶场、授权平台。政府/教育/军方域名会被工具层
   直接拒绝(内置护栏)，遇到拒绝就如实告诉用户，不要绕。
5. 长任务用 sec_job_start 后台跑，别把同步调用卡死。
6. 做完给结论：发现了什么、值不值得进一步查、下一步建议什么。
"""


def _load_tools():
    """从 mcp/server.py 里捞出所有 sec_* 工具"""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "secforge_srv", os.path.join(ROOT, "mcp", "server.py"))
    srv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(srv)
    tools = {}
    for name in dir(srv):
        if name.startswith("sec_") and callable(getattr(srv, name)):
            tools[name] = getattr(srv, name)
    return srv, tools


SRV, TOOLS = _load_tools()


def _schema(fn, name):
    """函数签名 + docstring -> OpenAI function schema"""
    doc = inspect.getdoc(fn) or ""
    lines = doc.splitlines()
    desc = lines[0].strip() if lines else name
    # 从 docstring 的 Args: 段里抠每个参数的说明
    pdesc = {}
    inargs = False
    for ln in lines[1:]:
        s = ln.strip()
        if re.match(r"^(Args|参数)\s*[:：]", s):
            inargs = True
            continue
        if inargs:
            if re.match(r"^(Returns|返回|Raises|Note|用法)\s*[:：]", s) or (ln and not ln.startswith(" ")):
                inargs = False
                continue
            m = re.match(r"^([A-Za-z_]\w*)\s*[:：]\s*(.+)$", s)
            if m:
                pdesc[m.group(1)] = m.group(2)[:160]
    props, required = {}, []
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        sig = None
    if sig:
        for p in sig.parameters.values():
            t = "string"
            ann = p.annotation
            if ann is int:
                t = "integer"
            elif ann is float:
                t = "number"
            elif ann is bool:
                t = "boolean"
            props[p.name] = {"type": t, "description": pdesc.get(p.name, "")}
            if p.default is inspect.Parameter.empty:
                required.append(p.name)
    return {"type": "function", "function": {
        "name": name,
        "description": (desc + "\n" + doc[len(desc):len(desc) + 700]).strip()[:900],
        "parameters": {"type": "object", "properties": props, "required": required}}}


TOOL_SCHEMAS = [_schema(f, n) for n, f in sorted(TOOLS.items())]


def _key():
    for p in (os.path.join(ROOT, ".env"), os.path.expanduser("~/.hermes/.env")):
        if not os.path.exists(p):
            continue
        for line in open(p, encoding="utf-8", errors="ignore"):
            if line.strip().startswith("DEEPSEEK_API_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return os.environ.get("DEEPSEEK_API_KEY", "")


class DeepSeekAgent:
    def __init__(self):
        self.history = []          # [{role, content, tool_calls?}, ...]
        self.model = MODEL
        self._stop = False

    def reset(self):
        self.history = []

    def stop(self):
        """协作式停止: 在两次工具调用之间退出(单次 HTTP 请求没法打断, 最多等一轮)"""
        self._stop = True

    def _api(self, msgs, timeout=180):
        body = {"model": self.model, "messages": msgs, "temperature": 0.3,
                "tools": TOOL_SCHEMAS, "max_tokens": 3000}
        req = urllib.request.Request(API, data=json.dumps(body).encode(), method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", "Bearer " + _key())
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"DeepSeek API {e.code}: {e.read().decode('utf-8', 'ignore')[:300]}")
        except Exception as e:
            raise RuntimeError(f"DeepSeek 连接失败: {e}")

    def run(self, user_msg, on_event):
        """跑一轮对话, on_event(kind, text) 用来往界面上推进度"""
        self.history.append({"role": "user", "content": user_msg})
        msgs = [{"role": "system", "content": SYS}] + self.history[-MAX_HISTORY:]
        for step in range(MAX_STEPS):
            if self._stop:
                self._stop = False
                return "（已按你的要求停下）"
            r = self._api(msgs)
            try:
                m = r["choices"][0]["message"]
            except (KeyError, IndexError):
                raise RuntimeError(f"返回格式异常: {str(r)[:300]}")
            tcs = m.get("tool_calls")
            if tcs:
                mm = {"role": "assistant", "content": m.get("content") or "", "tool_calls": tcs}
                msgs.append(mm)
                self.history.append(mm)
                for tc in tcs:
                    name = (tc.get("function") or {}).get("name", "")
                    raw = (tc.get("function") or {}).get("arguments") or "{}"
                    try:
                        args = json.loads(raw)
                    except Exception:
                        args = {}
                    on_event("tool", f"{name}({json.dumps(args, ensure_ascii=False)[:240]})")
                    if name not in TOOLS:
                        res = f"没有这个工具: {name}"
                    else:
                        try:
                            res = str(TOOLS[name](**args))
                        except TypeError as e:
                            res = f"参数不对: {e}"
                        except Exception as e:
                            res = f"工具执行出错: {type(e).__name__}: {e}"
                    on_event("result", res[:2000])
                    tm = {"role": "tool", "tool_call_id": tc.get("id", ""), "content": res[:20000]}
                    msgs.append(tm)
                    self.history.append(tm)
                continue
            ans = (m.get("content") or "").strip()
            self.history.append({"role": "assistant", "content": ans})
            return ans
        return "（工具调用轮数超过上限，我先停了。要不要我换个思路？）"


if __name__ == "__main__":
    # 命令行自测: python3 ui/deepseek_agent.py "帮我查 SQL 注入相关漏洞"
    import sys
    a = DeepSeekAgent()
    q = " ".join(sys.argv[1:]) or "用 sec_overview 看下现在状态"
    print(f"工具数: {len(TOOL_SCHEMAS)}  |  模型: {a.model}")
    print("答:", a.run(q, lambda k, t: print(f"  [{k}] {t}")))
