#!/bin/bash
# 攻击模拟 + 正常使用回归测试
BASE=http://127.0.0.1:8787
pass=0; fail=0
chk() { # chk 期望码 说明 curl参数...
  local want="$1" desc="$2"; shift 2
  local got
  got=$(curl -s -o /dev/null -w "%{http_code}" "$@")
  if [ "$got" = "$want" ]; then printf "  ✓ %-44s %s\n" "$desc" "$got"; pass=$((pass+1))
  else printf "  ❌ %-44s 得到 %s（期望 %s）\n" "$desc" "$got" "$want"; fail=$((fail+1)); fi
}

echo "=== 0) 拿页面并提取注入的令牌 ==="
PAGE=$(curl -s -H "Host: 127.0.0.1:8787" "$BASE/")
TOKEN=$(printf '%s' "$PAGE" | grep -o "const TOKEN='[^']*'" | cut -d"'" -f2)
echo "  令牌长度: ${#TOKEN}  （前 8 位 ${TOKEN:0:8}…）"
if [ "${#TOKEN}" -ge 20 ]; then echo "  ✓ 页面里确实注入了令牌"; pass=$((pass+1)); else echo "  ❌ 没注入"; fail=$((fail+1)); fi
printf '%s' "$PAGE" | grep -q "__SECFORGE_TOKEN__" && { echo "  ❌ 占位符没被替换掉"; fail=$((fail+1)); } || echo "  ✓ 占位符已被替换"

echo
echo "=== 1) 攻击模拟（全部应该 403）==="
chk 403 "跨站盲发，无令牌（模拟 <img> 标签）" -H "Host: 127.0.0.1:8787" "$BASE/api/chat?message=evil"
chk 403 "跨站盲发到扫描接口"                  -H "Host: 127.0.0.1:8787" "$BASE/api/run?tool=nmap&target=127.0.0.1"
chk 403 "DNS rebinding（Host=攻击者域名）"     -H "Host: evil.com" "$BASE/api/overview"
chk 403 "DNS rebinding 拿页面（想偷令牌）"     -H "Host: evil.attacker.com" "$BASE/"
chk 403 "伪造 Origin"                          -H "Host: 127.0.0.1:8787" -H "Origin: http://evil.com" "$BASE/api/overview"
chk 403 "浏览器标记的跨站"                     -H "Host: 127.0.0.1:8787" -H "Sec-Fetch-Site: cross-site" "$BASE/api/overview"
chk 403 "令牌错误"                             -H "Host: 127.0.0.1:8787" -H "X-SecForge-Token: wrong-token" "$BASE/api/overview"
chk 403 "POST 无令牌"                          -X POST -H "Host: 127.0.0.1:8787" -H "Content-Type: application/json" -d '{}' "$BASE/api/container"

echo
echo "=== 2) 正常使用（全部应该 200）==="
chk 200 "令牌放 Header"   -H "Host: 127.0.0.1:8787" -H "X-SecForge-Token: $TOKEN" "$BASE/api/overview"
chk 200 "令牌放 query（EventSource 只能这样）" -H "Host: 127.0.0.1:8787" "$BASE/api/overview?token=$TOKEN"
chk 200 "用 localhost 访问"  -H "Host: localhost:8787" -H "X-SecForge-Token: $TOKEN" "$BASE/api/overview"
chk 200 "POST 带令牌"  -X POST -H "Host: 127.0.0.1:8787" -H "X-SecForge-Token: $TOKEN" -H "Content-Type: application/json" -d '{"action":"status"}' "$BASE/api/container"
chk 200 "取页面（Host 正确，不需要令牌）" -H "Host: 127.0.0.1:8787" "$BASE/"

echo
echo "=== 3) 真的拿到数据了吗（不是空 200）==="
curl -s -H "Host: 127.0.0.1:8787" -H "X-SecForge-Token: $TOKEN" "$BASE/api/overview" \
  | head -c 150 | tr -d '\n'; echo

echo
echo "=== 结果 ==="
echo "  通过 $pass  失败 $fail"
[ "$fail" -eq 0 ] && echo "  全部通过 ✓" || echo "  有失败项 ❌"
exit $((fail > 0))
