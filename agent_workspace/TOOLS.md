# Tool Usage Notes

## 工具优先级（针对流量分析任务）

按"能用更专的工具就别用通用工具"优先：

| 任务 | **首选** | 备用 | 禁用 |
|---|---|---|---|
| 读 inputs/*.json | `read_file`（**一次性整文件读完，不要分页**） | — | `exec cat`、`exec python3 -c "json.load(...)"` |
| 写 outputs/*.json | `write_file` | — | `exec echo > file` |
| **IP → ASN/ISP/国家** | `mcp_ip2location_get_geolocation({"ip":"x.x.x.x"})` | — | `web_search`、`web_fetch ip-info-page`、`whois_lookup(IP)` |
| **域名页面/标题/证书摘要** | `mcp_firecrawl-mcp_firecrawl_scrape({"url":"https://<sni>/"})` | `web_fetch` | — |
| **域名搜索/反查 owner** | `mcp_firecrawl-mcp_firecrawl_search({"query":"...","limit":3})` | `web_search` | — |
| **域名 WHOIS** | `whois_lookup({"domain":"foo.com"})` | — | 传 IP 字面量进去（会被运行时拒） |
| **域名 DNS 记录** | `dns_records({"domain":"foo.com"})` | `domain_analysis`（慢） | 传 IP 字面量 |
| **找已读过的内容** | 直接复用对话历史里的工具结果 | — | `read_file .mybot/tool-results/*.txt` 分页拉 35 行 |

> 你看到 `mcp_xxx_yyy` 这种带前缀的工具名 = 来自外部 MCP server，**不是**普通工具，但调用方式完全相同。

## 已注册的 MCP 工具（mybot 启动时打印 `MCP: registered tool ...`）

- **ip2location**（1 个工具）
  - `mcp_ip2location_get_geolocation` — 入参 `{"ip": "<单个 IPv4 或 IPv6>"}`，**一次只传一个 IP**，**不要把多个 IP 拼成 "1.1.1.1, 2.2.2.2" 这种逗号字符串**（服务端不解析）。返回 ASN / ISP / country / city / region。
- **firecrawl-mcp**（15 个工具，常用 3 个）
  - `mcp_firecrawl-mcp_firecrawl_scrape` — 入参 `{"url": "https://...", "onlyMainContent": true}`。比 `web_fetch` 快、返回干净 markdown，能抓 SPA 渲染后内容。
  - `mcp_firecrawl-mcp_firecrawl_search` — 入参 `{"query": "...", "limit": 3}`。比 `web_search` 直接返回结构化结果。
  - `mcp_firecrawl-mcp_firecrawl_map` / `_crawl` / `_extract` 等：本任务用不上，跳过。

## 安全限制

- **`exec` 严禁使用**：你不需要 shell；`read_file` 已经能给你 inputs/*.json 的全文。每次 `exec python3 -c "json.load(...)"` 至少耗 3-10 秒，跑十几次就是几分钟。
- `restrictToWorkspace=true`：所有读写限制在 `agent_workspace/` 内。
- `whois_lookup` / `dns_*` / MCP 工具走外网，但都受下面的预算限制。

## 外部调用预算（运行时硬性强制）

runtime 会拦截以下越界调用并返回一条 `Error: ...` 的合成工具结果——**重试只会再吃一次 token**：

1. **per-tool 重复**：相同 `(tool, arg)` 调用超过 2 次直接阻断。
2. **per-target 合计**：对同一目标（域名 / URL host / IP），`web_fetch + web_search + whois_lookup + dns_records + dns_health_check + domain_analysis + mcp_firecrawl-* + mcp_ip2location_*` 合计 ≤ 2 次。
   - 例：先 `mcp_ip2location_get_geolocation 1.2.3.4` 再 `web_search "1.2.3.4 owner"`，第三次再对 `1.2.3.4` 调用任何一个工具都会被拒。
3. **域名工具拒收 IP**：`whois_lookup` / `dns_records` / `dns_health_check` / `domain_analysis` 的 `domain` 参数必须是真实域名；传 `8.8.8.8` / `2001:db8::1` 立刻被拒。

收到这类 Error 时直接基于已有证据出决策。

## 当 flow 里只有 IP（无 SNI/host/dns_query）

**唯一推荐路径**：
```
mcp_ip2location_get_geolocation({"ip": "<单个 IP>"})  → 拿 ASN/ISP
```
- 如果 ASN 命中云厂商（Microsoft / Google / Amazon / Cloudflare / Akamai 等）+ 端口 443 + ALPN h2 → 大概率 web；`app=<云厂商>`，confidence ≈ 0.5。
- ASN 是宽带/移动运营商（China Telecom / China Mobile / Comcast 等）→ 无法定位具体应用，配合 `classification_model` 给出 `unknown:<service_type>`，confidence ≤ 0.5。

**禁用路径**（看到这种 Tool call 就是错的）：
- `web_search "1.2.3.4 microsoft azure"`、`web_fetch https://www.lookip.net/ip/...`、`web_fetch https://www.abuseipdb.com/check/...`：慢（每次 5-15 秒）、被运行时反复拒、结果质量低。

## 默认 mybot 工具行为提醒

- `read_file` 一次性读完整个 chunk JSON（35-50 KB）完全在能力范围内。**不要**用 `offset/limit` 分页读 `agent_workspace/.mybot/tool-results/*.txt`——这些缓存文件是上一次工具结果被截断后留下的，分页读相当于让 LLM 慢动作回放自己之前看过的东西。
- `dns_records` 默认查 `[A, AAAA, MX, NS, TXT, CNAME, SOA]`；只关心几种时显式传 `record_types`，否则按默认。
- `glob` 按文件名通配；列目录用 `list_dir`。
