---
name: traffic_classify
description: 把单条未知流标注为 <app>:<service_type>，按证据优先级链推断并写到 outputs。
metadata: {"mybot":{"emoji":"🛰️"}}
---

# 未知流量复合标签

## 输入字段速查
- `hints.sni` / `hints.tls_san_dns`：TLS 客户端声明的服务名 / 证书 SAN。
- `hints.http_host` / `hints.http_user_agent`：明文 HTTP 头部。
- `hints.dns_query`：关联 DNS 查询。
- `hints.ndpi_app` / `hints.proto_stack`：nDPI 检测到的协议栈名。
- `hints.classification_model`：ET-BERT 模型预判（仅作 service_type 的低权重参考）。
- `stats.duration / total_bytes / data_ratio`：行为统计；用于 service_type 的兜底判断。
- `preprocess.reason`：模块A 把它判为未知的原因。

## 推断顺序

### 1. 加密流量 (`hints.is_encrypted == true`)
- 有 SNI/SAN → 优先：
  - 已知品牌（含 `gmail`、`outlook`、`bilibili`、`youtube`、`weixin/wechat`、`qq`、`spotify` 等）→ `app=<品牌>`，`service_type` 按品牌主业务给出。
  - 域名陌生 → 用 `web_fetch https://<sni>/` 抓取标题/响应头；解析失败时回退到证书/IP 类证据。
- 无 SNI → 用 `dst_ip` + 端口 + `tls_alpn` + `classification_model.label` 综合判断；常见情形：
  - ALPN=`h2` 或 `http/1.1`，dst_port=443 → `service_type=web`。
  - ALPN=`webrtc` 或大量小包对称传输 → `service_type=stream` 或 `interactive`。
- 主动验证：访问 `https://<dst_ip>/` 或 `https://<sni>/`，看 server 头/证书 CN 也能给 app 提供证据。

### 2. 明文流量 (`hints.is_encrypted == false`)
- 看 `http_host` + `http_user_agent` + `http_method` + `http_status_code`。
- `dns_query` 等于内部主机名（非 FQDN）→ 多半是内网服务，`app=internal`，`service_type=web` 或 `interactive`。

### 3. 行为兜底
- `c_to_s_bytes` 与 `s_to_c_bytes` 严重不对称（比例 > 10:1） + `total_bytes` > 1MB → 倾向 `bulk-transfer`。
- 持续时间 > 60s 且双向小包 → `interactive` 或 `stream`。
- 模型输出 `vpn` 时只在没有其他强证据时采纳。

## service_type 词表（必须从中选）
`bulk-transfer / interactive / stream / vpn / web`

## confidence 校准建议
- SNI 命中已知品牌：0.85 ~ 0.95。
- web_fetch 拿到与品牌强相关的标题/证书：0.7 ~ 0.85。
- 仅靠 ndpi/端口/统计：0.4 ~ 0.6。
- 只能靠 classification_model：0.3 ~ 0.5。
- 没有任何强证据：0，且 `final_label/app/service_type` 全置 null。

## 示例

### 示例 A — SNI 命中
```json
input.flow = {
  "flow_key": "tcp:10.0.0.2:53122<->142.250.72.165:443",
  "hints": {"is_encrypted": true, "sni": "smtp.googlemail.com", "tls_alpn": "h2"},
  "stats": {"duration": 4.1, "total_bytes": 21000}
}
=> decision = {
  "flow_key": "tcp:10.0.0.2:53122<->142.250.72.165:443",
  "final_label": "gmail:web",
  "app": "gmail",
  "service_type": "web",
  "confidence": 0.88,
  "reason": "SNI smtp.googlemail.com 命中 Google 邮件服务，端口 443 + ALPN h2 与 web 流量一致",
  "evidence": [
    {"source": "sni", "value": "smtp.googlemail.com", "weight": 0.9},
    {"source": "port", "value": 443, "weight": 0.2}
  ]
}
```

### 示例 B — 证据不足
```json
input.flow = {
  "flow_key": "udp:10.0.0.5:55050<->8.8.8.8:53",
  "hints": {"is_encrypted": false, "dns_query": null, "ndpi_app": "DNS"},
  "stats": {"duration": 0.05, "total_bytes": 200}
}
=> decision = {
  "flow_key": "udp:10.0.0.5:55050<->8.8.8.8:53",
  "final_label": null,
  "app": null,
  "service_type": null,
  "confidence": 0,
  "reason": "DNS 流量已被预处理判为系统协议；本应不会进入 Agent 列表，缺少进一步证据",
  "evidence": []
}
```
