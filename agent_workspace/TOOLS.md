# Tool Usage Notes

## 工具优先级（针对流量分析任务）

1. **read_file**：读取 inputs/*.json，是每个任务的入口动作。
2. **write_file**：把决策写到 outputs/*.json；这是最终交付的唯一通道。
3. **glob / grep**：当需要在 inputs/ 下查找特定 chunk 或在 sessions/ 找历史决策时使用。
4. **web_fetch**：当 SNI 已知但未命中白名单时，可以访问 `https://<sni>/` 抓首页标题/证书来辅助判断 app；遇到 IP-only 加密流量时，可尝试 reverse DNS / WHOIS 类公开网站。
5. **web_search**：用搜索引擎查 SNI 或 IP 归属作为 cert/ip 类证据。

## 安全限制

- `exec` 已在 config 中禁用。
- `restrictToWorkspace=true`：所有读写都限制在 `agent_workspace/` 内；不要尝试访问 `data/processed/` 等系统路径。

## 默认 mybot 工具行为提醒

- `glob` 默认按文件名通配；列目录用 `list_dir`。
- `grep` 默认 `output_mode=files_with_matches`，搜大目录时用 `output_mode=count` 先估量。
- `web_fetch` 大概率只能拿到 HTTP 文本头部摘要，不要期望解析 SPA 全部内容。
