# DNS Panel 上线检查清单（沙盒验证后执行）

## 1) 代码与备份
- [ ] 确认工作分支：`feat/full-auto-fixes-v1`
- [ ] 确认已推送备份分支与标签：
  - `backup/pre-rewrite-20260301-205253`
  - `backup-pre-rewrite-20260301-205253`
- [ ] 目标机器先备份 `instance/ecs_monitor.db` 与 `instance/encrypt.key`

## 2) 升级前验证
- [ ] `docker compose build --no-cache`
- [ ] `docker compose up -d`
- [ ] 检查登录/实例列表/流量图/导入导出路径

## 3) 密钥与迁移验证
- [ ] 下载备份 zip，确认含 `ecs_monitor.db` 与 `encrypt.key`
- [ ] 导出 CSV，确认包含 `ak_format` / `is_encrypted`
- [ ] 导入 CSV 到测试环境，确认 AK/SK 可正确识别

## 4) 流量统计验证
- [ ] 手动触发检查 2-3 次，确认 `current_month_traffic` 按增量变化
- [ ] 验证重启后统计不回退、不跳变

## 5) 防火墙（仅在明确端口清单确认后）
- [ ] 使用 `tools/firewall_open_safe.sh --plan` 先预览
- [ ] 最终确认端口后再 `--apply`

## 6) 回滚
- [ ] 保留旧容器镜像与数据库备份
- [ ] 若异常，回滚到备份分支版本并恢复 DB
