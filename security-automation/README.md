# Security Automation Template

这套模板面向发版前的自动化安全报告，包含四块内容：

- `SonarQube` 源码扫描
- `OWASP Dependency-Check` 依赖漏洞扫描
- `SBOM` 生成
- 部署后 `nmap` 端口扫描与 `tcpdump/tshark` 抓包摘要

## 工作流入口

工作流文件位于：

- `.github/workflows/release-security-report.yml`

默认使用 `workflow_dispatch` 手动触发，比较适合“RC 包部署完成后，发版前出一份安全报告”的场景。

## 需要配置的 GitHub Secrets

- `SONAR_TOKEN`
- `OSS_INDEX_USERNAME`
- `OSS_INDEX_PASSWORD`
- `RUNTIME_SCAN_SSH_USER`
- `RUNTIME_SCAN_SSH_KEY`
- `RUNTIME_SCAN_KNOWN_HOSTS` 可选

## 建议配置的 GitHub Variables

- `SONAR_HOST_URL`
- `SONAR_PROJECT_KEY`
- `SONAR_PROJECT_NAME`

## 远端测试环境前置条件

- 目标机已部署并启动待测版本
- 目标机已安装 `nmap`
- 目标机已安装 `tcpdump`
- SSH 用户具备运行 `sudo nmap` 和 `sudo tcpdump` 的权限

## 当前白名单

配置文件：

- `security-automation/config/allowed-ports.txt`

默认端口白名单为：

- `6667`
- `9091`
- `9092`
- `10710-10760`

## 当前实现边界

- `Dependency-Track` 目前按“先生成 SBOM，等平台恢复后再补自动上传”处理
- 抓包摘要基于主机级流量，若测试机上混跑其他服务，需要人工排除误报
- 默认只生成报告，不阻断发版
