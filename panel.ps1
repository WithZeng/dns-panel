# =============================================================================
# dns-panel 统一管理脚本（Windows PowerShell）
# 用法：
#   .\panel.ps1 deploy              首次部署
#   .\panel.ps1 update              更新
#   .\panel.ps1 update -SkipBackup -SkipPull
#   .\panel.ps1 restart             重启容器
#   .\panel.ps1 stop                停止服务
#   .\panel.ps1 status              容器状态
#   .\panel.ps1 logs                实时日志
#   .\panel.ps1 backup              手动备份数据库
#   .\panel.ps1 help                帮助
# =============================================================================
param(
    [Parameter(Position = 0)]
    [string]$Action = "help",
    [switch]$SkipBackup,
    [switch]$SkipPull
)
$ErrorActionPreference = "Stop"

$ServiceName  = "dns-panel"
$BackupDir    = "instance\backups"
$DbCandidates = @("instance\ecs_monitor.db", "ecs_monitor.db")

# ── 输出函数 ─────────────────────────────────────────────────────────────────
function Step($msg)  { Write-Host "`n========== $msg ==========" -ForegroundColor Magenta }
function Info($msg)  { Write-Host "[信息] $msg"  -ForegroundColor Cyan }
function Ok($msg)    { Write-Host "[完成] $msg"  -ForegroundColor Green }
function Warn($msg)  { Write-Host "[警告] $msg"  -ForegroundColor Yellow }
function Fail($msg)  { Write-Host "[错误] $msg"  -ForegroundColor Red; exit 1 }

# ── 通用函数 ─────────────────────────────────────────────────────────────────

function Get-PanelPort {
    $line = Get-Content ".env" -ErrorAction SilentlyContinue |
            Where-Object { $_ -match '^PANEL_PORT=' } |
            Select-Object -First 1
    if ($line) { return ($line -split '=', 2)[1].Trim() }
    return "5000"
}

function New-RandomHexSecret([int]$bytesLength = 32) {
    $bytes = New-Object byte[] $bytesLength
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    return ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
}

function Wait-HealthCheck([string]$port) {
    Info "等待服务就绪（端口 $port）..."
    $healthy = $false
    for ($i = 0; $i -lt 30; $i++) {
        try {
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$port/health" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
            if ($r.StatusCode -eq 200) { $healthy = $true; break }
        } catch {}
        Start-Sleep -Seconds 2
    }
    if ($healthy) { Ok "健康检查通过 ✓" }
    else { Warn "健康检查未通过，查看日志: docker compose logs --tail=50 $ServiceName" }
}

function Invoke-BackupDb {
    $dbFile = $null
    foreach ($c in $DbCandidates) {
        if (Test-Path $c) { $dbFile = $c; break }
    }
    if (-not $dbFile) { Warn "未找到数据库文件，跳过备份。"; return }
    if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir | Out-Null }
    $ts   = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $dest = "$BackupDir\ecs_monitor_$ts.db"
    Copy-Item $dbFile $dest
    Ok "数据库已备份 → $dest"
    Get-ChildItem $BackupDir -Filter "*.db" |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-14) } |
        Remove-Item -Force -ErrorAction SilentlyContinue
    Info "已清理 14 天前的旧备份。"
}

# ── deploy ───────────────────────────────────────────────────────────────────

function Invoke-Deploy {
    Step "第 1 步：检查 Docker"
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Fail "未找到 docker，请先安装 Docker Desktop。"
    }
    Ok "Docker 可用"

    Step "第 2 步：准备目录与配置"
    if (-not (Test-Path "instance")) { New-Item -ItemType Directory -Path "instance" | Out-Null }
    Ok "instance 目录已准备"

    if (-not (Test-Path ".env")) {
        $secret = New-RandomHexSecret
        @"
SECRET_KEY=$secret
TZ=Asia/Shanghai
PANEL_PORT=5000
PUBLIC_PANEL_URL=
DNS_FAILOVER_TEST_MODE=panel_local
DNS_PANEL_DISABLE_SCHEDULER=0
"@ | Set-Content -Path ".env" -Encoding UTF8
        Ok "已创建 .env"
    } else {
        Info ".env 已存在，保留现有配置"
    }

    $port = Get-PanelPort

    Step "第 3 步：检查端口"
    $listen = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
              Where-Object { $_.LocalPort -eq [int]$port }
    if ($listen) { Fail "端口 $port 已被占用，请修改 .env 中 PANEL_PORT。" }
    Ok "端口 $port 可用"

    Step "第 4 步：开放防火墙（IPv4 + IPv6）"
    $ruleName = "dns-panel-$port"
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existing) {
        Info "防火墙规则 '$ruleName' 已存在，跳过"
    } else {
        try {
            New-NetFirewallRule `
                -DisplayName $ruleName `
                -Direction Inbound -Protocol TCP `
                -LocalPort ([int]$port) -Action Allow `
                -AddressFamily Any -Profile Any `
                -Description "dns-panel auto rule $port (IPv4+IPv6)" | Out-Null
            Ok "防火墙已放行 TCP $port（IPv4 + IPv6）"
        } catch {
            Warn "防火墙规则创建失败（可能需要管理员权限），请手动放行端口 $port"
        }
    }

    Step "第 5 步：构建并启动容器"
    docker compose up -d --build
    Ok "容器启动命令已执行"

    Step "第 6 步：健康检查"
    Wait-HealthCheck $port

    Step "部署完成"
    Write-Host "访问地址 : http://localhost:$port"
    Write-Host "容器状态 : docker compose ps"
    Write-Host "查看日志 : docker compose logs -f $ServiceName"
    Write-Host "更新     : .\panel.ps1 update"
    Write-Host "初始密码 : Get-Content instance\initial_admin_credentials.txt"
}

# ── update ───────────────────────────────────────────────────────────────────

function Invoke-Update {
    if (-not (Test-Path "docker-compose.yml")) {
        Fail "找不到 docker-compose.yml，请在项目根目录运行。"
    }

    Step "第 1 步：备份数据库"
    if ($SkipBackup) { Info "已跳过备份（-SkipBackup）。" }
    else { Invoke-BackupDb }

    Step "第 2 步：拉取最新代码"
    if ($SkipPull) {
        Info "已跳过 git pull（-SkipPull）。"
    } else {
        $gitCmd = Get-Command git -ErrorAction SilentlyContinue
        $isRepo = & git rev-parse --is-inside-work-tree 2>$null
        if ($gitCmd -and ($isRepo -eq "true")) {
            $beforeHash = (& git rev-parse --short HEAD 2>$null) ?? "unknown"
            Info "当前版本：$beforeHash"
            & git pull --rebase --autostash
            $afterHash = (& git rev-parse --short HEAD 2>$null) ?? "unknown"
            if ($beforeHash -eq $afterHash) { Info "代码已是最新（$afterHash）。" }
            else { Ok "代码已更新：$beforeHash → $afterHash" }
        } else {
            Warn "不是 git 仓库或未安装 git，跳过。"
        }
    }

    Step "第 3 步：重建镜像并重启"
    Info "停止旧容器..."
    docker compose down --remove-orphans 2>&1 | Select-Object -Last 5
    Info "重建镜像..."
    docker compose build --no-cache
    if ($LASTEXITCODE -ne 0) { Fail "docker compose build 失败。" }
    docker compose up -d
    if ($LASTEXITCODE -ne 0) { Fail "docker compose up -d 失败。" }
    Ok "容器已重启。"

    Step "第 4 步：健康检查"
    $port = Get-PanelPort
    Wait-HealthCheck $port

    Step "更新完成"
    $ver = (& git rev-parse --short HEAD 2>$null) ?? "-"
    Write-Host "版本     : $ver"
    Write-Host "访问地址 : http://localhost:$port"
    Write-Host "回滚     : 从 $BackupDir\ 恢复数据库 → git checkout <版本> → .\panel.ps1 update -SkipPull"
}

# ── 快捷命令 ─────────────────────────────────────────────────────────────────

function Invoke-Restart {
    Info "重启容器..."
    docker compose restart
    Ok "容器已重启。"
    Wait-HealthCheck (Get-PanelPort)
}

function Invoke-Stop {
    Info "停止服务..."
    docker compose down
    Ok "服务已停止。"
}

function Invoke-Status {
    docker compose ps
}

function Invoke-Logs {
    docker compose logs -f $ServiceName
}

function Show-Help {
    Write-Host @"

dns-panel 管理脚本 (Windows)

用法：.\panel.ps1 <命令> [选项]

命令:
  deploy                首次部署（检查环境→生成配置→构建容器→开放防火墙）
  update [选项]         更新部署（备份DB→拉取代码→重建镜像→重启→健康检查）
      -SkipBackup         跳过数据库备份
      -SkipPull           跳过 git pull
  restart               重启容器
  stop                  停止服务
  status                查看容器状态
  logs                  实时查看日志
  backup                手动备份数据库
  help                  显示此帮助信息

示例：
  .\panel.ps1 deploy
  .\panel.ps1 update
  .\panel.ps1 update -SkipBackup
  .\panel.ps1 logs
"@
}

# ── 入口 ─────────────────────────────────────────────────────────────────────

switch ($Action.ToLower()) {
    "deploy"  { Invoke-Deploy }
    "update"  { Invoke-Update }
    "restart" { Invoke-Restart }
    "stop"    { Invoke-Stop }
    "status"  { Invoke-Status }
    "logs"    { Invoke-Logs }
    "backup"  { Invoke-BackupDb }
    "help"    { Show-Help }
    default   { Warn "未知命令: $Action"; Show-Help }
}
