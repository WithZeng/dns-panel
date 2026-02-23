# =============================================================================
# dns-panel 一键更新部署脚本（Windows PowerShell）
# 功能：备份数据库 → 拉取最新代码 → 重建镜像 → 重启容器 → 健康检查
# 用法：powershell -ExecutionPolicy Bypass -File .\update.ps1 [-SkipBackup] [-SkipPull]
# =============================================================================
param(
    [switch]$SkipBackup,
    [switch]$SkipPull
)
$ErrorActionPreference = "Stop"

$ServiceName = "dns-panel"
$BackupDir   = "instance\backups"
$DbCandidates = @("instance\ecs_monitor.db", "ecs_monitor.db")

function Step($msg)  { Write-Host "`n========== $msg ==========" -ForegroundColor Magenta }
function Info($msg)  { Write-Host "[信息] $msg"  -ForegroundColor Cyan }
function Ok($msg)    { Write-Host "[完成] $msg"  -ForegroundColor Green }
function Warn($msg)  { Write-Host "[警告] $msg"  -ForegroundColor Yellow }
function Fail($msg)  { Write-Host "[错误] $msg"  -ForegroundColor Red; exit 1 }

# ── 确认在项目根目录 ─────────────────────────────────────────────────────────
if (-not (Test-Path "docker-compose.yml")) {
    Fail "请在项目根目录运行此脚本（找不到 docker-compose.yml）。"
}

# ── 读取面板端口 ─────────────────────────────────────────────────────────────
function Get-PanelPort {
    $line = Get-Content ".env" -ErrorAction SilentlyContinue |
            Where-Object { $_ -match '^PANEL_PORT=' } |
            Select-Object -First 1
    if ($line) { return ($line -split '=', 2)[1].Trim() }
    return "5000"
}

# ─────────────────────────────────────────────────────────────────────────────
Step "第 1 步：备份数据库"
# ─────────────────────────────────────────────────────────────────────────────
if ($SkipBackup) {
    Info "已跳过备份（-SkipBackup）。"
} else {
    $dbFile = $null
    foreach ($c in $DbCandidates) {
        if (Test-Path $c) { $dbFile = $c; break }
    }

    if (-not $dbFile) {
        Warn "未找到数据库文件，跳过备份。"
    } else {
        if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir | Out-Null }
        $ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $dest = "$BackupDir\ecs_monitor_before_update_$ts.db"
        Copy-Item $dbFile $dest
        Ok "数据库已备份 → $dest"

        # 清理超过 14 天的旧备份
        Get-ChildItem $BackupDir -Filter "*.db" |
            Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-14) } |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Info "已清理 14 天前的旧备份。"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Step "第 2 步：拉取最新代码"
# ─────────────────────────────────────────────────────────────────────────────
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
        if ($beforeHash -eq $afterHash) {
            Info "代码已是最新，无变更（$afterHash）。"
        } else {
            Ok "代码已更新：$beforeHash → $afterHash"
        }
    } else {
        Warn "当前目录不是 git 仓库或未安装 git，跳过代码拉取。"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Step "第 3 步：重建镜像并重启容器"
# ─────────────────────────────────────────────────────────────────────────────
Info "停止旧容器..."
docker compose down --remove-orphans 2>&1 | Select-Object -Last 5

Info "重建镜像..."
docker compose build --no-cache
if ($LASTEXITCODE -ne 0) { Fail "docker compose build 失败。" }

Info "启动容器..."
docker compose up -d
if ($LASTEXITCODE -ne 0) { Fail "docker compose up -d 失败。" }
Ok "容器已重启。"

# ─────────────────────────────────────────────────────────────────────────────
Step "第 4 步：健康检查"
# ─────────────────────────────────────────────────────────────────────────────
$port = Get-PanelPort
Info "等待服务就绪（端口 $port）..."
$healthy = $false
for ($i = 0; $i -lt 30; $i++) {
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:$port/health" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
        if ($r.StatusCode -eq 200) { $healthy = $true; break }
    } catch {}
    Start-Sleep -Seconds 2
}

if ($healthy) {
    Ok "健康检查通过 ✓"
} else {
    Warn "健康检查未通过，请查看日志："
    Write-Host "  docker compose logs --tail=50 $ServiceName"
}

# ─────────────────────────────────────────────────────────────────────────────
Step "更新完成"
# ─────────────────────────────────────────────────────────────────────────────
$ver = (& git rev-parse --short HEAD 2>$null) ?? "-"
Write-Host "当前版本  : $ver"
Write-Host "访问地址  : http://localhost:$port"
Write-Host "容器状态  : docker compose ps"
Write-Host "实时日志  : docker compose logs -f $ServiceName"
Write-Host "回滚提示  : 如需回滚，从 $BackupDir\ 恢复数据库并 git checkout <旧版本> 后重新运行此脚本"
