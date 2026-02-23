$ErrorActionPreference = "Stop"

function Fail($msg) {
    Write-Host "[错误] $msg" -ForegroundColor Red
    exit 1
}

function Info($msg) {
    Write-Host "[信息] $msg" -ForegroundColor Cyan
}

function Ok($msg) {
    Write-Host "[完成] $msg" -ForegroundColor Green
}

function Test-DockerInstalled {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Fail "未找到 docker，请先安装 Docker Desktop。"
    }
    $null = docker version | Out-Null
}

function New-RandomHexSecret([int]$bytesLength = 32) {
    $bytes = New-Object byte[] $bytesLength
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    return ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
}

Write-Host "========== 第 1 步：检查 Docker =========="
Test-DockerInstalled
Ok "Docker 可用"

Write-Host "`n========== 第 2 步：准备目录与配置 =========="
if (-not (Test-Path "instance")) {
    New-Item -ItemType Directory -Path "instance" | Out-Null
}
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

$port = (Get-Content .env | Where-Object { $_ -match '^PANEL_PORT=' } | Select-Object -First 1)
if (-not $port) { $port = 'PANEL_PORT=5000' }
$port = ($port -split '=',2)[1].Trim()

Write-Host "`n========== 第 3 步：检查端口 =========="
$listen = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq [int]$port }
if ($listen) {
    Fail "端口 $port 已被占用，请修改 .env 中 PANEL_PORT。"
}
Ok "端口 $port 可用"

Write-Host "`n========== 第 3.5 步：开放防火墙（IPv4 + IPv6）=========="
$ruleName = "dns-panel-$port"
$existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if ($existing) {
    Info "Windows 防火墙规则 '$ruleName' 已存在，跳过创建"
} else {
    try {
        New-NetFirewallRule `
            -DisplayName $ruleName `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort ([int]$port) `
            -Action Allow `
            -AddressFamily Any `
            -Profile Any `
            -Description "dns-panel auto-created rule for port $port (IPv4+IPv6)" | Out-Null
        Ok "Windows 防火墙已放行 TCP $port（IPv4 + IPv6）"
    } catch {
        Write-Host "[警告] 防火墙规则创建失败（可能权限不足），请以管理员身份运行或手动放行端口 $port`n$_" -ForegroundColor Yellow
    }
}

Write-Host "`n========== 第 4 步：启动容器 =========="
docker compose up -d --build
Ok "容器启动命令已执行"

Write-Host "`n========== 第 5 步：健康检查 =========="
$healthy = $false
for ($i = 0; $i -lt 20; $i++) {
    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$port/health" -UseBasicParsing -TimeoutSec 3
        if ($resp.StatusCode -eq 200) {
            $healthy = $true
            break
        }
    } catch {}
    Start-Sleep -Seconds 2
}
if ($healthy) {
    Ok "健康检查通过"
} else {
    Write-Host "[警告] 健康检查未通过，请查看日志: docker compose logs -f dns-panel" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "部署完成。"
Write-Host "访问地址: http://localhost:$port"
Write-Host "容器状态: docker compose ps"
Write-Host "查看日志: docker compose logs -f dns-panel"
Write-Host "一键更新: powershell -ExecutionPolicy Bypass -File .\update.ps1"
