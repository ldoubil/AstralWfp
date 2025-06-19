# 测试过滤器效果的PowerShell脚本
Write-Host "测试网络连接到 124.71.134.95..." -ForegroundColor Yellow

# 测试TCP连接
Write-Host "测试TCP连接..." -ForegroundColor Cyan
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.ConnectTimeout = 5000
    $result = $tcp.BeginConnect("124.71.134.95", 80, $null, $null)
    $success = $result.AsyncWaitHandle.WaitOne(5000, $false)
    
    if ($success) {
        Write-Host "✅ TCP连接成功 - 过滤器可能未生效" -ForegroundColor Red
        $tcp.EndConnect($result)
    } else {
        Write-Host "❌ TCP连接失败 - 过滤器可能已生效" -ForegroundColor Green
    }
    
    $tcp.Close()
} catch {
    Write-Host "❌ TCP连接异常: $($_.Exception.Message) - 过滤器可能已生效" -ForegroundColor Green
}

# 测试HTTP请求
Write-Host "`n测试HTTP请求..." -ForegroundColor Cyan
try {
    $response = Invoke-WebRequest -Uri "http://124.71.134.95" -TimeoutSec 10 -UseBasicParsing
    Write-Host "✅ HTTP请求成功 - 过滤器可能未生效" -ForegroundColor Red
} catch {
    Write-Host "❌ HTTP请求失败: $($_.Exception.Message) - 过滤器可能已生效" -ForegroundColor Green
}

# 测试ping
Write-Host "`n测试PING..." -ForegroundColor Cyan
$ping = Test-Connection -ComputerName "124.71.134.95" -Count 2 -Quiet
if ($ping) {
    Write-Host "✅ PING成功 - ICMP未被过滤" -ForegroundColor Yellow
} else {
    Write-Host "❌ PING失败 - 网络可能不可达" -ForegroundColor Yellow
}

Write-Host "`n测试完成。" -ForegroundColor Yellow
