# AstralWFP - Windows 网络流量控制器

一个基于 Windows Filtering Platform (WFP) 的高级网络流量控制工具，支持应用程序级别的网络访问控制、协议拦截和端口管理。

## 🚀 主要功能

### 1. 应用程序级网络控制
- 基于应用程序路径的精确流量控制
- 支持 NT 路径转换，确保准确的应用程序识别
- 可阻止或允许特定应用程序的网络访问

### 2. 协议拦截功能
- **TCP 协议拦截**: 支持 HTTP、HTTPS、FTP、SSH 等协议
- **UDP 协议拦截**: 支持 DNS、DHCP、NTP、SNMP 等协议  
- **ICMP 协议拦截**: 支持 ping 等网络诊断工具
- **端口范围拦截**: 支持批量端口控制，如游戏端口、动态端口等

### 3. 高级过滤条件
- IP 地址/网段过滤（支持 CIDR 格式）
- 端口过滤（单个端口或端口范围）
- 流量方向控制（入站/出站/双向）
- 协议类型过滤
- 组合条件支持

### 4. 用户界面
- 现代化的 GUI 界面
- 实时规则管理
- 状态监控和错误提示
- 支持中文显示

## 📋 支持的协议和端口

| 协议 | 端口 | 用途 | 支持状态 |
|------|------|------|----------|
| HTTP | 80 | Web服务 | ✅ |
| HTTPS | 443 | 安全Web服务 | ✅ |
| FTP | 21 | 文件传输 | ✅ |
| SSH | 22 | 安全Shell | ✅ |
| Telnet | 23 | 远程登录 | ✅ |
| SMTP | 25 | 邮件发送 | ✅ |
| DNS | 53 | 域名解析 | ✅ |
| DHCP | 67/68 | 动态主机配置 | ✅ |
| NTP | 123 | 网络时间同步 | ✅ |
| SNMP | 161/162 | 网络管理 | ✅ |
| ICMP | - | 网络诊断 | ✅ |

## 🛠️ 安装和使用

### 系统要求
- Windows 10/11 或 Windows Server 2016+
- 管理员权限（WFP 需要管理员权限）
- Rust 1.70+

### 编译和运行

```bash
# 克隆项目
git clone <repository-url>
cd AstralWfp

# 编译项目
cargo build --release

# 运行GUI模式（默认）
cargo run

# 运行命令行模式
cargo run -- --cli

# 测试NT路径转换
cargo run -- --test-nt

# 测试协议拦截功能
cargo run -- --test-protocol

# 测试端口范围拦截
cargo run -- --test-port-ranges
```

## 📖 使用示例

### 基础用法

```rust
use astral_wfp::*;

// 创建WFP控制器
let mut controller = WfpController::new()?;
controller.initialize()?;

// 创建过滤规则
let rules = vec![
    // 阻止特定应用程序访问互联网
    FilterRule::new("阻止Chrome")
        .app_path("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")
        .direction(Direction::Outbound)
        .action(FilterAction::Block),
        
    // 阻止HTTP流量
    FilterRule::new("阻止HTTP")
        .remote_port(80)
        .protocol(Protocol::Tcp)
        .action(FilterAction::Block),
        
    // 阻止DNS查询
    FilterRule::new("阻止DNS")
        .remote_port(53)
        .protocol(Protocol::Udp)
        .action(FilterAction::Block),
        
    // 阻止ICMP (ping)
    FilterRule::new("阻止ICMP")
        .protocol(Protocol::Icmp)
        .direction(Direction::Both)
        .action(FilterAction::Block),
];

// 应用规则
controller.add_advanced_filters(&rules)?;
```

### 高级用法

```rust
// 端口范围拦截
let port_range_rules = vec![
    // 阻止Web服务端口范围
    FilterRule::new("阻止Web服务")
        .remote_port_range(80, 89)
        .protocol(Protocol::Tcp)
        .action(FilterAction::Block),
        
    // 阻止游戏端口范围
    FilterRule::new("阻止游戏")
        .remote_port_range(27015, 27020)
        .protocol(Protocol::Udp)
        .action(FilterAction::Block),
        
    // 阻止动态端口范围
    FilterRule::new("阻止动态端口")
        .remote_port_range(49152, 65535)
        .action(FilterAction::Block),
];

// 网段过滤
let network_rules = vec![
    // 阻止访问特定网段
    FilterRule::new("阻止恶意网段")
        .remote_ip("192.168.100.0/24")
        .action(FilterAction::Block),
        
    // 只允许本地网络
    FilterRule::new("允许本地网络")
        .remote_ip("192.168.1.0/24")
        .action(FilterAction::Allow),
];
```

## 🔧 API 参考

### FilterRule 构建器

```rust
FilterRule::new("规则名称")
    .app_path("应用程序路径")           // 目标应用程序
    .local_ip("本地IP")                // 本地 IP 地址
    .remote_ip("远程IP")               // 远程 IP 地址
    .local_port(u16)                   // 本地端口
    .remote_port(u16)                  // 远程端口
    .local_port_range(u16, u16)        // 本地端口范围
    .remote_port_range(u16, u16)       // 远程端口范围
    .protocol(Protocol)                // 协议类型
    .direction(Direction)              // 流量方向
    .action(FilterAction)              // 过滤动作
```

### 枚举类型

```rust
// 协议类型
pub enum Protocol {
    Tcp,    // TCP协议
    Udp,    // UDP协议
    Icmp,   // ICMP协议
}

// 流量方向
pub enum Direction {
    Inbound,   // 入站流量
    Outbound,  // 出站流量
    Both,      // 双向流量
}

// 过滤动作
pub enum FilterAction {
    Allow,     // 允许
    Block,     // 阻止
}
```

## 🎯 常见用例

### 1. 网络安全控制
```rust
// 阻止应用程序访问互联网，只允许本地网络
let security_rules = vec![
    FilterRule::new("阻止所有出站")
        .app_path(app_path)
        .direction(Direction::Outbound)
        .action(FilterAction::Block),
    
    FilterRule::new("允许本地网络")
        .app_path(app_path)
        .remote_ip("192.168.0.0/16")
        .action(FilterAction::Allow),
];
```

### 2. 协议访问控制
```rust
// 阻止特定协议访问
let protocol_rules = vec![
    FilterRule::new("阻止HTTP")
        .remote_port(80)
        .protocol(Protocol::Tcp)
        .action(FilterAction::Block),
    
    FilterRule::new("阻止HTTPS")
        .remote_port(443)
        .protocol(Protocol::Tcp)
        .action(FilterAction::Block),
    
    FilterRule::new("阻止DNS")
        .remote_port(53)
        .protocol(Protocol::Udp)
        .action(FilterAction::Block),
];
```

### 3. 应用程序隔离
```rust
// 完全隔离特定应用程序的网络访问
let isolation_rules = vec![
    FilterRule::new("完全网络隔离")
        .app_path("C:\\SuspiciousApp\\app.exe")
        .direction(Direction::Both)
        .action(FilterAction::Block),
];
```

### 4. 端口范围管理
```rust
// 批量管理端口访问
let port_rules = vec![
    FilterRule::new("阻止常用服务端口")
        .remote_port_range(20, 25)
        .protocol(Protocol::Tcp)
        .action(FilterAction::Block),
    
    FilterRule::new("阻止游戏端口")
        .remote_port_range(27015, 27020)
        .protocol(Protocol::Udp)
        .action(FilterAction::Block),
];
```

## ⚠️ 注意事项

- **管理员权限**: 本程序需要管理员权限运行
- **系统影响**: 过滤规则会影响系统网络行为，请谨慎使用
- **测试环境**: 建议在测试环境中先验证规则效果
- **自动清理**: 程序退出时会自动清理所有过滤器
- **规则优先级**: WFP 会根据规则权重和匹配顺序处理流量

## 🔍 故障排除

### 常见问题

1. **权限错误**: 确保以管理员身份运行程序
2. **路径转换失败**: 检查应用程序路径是否正确
3. **规则添加失败**: 检查过滤条件组合是否有效
4. **网络连接异常**: 检查是否有过于严格的规则阻止了正常流量

### 调试模式

使用以下命令启用详细日志：
```bash
cargo run -- --cli
```

## 📄 许可证

MIT License

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

**AstralWFP** - 强大的 Windows 网络流量控制工具 🛡️