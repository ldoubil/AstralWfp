# AstralWfp - Windows Filtering Platform 控制器

一个基于 Rust 的 Windows Filtering Platform (WFP) 控制器，提供强大的网络流量过滤功能。

## 功能特性

### 🔧 基础功能
- ✅ WFP 引擎初始化和管理
- ✅ 应用程序级别的网络过滤
- ✅ IPv4 和 IPv6 支持
- ✅ TCP 和 UDP 协议支持
- ✅ 入站和出站流量控制

### 🚀 高级功能
- ✅ **IP 地址过滤**: 支持精确的本地和远程 IP 地址过滤
- ✅ **端口过滤**: 支持本地和远程端口过滤
- ✅ **协议过滤**: TCP/UDP 协议选择
- ✅ **方向控制**: 入站/出站流量控制
- ✅ **动作设置**: 允许/阻止操作
- ✅ **应用程序路径**: 精确的应用程序级别控制

## 快速开始

### 基础使用

```rust
use windows::core::*;
use astral_wfp::*;

fn main() -> Result<()> {
    // 创建控制器
    let mut wfp_controller = WfpController::new()?;
    
    // 初始化 WFP 引擎
    wfp_controller.initialize()?;
    
    // 添加基础过滤器
    let app_path = r"C:\Windows\System32\notepad.exe";
    wfp_controller.add_filters(app_path)?;
    
    // 运行控制器
    wfp_controller.run()?;
    
    // 清理资源
    wfp_controller.cleanup()?;
    
    Ok(())
}
```

### 高级过滤规则

```rust
use astral_wfp::*;
use std::net::{IpAddr, Ipv4Addr};

// 创建高级过滤规则
let rules = vec![
    // 阻止访问特定 IP
    FilterRule::new("阻止百度")
        .app_path(r"C:\Windows\System32\notepad.exe")
        .remote_ip(IpAddr::V4(Ipv4Addr::new(220, 181, 38, 148)))
        .action(FilterAction::Block),
    
    // 阻止 HTTP 流量
    FilterRule::new("阻止HTTP")
        .app_path(r"C:\Windows\System32\notepad.exe")
        .remote_port(80)
        .protocol(Protocol::Tcp)
        .direction(Direction::Outbound)
        .action(FilterAction::Block),
    
    // 允许本地网络
    FilterRule::new("允许本地网络")
        .app_path(r"C:\Windows\System32\notepad.exe")
        .remote_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)))
        .action(FilterAction::Allow),
];

// 应用高级规则
wfp_controller.add_advanced_filters(&rules)?;
```

## API 参考

### FilterRule 构建器

`FilterRule` 提供了流畅的 API 来构建复杂的过滤规则：

```rust
FilterRule::new("规则名称")
    .app_path("应用程序路径")           // 目标应用程序
    .local_ip(IpAddr)                  // 本地 IP 地址
    .remote_ip(IpAddr)                 // 远程 IP 地址
    .local_port(u16)                   // 本地端口
    .remote_port(u16)                  // 远程端口
    .protocol(Protocol)                // TCP/UDP
    .direction(Direction)              // Inbound/Outbound
    .action(FilterAction)              // Allow/Block
```

### 枚举类型

```rust
// 协议类型
pub enum Protocol {
    Tcp,
    Udp,
}

// 流量方向
pub enum Direction {
    Inbound,   // 入站
    Outbound,  // 出站
}

// 过滤动作
pub enum FilterAction {
    Allow,     // 允许
    Block,     // 阻止
}
```

## 示例

### 运行基础示例

```bash
cargo run
```

### 运行高级过滤示例

```bash
cargo run --example advanced_filtering
```

## 常见用例

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
        .remote_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)))
        .action(FilterAction::Allow),
];
```

### 2. 端口访问控制
```rust
// 阻止特定端口访问
let port_rules = vec![
    FilterRule::new("阻止HTTP")
        .remote_port(80)
        .action(FilterAction::Block),
    
    FilterRule::new("阻止HTTPS")
        .remote_port(443)
        .action(FilterAction::Block),
];
```

### 3. 应用程序隔离
```rust
// 完全隔离特定应用程序的网络访问
let isolation_rules = vec![
    FilterRule::new("完全网络隔离")
        .app_path(r"C:\SuspiciousApp\app.exe")
        .direction(Direction::Outbound)
        .action(FilterAction::Block),
    
    FilterRule::new("阻止入站连接")
        .app_path(r"C:\SuspiciousApp\app.exe")
        .direction(Direction::Inbound)
        .action(FilterAction::Block),
];
```

## 系统要求

- Windows 10/11 或 Windows Server 2016+
- 管理员权限（WFP 需要管理员权限）
- Rust 1.70+

## 注意事项

⚠️ **重要提醒**:
- 本程序需要管理员权限运行
- 过滤规则会影响系统网络行为，请谨慎使用
- 建议在测试环境中先验证规则效果
- 程序退出时会自动清理所有过滤器

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！