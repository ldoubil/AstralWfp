# Astral Windows Filtering Platform (WFP) 使用指南

## 简介

Astral WFP 是一个用于 Windows 平台的高级网络流量过滤管理模块。它提供了一个简单而强大的接口来管理 Windows 防火墙规则和网络流量过滤。

## 主要特性

- 支持 IPv4 和 IPv6 地址过滤
- 支持应用程序级别的网络控制
- 支持端口和协议过滤
- 支持入站/出站流量控制
- 支持 CIDR 格式的网段过滤
- 简单直观的 API 设计

## 快速开始

### 基本使用示例

```rust
use astral_wfp::{WfpController, FilterRule, Direction, FilterAction, Protocol};
use std::net::IpAddr;

fn main() -> windows::core::Result<()> {
    // 创建并初始化 WFP 控制器
    let mut controller = WfpController::new()?;
    controller.initialize()?;

    // 创建一个简单的过滤规则
    let rule = FilterRule::new("Block_Example")
        .direction(Direction::Both)
        .action(FilterAction::Block);

    // 添加规则
    controller.add_advanced_filters(&[rule])?;

    // 运行控制器（等待用户输入）
    controller.run()?;

    // 清理资源
    controller.cleanup()?;
    
    Ok(())
}
```

## 详细 API 说明

### FilterRule 结构体

`FilterRule` 是创建过滤规则的主要结构体，提供了流畅的构建器模式 API。

#### 基本属性

- `name`: String - 规则名称
- `app_path`: Option<String> - 应用程序路径
- `local_ip`: Option<IpAddr> - 本地 IP 地址
- `remote_ip`: Option<IpAddr> - 远程 IP 地址
- `local_ip_network`: Option<IpNetwork> - 本地 IP 网段
- `remote_ip_network`: Option<IpNetwork> - 远程 IP 网段
- `local_port`: Option<u16> - 本地端口
- `remote_port`: Option<u16> - 远程端口
- `protocol`: Option<Protocol> - 协议类型
- `direction`: Direction - 流量方向
- `action`: FilterAction - 过滤动作

#### 构建方法

```rust
// 创建新规则
let rule = FilterRule::new("规则名称");

// 设置应用程序路径
rule.app_path("C:\\Program Files\\App\\app.exe");

// 设置 IP 地址
rule.local_ip(IpAddr::V4("192.168.1.1".parse().unwrap()));
rule.remote_ip(IpAddr::V4("8.8.8.8".parse().unwrap()));

// 设置 CIDR 网段
rule.local_ip_cidr("192.168.0.0/24")?;
rule.remote_ip_cidr("10.0.0.0/8")?;

// 设置端口
rule.local_port(80);
rule.remote_port(443);

// 设置协议
rule.protocol(Protocol::Tcp);

// 设置方向
rule.direction(Direction::Inbound);

// 设置动作
rule.action(FilterAction::Block);
```

### Direction 枚举

控制流量方向：

- `Inbound` - 入站流量
- `Outbound` - 出站流量
- `Both` - 双向流量

### Protocol 枚举

支持的协议类型：

- `Tcp` - TCP 协议
- `Udp` - UDP 协议
- `Icmp` - ICMP 协议

### FilterAction 枚举

过滤动作：

- `Allow` - 允许流量通过
- `Block` - 阻止流量

### IpNetwork 结构体

用于表示 CIDR 格式的网段：

```rust
// 从 CIDR 字符串创建
let network = IpNetwork::from_cidr("192.168.0.0/24")?;

// 直接创建
let network = IpNetwork::new(
    IpAddr::V4("192.168.0.0".parse().unwrap()),
    24
);
```

## 常见使用场景

### 1. 阻止特定应用程序的网络访问

```rust
let rule = FilterRule::new("Block_App")
    .app_path("C:\\Program Files\\App\\app.exe")
    .action(FilterAction::Block);
```

### 2. 限制特定 IP 地址的访问

```rust
let rule = FilterRule::new("Block_IP")
    .remote_ip(IpAddr::V4("1.2.3.4".parse().unwrap()))
    .action(FilterAction::Block);
```

### 3. 控制特定端口的流量

```rust
let rule = FilterRule::new("Block_Port")
    .local_port(80)
    .protocol(Protocol::Tcp)
    .action(FilterAction::Block);
```

### 4. 阻止特定网段的访问

```rust
let rule = FilterRule::new("Block_Network")
    .remote_ip_cidr("192.168.0.0/16")?
    .action(FilterAction::Block);
```

## 注意事项

1. 需要管理员权限运行
2. 规则按添加顺序生效
3. 清理时会自动移除所有添加的规则
4. 支持 IPv4 和 IPv6

## 错误处理

所有可能失败的操作都返回 `windows::core::Result<T>`，建议适当处理错误：

```rust
fn main() {
    match run_wfp() {
        Ok(_) => println!("成功完成"),
        Err(e) => eprintln!("发生错误: {:?}", e),
    }
}

fn run_wfp() -> windows::core::Result<()> {
    let mut controller = WfpController::new()?;
    controller.initialize()?;
    // ...其他操作
    Ok(())
}
```
