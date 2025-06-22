#![cfg(test)]

use crate::{
    WfpController,
    FilterRule,
    Direction,
    FilterAction,
    Protocol,
    IpNetwork
};
use crate::nt::get_nt_path;
use std::net::IpAddr;
use windows::core::Result;

/// 测试 WFP 控制器的创建和初始化
#[test]
fn test_controller_creation() -> Result<()> {
    let mut controller = WfpController::new()?;
    controller.initialize()?;
    controller.cleanup()?;
    Ok(())
}

/// 测试 IP 网段解析
#[test]
fn test_ip_network_parsing() {
    // 测试有效的 IPv4 CIDR
    let network = IpNetwork::from_cidr("192.168.0.0/24");
    assert!(network.is_ok());
    let network = network.unwrap();
    assert_eq!(network.prefix_len, 24);
    
    // 测试有效的 IPv6 CIDR
    let network = IpNetwork::from_cidr("2001:db8::/32");
    assert!(network.is_ok());
    let network = network.unwrap();
    assert_eq!(network.prefix_len, 32);
    
    // 测试无效的 CIDR
    assert!(IpNetwork::from_cidr("invalid").is_err());
    assert!(IpNetwork::from_cidr("192.168.0.0").is_err());
    assert!(IpNetwork::from_cidr("192.168.0.0/33").is_err());
}

/// 测试过滤规则构建器
#[test]
fn test_filter_rule_builder() {
    let rule = FilterRule::new("Test_Rule")
        .app_path("C:\\test\\app.exe")
        .local_port(80)
        .remote_port(443)
        .protocol(Protocol::Tcp)
        .direction(Direction::Inbound)
        .action(FilterAction::Block);
    
    assert_eq!(rule.name, "Test_Rule");
    assert_eq!(rule.app_path, Some("C:\\test\\app.exe".to_string()));
    assert_eq!(rule.local_port, Some(80));
    assert_eq!(rule.remote_port, Some(443));
    assert!(matches!(rule.protocol, Some(Protocol::Tcp)));
    assert!(matches!(rule.direction, Direction::Inbound));
    assert!(matches!(rule.action, FilterAction::Block));
}

/// 测试完整的过滤规则添加流程
#[test]
fn test_add_filter_rules() -> Result<()> {
    let mut controller = WfpController::new()?;
    controller.initialize()?;
    
    // 创建多个测试规则
    let rules = vec![
        // 阻止特定应用程序的网络访问
        FilterRule::new("Block_App")
            .app_path("C:\\test\\app.exe")
            .action(FilterAction::Block),
            
        // 阻止特定 IP 地址
        FilterRule::new("Block_IP")
            .remote_ip(IpAddr::V4("1.2.3.4".parse().unwrap()))
            .action(FilterAction::Block),
            
        // 控制特定端口的流量
        FilterRule::new("Block_Port")
            .local_port(80)
            .protocol(Protocol::Tcp)
            .action(FilterAction::Block),
    ];
    
    // 添加规则
    controller.add_advanced_filters(&rules)?;
    
    // 清理
    controller.cleanup()?;
    Ok(())
}

/// 测试 CIDR 规则
#[test]
fn test_cidr_rules() -> Result<()> {
    let mut controller = WfpController::new()?;
    controller.initialize()?;
    
    let rule = FilterRule::new("Block_Network")
        .remote_ip_cidr("192.168.0.0/16")?
        .action(FilterAction::Block);
    
    controller.add_advanced_filters(&[rule])?;
    controller.cleanup()?;
    Ok(())
}

/// 测试双向流量规则
#[test]
fn test_bidirectional_rules() -> Result<()> {
    let mut controller = WfpController::new()?;
    controller.initialize()?;
    
    let rule = FilterRule::new("Bidirectional_Block")
        .remote_port(80)
        .protocol(Protocol::Tcp)
        .direction(Direction::Both)
        .action(FilterAction::Block);
    
    controller.add_advanced_filters(&[rule])?;
    controller.cleanup()?;
    Ok(())
}

/// 集成测试：复杂规则组合
#[test]
fn test_complex_rule_combination() -> Result<()> {
    let mut controller = WfpController::new()?;
    controller.initialize()?;
    
    let rules = vec![
        // HTTP 阻止规则
        FilterRule::new("Block_HTTP")
            .local_port(80)
            .protocol(Protocol::Tcp)
            .direction(Direction::Both)
            .action(FilterAction::Block),
            
        // 特定网段允许规则
        FilterRule::new("Allow_Internal")
            .remote_ip_cidr("10.0.0.0/8")?
            .action(FilterAction::Allow),
            
        // 特定应用程序规则
        FilterRule::new("App_Control")
            .app_path("C:\\test\\app.exe")
            .remote_port(443)
            .protocol(Protocol::Tcp)
            .action(FilterAction::Allow),
    ];
    
    controller.add_advanced_filters(&rules)?;
    controller.cleanup()?;
    Ok(())
}

/// 测试NT路径转换功能
#[test]
fn test_nt_path_conversion() {
    // 测试常见的Windows路径转换
    let test_cases = vec![
        ("C:\\Windows\\System32\\notepad.exe", true),
        ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", true),
        ("D:\\test\\app.exe", true),
        ("invalid_path", false),
    ];
    
    for (path, should_succeed) in test_cases {
        let result = get_nt_path(path);
        match result {
            Some(nt_path) => {
                assert!(should_succeed, "路径 {} 应该转换失败，但得到了: {}", path, nt_path);
                println!("✓ {} -> {}", path, nt_path);
                // 验证NT路径格式
                assert!(nt_path.starts_with("\\device\\") || nt_path.starts_with("\\??\\"));
            },
            None => {
                assert!(!should_succeed, "路径 {} 应该转换成功，但失败了", path);
                println!("✗ {} -> 转换失败", path);
            }
        }
    }
}

/// 测试带NT路径转换的过滤规则
#[test]
fn test_filter_rule_with_nt_path() -> Result<()> {
    let mut controller = WfpController::new()?;
    controller.initialize()?;
    
    // 测试应用程序路径转换
    let app_path = "C:\\Windows\\System32\\notepad.exe";
    let nt_path = match get_nt_path(app_path) {
        Some(path) => path,
        None => {
            println!("⚠️ 跳过测试：无法转换路径 {}", app_path);
            return Ok(());
        }
    };
    
    let rule = FilterRule::new("NT路径测试")
        .app_path(&nt_path)
        .remote_ip("8.8.8.8")
        .action(FilterAction::Block);
    
    controller.add_advanced_filters(&[rule])?;
    controller.cleanup()?;
    Ok(())
}
