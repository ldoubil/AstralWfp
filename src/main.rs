mod astral_wfp;

use windows::core::*;
use astral_wfp::WfpController;



fn main() -> Result<()> {
    use astral_wfp::*;
    use std::net::{IpAddr, Ipv4Addr};

    // 创建WFP控制器实例
    let mut wfp_controller = WfpController::new()?;

    // 初始化WFP引擎
    wfp_controller.initialize()?;

    // 设置要控制的应用程序路径
    let app_path = r"\device\harddiskvolume3\users\kevin\appdata\roaming\.minecraft\runtime\java-runtime-delta\bin\javaw.exe";
    println!("🎯 目标应用程序: {}", app_path);


    println!("\n🔧 添加高级过滤器规则...");
    let advanced_rules = vec![
 
        
        // 阻止10.126.126.1/12网段的出站连接
        FilterRule::new("阻止10.126.126.1/12出站TCP")
            .app_path(app_path)
            .local_ip_cidr("10.126.126.1/12").unwrap()
            .protocol(Protocol::Tcp)
            .direction(Direction::Outbound)
            .action(FilterAction::Block),
        
        FilterRule::new("阻止10.126.126.1/12出站UDP")
            .app_path(app_path)
            .local_ip_cidr("10.126.126.1/12").unwrap()
            .protocol(Protocol::Udp)
            .direction(Direction::Outbound)
            .action(FilterAction::Block),
        
        // 阻止来自10.126.126.1/12网段的入站连接
        FilterRule::new("阻止10.126.126.1/12入站TCP")
            .app_path(app_path)
            .local_ip_cidr("10.126.126.1/12").unwrap()
            .protocol(Protocol::Tcp)
            .direction(Direction::Inbound)
            .action(FilterAction::Block),
        
        FilterRule::new("阻止10.126.126.1/12入站UDP")
            .app_path(app_path)
            .local_ip_cidr("10.126.126.1/12").unwrap()
            .protocol(Protocol::Udp)
            .direction(Direction::Inbound)
            .action(FilterAction::Block),
    ];
    
    wfp_controller.add_advanced_filters(&advanced_rules)?;

    // 运行控制器
    wfp_controller.run()?;

    // 清理资源
    wfp_controller.cleanup()?;

    println!("\n✅ 程序已安全退出");
    Ok(())
}
