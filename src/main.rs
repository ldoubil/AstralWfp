mod astral_wfp;
mod nt;
mod gui;

use windows::core::*;
use crate::nt::get_nt_path;
use crate::gui::WfpGui;
use tokio::io::{self, AsyncBufReadExt};
use eframe::NativeOptions;

fn test_nt_path_conversion() {
    println!("🧪 测试NT路径转换功能");
    println!("========================");
    
    let test_cases = vec![
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "D:\\test\\app.exe",
        "invalid_path",
    ];
    
    for path in test_cases {
        match get_nt_path(path) {
            Some(nt_path) => {
                println!("✓ {} -> {}", path, nt_path);
            },
            None => {
                println!("✗ {} -> 转换失败", path);
            }
        }
    }
    println!("========================\n");
}

fn test_app_id_remote_ip_filter() -> windows::core::Result<()> {
    use astral_wfp::*;
    let path = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
    let nt_path = match get_nt_path(path) {
        Some(path) => path,
        None => {
            eprintln!("转换失败");
            return Ok(());
        }
    };

    let nt_path: &'static str = Box::leak(nt_path.into_boxed_str());
    // 创建WFP控制器实例
    let mut wfp_controller = WfpController::new()?;

    // 初始化WFP引擎
    wfp_controller.initialize()?;

    println!("🎯 目标应用程序: {:?}", nt_path);
    println!("🔧 基于测试结果添加APP_ID + 远程IP过滤规则...");
    
    let rules: Vec<FilterRule> = vec![        // 测试1: 阻止Edge访问特定IP (双向阻止)
        FilterRule::new("阻止Edge访问124.71.134.95")
            .app_path(nt_path)
            .remote_ip("183.131.147.29")
            .direction(Direction::Outbound)  // 改回 Outbound 或使用 Both
            .action(FilterAction::Block),

    ];

    match wfp_controller.add_advanced_filters(&rules) {
        Ok(filter_ids) => {
            println!("\n✅ 过滤规则添加成功！");
            println!("共添加了 {} 个过滤器", filter_ids.len());
            println!("现在可以测试Edge是否无法访问124.71.134.95");
            println!("按Ctrl+C或回车键结束测试...");
        },
        Err(e) => {
            eprintln!("❌ 添加过滤规则失败: {:?}", e);
        }
    }

    Ok(())
}

fn test_common_protocols() -> windows::core::Result<()> {
    use astral_wfp::*;
    
    println!("🌐 常见协议拦截示例");
    println!("====================");
    
    // 创建WFP控制器实例
    let mut wfp_controller = WfpController::new()?;
    wfp_controller.initialize()?;

    // 常见协议和端口定义
    let common_protocols = vec![
        ("HTTP", 80, Protocol::Tcp),
        ("HTTPS", 443, Protocol::Tcp),
        ("FTP", 21, Protocol::Tcp),
        ("SSH", 22, Protocol::Tcp),
        ("Telnet", 23, Protocol::Tcp),
        ("SMTP", 25, Protocol::Tcp),
        ("DNS", 53, Protocol::Udp),
        ("DHCP", 67, Protocol::Udp),
        ("DHCP", 68, Protocol::Udp),
        ("NTP", 123, Protocol::Udp),
        ("SNMP", 161, Protocol::Udp),
        ("SNMP", 162, Protocol::Udp),
    ];

    println!("支持的协议和端口：");
    for (name, port, protocol) in &common_protocols {
        println!("  - {} (端口 {}, {})", name, port, protocol);
    }
    println!();

    // 创建示例规则
    let example_rules = vec![
        // 阻止HTTP流量
        FilterRule::new("阻止HTTP")
            .remote_port(80)
            .protocol(Protocol::Tcp)
            .direction(Direction::Outbound)
            .action(FilterAction::Block),
            
        // 阻止HTTPS流量
        FilterRule::new("阻止HTTPS")
            .remote_port(443)
            .protocol(Protocol::Tcp)
            .direction(Direction::Outbound)
            .action(FilterAction::Block),
            
        // 阻止DNS查询
        FilterRule::new("阻止DNS")
            .remote_port(53)
            .protocol(Protocol::Udp)
            .direction(Direction::Outbound)
            .action(FilterAction::Block),
            
        // 阻止ICMP (ping)
        FilterRule::new("阻止ICMP")
            .protocol(Protocol::Icmp)
            .direction(Direction::Both)
            .action(FilterAction::Block),
    ];

    match wfp_controller.add_advanced_filters(&example_rules) {
        Ok(filter_ids) => {
            println!("✅ 常见协议拦截规则添加成功！");
            println!("共添加了 {} 个过滤器", filter_ids.len());
            println!("现在可以测试以下拦截效果：");
            println!("  - HTTP (端口80) 被阻止");
            println!("  - HTTPS (端口443) 被阻止");
            println!("  - DNS (端口53) 被阻止");
            println!("  - ICMP (ping) 被阻止");
            println!();
            println!("💡 提示：");
            println!("  - 使用 'ping google.com' 测试ICMP拦截");
            println!("  - 使用浏览器访问HTTP网站测试HTTP拦截");
            println!("  - 使用 'nslookup google.com' 测试DNS拦截");
        },
        Err(e) => {
            eprintln!("❌ 添加协议拦截规则失败: {:?}", e);
        }
    }

    Ok(())
}

fn test_port_ranges() -> windows::core::Result<()> {
    use astral_wfp::*;
    
    println!("🎯 端口范围拦截示例");
    println!("====================");
    
    // 创建WFP控制器实例
    let mut wfp_controller = WfpController::new()?;
    wfp_controller.initialize()?;

    // 测试端口范围拦截规则
    let port_range_rules = vec![
        // 阻止常用Web服务端口范围
        FilterRule::new("阻止Web服务端口")
            .remote_port_range(80, 89)
            .protocol(Protocol::Tcp)
            .direction(Direction::Outbound)
            .action(FilterAction::Block),
            
        // 阻止常用游戏端口范围
        FilterRule::new("阻止游戏端口")
            .remote_port_range(27015, 27020)
            .protocol(Protocol::Udp)
            .direction(Direction::Both)
            .action(FilterAction::Block),
            
        // 阻止动态端口范围
        FilterRule::new("阻止动态端口")
            .remote_port_range(49152, 65535)
            .direction(Direction::Outbound)
            .action(FilterAction::Block),
    ];

    match wfp_controller.add_advanced_filters(&port_range_rules) {
        Ok(filter_ids) => {
            println!("✅ 端口范围拦截规则添加成功！");
            println!("共添加了 {} 个过滤器", filter_ids.len());
            println!("现在可以测试以下拦截效果：");
            println!("  - Web服务端口 80-89 被阻止");
            println!("  - 游戏端口 27015-27020 被阻止");
            println!("  - 动态端口 49152-65535 被阻止");
            println!();
            println!("💡 提示：");
            println!("  - 端口范围功能可以批量阻止多个端口");
            println!("  - 适用于阻止特定类型的服务或应用程序");
        },
        Err(e) => {
            eprintln!("❌ 添加端口范围拦截规则失败: {:?}", e);
        }
    }

    Ok(())
}

fn run_gui() -> Result<()> {
    let options = NativeOptions {
        ..Default::default()
    };
    
    eframe::run_native(
        "AstralWFP",
        options,
        Box::new(|_cc| Box::new(WfpGui::default())),
    ).map_err(|e| Error::new(windows::core::HRESULT(0x80004005u32 as i32), (&e.to_string()).into()))
}

fn main() -> Result<()> {
    // 设置Windows控制台为UTF-8，防止中文乱码
    #[cfg(windows)]
    {
        use windows::Win32::System::Console::{SetConsoleOutputCP, SetConsoleCP};
        unsafe {
            SetConsoleOutputCP(65001);
            SetConsoleCP(65001);
        }
    }
    // 检查命令行参数
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() > 1 {
        match args[1].as_str() {
            "--cli" => {
                // 命令行模式
                println!("🌐 AstralWFP 网络流量控制器 - 命令行模式");
                println!("==========================================");
                test_nt_path_conversion();
                test_app_id_remote_ip_filter()?;
                test_common_protocols()?;
                test_port_ranges()?;

                println!("按回车键退出程序...");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).unwrap();
            },
            "--test-nt" => {
                // 只测试NT路径转换
                println!("🧪 NT路径转换测试模式");
                println!("======================");
                test_nt_path_conversion();
                println!("测试完成，按回车键退出...");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).unwrap();
            },
            "--test-protocol" => {
                // 测试协议拦截功能
                println!("🧪 协议拦截测试模式");
                println!("====================");
                test_common_protocols()?;
                println!("测试完成，按回车键退出...");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).unwrap();
            },
            "--test-port-ranges" => {
                // 测试端口范围拦截功能
                println!("🧪 端口范围拦截测试模式");
                println!("========================");
                test_port_ranges()?;
                println!("测试完成，按回车键退出...");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).unwrap();
            },
            _ => {
                println!("🌐 AstralWFP 网络流量控制器");
                println!("使用 --cli 参数启动命令行模式");
                println!("使用 --test-nt 参数测试NT路径转换");
                println!("使用 --test-protocol 参数测试协议拦截");
                println!("使用 --test-port-ranges 参数测试端口范围拦截");
                run_gui()?;
            }
        }
    } else {
        // GUI模式（默认）
        println!("🌐 AstralWFP 网络流量控制器 - GUI模式");
        println!("使用 --cli 参数启动命令行模式");
        println!("使用 --test-nt 参数测试NT路径转换");
        println!("使用 --test-protocol 参数测试协议拦截");
        println!("使用 --test-port-ranges 参数测试端口范围拦截");
        run_gui()?;
    }

    Ok(())
}
