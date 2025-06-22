mod astral_wfp;
mod nt;
mod gui;

use windows::core::*;
use crate::nt::get_nt_path;
use crate::gui::WfpGui;
use tokio::io::{self, AsyncBufReadExt};
use eframe::NativeOptions;

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
    
    let rules = vec![        // 测试1: 阻止Edge访问特定IP (双向阻止)
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
    
    if args.len() > 1 && args[1] == "--cli" {
        // 命令行模式
        println!("🌐 AstralWFP 网络流量控制器 - 命令行模式");
        println!("==========================================");
        test_app_id_remote_ip_filter()?;

        println!("按回车键退出程序...");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
    } else {
        // GUI模式（默认）
        println!("🌐 AstralWFP 网络流量控制器 - GUI模式");
        println!("使用 --cli 参数启动命令行模式");
        run_gui()?;
    }

    Ok(())
}
