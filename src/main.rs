mod astral_wfp;
mod nt;
use windows::core::*;
use crate::nt::get_nt_path;
use tokio::io::{self, AsyncBufReadExt};


async fn test_app_id_remote_ip_filter() -> windows::core::Result<()> {
    use astral_wfp::*;
    let path = r"C:\program files (x86)\microsoft\edge\application\msedge.exe";
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
            .remote_ip("124.71.134.95")
            .direction(Direction::Both)  // 改回 Outbound 或使用 Both
            .action(FilterAction::Block),

    ];

    match wfp_controller.add_advanced_filters(&rules) {
        Ok(()) => {
            println!("\n✅ 过滤规则添加成功！");
            println!("现在可以测试Edge是否无法访问124.71.134.95");
            println!("按Ctrl+C或回车键结束测试...");
        },
        Err(e) => {
            eprintln!("❌ 添加过滤规则失败: {:?}", e);
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    
    tokio::spawn(async {
        if let Err(e) = test_app_id_remote_ip_filter().await {
            eprintln!("测试执行出错: {:?}", e);
        }
    });

    let mut stdin = io::BufReader::new(io::stdin()).lines();
    println!("按回车键退出程序...");
    let _ = stdin.next_line().await;

    Ok(())
}
