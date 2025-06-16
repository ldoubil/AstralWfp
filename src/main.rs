mod astral_wfp;
mod nt;
use windows::core::*;
use crate::nt::get_nt_path;
use tokio::io::{self, AsyncBufReadExt};


async fn jjk() -> windows::core::Result<()> {
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
    println!("\n🔧 添加禁止所有网络连接的规则...");
    let advanced_rules = vec![
        // 阻止所有IPv4连接
        FilterRule::new("禁止 Chrome IPv4 访问")            .app_path(nt_path)
            .remote_ip("192.168.31.1")  // 修正为正确的 IP 地址格式
            .direction(Direction::Both)   // 明确指定方向
            .action(FilterAction::Block)  // 明确指定动作
    ];

    wfp_controller.add_advanced_filters(&advanced_rules)?;

    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    
    tokio::spawn(async {
        if let Err(e) = jjk().await {
            eprintln!("任务执行出错: {:?}", e);
        }
    });
let mut stdin = io::BufReader::new(io::stdin()).lines();
println!("按回车键退出程序...");
let _ = stdin.next_line().await;

    Ok(())
}
