mod astral_wfp;
mod nt;
use windows::core::*;

use crate::nt::get_nt_path;



fn main() -> Result<()> {
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

    // 运行控制器
    wfp_controller.run()?;

    // 清理资源
    wfp_controller.cleanup()?;

    println!("\n✅ 程序已安全退出");
    // 添加这行代码，等待用户按下回车键
    println!("按 Enter 键退出...");
    let mut buffer = String::new();
    std::io::stdin().read_line(&mut buffer).unwrap();
    Ok(())
}
