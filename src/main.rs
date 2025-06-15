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
        // 禁止 Chrome 的所有网络连接（入站和出站，所有协议、所有端口、所有 IP）
        FilterRule::new("禁止 Chrome 所有网络连接")
            .app_path(nt_path)
            .direction(Direction::Both)
            .action(FilterAction::Block),
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
