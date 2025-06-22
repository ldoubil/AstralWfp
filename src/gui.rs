use eframe::egui;
use std::sync::{Arc, Mutex};
use crate::astral_wfp::{WfpController, FilterRule, Direction, FilterAction, Protocol};
use crate::nt::get_nt_path;

// 规则信息结构体
#[derive(Debug, Clone)]
pub struct RuleInfo {
    pub rule: FilterRule,
    pub filter_ids: Vec<u64>,  // 存储该规则对应的所有过滤器ID
    pub is_active: bool,       // 规则是否激活
}

pub struct WfpGui {
    wfp_controller: Arc<Mutex<Option<WfpController>>>,
    
    // 状态
    is_initialized: bool,
    status_message: String,
    status_color: egui::Color32,
    
    // 规则管理
    rules: Vec<RuleInfo>,

    // 规则添加表单
    rule_name: String,
    app_path: String,
    local_ip: String,
    remote_ip: String,
    local_port: String,
    remote_port: String,
    selected_protocol: Option<Protocol>,
    selected_direction: Direction,
    selected_action: FilterAction,
}

impl Default for WfpGui {
    fn default() -> Self {
        Self {
            wfp_controller: Arc::new(Mutex::new(None)),
            is_initialized: false,
            status_message: "准备就绪".to_string(),
            status_color: egui::Color32::GREEN,
            rules: Vec::new(),
            rule_name: "新规则".to_string(),
            app_path: "".to_string(),
            local_ip: "".to_string(),
            remote_ip: "".to_string(),
            local_port: "".to_string(),
            remote_port: "".to_string(),
            selected_protocol: None,
            selected_direction: Direction::Both,
            selected_action: FilterAction::Block,
        }
    }
}

impl eframe::App for WfpGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 设置支持中文的字体（NotoSansCJKsc-Black.otf）
        let mut fonts = egui::FontDefinitions::default();
        fonts.font_data.insert(
            "my_chinese".to_owned(),
            egui::FontData::from_static(include_bytes!("../assets/fonts/NotoSansCJKsc-Black.otf")),
        );
        fonts.families
            .get_mut(&egui::FontFamily::Proportional)
            .unwrap()
            .insert(0, "my_chinese".to_owned());
        fonts.families
            .get_mut(&egui::FontFamily::Monospace)
            .unwrap()
            .insert(0, "my_chinese".to_owned());
        ctx.set_fonts(fonts);
        
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🛡️ AstralWfp");
            ui.add_space(8.0);
            // 状态显示
            ui.horizontal(|ui| {
                ui.label("状态:");
                if self.is_initialized {
                    ui.colored_label(egui::Color32::GREEN, "✅ 已初始化");
                } else {
                    ui.colored_label(egui::Color32::RED, "❌ 未初始化");
                }
                ui.label(&self.status_message);
            });
            ui.add_space(8.0);
            // 规则添加表单卡片
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.heading("➕ 添加规则");
                let mut input_error = None;
                ui.horizontal(|ui| {
                    ui.label("名称:");
                    ui.text_edit_singleline(&mut self.rule_name);
                });
                ui.horizontal(|ui| {
                    ui.label("应用程序路径:");
                    ui.text_edit_singleline(&mut self.app_path);
                });
                ui.horizontal(|ui| {
                    ui.label("本地IP:");
                    if ui.text_edit_singleline(&mut self.local_ip).lost_focus() && !self.local_ip.is_empty() {
                        if self.local_ip.parse::<std::net::IpAddr>().is_err() && !self.local_ip.contains('/') {
                            input_error = Some("本地IP格式错误");
                        }
                    }
                    ui.label("本地端口:");
                    if ui.text_edit_singleline(&mut self.local_port).lost_focus() && !self.local_port.is_empty() {
                        if self.local_port.parse::<u16>().is_err() {
                            input_error = Some("本地端口格式错误");
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("远程IP:");
                    if ui.text_edit_singleline(&mut self.remote_ip).lost_focus() && !self.remote_ip.is_empty() {
                        if self.remote_ip.parse::<std::net::IpAddr>().is_err() && !self.remote_ip.contains('/') {
                            input_error = Some("远程IP格式错误");
                        }
                    }
                    ui.label("远程端口:");
                    if ui.text_edit_singleline(&mut self.remote_port).lost_focus() && !self.remote_port.is_empty() {
                        if self.remote_port.parse::<u16>().is_err() {
                            input_error = Some("远程端口格式错误");
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("协议:");
                    egui::ComboBox::from_id_source("protocol")
                        .selected_text(match self.selected_protocol {
                            Some(Protocol::Tcp) => "TCP",
                            Some(Protocol::Udp) => "UDP",
                            Some(Protocol::Icmp) => "ICMP",
                            Some(Protocol::IcmpV6) => "ICMPv6",
                            Some(Protocol::Igmp) => "IGMP",
                            Some(Protocol::Ah) => "AH",
                            Some(Protocol::Esp) => "ESP",
                            Some(Protocol::Gre) => "GRE",
                            Some(Protocol::Ipsec) => "IPSEC",
                            Some(Protocol::Any) => "任意协议",
                            None => "任意协议",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.selected_protocol, Some(Protocol::Tcp), "TCP");
                            ui.selectable_value(&mut self.selected_protocol, Some(Protocol::Udp), "UDP");
                            ui.selectable_value(&mut self.selected_protocol, Some(Protocol::Icmp), "ICMP");
                            ui.selectable_value(&mut self.selected_protocol, Some(Protocol::IcmpV6), "ICMPv6");
                            ui.selectable_value(&mut self.selected_protocol, Some(Protocol::Igmp), "IGMP");
                            ui.selectable_value(&mut self.selected_protocol, Some(Protocol::Ah), "AH");
                            ui.selectable_value(&mut self.selected_protocol, Some(Protocol::Esp), "ESP");
                            ui.selectable_value(&mut self.selected_protocol, Some(Protocol::Gre), "GRE");
                            ui.selectable_value(&mut self.selected_protocol, Some(Protocol::Ipsec), "IPSEC");
                            ui.selectable_value(&mut self.selected_protocol, Some(Protocol::Any), "任意协议");
                            ui.selectable_value(&mut self.selected_protocol, None, "任意协议");
                        });
                });
                ui.horizontal(|ui| {
                    ui.label("方向:");
                    egui::ComboBox::from_id_source("direction")
                        .selected_text(match self.selected_direction {
                            Direction::Inbound => "入站",
                            Direction::Outbound => "出站",
                            Direction::Both => "双向",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.selected_direction, Direction::Inbound, "入站");
                            ui.selectable_value(&mut self.selected_direction, Direction::Outbound, "出站");
                            ui.selectable_value(&mut self.selected_direction, Direction::Both, "双向");
                        });
                });
                ui.horizontal(|ui| {
                    ui.label("动作:");
                    egui::ComboBox::from_id_source("action")
                        .selected_text(match self.selected_action {
                            FilterAction::Allow => "允许",
                            FilterAction::Block => "阻止",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.selected_action, FilterAction::Allow, "允许");
                            ui.selectable_value(&mut self.selected_action, FilterAction::Block, "阻止");
                        });
                });
                if let Some(err) = input_error {
                    ui.colored_label(egui::Color32::RED, err);
                }
                if ui.add_enabled(input_error.is_none(), egui::Button::new("添加规则")).clicked() {
                    self.add_rule();
                }
            });
            ui.add_space(12.0);
            // 规则列表卡片
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.heading("📋 当前规则");
                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .max_height(ui.available_height() - 120.0)
                    .show(ui, |ui| {
                        if self.rules.is_empty() {
                            ui.label("暂无规则");
                        } else {
                            let mut to_remove: Option<usize> = None;
                            let available_width = ui.available_width();
                            let card_width = 280.0; // 卡片宽度
                            let cards_per_row = (available_width / card_width).max(1.0) as usize;
                            
                            for (i, rule_info) in self.rules.iter().enumerate() {
                                if i % cards_per_row == 0 {
                                    ui.horizontal(|ui| {
                                        for j in 0..cards_per_row {
                                            let rule_index = i + j;
                                            if rule_index < self.rules.len() {
                                                let rule_info = &self.rules[rule_index];
                                                ui.vertical(|ui| {
                                                    egui::Frame::group(ui.style())
                                                        .show(ui, |ui| {
                                                            ui.set_min_size(egui::vec2(card_width - 10.0, 160.0));
                                                            ui.horizontal(|ui| {
                                                                ui.label(format!("规则 {}", rule_index + 1));
                                                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                                    if ui.button("🗑️").clicked() {
                                                                        to_remove = Some(rule_index);
                                                                    }
                                                                });
                                                            });
                                                            ui.label(format!("名称: {}", rule_info.rule.name));
                                                            ui.label(format!("动作: {:?}", rule_info.rule.action));
                                                            ui.label(format!("方向: {:?}", rule_info.rule.direction));
                                                            if let Some(app_path) = &rule_info.rule.app_path {
                                                                ui.label(format!("应用程序: {}", app_path));
                                                            }
                                                            if let Some(protocol) = &rule_info.rule.protocol {
                                                                ui.label(format!("协议: {}", protocol));
                                                            }
                                                            if let Some(ip) = &rule_info.rule.local {
                                                                ui.label(format!("本地IP: {}", ip));
                                                            }
                                                            if let Some(ip) = &rule_info.rule.remote {
                                                                ui.label(format!("远程IP: {}", ip));
                                                            }
                                                            if let Some(port) = rule_info.rule.local_port {
                                                                ui.label(format!("本地端口: {}", port));
                                                            }
                                                            if let Some(port) = rule_info.rule.remote_port {
                                                                ui.label(format!("远程端口: {}", port));
                                                            }
                                                        });
                                                });
                                                if j < cards_per_row - 1 && rule_index + 1 < self.rules.len() {
                                                    ui.add_space(10.0);
                                                }
                                            }
                                        }
                                    });
                                    ui.add_space(8.0);
                                }
                            }
                            if let Some(index) = to_remove {
                                if let Err(e) = self.remove_rule(index) {
                                    eprintln!("删除规则失败: {}", e);
                                }
                            }
                        }
                    });
            });
            ui.add_space(12.0);
            // 操作按钮
            ui.horizontal(|ui| {
                if ui.button("🔄 刷新规则").clicked() {
                    self.refresh_rules();
                }
                if ui.button("🚀 初始化防火墙").clicked() {
                    if let Err(e) = self.initialize_wfp() {
                        eprintln!("初始化失败: {}", e);
                    }
                }
            });
        });
    }
}

impl WfpGui {
    fn initialize_wfp(&mut self) -> Result<(), String> {
        let mut controller = WfpController::new().map_err(|e| e.to_string())?;
        match controller.initialize() {
            Ok(()) => {
                *self.wfp_controller.lock().unwrap() = Some(controller);
                self.is_initialized = true;
                self.status_message = "WFP已初始化".to_string();
                self.status_color = egui::Color32::GREEN;
                self.refresh_rules();
                Ok(())
            }
            Err(e) => {
                self.status_message = format!("初始化失败: {:?}", e);
                self.status_color = egui::Color32::RED;
                Err(e.to_string())
            }
        }
    }
    
    fn add_rule(&mut self) {
        if !self.is_initialized {
            self.status_message = "请先初始化WFP".to_string();
            self.status_color = egui::Color32::RED;
            return;
        }
        let mut rule = FilterRule::new(&self.rule_name)
            .direction(self.selected_direction.clone())
            .action(self.selected_action.clone());
        if !self.app_path.is_empty() {
            // 对应用程序路径进行NT转换
            let nt_path = match get_nt_path(&self.app_path) {
                Some(path) => path,
                None => {
                    self.status_message = format!("应用程序路径转换失败: {}", self.app_path);
                    self.status_color = egui::Color32::RED;
                    return;
                }
            };
            rule = rule.app_path(&nt_path);
        }
        if !self.local_ip.is_empty() {
            rule = rule.local_ip(&self.local_ip);
        }
        if !self.remote_ip.is_empty() {
            rule = rule.remote_ip(&self.remote_ip);
        }
        if let Ok(port) = self.local_port.parse::<u16>() {
            rule = rule.local_port(port);
        }
        if let Ok(port) = self.remote_port.parse::<u16>() {
            rule = rule.remote_port(port);
        }
        if let Some(protocol) = &self.selected_protocol {
            rule = rule.protocol(protocol.clone());
        }
        if let Some(controller) = &mut *self.wfp_controller.lock().unwrap() {
            match controller.add_advanced_filters(&[rule.clone()]) {
                Ok(filter_ids) => {
                    let rule_info = RuleInfo {
                        rule,
                        filter_ids,
                        is_active: true,
                    };
                    self.rules.push(rule_info);
                    self.status_message = "规则添加成功".to_string();
                    self.status_color = egui::Color32::GREEN;
                }
                Err(e) => {
                    self.status_message = format!("添加规则失败: {:?}", e);
                    self.status_color = egui::Color32::RED;
                }
            }
        }
    }
    
    fn remove_rule(&mut self, index: usize) -> Result<(), String> {
        if index < self.rules.len() {
            let rule_info = &self.rules[index];
            if let Some(controller) = &mut *self.wfp_controller.lock().unwrap() {
                for &filter_id in &rule_info.filter_ids {
                    if let Err(e) = controller.remove_filter(filter_id) {
                        eprintln!("删除过滤器 {} 失败: {}", filter_id, e);
                    }
                }
            }
            self.rules.remove(index);
            Ok(())
        } else {
            Err(format!("索引 {} 超出范围", index))
        }
    }
    
    fn refresh_rules(&mut self) {
        if !self.is_initialized {
            self.status_message = "请先初始化WFP".to_string();
            self.status_color = egui::Color32::RED;
            return;
        }
        if let Some(controller) = &mut *self.wfp_controller.lock().unwrap() {
            match controller.get_rules() {
                Ok(rules) => {
                    self.rules.clear();
                    for rule in rules {
                        let filter_ids = controller.get_filter_ids(&rule).unwrap_or_default();
                        let rule_info = RuleInfo {
                            rule,
                            filter_ids,
                            is_active: true,
                        };
                        self.rules.push(rule_info);
                    }
                    self.status_message = "规则刷新成功".to_string();
                    self.status_color = egui::Color32::GREEN;
                }
                Err(e) => {
                    self.status_message = format!("刷新规则失败: {:?}", e);
                    self.status_color = egui::Color32::RED;
                }
            }
        } else {
            self.status_message = "WFP未初始化".to_string();
            self.status_color = egui::Color32::RED;
        }
    }
} 