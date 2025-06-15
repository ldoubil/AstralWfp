//! Astral Windows Filtering Platform (WFP) 管理模块
//! 
//! 本模块提供了一个高级抽象层，用于管理 Windows 防火墙和网络流量过滤。
//! 主要功能包括：
//! - 创建和管理网络过滤规则
//! - 支持 IPv4 和 IPv6 地址过滤
//! - 支持应用程序级别的网络控制
//! - 支持端口和协议过滤
//! - 支持入站/出站流量控制

// 标准库导入
use std::{
    ffi::OsStr,
    os::windows::ffi::OsStrExt,
    ptr,
    net::IpAddr,
    sync::atomic::{AtomicU64, Ordering},
};

// Windows API 导入
use windows::{
    Win32::Foundation::*, 
    Win32::NetworkManagement::WindowsFilteringPlatform::*,
    Win32::System::Rpc::*, 
    core::*,
};

/// WFP常量定义
const WFP_ACTION_BLOCK: u32 = 0x00000001 | 0x00001000;  // 阻止动作
const WFP_ACTION_PERMIT: u32 = 0x00000002 | 0x00001000; // 允许动作

/// 过滤器权重值
static WEIGHT_VALUE: AtomicU64 = AtomicU64::new(1000);
/// 过滤器有效权重值
static EFFECTIVE_WEIGHT_VALUE: AtomicU64 = AtomicU64::new(0);

/// CIDR网段结构体
#[derive(Debug, Clone)]
pub struct IpNetwork {
    /// IP地址
    pub ip: IpAddr,
    /// 前缀长度
    pub prefix_len: u8,
}

impl IpNetwork {
    /// 创建新的网段
    pub fn new(ip: IpAddr, prefix_len: u8) -> Self {
        Self { ip, prefix_len }
    }
    
    /// 从CIDR字符串创建网段
    pub fn from_cidr(cidr: &str) -> std::result::Result<Self, String> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err("无效的CIDR格式".to_string());
        }
        
        let ip: IpAddr = parts[0].parse().map_err(|_| "无效的IP地址")?;
        let prefix_len: u8 = parts[1].parse().map_err(|_| "无效的前缀长度")?;
        
        // 验证前缀长度
        let max_prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        
        if prefix_len > max_prefix {
            return Err(format!("前缀长度 {} 超过最大值 {}", prefix_len, max_prefix));
        }
        
        Ok(Self::new(ip, prefix_len))
    }
}

/// 网络协议枚举
#[derive(Debug, Clone)]
pub enum Protocol {
    /// TCP协议
    Tcp,
    /// UDP协议
    Udp,
    /// ICMP协议
    Icmp,
}

/// 流量方向枚举
#[derive(Debug, Clone)]
pub enum Direction {
    /// 入站流量
    Inbound,
    /// 出站流量
    Outbound,
    /// 双向流量
    Both,
}

/// 过滤动作枚举
#[derive(Debug, Clone)]
pub enum FilterAction {
    /// 允许流量通过
    Allow,
    /// 阻止流量通过
    Block,
}

/// 过滤规则结构体
#[derive(Debug, Clone)]
pub struct FilterRule {
    /// 规则名称
    pub name: String,
    /// 应用程序路径
    pub app_path: Option<String>,
    /// 本地IP地址
    pub local_ip: Option<IpAddr>,
    /// 远程IP地址
    pub remote_ip: Option<IpAddr>,
    /// 本地IP网段
    pub local_ip_network: Option<IpNetwork>,
    /// 远程IP网段
    pub remote_ip_network: Option<IpNetwork>,
    /// 本地端口
    pub local_port: Option<u16>,
    /// 远程端口
    pub remote_port: Option<u16>,
    /// 协议类型
    pub protocol: Option<Protocol>,
    /// 流量方向
    pub direction: Direction,
    /// 过滤动作
    pub action: FilterAction,
}

impl FilterRule {
    /// 创建新的过滤规则
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            app_path: None,
            local_ip: None,
            remote_ip: None,
            local_ip_network: None,
            remote_ip_network: None,
            local_port: None,
            remote_port: None,
            protocol: None,
            direction: Direction::Both,
            action: FilterAction::Block,
        }
    }

    /// 设置应用程序路径
    pub fn app_path(mut self, path: &str) -> Self {
        self.app_path = Some(path.to_string());
        self
    }

    /// 设置本地IP地址
    pub fn local_ip(mut self, ip: IpAddr) -> Self {
        self.local_ip = Some(ip);
        self
    }

    /// 设置远程IP地址
    pub fn remote_ip(mut self, ip: IpAddr) -> Self {
        self.remote_ip = Some(ip);
        self
    }

    /// 设置本地IP网段
    pub fn local_ip_network(mut self, network: IpNetwork) -> Self {
        self.local_ip_network = Some(network);
        self
    }

    /// 设置远程IP网段
    pub fn remote_ip_network(mut self, network: IpNetwork) -> Self {
        self.remote_ip_network = Some(network);
        self
    }

    /// 从CIDR字符串设置本地IP网段
    pub fn local_ip_cidr(mut self, cidr: &str) -> std::result::Result<Self, String> {
        self.local_ip_network = Some(IpNetwork::from_cidr(cidr)?);
        Ok(self)
    }

    /// 从CIDR字符串设置远程IP网段
    pub fn remote_ip_cidr(mut self, cidr: &str) -> std::result::Result<Self, String> {
        self.remote_ip_network = Some(IpNetwork::from_cidr(cidr)?);
        Ok(self)
    }

    /// 设置本地端口
    pub fn local_port(mut self, port: u16) -> Self {
        self.local_port = Some(port);
        self
    }

    /// 设置远程端口
    pub fn remote_port(mut self, port: u16) -> Self {
        self.remote_port = Some(port);
        self
    }

    /// 设置协议类型
    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// 设置流量方向
    pub fn direction(mut self, direction: Direction) -> Self {
        self.direction = direction;
        self
    }

    /// 设置过滤动作
    pub fn action(mut self, action: FilterAction) -> Self {
        self.action = action;
        self
    }
}

/// 创建宽字符字符串的辅助函数
pub fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// WFP控制器结构体
pub struct WfpController {
    /// WFP引擎句柄
    engine_handle: HANDLE,
    /// 过滤器ID列表
    filter_ids: Vec<u64>,
}

impl WfpController {
    /// 创建新的WFP控制器实例
    pub fn new() -> Result<Self> {
        Ok(Self {
            engine_handle: HANDLE::default(),
            filter_ids: Vec::new(),
        })
    }

    /// 初始化WFP引擎
    /// 
    /// # Returns
    /// - `Ok(())` 如果初始化成功
    /// - `Err(Error)` 如果初始化失败
    pub fn initialize(&mut self) -> Result<()> {
        unsafe {
            println!("正在初始化 Windows Filtering Platform...");

            // 创建会话名称
            let session_name = to_wide_string("AstralWFP Manager");
            let session_desc = to_wide_string("AstralWFP网络流量管理会话");

            let session = FWPM_SESSION0 {
                sessionKey: GUID::zeroed(),
                displayData: FWPM_DISPLAY_DATA0 {
                    name: PWSTR(session_name.as_ptr() as *mut u16),
                    description: PWSTR(session_desc.as_ptr() as *mut u16),
                },
                flags: FWPM_SESSION_FLAG_DYNAMIC,
                txnWaitTimeoutInMSec: 0,
                processId: 0,
                sid: ptr::null_mut(),
                username: PWSTR::null(),
                kernelMode: FALSE,
            };

            // 打开WFP会话
            let result = FwpmEngineOpen0(
                None,
                RPC_C_AUTHN_DEFAULT as u32,
                None,
                Some(&session),
                &mut self.engine_handle,
            );

            if WIN32_ERROR(result) == ERROR_SUCCESS {
                println!("✓ WFP引擎打开成功！");
                Ok(())
            } else {
                println!("❌ 打开WFP引擎失败: {} (可能需要管理员权限)", result);
                Err(Error::from_win32())
            }
        }
    }

    /// 创建过滤器并添加到WFP引擎
    /// 
    /// # Arguments
    /// * `rule` - 过滤规则
    /// * `layer_key` - WFP层标识符
    /// 
    /// # Returns
    /// - `Ok(u64)` 如果添加成功，返回过滤器ID
    /// - `Err(Error)` 如果添加失败
    /// 
    /// # Safety
    /// 此函数使用了Windows API，需要在unsafe块中调用
    unsafe fn add_advanced_network_filter(
        &self,
        rule: &FilterRule,
        layer_key: GUID,
    ) -> Result<u64> {
        // 创建过滤器结构
        let filter = FWPM_FILTER0 {
            filterKey: GUID::zeroed(),
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(to_wide_string(&rule.name).as_ptr() as *mut u16),
                description: PWSTR(to_wide_string(&format!("控制 {} 的网络流量", rule.name)).as_ptr() as *mut u16),
            },
            flags: FWPM_FILTER_FLAGS(0),
            providerKey: ptr::null_mut(),
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: ptr::null_mut(),
            },
            layerKey: layer_key,
            subLayerKey: FWPM_SUBLAYER_UNIVERSAL,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_VALUE0_0 {
                    uint64: WEIGHT_VALUE.load(Ordering::SeqCst) as *mut u64,
                },
            },
            numFilterConditions: 0,
            filterCondition: ptr::null_mut(),
            action: FWPM_ACTION0 {
                r#type: match rule.action {
                    FilterAction::Allow => WFP_ACTION_PERMIT,
                    FilterAction::Block => WFP_ACTION_BLOCK,
                },
                Anonymous: FWPM_ACTION0_0 {
                    calloutKey: GUID::zeroed(),
                },
            },
            Anonymous: FWPM_FILTER0_0 {
                rawContext: 0,
            },
            reserved: ptr::null_mut(),
            filterId: 0,
            effectiveWeight: FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_VALUE0_0 {
                    uint64: EFFECTIVE_WEIGHT_VALUE.load(Ordering::SeqCst) as *mut u64,
                },
            },
        };

        // 用于存储新添加的过滤器ID
        let mut filter_id = 0u64;
        
        // 添加过滤器到WFP引擎
        unsafe {
            let add_result = FwpmFilterAdd0(
                self.engine_handle,
                &filter,
                None,
                Some(&mut filter_id)
            );

            if WIN32_ERROR(add_result) == ERROR_SUCCESS {
                Ok(filter_id)
            } else {
                println!("❌ 添加过滤器 '{}' 失败: {}", rule.name, add_result);
                Err(Error::from_win32())
            }
        }
    }

    /// 添加高级过滤器规则
    /// 
    /// # Arguments
    /// * `rules` - 过滤规则数组
    /// 
    /// # Returns
    /// - `Ok(())` 如果所有过滤器添加成功
    /// - `Err(Error)` 如果添加失败
    pub fn add_advanced_filters(&mut self, rules: &[FilterRule]) -> Result<()> {
        unsafe {
            let mut added_count = 0;
            
            for rule in rules {
                // 根据规则获取对应的WFP层
                for layer_key in self.get_layers_for_rule(rule) {
                    if let Ok(filter_id) = self.add_advanced_network_filter(rule, layer_key) {
                        self.filter_ids.push(filter_id);
                        added_count += 1;
                        println!("✓ {}过滤器添加成功 (ID: {}) - 层: {:?}", rule.name, filter_id, layer_key);
                    }
                }
            }

            if added_count > 0 {
                println!(
                    "\n🔍 网络流量控制已启动，共添加了 {} 个过滤器",
                    added_count
                );
                Ok(())
            } else {
                println!("❌ 没有成功添加任何过滤器");
                Err(Error::from_win32())
            }
        }
    }

    /// 根据规则获取对应的WFP层
    fn get_layers_for_rule(&self, rule: &FilterRule) -> Vec<GUID> {
        let mut layers = Vec::new();
        
        // 根据IP地址类型和方向确定层
        let is_ipv6 = rule.local_ip.map_or(false, |ip| ip.is_ipv6()) || 
                      rule.remote_ip.map_or(false, |ip| ip.is_ipv6());
        
        match rule.direction {
            Direction::Outbound => {
                if is_ipv6 {
                    layers.push(FWPM_LAYER_ALE_AUTH_CONNECT_V6);
                } else {
                    layers.push(FWPM_LAYER_ALE_AUTH_CONNECT_V4);
                }
            },
            Direction::Inbound => {
                if is_ipv6 {
                    layers.push(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6);
                } else {
                    layers.push(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4);
                }
            },
            Direction::Both => {
                if is_ipv6 {
                    layers.push(FWPM_LAYER_ALE_AUTH_CONNECT_V6);
                    layers.push(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6);
                } else {
                    layers.push(FWPM_LAYER_ALE_AUTH_CONNECT_V4);
                    layers.push(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4);
                }
            }
        }
        
        // 如果没有指定IP类型，同时添加IPv4和IPv6层
        if layers.is_empty() {
            match rule.direction {
                Direction::Outbound => {
                    layers.push(FWPM_LAYER_ALE_AUTH_CONNECT_V4);
                    layers.push(FWPM_LAYER_ALE_AUTH_CONNECT_V6);
                },
                Direction::Inbound => {
                    layers.push(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4);
                    layers.push(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6);
                },
                Direction::Both => {
                    layers.push(FWPM_LAYER_ALE_AUTH_CONNECT_V4);
                    layers.push(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4);
                    layers.push(FWPM_LAYER_ALE_AUTH_CONNECT_V6);
                    layers.push(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6);
                }
            }
        }
        
        layers
    }

    /// 等待用户输入并运行
    pub fn run(&self) -> Result<()> {
        println!("📊 过滤器正在运行...");
        println!("\n按 Enter 键停止并退出\n");

        // 等待用户输入
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        Ok(())
    }

    /// 清理过滤器并关闭WFP引擎
    pub fn cleanup(&mut self) -> Result<()> {
        unsafe {
            println!("\n🛑 停止过滤器，正在清理...");

            // 清理过滤器
            for filter_id in &self.filter_ids {
                let delete_result = FwpmFilterDeleteById0(self.engine_handle, *filter_id);
                if WIN32_ERROR(delete_result) == ERROR_SUCCESS {
                    println!("✓ 过滤器 {} 已删除", filter_id);
                } else {
                    println!("⚠️  删除过滤器 {} 失败: {}", filter_id, delete_result);
                }
            }

            // 关闭引擎
            let result = FwpmEngineClose0(self.engine_handle);
            if WIN32_ERROR(result) != ERROR_SUCCESS {
                println!("❌ 关闭WFP引擎失败: {}", result);
                return Err(Error::from_win32());
            }
            println!("✓ WFP引擎已关闭");
            Ok(())
        }
    }
}