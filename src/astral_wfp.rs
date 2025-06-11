use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows::{
    Win32::Foundation::*, Win32::NetworkManagement::WindowsFilteringPlatform::*,
    Win32::System::Rpc::*, core::*,
};

// CIDR网段结构体
#[derive(Debug, Clone)]
pub struct IpNetwork {
    pub ip: IpAddr,
    pub prefix_len: u8,
}

impl IpNetwork {
    pub fn new(ip: IpAddr, prefix_len: u8) -> Self {
        Self { ip, prefix_len }
    }
    
    pub fn from_cidr(cidr: &str) -> std::result::Result<Self, String> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err("Invalid CIDR format".to_string());
        }
        
        let ip: IpAddr = parts[0].parse().map_err(|_| "Invalid IP address")?;
        let prefix_len: u8 = parts[1].parse().map_err(|_| "Invalid prefix length")?;
        
        // 验证前缀长度
        let max_prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        
        if prefix_len > max_prefix {
            return Err(format!("Prefix length {} exceeds maximum {}", prefix_len, max_prefix));
        }
        
        Ok(Self::new(ip, prefix_len))
    }
    
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.ip, ip) {
            (IpAddr::V4(network_ip), IpAddr::V4(test_ip)) => {
                let mask = !((1u32 << (32 - self.prefix_len)) - 1);
                let network_addr = u32::from(network_ip) & mask;
                let test_addr = u32::from(*test_ip) & mask;
                network_addr == test_addr
            }
            (IpAddr::V6(network_ip), IpAddr::V6(test_ip)) => {
                let network_bytes = network_ip.octets();
                let test_bytes = test_ip.octets();
                let prefix_bytes = self.prefix_len / 8;
                let prefix_bits = self.prefix_len % 8;
                
                // 比较完整字节
                for i in 0..prefix_bytes as usize {
                    if network_bytes[i] != test_bytes[i] {
                        return false;
                    }
                }
                
                // 比较部分字节
                if prefix_bits > 0 {
                    let mask = 0xFF << (8 - prefix_bits);
                    let network_byte = network_bytes[prefix_bytes as usize] & mask;
                    let test_byte = test_bytes[prefix_bytes as usize] & mask;
                    if network_byte != test_byte {
                        return false;
                    }
                }
                
                true
            }
            _ => false, // IPv4 vs IPv6 不匹配
        }
    }
}

// WFP 常量定义
const FWP_ACTION_BLOCK: u32 = 0x00000001 | 0x00001000;
const FWP_ACTION_PERMIT: u32 = 0x00000002 | 0x00001000;
static mut WEIGHT_VALUE: u64 = 1000;
static mut EFFECTIVE_WEIGHT_VALUE: u64 = 0;

// 过滤规则结构体
#[derive(Debug, Clone)]
pub struct FilterRule {
    pub name: String,
    pub app_path: Option<String>,
    pub local_ip: Option<IpAddr>,
    pub remote_ip: Option<IpAddr>,
    pub local_ip_network: Option<IpNetwork>,
    pub remote_ip_network: Option<IpNetwork>,
    pub local_port: Option<u16>,
    pub remote_port: Option<u16>,
    pub protocol: Option<Protocol>,
    pub direction: Direction,
    pub action: FilterAction,
}

#[derive(Debug, Clone)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

// 流量方向枚举
#[derive(Debug, Clone)]
pub enum Direction {
    Inbound,     // 入站流量
    Outbound,    // 出站流量
    Both,        // 双向流量
}
#[derive(Debug, Clone)]
pub enum FilterAction {
    Allow,
    Block,
}

impl FilterRule {
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

    pub fn app_path(mut self, path: &str) -> Self {
        self.app_path = Some(path.to_string());
        self
    }

    pub fn local_ip(mut self, ip: IpAddr) -> Self {
        self.local_ip = Some(ip);
        self
    }

    pub fn remote_ip(mut self, ip: IpAddr) -> Self {
        self.remote_ip = Some(ip);
        self
    }

    pub fn local_ip_network(mut self, network: IpNetwork) -> Self {
        self.local_ip_network = Some(network);
        self
    }

    pub fn remote_ip_network(mut self, network: IpNetwork) -> Self {
        self.remote_ip_network = Some(network);
        self
    }

    pub fn local_ip_cidr(mut self, cidr: &str) -> std::result::Result<Self, String> {
        self.local_ip_network = Some(IpNetwork::from_cidr(cidr)?);
        Ok(self)
    }

    pub fn remote_ip_cidr(mut self, cidr: &str) -> std::result::Result<Self, String> {
        self.remote_ip_network = Some(IpNetwork::from_cidr(cidr)?);
        Ok(self)
    }

    pub fn local_port(mut self, port: u16) -> Self {
        self.local_port = Some(port);
        self
    }

    pub fn remote_port(mut self, port: u16) -> Self {
        self.remote_port = Some(port);
        self
    }

    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    pub fn direction(mut self, direction: Direction) -> Self {
        self.direction = direction;
        self
    }

    pub fn action(mut self, action: FilterAction) -> Self {
        self.action = action;
        self
    }
}

// 创建宽字符字符串的辅助函数
pub fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

// WFP控制器结构体
pub struct WfpController {
    engine_handle: HANDLE,
    filter_ids: Vec<u64>,
}

impl WfpController {
    // 创建新的WFP控制器实例
    pub fn new() -> Result<Self> {
        Ok(Self {
            engine_handle: HANDLE::default(),
            filter_ids: Vec::new(),
        })
    }

    // 初始化WFP引擎
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


    // 添加高级过滤器（支持复杂规则）
    pub fn add_advanced_filters(&mut self, rules: &[FilterRule]) -> Result<()> {
        unsafe {
            let mut added_count = 0;
            
            for rule in rules {
                // 根据方向和IP版本确定需要的层
                let layers = self.get_layers_for_rule(rule);
                
                for layer in layers {
                    if let Ok(filter_id) = self.add_advanced_network_filter(rule, layer) {
                        self.filter_ids.push(filter_id);
                        added_count += 1;
                        println!("✓ {}过滤器添加成功 (ID: {}) - 层: {:?}", rule.name, filter_id, layer);
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

    // 根据规则获取对应的WFP层
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

    // 等待用户输入并运行
    pub fn run(&self) -> Result<()> {
        println!("📊 过滤器正在运行...");
        println!("\n按 Enter 键停止并退出\n");

        // 等待用户输入
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        Ok(())
    }

    // 清理过滤器
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

    // 添加高级网络过滤器的内部方法
    unsafe fn add_advanced_network_filter(
        &self,
        rule: &FilterRule,
        layer_key: GUID,
    ) -> Result<u64> {
        // 将过滤器名称转换为宽字符串
        let filter_name = to_wide_string(&rule.name);
        // 生成过滤器描述并转换为宽字符串
        let filter_desc = to_wide_string(&format!("控制 {} 的网络流量", rule.name));

        // 创建过滤条件向量
        let mut conditions = Vec::new();
        
        // 添加应用程序路径条件
        let mut app_id_data = None;
        if let Some(app_path) = &rule.app_path {
            let appid_utf16: Vec<u16> = app_path
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            
            let app_id = FWP_BYTE_BLOB {
                size: (appid_utf16.len() * 2) as u32,
                data: appid_utf16.as_ptr() as *mut u8,
            };
            
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        byteBlob: &app_id as *const _ as *mut _,
                    },
                },
            });
            
            app_id_data = Some((appid_utf16, app_id));
            println!("✓ APP_ID条件已添加到过滤器: {}", app_path);
        }
        
        // 添加本地IP条件
        let mut local_ip_data = None;
        if let Some(local_ip) = rule.local_ip {
            match local_ip {
                IpAddr::V4(ipv4) => {
                    let ip_bytes = ipv4.octets();
                    let ip_value = u32::from_be_bytes(ip_bytes);
                    
                    conditions.push(FWPM_FILTER_CONDITION0 {
                        fieldKey: FWPM_CONDITION_IP_LOCAL_ADDRESS,
                        matchType: FWP_MATCH_EQUAL,
                        conditionValue: FWP_CONDITION_VALUE0 {
                            r#type: FWP_UINT32,
                            Anonymous: FWP_CONDITION_VALUE0_0 {
                                uint32: ip_value,
                            },
                        },
                    });
                    println!("✓ 本地IPv4地址条件已添加: {}", ipv4);
                },
                IpAddr::V6(ipv6) => {
                    let ip_bytes = ipv6.octets();
                    let byte_array = FWP_BYTE_ARRAY16 {
                        byteArray16: ip_bytes,
                    };
                    
                    conditions.push(FWPM_FILTER_CONDITION0 {
                        fieldKey: FWPM_CONDITION_IP_LOCAL_ADDRESS,
                        matchType: FWP_MATCH_EQUAL,
                        conditionValue: FWP_CONDITION_VALUE0 {
                            r#type: FWP_BYTE_ARRAY16_TYPE,
                            Anonymous: FWP_CONDITION_VALUE0_0 {
                                byteArray16: &byte_array as *const _ as *mut _,
                            },
                        },
                    });
                    local_ip_data = Some(byte_array);
                    println!("✓ 本地IPv6地址条件已添加: {}", ipv6);
                }
            }
        }
        
        // 添加远程IP条件
        let mut remote_ip_data = None;
        if let Some(remote_ip) = rule.remote_ip {
            match remote_ip {
                IpAddr::V4(ipv4) => {
                    let ip_bytes = ipv4.octets();
                    let ip_value = u32::from_be_bytes(ip_bytes);
                    
                    conditions.push(FWPM_FILTER_CONDITION0 {
                        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        matchType: FWP_MATCH_EQUAL,
                        conditionValue: FWP_CONDITION_VALUE0 {
                            r#type: FWP_UINT32,
                            Anonymous: FWP_CONDITION_VALUE0_0 {
                                uint32: ip_value,
                            },
                        },
                    });
                    println!("✓ 远程IPv4地址条件已添加: {}", ipv4);
                },
                IpAddr::V6(ipv6) => {
                    let ip_bytes = ipv6.octets();
                    let byte_array = FWP_BYTE_ARRAY16 {
                        byteArray16: ip_bytes,
                    };
                    
                    conditions.push(FWPM_FILTER_CONDITION0 {
                        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        matchType: FWP_MATCH_EQUAL,
                        conditionValue: FWP_CONDITION_VALUE0 {
                            r#type: FWP_BYTE_ARRAY16_TYPE,
                            Anonymous: FWP_CONDITION_VALUE0_0 {
                                byteArray16: &byte_array as *const _ as *mut _,
                            },
                        },
                    });
                    remote_ip_data = Some(byte_array);
                    println!("✓ 远程IPv6地址条件已添加: {}", ipv6);
                }
            }
        }
        
        // 添加远程IP网段条件
        let mut remote_network_data = None;
        if let Some(remote_network) = &rule.remote_ip_network {
            match remote_network.ip {
                IpAddr::V4(network_ip) => {
                    let network_bytes = network_ip.octets();
                    let mask = !((1u32 << (32 - remote_network.prefix_len)) - 1);
                    let network_addr = u32::from_be_bytes(network_bytes) & mask;
                    
                    let range = FWP_RANGE0 {
                        valueLow: FWP_VALUE0 {
                            r#type: FWP_UINT32,
                            Anonymous: FWP_VALUE0_0 {
                                uint32: network_addr,
                            },
                        },
                        valueHigh: FWP_VALUE0 {
                            r#type: FWP_UINT32,
                            Anonymous: FWP_VALUE0_0 {
                                uint32: network_addr | !mask,
                            },
                        },
                    };
                    
                    conditions.push(FWPM_FILTER_CONDITION0 {
                        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        matchType: FWP_MATCH_RANGE,
                        conditionValue: FWP_CONDITION_VALUE0 {
                            r#type: FWP_RANGE_TYPE,
                            Anonymous: FWP_CONDITION_VALUE0_0 {
                                rangeValue: &range as *const _ as *mut _,
                            },
                        },
                    });
                    remote_network_data = Some(range);
                    println!("✓ 远程IPv4网段条件已添加: {}/{}", network_ip, remote_network.prefix_len);
                },
                IpAddr::V6(_) => {
                    println!("⚠️ IPv6网段过滤暂不支持，将跳过此条件");
                }
            }
        }
        
        // 添加本地端口条件
        if let Some(local_port) = rule.local_port {
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_LOCAL_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint16: local_port,
                    },
                },
            });
            println!("✓ 本地端口条件已添加: {}", local_port);
        }
        
        // 添加远程端口条件
        if let Some(remote_port) = rule.remote_port {
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint16: remote_port,
                    },
                },
            });
            println!("✓ 远程端口条件已添加: {}", remote_port);
        }
        
        // 添加协议条件
        if let Some(protocol) = &rule.protocol {
            let protocol_value = match protocol {
                Protocol::Tcp => 6u8,
                Protocol::Udp => 17u8,
                Protocol::Icmp => 1u8,
            };
            
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint8: protocol_value,
                    },
                },
            });
            println!("✓ 协议条件已添加: {:?}", protocol);
        }
        
        // 获取条件数量
        let num_conditions = conditions.len() as u32;
        
        // 确定过滤器动作
        let action_type = match rule.action {
            FilterAction::Allow => FWP_ACTION_PERMIT,
            FilterAction::Block => FWP_ACTION_BLOCK,
        };

        // 创建过滤器结构
        let filter = FWPM_FILTER0 {
            filterKey: GUID::zeroed(),
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(filter_name.as_ptr() as *mut u16),
                description: PWSTR(filter_desc.as_ptr() as *mut u16),
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
                    uint64: unsafe { &raw mut WEIGHT_VALUE as *mut u64 },
                },
            },
            numFilterConditions: num_conditions,
            filterCondition: if num_conditions > 0 {
                conditions.as_ptr() as *mut _
            } else {
                ptr::null_mut()
            },
            action: FWPM_ACTION0 {
                r#type: action_type,
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
                    uint64: unsafe { &raw mut EFFECTIVE_WEIGHT_VALUE as *mut u64 },
                },
            },
        };

        // 用于存储新添加的过滤器ID
        let mut filter_id = 0u64;
        // 添加过滤器到WFP引擎
        let add_result = FwpmFilterAdd0(self.engine_handle, &filter, None, Some(&mut filter_id));

        // 检查添加结果
        if WIN32_ERROR(add_result) == ERROR_SUCCESS {
            Ok(filter_id)
        } else {
            println!("❌ 添加过滤器 '{}' 失败: {}", rule.name, add_result);
            Err(Error::from_win32())
        }
    }

    // 添加网络过滤器的内部方法（保持向后兼容）
    unsafe fn add_network_filter(
        &self,
        name: &str,
        layer_key: GUID,
        appid: Option<&[u16]>,
    ) -> Result<u64> {
        // 将过滤器名称转换为宽字符串
        let filter_name = to_wide_string(name);
        // 生成过滤器描述并转换为宽字符串
        let filter_desc = to_wide_string(&format!("控制 {} 的网络流量", name));

        // 创建过滤条件向量
        let mut conditions = Vec::new();
        // 如果提供了应用程序路径，添加应用程序ID条件

        if let Some(appid_utf16) = appid {
            let app_id = FWP_BYTE_BLOB {
                size: (appid_utf16.len() * 2) as u32,
                data: appid_utf16.as_ptr() as *mut u8,
            };

            // 添加应用程序ID匹配条件
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_APP_ID, // 使用应用程序ID字段
                matchType: FWP_MATCH_EQUAL,          // 使用相等匹配
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE, // 值类型为字节blob
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        byteBlob: &app_id as *const _ as *mut _,
                    },
                },
            });

            println!("✓ APP_ID条件已添加到过滤器");
            println!("========================\n");
        }
        // 获取条件数量
        let num_conditions = conditions.len() as u32;

        // 创建过滤器结构
        let filter = FWPM_FILTER0 {
            filterKey: GUID::zeroed(), // 使用空GUID
            displayData: FWPM_DISPLAY_DATA0 {
                // 显示信息
                name: PWSTR(filter_name.as_ptr() as *mut u16),
                description: PWSTR(filter_desc.as_ptr() as *mut u16),
            },
            flags: FWPM_FILTER_FLAGS(0),  // 无特殊标志
            providerKey: ptr::null_mut(), // 无提供者
            providerData: FWP_BYTE_BLOB {
                // 空提供者数据
                size: 0,
                data: ptr::null_mut(),
            },
            layerKey: layer_key,                  // 设置过滤层
            subLayerKey: FWPM_SUBLAYER_UNIVERSAL, // 使用通用子层
            weight: FWP_VALUE0 {
                // 设置权重
                r#type: FWP_UINT64,
                Anonymous: FWP_VALUE0_0 {
                    uint64: unsafe { &raw mut WEIGHT_VALUE as *mut u64 },
                },
            },
            numFilterConditions: num_conditions, // 条件数量
            filterCondition: if num_conditions > 0 {
                conditions.as_ptr() as *mut _
            } else {
                ptr::null_mut()
            }, // 条件数组
            action: FWPM_ACTION0 {
                // 设置动作为阻止
                r#type: FWP_ACTION_BLOCK,
                Anonymous: FWPM_ACTION0_0 {
                    calloutKey: GUID::zeroed(),
                },
            },
            Anonymous: FWPM_FILTER0_0 {
                // 原始上下文
                rawContext: 0,
            },
            reserved: ptr::null_mut(), // 保留字段
            filterId: 0,               // 过滤器ID初始化为0
            effectiveWeight: FWP_VALUE0 {
                // 有效权重
                r#type: FWP_UINT64,
                Anonymous: FWP_VALUE0_0 {
                    uint64: unsafe { &raw mut EFFECTIVE_WEIGHT_VALUE as *mut u64 },
                },
            },
        };

        // 用于存储新添加的过滤器ID
        let mut filter_id = 0u64;
        // 添加过滤器到WFP引擎
        let add_result = unsafe { FwpmFilterAdd0(self.engine_handle, &filter, None, Some(&mut filter_id)) };

        // 检查添加结果
        if WIN32_ERROR(add_result) == ERROR_SUCCESS {
            Ok(filter_id) // 成功返回过滤器ID
        } else {
            println!("❌ 添加过滤器 '{}' 失败: {}", name, add_result);
            Err(Error::from_win32()) // 失败返回错误
        }
    }
}