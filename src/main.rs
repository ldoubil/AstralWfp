use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use windows::{
    Win32::Foundation::*, Win32::NetworkManagement::WindowsFilteringPlatform::*,
    Win32::System::IO::OVERLAPPED, Win32::System::Rpc::*, core::*,
};

// WFP 常量定义
const FWP_ACTION_PERMIT: u32 = 0x00000002 | 0x00001000;
const FWP_ACTION_BLOCK: u32 = 0x00000001 | 0x00001000;
static mut WEIGHT_VALUE: u64 = 1000;
static mut EFFECTIVE_WEIGHT_VALUE: u64 = 0;

// 创建宽字符字符串的辅助函数
fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn main() -> Result<()> {
    unsafe {
        println!("正在初始化 Windows Filtering Platform...");

        // 打开WFP引擎
        let mut engine_handle = HANDLE::default();

        // 创建会话名称
        let session_name = to_wide_string("WFP Traffic Control");
        let session_desc = to_wide_string("控制指定程序网络流量的WFP会话");

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
            &mut engine_handle,
        );

        if WIN32_ERROR(result) == ERROR_SUCCESS {
            println!("✓ WFP引擎打开成功！");

            // 添加过滤器来控制网络流量
            let mut filter_ids = Vec::new();
// 入站TCP/UDP IPv6
let appid_utf16: Vec<u16> = "\\device\\harddiskvolume3\\program files (x86)\\microsoft\\edge\\application\\msedge.exe"
.encode_utf16()
.chain(std::iter::once(0)) // 结尾补0
.collect();
            // 添加监听层控制（防止程序作为服务器）
            if let Ok(filter_id) = add_network_filter(
                engine_handle,
                "IPv4监听控制",
                FWPM_LAYER_ALE_AUTH_LISTEN_V4,
                Some(&appid_utf16),
            ) {
                filter_ids.push(filter_id);
                println!("✓ IPv4监听过滤器添加成功 (ID: {})", filter_id);
            }

            if let Ok(filter_id) = add_network_filter(
                engine_handle,
                "IPv6监听控制",
                FWPM_LAYER_ALE_AUTH_LISTEN_V6,
                Some(&appid_utf16),
            ) {
                filter_ids.push(filter_id);
                println!("✓ IPv6监听过滤器添加成功 (ID: {})", filter_id);
            }

            // 添加流建立后的控制
            if let Ok(filter_id) = add_network_filter(
                engine_handle,
                "IPv4流建立控制",
                FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
                Some(&appid_utf16),
            ) {
                filter_ids.push(filter_id);
                println!("✓ IPv4流建立过滤器添加成功 (ID: {})", filter_id);
            }

            if let Ok(filter_id) = add_network_filter(
                engine_handle,
                "IPv6流建立控制",
                FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
                Some(&appid_utf16),
            ) {
                filter_ids.push(filter_id);
                println!("✓ IPv6流建立过滤器添加成功 (ID: {})", filter_id);
            }

            // 1. 控制出站IPv4传输层
            // 添加出站控制
            if let Ok(filter_id) = add_network_filter(
                engine_handle,
                "出站IPv4 TCP控制",
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                Some(&appid_utf16),
            ) {
                filter_ids.push(filter_id);
                println!("✓ 出站IPv4 TCP过滤器添加成功 (ID: {})", filter_id);
            }
            // 入站TCP/UDP IPv4
            if let Ok(filter_id) = add_network_filter(
                engine_handle,
                "入站IPv4 TCP/UDP控制",
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                Some(&appid_utf16),
            ) {
                filter_ids.push(filter_id);
                println!("✓ 入站IPv4 TCP/UDP过滤器添加成功 (ID: {})", filter_id);
            }

            // 出站TCP IPv6
            if let Ok(filter_id) = add_network_filter(
                engine_handle,
                "出站IPv6 TCP控制",
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                Some(&appid_utf16),
            ) {
                filter_ids.push(filter_id);
                println!("✓ 出站IPv6 TCP过滤器添加成功 (ID: {})", filter_id);
            }
            
            if let Ok(filter_id) = add_network_filter(
                engine_handle,
                "入站IPv6 TCP/UDP控制",
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                Some(&appid_utf16),
            ) {
                filter_ids.push(filter_id);
                println!("✓ 入站IPv6 TCP/UDP过滤器添加成功 (ID: {})", filter_id);
            }

            if !filter_ids.is_empty() {
                println!(
                    "\n🔍 网络流量控制已启动，共添加了 {} 个过滤器",
                    filter_ids.len()
                );
                println!("📊 过滤器正在运行...");
                println!("\n按 Enter 键停止并退出\n");

                // 等待用户输入
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).unwrap();

                println!("\n🛑 停止过滤器，正在清理...");

                // 清理过滤器
                for filter_id in filter_ids {
                    let delete_result = FwpmFilterDeleteById0(engine_handle, filter_id);
                    if WIN32_ERROR(delete_result) == ERROR_SUCCESS {
                        println!("✓ 过滤器 {} 已删除", filter_id);
                    } else {
                        println!("⚠️  删除过滤器 {} 失败: {}", filter_id, delete_result);
                    }
                }
            } else {
                println!("❌ 没有成功添加任何过滤器");
            }

            // 关闭引擎
            let result = FwpmEngineClose0(engine_handle);
            if WIN32_ERROR(result) != ERROR_SUCCESS {
                println!("❌ 关闭WFP引擎失败: {}", result);
                return Err(Error::from_win32());
            }
            println!("✓ WFP引擎已关闭");
        } else {
            println!("❌ 打开WFP引擎失败: {} (可能需要管理员权限)", result);
            return Err(Error::from_win32());
        }
    }

    Ok(())
}

// 添加网络过滤器的辅助函数
// 参数说明:
// engine_handle: WFP引擎句柄
// name: 过滤器名称
// layer_key: 过滤层GUID
// app_path: 可选的应用程序路径
unsafe fn add_network_filter(
    engine_handle: HANDLE,
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
    let add_result = unsafe { FwpmFilterAdd0(engine_handle, &filter, None, Some(&mut filter_id)) };

    // 检查添加结果
    if WIN32_ERROR(add_result) == ERROR_SUCCESS {
        Ok(filter_id) // 成功返回过滤器ID
    } else {
        println!("❌ 添加过滤器 '{}' 失败: {}", name, add_result);
        Err(Error::from_win32()) // 失败返回错误
    }
}
