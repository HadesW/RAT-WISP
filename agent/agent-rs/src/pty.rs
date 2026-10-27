// Pseudo-terminal for the Type2 shell channel: ConPTY on Windows, a POSIX
// pty on Linux. A real terminal gives the operator what a pipe cannot:
// remote echo, line editing, Ctrl+C/job control and resize.
#[cfg(windows)]
mod imp {
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicBool, Ordering};

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Console::{
        ClosePseudoConsole, CreatePseudoConsole, ResizePseudoConsole, SetConsoleCtrlHandler, COORD,
        HPCON,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
        TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
        EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
        PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
    };

    pub struct Pty {
        input: File,  // our write end -> ConPTY reads it
        output: File, // ConPTY writes it -> our read end
        hpc: HPCON,
        proc: HANDLE,
        closed: AtomicBool,
    }

    // SAFETY: Win32 handles are process-wide kernel objects; the struct only
    // carries them between the reader/writer/control threads.
    unsafe impl Send for Pty {}
    unsafe impl Sync for Pty {}

    impl Pty {
        pub fn spawn(cols: u16, rows: u16) -> io::Result<(Pty, &'static str)> {
            unsafe {
                // Never hand a parent's "ignore Ctrl+C" flag to the shell:
                // launchers (IDEs, schedulers) often set it, and the shell
                // would then be unable to interrupt anything.
                SetConsoleCtrlHandler(None, 0);
                let mut in_read: HANDLE = null_mut();
                let mut in_write: HANDLE = null_mut();
                let mut out_read: HANDLE = null_mut();
                let mut out_write: HANDLE = null_mut();
                if CreatePipe(&mut in_read, &mut in_write, null(), 0) == 0 {
                    return Err(io::Error::last_os_error());
                }
                if CreatePipe(&mut out_read, &mut out_write, null(), 0) == 0 {
                    let e = io::Error::last_os_error();
                    CloseHandle(in_read);
                    CloseHandle(in_write);
                    return Err(e);
                }
                let mut hpc: HPCON = 0;
                let hr = CreatePseudoConsole(
                    COORD {
                        X: cols as i16,
                        Y: rows as i16,
                    },
                    in_read,
                    out_write,
                    0,
                    &mut hpc,
                );
                // ConPTY owns the pty-side ends from now on.
                CloseHandle(in_read);
                CloseHandle(out_write);
                if hr < 0 {
                    CloseHandle(in_write);
                    CloseHandle(out_read);
                    return Err(io::Error::other(format!("CreatePseudoConsole HRESULT {hr:#x}")));
                }

                let mut size = 0usize;
                InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size);
                let words = size.div_ceil(size_of::<usize>()).max(1);
                let mut attrs = vec![0usize; words];
                let list = attrs.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
                let cleanup = |hpc: HPCON, i: HANDLE, o: HANDLE| {
                    ClosePseudoConsole(hpc);
                    CloseHandle(i);
                    CloseHandle(o);
                };
                if InitializeProcThreadAttributeList(list, 1, 0, &mut size) == 0 {
                    let e = io::Error::last_os_error();
                    cleanup(hpc, in_write, out_read);
                    return Err(e);
                }
                let ok = UpdateProcThreadAttribute(
                    list,
                    0,
                    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                    // The attribute consumes the HPCON value itself as lpValue,
                    // not a pointer to a local copy (see Microsoft's EchoCon).
                    hpc as *const _,
                    size_of::<HPCON>(),
                    null_mut(),
                    null(),
                );
                if ok == 0 {
                    let e = io::Error::last_os_error();
                    DeleteProcThreadAttributeList(list);
                    cleanup(hpc, in_write, out_read);
                    return Err(e);
                }

                let mut si: STARTUPINFOEXW = zeroed();
                si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
                // Invalid std handles keep the child from inheriting our own
                // (possibly redirected) stdio instead of the pty's console.
                si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
                si.StartupInfo.hStdInput = INVALID_HANDLE_VALUE;
                si.StartupInfo.hStdOutput = INVALID_HANDLE_VALUE;
                si.StartupInfo.hStdError = INVALID_HANDLE_VALUE;
                si.lpAttributeList = list;
                let mut pi: PROCESS_INFORMATION = zeroed();
                // UTF-8 console for Chinese/English; /Q silences command echo.
                let mut cmd: Vec<u16> = OsStr::new("cmd.exe /Q /K chcp 65001>nul")
                    .encode_wide()
                    .chain(Some(0))
                    .collect();
                let ok = CreateProcessW(
                    null(),
                    cmd.as_mut_ptr(),
                    null(),
                    null(),
                    0,
                    EXTENDED_STARTUPINFO_PRESENT,
                    null(),
                    null(),
                    &si.StartupInfo as *const STARTUPINFOW,
                    &mut pi,
                );
                DeleteProcThreadAttributeList(list);
                drop(attrs);
                if ok == 0 {
                    let e = io::Error::last_os_error();
                    cleanup(hpc, in_write, out_read);
                    return Err(e);
                }
                CloseHandle(pi.hThread);

                let pty = Pty {
                    input: File::from_raw_handle(in_write as RawHandle),
                    output: File::from_raw_handle(out_read as RawHandle),
                    hpc,
                    proc: pi.hProcess,
                    closed: AtomicBool::new(false),
                };
                Ok((pty, "cmd"))
            }
        }

        pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            let mut f = &self.output;
            f.read(buf)
        }

        pub fn write_all(&self, data: &[u8]) -> io::Result<()> {
            let mut f = &self.input;
            f.write_all(data)?;
            f.flush()
        }

        pub fn resize(&self, cols: u16, rows: u16) {
            if self.closed.load(Ordering::Relaxed) {
                return;
            }
            let size = COORD {
                X: cols as i16,
                Y: rows as i16,
            };
            unsafe {
                ResizePseudoConsole(self.hpc, size);
            }
        }

        pub fn kill(&self) {
            if self.closed.swap(true, Ordering::SeqCst) {
                return;
            }
            unsafe {
                TerminateProcess(self.proc, 1);
                WaitForSingleObject(self.proc, 1000);
                CloseHandle(self.proc);
                ClosePseudoConsole(self.hpc);
            }
        }
    }

    impl Drop for Pty {
        fn drop(&mut self) {
            self.kill();
        }
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::ffi::CStr;
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::fd::{FromRawFd, RawFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::sync::Mutex;

    use libc::{c_char, c_int};

    extern "C" {
        fn posix_openpt(flags: c_int) -> c_int;
        fn grantpt(fd: c_int) -> c_int;
        fn unlockpt(fd: c_int) -> c_int;
        fn ptsname_r(fd: c_int, buf: *mut c_char, len: usize) -> c_int;
    }

    pub struct Pty {
        master: File,
        fd: RawFd,
        child: Mutex<Option<Child>>,
    }

    impl Pty {
        pub fn spawn(cols: u16, rows: u16) -> io::Result<(Pty, &'static str)> {
            unsafe {
                let fd = posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                if grantpt(fd) != 0 || unlockpt(fd) != 0 {
                    let e = io::Error::last_os_error();
                    libc::close(fd);
                    return Err(e);
                }
                // The shell must never inherit the master side.
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                let mut name = [0 as c_char; 256];
                if ptsname_r(fd, name.as_mut_ptr(), name.len()) != 0 {
                    let e = io::Error::last_os_error();
                    libc::close(fd);
                    return Err(e);
                }
                let path = CStr::from_ptr(name.as_ptr()).to_string_lossy().into_owned();
                let master = File::from_raw_fd(fd);
                let ws = libc::winsize {
                    ws_row: rows,
                    ws_col: cols,
                    ws_xpixel: 0,
                    ws_ypixel: 0,
                };
                libc::ioctl(fd, libc::TIOCSWINSZ as _, &ws);

                let slave = OpenOptions::new().read(true).write(true).open(&path)?;
                let (shell, label) = if std::path::Path::new("/bin/bash").exists() {
                    ("/bin/bash", "bash")
                } else {
                    ("/bin/sh", "sh")
                };
                let mut cmd = Command::new(shell);
                cmd.arg("-i")
                    .env("TERM", "xterm-256color")
                    .env("COLORTERM", "truecolor")
                    .stdin(Stdio::from(slave.try_clone()?))
                    .stdout(Stdio::from(slave.try_clone()?))
                    .stderr(Stdio::from(slave));
                // Keep an existing UTF-8 locale; otherwise force C.UTF-8.
                let utf8 = std::env::var("LC_ALL")
                    .or_else(|_| std::env::var("LANG"))
                    .ok()
                    .filter(|v| {
                        let l = v.to_ascii_lowercase();
                        l.contains("utf-8") || l.contains("utf8")
                    })
                    .unwrap_or_else(|| "C.UTF-8".to_string());
                cmd.env("LANG", &utf8).env("LC_ALL", &utf8);
                cmd.pre_exec(|| {
                    if libc::setsid() < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
                let child = cmd.spawn()?;
                Ok((
                    Pty {
                        master,
                        fd,
                        child: Mutex::new(Some(child)),
                    },
                    label,
                ))
            }
        }

        pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            let mut f = &self.master;
            f.read(buf)
        }

        pub fn write_all(&self, data: &[u8]) -> io::Result<()> {
            let mut f = &self.master;
            f.write_all(data)?;
            f.flush()
        }

        pub fn resize(&self, cols: u16, rows: u16) {
            let ws = libc::winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            unsafe {
                libc::ioctl(self.fd, libc::TIOCSWINSZ as _, &ws);
            }
        }

        pub fn kill(&self) {
            if let Some(mut c) = self.child.lock().unwrap().take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    impl Drop for Pty {
        fn drop(&mut self) {
            self.kill();
        }
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod imp {
    use std::io;

    pub struct Pty;

    impl Pty {
        pub fn spawn(_cols: u16, _rows: u16) -> io::Result<(Pty, &'static str)> {
            Err(io::Error::other("pty unsupported on this platform"))
        }
        pub fn read(&self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("pty unsupported"))
        }
        pub fn write_all(&self, _data: &[u8]) -> io::Result<()> {
            Err(io::Error::other("pty unsupported"))
        }
        pub fn resize(&self, _cols: u16, _rows: u16) {}
        pub fn kill(&self) {}
    }
}

pub use imp::Pty;
