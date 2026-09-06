//! Interactive, hidden secret entry for `akey set`, with a piped-input
//! fast path that is byte-for-byte the old behavior.
//!
//! `akey set <name>` used to `read_to_string` stdin to EOF and echo the
//! secret. Interactively that hangs (Enter is not EOF) and shows the key.
//! This module makes the read **mode-aware**:
//!
//! * **stdin is a TTY (interactive):** print a prompt to stderr, read one
//!   line with terminal echo disabled (Enter finishes; the secret is never
//!   shown), then print a trailing newline to stderr.
//! * **stdin is not a TTY (piped/redirected):** read to EOF exactly as
//!   before: `Get-Content key.txt | akey set work` and password-manager
//!   pipes are unchanged.
//!
//! The no-echo terminal mode is toggled with the platform's own FFI (no
//! third-party crate, mirroring `rawterm-rs`'s approach) and is **always
//! restored** via a [`Drop`] guard, so a panic or early return can never
//! leave the user's terminal with echo off.
//!
//! Nothing here logs, prints, or returns the secret except as the return
//! value of [`read_secret`] / [`read_secret_from`], which flows only into
//! the vault store path in `main`.

use std::io::{self, Read};

/// Read a secret for `label` from `stdin`, mode-aware.
///
/// This is the entry point `main` calls. It detects whether stdin is a
/// terminal and dispatches to the hidden interactive read or the piped
/// read-to-EOF path. The returned `String` is raw input; the caller cleans
/// it (trim + BOM strip) via `store::clean_secret_input`, exactly as before.
pub fn read_secret(label: &str) -> io::Result<String> {
    read_secret_from(&mut io::stdin(), sys::stdin_is_tty(), label)
}

/// The testable seam: given a reader, whether that reader is a TTY, and a
/// prompt label, produce the raw secret input.
///
/// * `is_tty == false` (piped/redirected): read the reader to EOF, the
///   verbatim pre-0.2.1 behavior.
/// * `is_tty == true` (interactive): prompt on stderr and read one hidden
///   line from the real console (the `reader` argument is unused in this
///   branch (a live TTY reads from the OS console handle, not a captured
///   stream), which is exactly why tests exercise the piped branch and the
///   FFI is validated by the restore guard + review).
pub fn read_secret_from<R: Read>(reader: &mut R, is_tty: bool, label: &str) -> io::Result<String> {
    if is_tty {
        read_hidden_line(label)
    } else {
        let mut input = String::new();
        reader.read_to_string(&mut input)?;
        Ok(input)
    }
}

/// Prompt on stderr and read a single line from the console with echo
/// disabled, restoring the terminal mode on every exit path.
fn read_hidden_line(label: &str) -> io::Result<String> {
    eprint!("Enter API key for {label:?} (input hidden): ");
    // The guard disables echo now and restores the original mode when it
    // drops: on success, on `?`, or on panic.
    let mut guard = sys::NoEcho::enter()?;
    let line = guard.read_line();
    // The user's Enter was not echoed; move the cursor to the next line so
    // the following output is not glued to the prompt.
    eprintln!();
    line
}

// --- platform edge ---------------------------------------------------------
//
// Our own minimal FFI, mirroring `rawterm-rs` but without depending on it:
// * `stdin_is_tty()`: TTY detection.
// * `NoEcho`: a guard that disables echo on `enter()` and restores the
//   saved mode on `Drop`, and reads one line while echo is off.

#[cfg(windows)]
mod sys {
    use std::ffi::c_void;
    use std::io;

    type Handle = *mut c_void;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(which: u32) -> Handle;
        fn GetConsoleMode(handle: Handle, mode: *mut u32) -> i32;
        fn SetConsoleMode(handle: Handle, mode: u32) -> i32;
        fn ReadConsoleW(
            handle: Handle,
            buffer: *mut u16,
            to_read: u32,
            read: *mut u32,
            reserved: *mut c_void,
        ) -> i32;
    }

    const STD_INPUT_HANDLE: u32 = -10i32 as u32;
    const INVALID_HANDLE: Handle = -1isize as Handle;

    const ENABLE_LINE_INPUT: u32 = 0x0002;
    const ENABLE_ECHO_INPUT: u32 = 0x0004;

    fn stdin_handle() -> Handle {
        // SAFETY: GetStdHandle takes a well-known constant and returns a
        // handle (or an invalid/null sentinel the callers check); no pointers.
        unsafe { GetStdHandle(STD_INPUT_HANDLE) }
    }

    /// True iff stdin is a console: `GetConsoleMode` succeeds only for a
    /// real console handle (it fails for a pipe or a redirected file).
    pub fn stdin_is_tty() -> bool {
        let h = stdin_handle();
        if h.is_null() || h == INVALID_HANDLE {
            return false;
        }
        let mut mode = 0u32;
        // SAFETY: `h` is a non-null, non-invalid handle (checked above);
        // `&mut mode` is a valid pointer to a live u32 for the call.
        unsafe { GetConsoleMode(h, &mut mode) != 0 }
    }

    /// Console with `ENABLE_ECHO_INPUT` cleared; restores the saved mode on
    /// drop. `ENABLE_LINE_INPUT` is kept so the console still buffers to
    /// Enter, so `ReadConsoleW` returns one line.
    pub struct NoEcho {
        handle: Handle,
        saved: u32,
    }

    impl NoEcho {
        pub fn enter() -> io::Result<NoEcho> {
            let handle = stdin_handle();
            if handle.is_null() || handle == INVALID_HANDLE {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "no console handle",
                ));
            }
            let mut saved = 0u32;
            // SAFETY: `handle` is non-null/non-invalid (checked above);
            // `&mut saved` is a valid pointer to a live u32 for the call.
            if unsafe { GetConsoleMode(handle, &mut saved) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // Keep line buffering (so Enter finishes the read); drop echo.
            let hidden = (saved | ENABLE_LINE_INPUT) & !ENABLE_ECHO_INPUT;
            // SAFETY: `handle` is the same valid console handle; `hidden` is a
            // plain mode bitmask. On failure we return before storing the
            // guard, so nothing needs restoring (the mode was not changed).
            if unsafe { SetConsoleMode(handle, hidden) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(NoEcho { handle, saved })
        }

        /// Read one line (through the terminating Enter) as UTF-8, without
        /// the trailing CR/LF; `store::clean_secret_input` trims anyway,
        /// but this keeps the return value a single clean line.
        pub fn read_line(&mut self) -> io::Result<String> {
            let mut units = [0u16; 4096];
            let mut read = 0u32;
            // SAFETY: `self.handle` is a valid console handle from `enter()`.
            // `units` is a live [u16; 4096] on the stack; `units.len() as u32`
            // (4096) is the buffer capacity in code units and fits in u32.
            // The OS writes at most that many units and reports the count in
            // `read` (a live u32), so the later `&units[..read as usize]`
            // slice is in bounds. The reserved parameter is documented NULL.
            let ok = unsafe {
                ReadConsoleW(
                    self.handle,
                    units.as_mut_ptr(),
                    units.len() as u32,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut s = String::from_utf16_lossy(&units[..read as usize]);
            while s.ends_with('\n') || s.ends_with('\r') {
                s.pop();
            }
            Ok(s)
        }
    }

    impl Drop for NoEcho {
        fn drop(&mut self) {
            // SAFETY: `self.handle` is the valid console handle captured in
            // `enter()`; `self.saved` is the exact mode read there. Restoring
            // it is idempotent and cannot leave the console half-configured.
            unsafe {
                SetConsoleMode(self.handle, self.saved);
            }
        }
    }
}

#[cfg(unix)]
mod sys {
    use std::io::{self, BufRead};

    const STDIN_FD: i32 = 0;
    const TCSANOW: i32 = 0;

    // termios layout and the ECHO flag are per-OS; mirror rawterm-rs's plat
    // split. We only ever clear/restore ECHO, so we need just that flag and
    // the struct size, but we save and restore the whole struct verbatim.
    #[cfg(target_os = "linux")]
    mod plat {
        pub type Flag = u32;
        pub const NCCS: usize = 32;
        pub const ECHO: Flag = 0o0010;

        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct Termios {
            pub c_iflag: Flag,
            pub c_oflag: Flag,
            pub c_cflag: Flag,
            pub c_lflag: Flag,
            pub c_line: u8,
            pub c_cc: [u8; NCCS],
            pub c_ispeed: Flag,
            pub c_ospeed: Flag,
        }
    }

    #[cfg(target_os = "macos")]
    mod plat {
        pub type Flag = u64;
        pub const NCCS: usize = 20;
        pub const ECHO: Flag = 0x0008;

        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct Termios {
            pub c_iflag: Flag,
            pub c_oflag: Flag,
            pub c_cflag: Flag,
            pub c_lflag: Flag,
            pub c_cc: [u8; NCCS],
            pub c_ispeed: Flag,
            pub c_ospeed: Flag,
        }
    }

    use plat::{Termios, ECHO};

    extern "C" {
        fn isatty(fd: i32) -> i32;
        fn tcgetattr(fd: i32, termios: *mut Termios) -> i32;
        fn tcsetattr(fd: i32, action: i32, termios: *const Termios) -> i32;
    }

    pub fn stdin_is_tty() -> bool {
        // SAFETY: isatty takes an fd by value and returns 1/0; no pointers.
        unsafe { isatty(STDIN_FD) == 1 }
    }

    /// termios with `ECHO` cleared; restores the saved termios on drop.
    /// `ICANON` is left on, so the kernel still delivers a full line on
    /// Enter and we read it with the standard line reader.
    pub struct NoEcho {
        saved: Termios,
    }

    impl NoEcho {
        pub fn enter() -> io::Result<NoEcho> {
            // SAFETY: Termios is a plain C struct of integer/array fields, so
            // the all-zeros bit pattern is a valid (if meaningless) value;
            // tcgetattr overwrites it immediately below before any use.
            let mut saved = unsafe { std::mem::zeroed::<Termios>() };
            // SAFETY: `&mut saved` points to a live, correctly-laid-out
            // Termios for the duration of the call; STDIN_FD (0) is open.
            if unsafe { tcgetattr(STDIN_FD, &mut saved) } != 0 {
                return Err(io::Error::last_os_error());
            }
            let mut hidden = saved;
            hidden.c_lflag &= !ECHO;
            // SAFETY: `&hidden` points to a live Termios derived from the one
            // tcgetattr filled; TCSANOW is a valid action. On failure we
            // return before storing the guard, so nothing needs restoring
            // (tcsetattr made no change when it reports failure).
            if unsafe { tcsetattr(STDIN_FD, TCSANOW, &hidden) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(NoEcho { saved })
        }

        pub fn read_line(&mut self) -> io::Result<String> {
            let mut line = String::new();
            io::stdin().lock().read_line(&mut line)?;
            while line.ends_with('\n') || line.ends_with('\r') {
                line.pop();
            }
            Ok(line)
        }
    }

    impl Drop for NoEcho {
        fn drop(&mut self) {
            // SAFETY: `self.saved` is the valid Termios captured by a
            // successful tcgetattr in `enter()`; STDIN_FD (0) is open for the
            // process lifetime. Restoring it cannot leave the tty misconfigured.
            unsafe {
                tcsetattr(STDIN_FD, TCSANOW, &self.saved);
            }
        }
    }
}
