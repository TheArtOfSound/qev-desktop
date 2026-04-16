// Prevents a console window from appearing on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// QEV — desktop binary shim.
//
// All real logic lives in lib.rs so that both the desktop binary and
// the Android `cdylib`/`staticlib` can share the same code. See
// lib.rs for the full module docs.

fn main() {
    qev::run();
}
