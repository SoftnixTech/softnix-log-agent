#[cfg(windows)]
pub mod eventlog;
// Pure-Rust Event Log XML parser: used by `eventlog` on Windows, and compiled
// in test builds everywhere so its tests run in every CI job and locally.
#[cfg(any(windows, test))]
mod eventlog_xml;
pub mod file;
pub mod syslog;
