//! OS service integration: systemd on Linux, Windows Service on Windows.

use anyhow::Result;

#[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
pub const SERVICE_NAME: &str = "softnix-log-agent";

// ---------------------------------------------------------------------------
// Linux (systemd)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub mod platform {
    use super::SERVICE_NAME;
    use anyhow::{bail, Context, Result};
    use std::process::Command;

    const UNIT_PATH: &str = "/etc/systemd/system/softnix-log-agent.service";

    fn unit_file(exe: &str, config: &str) -> String {
        format!(
            r#"[Unit]
Description=Softnix Log Agent
Documentation=https://www.softnix.co.th
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe} run --config {config}
Restart=on-failure
RestartSec=5
# Least privilege hardening
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=/var/lib/softnix-log-agent
LimitNOFILE=65536
MemoryMax=512M

[Install]
WantedBy=multi-user.target
"#
        )
    }

    fn systemctl(args: &[&str]) -> Result<()> {
        let status = Command::new("systemctl")
            .args(args)
            .status()
            .context("cannot run systemctl (is this a systemd host? are you root?)")?;
        if !status.success() {
            bail!("systemctl {} failed with {status}", args.join(" "));
        }
        Ok(())
    }

    pub fn install(config: &str) -> Result<()> {
        let exe = std::env::current_exe()?.display().to_string();
        std::fs::write(UNIT_PATH, unit_file(&exe, config))
            .with_context(|| format!("cannot write {UNIT_PATH} (run as root)"))?;
        std::fs::create_dir_all("/var/lib/softnix-log-agent").ok();
        systemctl(&["daemon-reload"])?;
        systemctl(&["enable", SERVICE_NAME])?;
        println!("installed systemd unit {UNIT_PATH} (enabled at boot)");
        println!("start it with: systemctl start {SERVICE_NAME}");
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let _ = systemctl(&["stop", SERVICE_NAME]);
        let _ = systemctl(&["disable", SERVICE_NAME]);
        std::fs::remove_file(UNIT_PATH).ok();
        systemctl(&["daemon-reload"])?;
        println!("removed {UNIT_PATH}");
        Ok(())
    }

    pub fn start() -> Result<()> {
        systemctl(&["start", SERVICE_NAME])
    }
    pub fn stop() -> Result<()> {
        systemctl(&["stop", SERVICE_NAME])
    }
    pub fn restart() -> Result<()> {
        systemctl(&["restart", SERVICE_NAME])
    }
}

// ---------------------------------------------------------------------------
// Windows (Service Control Manager)
// ---------------------------------------------------------------------------

#[cfg(windows)]
pub mod platform {
    use super::SERVICE_NAME;
    use anyhow::{Context, Result};
    use std::ffi::OsString;
    use windows_service::service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    pub fn install(config: &str) -> Result<()> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .context("cannot connect to service manager (run as Administrator)")?;
        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from("Softnix Log Agent"),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: std::env::current_exe()?,
            launch_arguments: vec![
                OsString::from("service-run"),
                OsString::from("--config"),
                OsString::from(config),
            ],
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        };
        manager.create_service(&info, ServiceAccess::QUERY_STATUS)?;
        println!("installed Windows service {SERVICE_NAME} (auto start)");
        println!("start it with: softnix-log-agent service start");
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = manager.open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
        )?;
        let _ = service.stop();
        service.delete()?;
        println!("removed Windows service {SERVICE_NAME}");
        Ok(())
    }

    pub fn start() -> Result<()> {
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = manager.open_service(SERVICE_NAME, ServiceAccess::START)?;
        service.start::<&str>(&[])?;
        println!("service started");
        Ok(())
    }

    pub fn stop() -> Result<()> {
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = manager.open_service(SERVICE_NAME, ServiceAccess::STOP)?;
        service.stop()?;
        println!("service stopped");
        Ok(())
    }

    pub fn restart() -> Result<()> {
        stop().ok();
        std::thread::sleep(std::time::Duration::from_secs(2));
        start()
    }
}

// ---------------------------------------------------------------------------
// Other platforms (e.g. macOS for development)
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "linux", windows)))]
pub mod platform {
    use anyhow::{bail, Result};

    pub fn install(_config: &str) -> Result<()> {
        bail!("service management is supported on Linux (systemd) and Windows only; run in foreground with `softnix-log-agent run`")
    }
    pub fn uninstall() -> Result<()> {
        bail!("service management is supported on Linux and Windows only")
    }
    pub fn start() -> Result<()> {
        bail!("service management is supported on Linux and Windows only")
    }
    pub fn stop() -> Result<()> {
        bail!("service management is supported on Linux and Windows only")
    }
    pub fn restart() -> Result<()> {
        bail!("service management is supported on Linux and Windows only")
    }
}

pub fn install(config: &str) -> Result<()> {
    platform::install(config)
}
pub fn uninstall() -> Result<()> {
    platform::uninstall()
}
pub fn start() -> Result<()> {
    platform::start()
}
pub fn stop() -> Result<()> {
    platform::stop()
}
pub fn restart() -> Result<()> {
    platform::restart()
}
