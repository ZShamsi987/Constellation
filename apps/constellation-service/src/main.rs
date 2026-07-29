//! Native Windows Service Control Manager host for `constellationd`.

#[cfg(windows)]
mod windows_host {
    use std::ffi::OsString;
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;

    use anyhow::{Context, Result};
    use windows_service::define_windows_service;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{
        self, ServiceControlHandlerResult, ServiceStatusHandle,
    };
    use windows_service::service_dispatcher;

    const SERVICE_NAME: &str = "Constellation";

    define_windows_service!(ffi_service_main, service_main);

    pub fn run() -> Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .context("start Windows service dispatcher")
    }

    fn service_main(_arguments: Vec<OsString>) {
        let _ignored = run_service();
    }

    fn run_service() -> Result<()> {
        let (stop_sender, stop_receiver) = mpsc::channel();
        let event_handler = move |event| match event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ignored = stop_sender.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
            .context("register Windows service controls")?;
        set_status(
            &status_handle,
            ServiceState::StartPending,
            Duration::from_secs(20),
        )?;
        let mut daemon = start_daemon()?;
        set_status(&status_handle, ServiceState::Running, Duration::ZERO)?;
        supervise(&mut daemon, &stop_receiver)?;
        set_status(
            &status_handle,
            ServiceState::StopPending,
            Duration::from_secs(10),
        )?;
        if daemon.try_wait().context("query daemon state")?.is_none() {
            daemon.kill().context("stop daemon")?;
            let _status = daemon.wait().context("wait for daemon shutdown")?;
        }
        set_status(&status_handle, ServiceState::Stopped, Duration::ZERO)
    }

    fn start_daemon() -> Result<Child> {
        let host = std::env::current_exe().context("locate service host")?;
        let directory = host
            .parent()
            .context("service host has no parent directory")?;
        Command::new(directory.join("constellationd.exe"))
            .args(["--role", "all"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("start constellationd")
    }

    fn supervise(daemon: &mut Child, stop_receiver: &mpsc::Receiver<()>) -> Result<()> {
        loop {
            if stop_receiver.recv_timeout(Duration::from_secs(1)).is_ok() {
                return Ok(());
            }
            if daemon.try_wait().context("check daemon health")?.is_some() {
                anyhow::bail!("constellationd exited unexpectedly");
            }
        }
    }

    fn set_status(
        handle: &ServiceStatusHandle,
        state: ServiceState,
        wait_hint: Duration,
    ) -> Result<()> {
        handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: if state == ServiceState::Running {
                    ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
                } else {
                    ServiceControlAccept::empty()
                },
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint,
                process_id: None,
            })
            .context("publish Windows service status")
    }
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    windows_host::run()
}

#[cfg(not(windows))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("constellation-service is only used by Windows Service Control Manager")
}
