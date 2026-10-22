//! Private logind bus: only public synthetic fixtures use the returned null fd.
use dbus::{
    blocking::Connection,
    channel::{Channel, MatchingReceiver, Sender},
    message::MatchRule,
};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    os::fd::IntoRawFd,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

pub struct LogindFixture {
    address: String,
    daemon: Child,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    _directory: tempfile::TempDir,
}

impl LogindFixture {
    pub fn new() -> Self {
        Self::with_sleep_state(false)
    }

    pub fn with_sleep_state(sleeping: bool) -> Self {
        let directory = tempfile::tempdir().expect("private bus directory");
        let address = format!("unix:path={}", directory.path().join("bus").display());
        let config = directory.path().join("bus.conf");
        // Nix's dbus-daemon --session expects /etc/dbus-1/session.conf, which
        // is not the hosted Ubuntu runner's configuration path. This synthetic
        // bus needs no host configuration, service activation or credentials.
        std::fs::write(
            &config,
            r#"<busconfig>
  <type>session</type>
  <listen>unix:tmpdir=/tmp</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow user="*"/>
    <allow own="*"/>
    <allow send_destination="*"/>
    <allow receive_sender="*"/>
  </policy>
</busconfig>
"#,
        )
        .expect("isolated fixture bus configuration");
        let mut daemon = Command::new("dbus-daemon")
            .arg("--config-file")
            .arg(config)
            .args(["--nofork", "--print-address", "--address", &address])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("private dbus daemon");
        let mut announced = String::new();
        BufReader::new(daemon.stdout.take().expect("bus address pipe"))
            .read_line(&mut announced)
            .expect("bus address");
        assert!(
            !announced.trim().is_empty(),
            "private fixture bus did not announce an address"
        );
        let mut channel = Channel::open_private(announced.trim()).expect("connect fixture bus");
        channel.register().expect("register bus connection");
        let connection = Connection::from(channel);
        connection
            .request_name("org.freedesktop.login1", false, true, false)
            .expect("fixture logind name");
        connection.start_receive(
            MatchRule::new_method_call().with_path("/org/freedesktop/login1"),
            Box::new(move |message, connection| {
                if message.member().map(|member| member.to_string()).as_deref() == Some("Get") {
                    let (interface, property): (String, String) =
                        message.read2().expect("property request");
                    assert_eq!(interface, "org.freedesktop.login1.Manager");
                    assert_eq!(property, "PreparingForSleep");
                    connection
                        .send(
                            message
                                .method_return()
                                .append1(dbus::arg::Variant(sleeping)),
                        )
                        .expect("sleep state response");
                    return true;
                }
                assert_eq!(
                    message.member().map(|member| member.to_string()).as_deref(),
                    Some("Inhibit")
                );
                let (what, _who, _why, mode): (String, String, String, String) =
                    message.read4().expect("inhibitor arguments");
                assert_eq!(what, "sleep");
                assert_eq!(mode, "block");
                let fd = File::open("/dev/null")
                    .expect("synthetic inhibitor fd")
                    .into_raw_fd();
                // SAFETY: ownership of this newly opened descriptor is transferred.
                let fd = unsafe { dbus::arg::OwnedFd::new(fd) };
                connection
                    .send(message.method_return().append1(fd))
                    .expect("inhibitor response");
                true
            }),
        );
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            while !stopping.load(Ordering::Acquire) {
                connection
                    .process(Duration::from_millis(20))
                    .expect("fixture bus processing");
            }
        });
        Self {
            address: announced.trim().to_owned(),
            daemon,
            stop,
            worker: Some(worker),
            _directory: directory,
        }
    }

    pub fn configure(&self, command: &mut Command) {
        command.env("DBUS_SYSTEM_BUS_ADDRESS", &self.address);
    }
}

impl Drop for LogindFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("fixture worker shutdown");
        }
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}
