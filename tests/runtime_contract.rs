//! Regression test for the standalone supervised runtime contract.
//!
//! AIGOSD supervises the packaged layer binary as a long-lived process. A
//! prior hardening pass replaced the startup/run loop with an intentional
//! error exit. This test spawns the built binary, asserts the canonical
//! startup line, verifies liveness, and then terminates the process.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

struct LayerProcess(Child);

impl Drop for LayerProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn standalone_runtime_emits_startup_line_and_stays_alive() {
    let child = Command::new(env!("CARGO_BIN_EXE_zt-aas"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the layer binary");
    let mut layer = LayerProcess(child);
    let stdout = layer.0.stdout.take().expect("capture layer stdout");

    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut first_line = String::new();
        let outcome = match reader.read_line(&mut first_line) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(first_line.trim_end().to_string()),
        };
        let _ = sender.send(outcome);
    });

    let deadline = Instant::now() + Duration::from_secs(30);
    let startup = loop {
        match receiver.try_recv() {
            Ok(Some(line)) => break line,
            Ok(None) => panic!("layer exited without emitting a startup line"),
            Err(mpsc::TryRecvError::Empty) => {
                if layer.0.try_wait().ok().flatten().is_some() {
                    panic!("layer exited without emitting a startup line");
                }
                if Instant::now() > deadline {
                    panic!("timed out waiting for the canonical startup line");
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                panic!("startup reader terminated unexpectedly");
            }
        }
    };

    assert_eq!(startup, "zt-aas layer running...");

    // The supervised layer must remain alive until terminated externally.
    thread::sleep(Duration::from_secs(2));
    assert!(
        layer.0.try_wait().expect("poll the layer process").is_none(),
        "layer exited instead of remaining alive"
    );

    layer.0.kill().expect("terminate the layer after the smoke window");
    let _ = layer.0.wait();
}
