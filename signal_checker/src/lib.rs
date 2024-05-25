use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::flag;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

static RECEIVED_SIGNAL: AtomicBool = AtomicBool::new(false);

pub fn handle_signals() {
    let term = Arc::new(AtomicBool::new(false));
    let term_clone = Arc::clone(&term);
    flag::register(SIGINT, term_clone).expect("Error setting SIGINT handler");
    let term_clone = Arc::clone(&term);
    flag::register(SIGTERM, term_clone).expect("Error setting SIGTERM handler");
    if term.load(Ordering::Relaxed) {
        RECEIVED_SIGNAL.store(true, Ordering::Relaxed);
    }
}

pub fn signal_received() -> bool {
    RECEIVED_SIGNAL.load(Ordering::Relaxed)
}
