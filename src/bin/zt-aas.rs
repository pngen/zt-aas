fn main() {
    eprintln!(
        "{} is a library policy runtime, not a standalone OS sandbox; integrate it into an isolated supervisor",
        env!("CARGO_PKG_NAME")
    );
    std::process::exit(2);
}
