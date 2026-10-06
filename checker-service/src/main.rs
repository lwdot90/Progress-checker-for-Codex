use std::path::PathBuf;
use tokio_util::sync::CancellationToken;
#[tokio::main]
async fn main() {
    let mut root = None;
    let mut state = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => root = args.next().map(PathBuf::from),
            "--state-dir" => state = args.next().map(PathBuf::from),
            "--help" => {
                println!("progress-checker-service --root PROJECT --state-dir PRIVATE_DIRECTORY");
                return;
            }
            _ => {
                eprintln!("unknown argument: {arg}");
                std::process::exit(2)
            }
        }
    }
    let (Some(root), Some(state)) = (root, state) else {
        eprintln!("--root and --state-dir are required");
        std::process::exit(2)
    };
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    tokio::spawn(async move {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {_ = term.recv()=>{},_ = tokio::signal::ctrl_c()=>{}}
        signal.cancel();
    });
    if let Err(error) = checker_service::server::serve(&root, &state, shutdown).await {
        eprintln!("{error}");
        std::process::exit(1)
    }
}
