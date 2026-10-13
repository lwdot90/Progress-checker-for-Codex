pub mod client;
pub mod protocol;
#[cfg(unix)]
pub mod server;
#[cfg(not(unix))]
pub mod server {
    pub async fn serve(
        _root: &std::path::Path,
        _state: &std::path::Path,
        _shutdown: tokio_util::sync::CancellationToken,
    ) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "native Windows protected service transport and human approval are not qualified",
        ))
    }
}

pub use server::serve;
