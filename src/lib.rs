pub mod authorization;
pub mod error;
pub mod service;
pub mod utils;
pub mod http;
pub type GenericResult<T> = Result<T, String>;
#[cfg(target_family = "unix")]
pub async fn random(buff: &mut [u8]) -> Result<usize, std::io::Error> {
    use tokio::io::AsyncReadExt;

    let mut fd = tokio::fs::OpenOptions::new()
        .read(true)
        .open("/dev/urandom")
        .await?;
    let ret = fd.read_exact(buff).await?;
    Ok(ret)
}
#[macro_export]
macro_rules! random_str {
    ($need_size:expr) => {
        {
            let mut buff=[0u8;$need_size];
            let _=crate::random(&mut buff).await;
            hex::encode(buff)
        }
    };
}
