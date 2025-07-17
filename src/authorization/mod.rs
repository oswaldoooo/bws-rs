pub mod v2;
pub mod v4;
pub trait AccesskeyStore:Send+Sync {
    fn get<'a>(
        &'a self,
        accesskey: &'a str,
    ) -> std::pin::Pin<Box<dyn 'a+Send+Sync+std::future::Future<Output = Result<Option<String>, String>>>>;
}
