use bws_rs::service::s3::*;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    let sg = Arc::new(StaticGetter {});
    let r = axum::Router::new()
        .layer(axum::middleware::from_fn(bws_rs::http::axum::handle_fn))
        .layer(axum::middleware::from_fn(
            bws_rs::http::axum::handle_authorization_middleware,
        ))
        .layer(axum::Extension(
            sg.clone() as Arc<dyn ListBucketHandler + Send + Sync>
        ))
        .layer(axum::Extension(
            sg.clone() as Arc<dyn GetObjectHandler + Send + Sync>
        ))
        .layer(axum::Extension(
            sg.clone() as Arc<dyn GetBucketLocationHandler + Send + Sync>
        ))
        .layer(axum::Extension(
            sg.clone() as Arc<dyn HeadHandler + Send + Sync>
        ))
        .layer(axum::Extension(sg.clone()
            as Arc<
                dyn bws_rs::authorization::AccesskeyStore + Send + Sync,
            >));
    let l = tokio::net::TcpListener::bind("127.0.0.1:9900").await?;
    axum::serve(l, r).await?;
    Ok(())
}

struct StaticGetter {}
impl bws_rs::authorization::AccesskeyStore for StaticGetter {
    fn get<'a>(
        &'a self,
        accesskey: &'a str,
    ) -> std::pin::Pin<
        Box<dyn 'a + Send + Sync + std::future::Future<Output = Result<Option<String>, String>>>,
    > {
        Box::pin(async move { Ok(Some(format!("{accesskey}12345"))) })
    }
}
impl ListBucketHandler for StaticGetter {
    fn handle<'a>(
        &'a self,
        _opt: &'a bws_rs::service::s3::ListBucketsOption,
    ) -> std::pin::Pin<
        Box<
            dyn 'a
                + Send
                + std::future::Future<Output = Result<Vec<bws_rs::service::s3::Bucket>, String>>,
        >,
    > {
        Box::pin(async move {
            Ok(vec![bws_rs::service::s3::Bucket {
                name: "itest".to_string(),
                creation_date: chrono::Utc::now().to_rfc3339(),
                bucket_region: "us-east-1".to_string(),
            }])
        })
    }
}
static OBJECT_CONTENT: &str = "hello world!";
static OBJECT_MD5: &str = "5eb63bbbe01eeed093cb22bb8f5acdc3";
impl HeadHandler for StaticGetter {
    fn lookup<'a>(
        &self,
        _bucket: &str,
        _object: &str,
    ) -> std::pin::Pin<
        Box<
            dyn 'a
                + Send
                + Sync
                + std::future::Future<Output = Result<Option<HeadObjectResult>, Error>>,
        >,
    > {
        Box::pin(async move {
            let mut obj = HeadObjectResult::default();
            obj.etag = Some(OBJECT_MD5.to_string());
            obj.content_length = Some(OBJECT_CONTENT.len());
            obj.last_modified = Some(
                chrono::Utc::now()
                    .format("%a, %d %b %Y %H:%M:%S GMT")
                    .to_string(),
            );
            Ok(Some(obj))
        })
    }
}
impl GetObjectHandler for StaticGetter {
    fn handle<'a>(
        &'a self,
        _bucket: &str,
        _object: &str,
        _opt: bws_rs::service::s3::GetObjectOption,
        out: tokio::sync::Mutex<
            std::pin::Pin<Box<dyn 'a + Send + bws_rs::utils::io::PollWrite + Unpin>>,
        >,
    ) -> std::pin::Pin<Box<dyn 'a + Send + std::future::Future<Output = Result<(), String>>>> {
        Box::pin(async move {
            let _ = out.lock().await.poll_write(OBJECT_CONTENT.as_bytes()).await;
            todo!()
        })
    }
}
impl GetBucketLocationHandler for StaticGetter {}
