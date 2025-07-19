use axum::response::IntoResponse;
use futures::StreamExt;
use tokio::io::AsyncWriteExt;

use crate::service::s3::VRequest;

pub struct Request {
    request: axum::http::Request<axum::body::Body>,
    query: Option<std::collections::HashMap<String, String>>,
}
impl From<Request> for axum::extract::Request {
    fn from(val: Request) -> Self {
        val.request
    }
}
impl From<axum::extract::Request> for Request {
    fn from(value: axum::extract::Request) -> Self {
        let query = value.uri().query().map(|query| {
            query
                .split("&")
                .map(|item| {
                    item.find("=")
                        .map_or((item.to_string(), "".to_string()), |pos| {
                            (item[..pos].to_string(), item[pos + 1..].to_string())
                        })
                })
                .collect::<std::collections::HashMap<String, String>>()
        });
        Self {
            request: value,
            query,
        }
    }
}
impl crate::authorization::v4::VHeader for Request {
    fn get_header(&self, key: &str) -> Option<String> {
        self.request
            .headers()
            .get(key)
            .and_then(|value| value.to_str().ok().map(|value| value.to_string()))
    }

    fn set_header(&mut self, key: &str, val: &str) {
        let key: axum::http::HeaderName = key.to_string().parse().unwrap();
        self.request.headers_mut().insert(key, val.parse().unwrap());
    }

    fn delete_header(&mut self, key: &str) {
        self.request.headers_mut().remove(key);
    }

    fn rng_header(&self, mut cb: impl FnMut(&str, &str) -> bool) {
        for (k, v) in self.request.headers().iter() {
            if !cb(k.as_str(), unsafe {
                std::str::from_utf8_unchecked(v.as_bytes())
            }) {
                return;
            }
        }
    }
}
impl crate::service::s3::VRequest for Request {
    fn method(&self) -> String {
        self.request.method().as_str().to_string()
    }

    fn url_path(&self) -> String {
        self.request.uri().path().to_string()
    }

    fn get_query(&self, k: &str) -> Option<String> {
        self.query
            .as_ref()
            .and_then(|query| query.get(k))
            .map(|v| v.to_string())
    }

    fn all_query(&self, mut cb: impl FnMut(&str, &str) -> bool) {
        self.query
            .as_ref()
            .map(|query| query.iter().all(|(k, v)| cb(k, v)));
    }
}
impl crate::service::s3::VRequestPlus for Request {
    fn body<'a>(
        self,
    ) -> std::pin::Pin<
        Box<dyn 'a + Send + std::future::Future<Output = Result<Vec<u8>, std::io::Error>>>,
    > {
        Box::pin(async move {
            let mut bodystream = self.request.into_body().into_data_stream();
            let mut ret = Vec::new();
            while let Some(bodystream) = bodystream.next().await {
                let bytes = bodystream.map_err(std::io::Error::other)?;
                ret.extend_from_slice(bytes.iter().as_slice());
            }
            Ok(ret)
        })
    }
}
pub struct BodyReader(axum_core::body::BodyDataStream);
impl crate::utils::io::PollRead for BodyReader {
    fn poll_read<'a>(
        &'a mut self,
    ) -> std::pin::Pin<
        Box<dyn 'a + Send + std::future::Future<Output = Result<Option<Vec<u8>>, String>>>,
    > {
        Box::pin(async move {
            let data = self.0.next().await;
            match data {
                Some(ret) => match ret {
                    Ok(ret) => Ok(Some(ret.to_vec())),
                    Err(err) => Err(err.to_string()),
                },
                None => Ok(None),
            }
        })
    }
}
impl crate::service::s3::BodyReader for Request {
    type BodyReader = BodyReader;

    fn get_body_reader<'b>(
        self,
    ) -> std::pin::Pin<
        Box<dyn 'b + Send + std::future::Future<Output = Result<Self::BodyReader, String>>>,
    > {
        Box::pin(async move {
            let ret: axum::body::Body = self.request.into_body();
            Ok(BodyReader(ret.into_data_stream()))
        })
    }
}
pub struct HeaderWarp(axum::http::HeaderMap);
impl crate::authorization::v4::VHeader for HeaderWarp {
    fn get_header(&self, key: &str) -> Option<String> {
        self.0
            .get(key)
            .and_then(|value| value.to_str().ok().map(|value| value.to_string()))
    }

    fn set_header(&mut self, key: &str, val: &str) {
        let key: axum::http::HeaderName = key.to_string().parse().unwrap();
        self.0.insert(key, val.parse().unwrap());
    }

    fn delete_header(&mut self, key: &str) {
        self.0.remove(key);
    }

    fn rng_header(&self, mut cb: impl FnMut(&str, &str) -> bool) {
        for (k, v) in self.0.iter() {
            if !cb(k.as_str(), unsafe {
                std::str::from_utf8_unchecked(v.as_bytes())
            }) {
                return;
            }
        }
    }
}
impl crate::service::s3::HeaderTaker for Request {
    type Head = HeaderWarp;

    fn take_header(&self) -> Self::Head {
        HeaderWarp(self.request.headers().clone())
    }
}
pub struct Response {
    status: u16,
    headers: axum::http::HeaderMap,
    body: tokio::io::BufWriter<Vec<u8>>,
}
impl Default for Response {
    fn default() -> Self {
        Self {
            status: Default::default(),
            headers: Default::default(),
            body: tokio::io::BufWriter::new(Default::default()),
        }
    }
}
impl From<Response> for axum::response::Response {
    fn from(val: Response) -> Self {
        let mut respbuilder = axum::response::Response::builder().status(if val.status == 0 {
            200
        } else {
            val.status
        });
        if !val.headers.is_empty() {
            if let Some(header) = respbuilder.headers_mut() {
                *header = val.headers;
            }
        }
        let raw = val.body.into_inner();
        log::info!("result length {}", raw.len());
        respbuilder.body(raw.into()).unwrap()
        // (
        //     axum::http::StatusCode::from_u16(if val.status == 0 { 200 } else { val.status })
        //         .unwrap(),
        //     raw,
        // )
        //     .into_response()
    }
}
impl crate::authorization::v4::VHeader for Response {
    fn get_header(&self, key: &str) -> Option<String> {
        self.headers
            .get(key)
            .and_then(|v| v.to_str().ok().map(|v| v.to_string()))
    }

    fn set_header(&mut self, key: &str, val: &str) {
        log::info!("set header {key} {val}");
        self.headers.insert(
            key.to_string().parse::<axum::http::HeaderName>().unwrap(),
            val.parse().unwrap(),
        );
    }

    fn delete_header(&mut self, key: &str) {
        self.headers.remove(key);
    }

    fn rng_header(&self, mut cb: impl FnMut(&str, &str) -> bool) {
        self.headers.iter().all(|(k, v)| {
            cb(k.as_str(), unsafe {
                std::str::from_utf8_unchecked(v.as_bytes())
            })
        });
    }
}
pub struct BodyWriter<'a>(&'a mut tokio::io::BufWriter<Vec<u8>>);
impl<'b> crate::utils::io::PollWrite for BodyWriter<'b> {
    fn poll_write<'a>(
        &'a mut self,
        buff: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn 'a + Send + std::future::Future<Output = Result<usize, std::io::Error>>>,
    > {
        Box::pin(async move {
            log::info!("write buff {}", buff.len());
            let _ = self.0.write_all(buff).await;
            let _ = self.0.flush().await;
            Ok(buff.len())
        })
    }
}
impl crate::service::s3::BodyWriter for Response {
    type BodyWriter<'a>
    = BodyWriter<'a> where Self: 'a;

    fn get_body_writer<'b>(
        &'b mut self,
    ) -> std::pin::Pin<
        Box<dyn 'b + Send + std::future::Future<Output = Result<Self::BodyWriter<'_>, String>>>,
    > {
        Box::pin(async move { Ok(BodyWriter(&mut self.body)) })
    }
}
impl crate::service::s3::VResponse for Response {
    fn set_status(&mut self, status: u16) {
        self.status = status;
    }

    fn send_header(&mut self) {}
}
pub async fn handle_fn(
    req: axum::extract::Request<axum::body::Body>,
    _next: axum::middleware::Next,
) -> axum::response::Response {
    use crate::service::s3::*;
    use axum::http::StatusCode;
    use std::sync::Arc;
    let multipart_obj = req
        .extensions()
        .get::<Arc<dyn MultiUploadObjectHandler + Send + Sync>>()
        .cloned();
    match *req.method() {
        axum::http::Method::PUT => {
            let put_obj = req
                .extensions()
                .get::<std::sync::Arc<dyn crate::service::s3::PutObjectHandler + Sync + Send>>()
                .cloned();
            let create_bkt_obj = req
                .extensions()
                .get::<std::sync::Arc<dyn crate::service::s3::CreateBucketHandler + Sync + Send>>()
                .cloned();
            let v4head = req
                .extensions()
                .get::<crate::authorization::v4::V4Head>()
                .cloned();
            let path = req.uri().path();
            let rpath = path
                .trim_start_matches('/')
                .splitn(2, '/')
                .collect::<Vec<&str>>();
            let rpath_len = rpath.len();
            if rpath_len == 0 {
                log::info!("args length invalid");
                (StatusCode::BAD_REQUEST, b"").into_response()
            } else {
                let is_create_bkt = rpath_len == 1 || (rpath_len == 2 && rpath[1].is_empty());
                let req = Request::from(req);
                let mut resp = Response::default();
                if is_create_bkt {
                    //create bucket
                    match create_bkt_obj {
                        Some(create_bkt_obj) => {
                            crate::service::s3::handle_create_bucket(
                                req,
                                &mut resp,
                                &create_bkt_obj,
                            )
                            .await;
                        }
                        None => {
                            log::warn!("not open create bucket method");
                            return (StatusCode::FORBIDDEN, b"").into_response();
                        }
                    }
                } else {
                    let xid = req.get_query("x-id");
                    if let Some(xid) = xid {
                        if xid.as_str() == "UploadPart" {
                            let mut resp = Response::default();

                            // let upload_id = req.get_query("uploadId");
                            // let part_number = req.get_query("partNumber");
                            // if upload_id.is_none() || part_number.is_none() {
                            //     return (axum::http::StatusCode::BAD_REQUEST, b"").into_response();
                            // }

                            return match multipart_obj {
                                Some(multipart_obj) => {
                                    handle_multipart_upload_part(req, &mut resp, &multipart_obj)
                                        .await;
                                    resp.into()
                                }
                                None => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, b"")
                                    .into_response(),
                            };
                        }
                    }

                    //put object
                    match put_obj {
                        Some(put_obj) => {
                            crate::service::s3::handle_put_object(
                                v4head.unwrap(),
                                req,
                                &mut resp,
                                &put_obj,
                            )
                            .await;
                        }
                        None => {
                            log::warn!("not open put object method");
                            return (StatusCode::FORBIDDEN, b"").into_response();
                        }
                    }
                }
                resp.into()
            }
        }
        axum::http::Method::GET => {
            if req.uri().path().starts_with("/probe-bsign") {
                return (axum::http::StatusCode::OK, b"").into_response();
            }
            let get_obj = req
                .extensions()
                .get::<Arc<dyn crate::service::s3::GetObjectHandler + Send + Sync>>()
                .cloned();
            let listbkt_obj = req
                .extensions()
                .get::<Arc<dyn crate::service::s3::ListBucketHandler + Send + Sync>>()
                .cloned();
            let getbkt_loc_obj = req
                .extensions()
                .get::<Arc<dyn crate::service::s3::GetBucketLocationHandler + Send + Sync>>()
                .cloned();
            let req = Request::from(req);
            let url_path = req.url_path();
            log::info!("path is {}", url_path.trim_start_matches('/').is_empty());
            if let Some(lt) = req.get_query("list-type") {
                if lt == "2" || url_path.trim_start_matches('/').is_empty() {
                    log::info!("is list bucket");
                    //get bucket object
                    match listbkt_obj {
                        Some(listbkt_obj) => {
                            let mut resp = Response::default();
                            crate::service::s3::handle_get_list_buckets(
                                req,
                                &mut resp,
                                &listbkt_obj,
                            )
                            .await;
                            return resp.into();
                        }
                        None => {
                            log::warn!("not open head method");
                            let ret = (StatusCode::FORBIDDEN, b"").into_response();
                            return ret;
                        }
                    }
                }
            } else if url_path.trim_start_matches('/').is_empty() {
                log::info!("is list bucket");
                //get bucket object
                match listbkt_obj {
                    Some(listbkt_obj) => {
                        let mut resp = Response::default();
                        crate::service::s3::handle_get_list_buckets(req, &mut resp, &listbkt_obj)
                            .await;
                        return resp.into();
                    }
                    None => {
                        log::warn!("not open head method");
                        let ret = (StatusCode::FORBIDDEN, b"").into_response();
                        return ret;
                    }
                }
            }
            if let Some(loc) = req.get_query("location") {
                //get bucket location
                return match getbkt_loc_obj {
                    Some(bkt) => {
                        match bkt
                            .handle(if loc.is_empty() { None } else { Some(&loc) })
                            .await
                        {
                            Ok(loc) => {
                                let lc = match loc {
                                    Some(loc) => bucket::LocationConstraint::new(loc),
                                    None => bucket::LocationConstraint::new(""),
                                };
                                match quick_xml::se::to_string(&lc) {
                                    Ok(content) => (StatusCode::OK, content).into_response(),
                                    Err(err) => {
                                        log::error!("xml encode error {err}");
                                        (StatusCode::INTERNAL_SERVER_ERROR, b"").into_response()
                                    }
                                }
                            }
                            Err(_) => {
                                log::error!("get bucket location error");
                                (StatusCode::INTERNAL_SERVER_ERROR, b"").into_response()
                            }
                        }
                    }
                    None => {
                        log::warn!("not open get bucket location method");
                        (StatusCode::FORBIDDEN, b"").into_response()
                    }
                };
            }
            //get object
            match get_obj {
                Some(obj) => {
                    let mut resp = Response::default();
                    crate::service::s3::handle_get_object(req, &mut resp, &obj).await;
                    resp.into()
                }
                None => {
                    log::warn!("not open get object method");
                    (StatusCode::FORBIDDEN, b"").into_response()
                }
            }
        }
        axum::http::Method::DELETE => {
            let path = req.uri().path().trim_start_matches('/');
            if path.is_empty() {
                return (StatusCode::BAD_REQUEST, b"").into_response();
            }
            let rr = path.split("/").collect::<Vec<&str>>();
            let rr_len = rr.len();
            if rr_len == 1 || (rr_len == 2 && rr[1].is_empty()) {
                match req
                    .extensions()
                    .get::<Arc<dyn DeleteBucketHandler + Send + Sync>>()
                    .cloned()
                {
                    Some(delete_bkt_obj) => {
                        let mut resp = Response::default();
                        handle_delete_bucket(Request::from(req), &mut resp, &delete_bkt_obj).await;
                        resp.into()
                    }
                    None => {
                        log::warn!("not open get delete bucket method");
                        (StatusCode::FORBIDDEN, b"").into_response()
                    }
                }
            } else {
                match req
                    .extensions()
                    .get::<Arc<dyn DeleteObjectHandler + Send + Sync>>()
                    .cloned()
                {
                    Some(delete_obj_obj) => {
                        let mut resp = Response::default();
                        handle_delete_object(Request::from(req), &mut resp, &delete_obj_obj).await;
                        resp.into()
                    }
                    None => {
                        log::warn!("not open get delete bucket method");
                        (StatusCode::FORBIDDEN, b"").into_response()
                    }
                }
            }
        }
        axum::http::Method::HEAD => {
            let head_obj = req
                .extensions()
                .get::<std::sync::Arc<dyn crate::service::s3::HeadHandler + Sync + Send>>()
                .cloned();
            if head_obj.is_none() {
                log::warn!("not open head features");
                return (StatusCode::INTERNAL_SERVER_ERROR, b"").into_response();
            }
            let head_obj = head_obj.unwrap();
            let req = Request::from(req);
            let raw_path = req.url_path();
            let args = raw_path
                .trim_start_matches('/')
                .splitn(2, '/')
                .collect::<Vec<&str>>();
            if args.len() != 2 {
                return (StatusCode::BAD_REQUEST, b"").into_response();
            }
            match head_obj.lookup(args[0], args[1]).await {
                Ok(metadata) => match metadata {
                    Some(head) => {
                        use crate::authorization::v4::VHeader;
                        let mut resp = Response::default();
                        if let Some(v) = head.content_length {
                            resp.set_header("content-length", v.to_string().as_str())
                        }
                        if let Some(v) = head.etag {
                            resp.set_header("etag", &v);
                        }
                        if let Some(v) = head.content_type {
                            resp.set_header("content-type", &v);
                        }
                        if let Some(v) = head.last_modified {
                            resp.set_header("last-modified", &v);
                        }
                        (StatusCode::OK, b"").into_response()
                    }
                    None => (StatusCode::NOT_FOUND, b"").into_response(),
                },
                Err(err) => {
                    log::error!("lookup object metadata error {err}");
                    (StatusCode::INTERNAL_SERVER_ERROR, b"").into_response()
                }
            }
        }
        axum::http::Method::POST => match multipart_obj {
            Some(multipart_obj) => {
                let mut resp = Response::default();
                let is_create_session = if let Some(query) = req.uri().query() {
                    query.contains("uploads=")
                } else {
                    false
                };
                let req = Request::from(req);
                if is_create_session {
                    handle_multipart_create_session(req, &mut resp, &multipart_obj).await;
                } else if req.get_query("uploadId").is_some() {
                    handle_multipart_complete_session(req, &mut resp, &multipart_obj).await;
                } else {
                    return (StatusCode::BAD_REQUEST, b"").into_response();
                }
                resp.into()
            }
            None => {
                log::warn!("not open multipart object features");
                (StatusCode::INTERNAL_SERVER_ERROR, b"").into_response()
            }
        },
        _ => (StatusCode::METHOD_NOT_ALLOWED, b"").into_response(),
    }
}
pub async fn handle_authorization_middleware(
    req: axum::extract::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> impl axum::response::IntoResponse {
    let ret = req
        .extensions()
        .get::<std::sync::Arc<dyn crate::authorization::AccesskeyStore + Send + Sync>>()
        .cloned();
    let ak_store = match ret {
        Some(ret) => ret,
        None => {
            return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, b"").into_response();
        }
    };
    let req = Request::from(req);
    let base_arg = match crate::authorization::v4::extract_args(&req) {
        Ok(arg) => arg,
        Err(_) => {
            return (axum::http::StatusCode::BAD_REQUEST, b"").into_response();
        }
    };
    let mut query = Vec::new();
    req.all_query(|k, v| {
        query.push(crate::utils::BaseKv {
            key: k.to_string(),
            val: v.to_string(),
        });
        true
    });
    let secretkey = match ak_store.get(&base_arg.access_key).await {
        Ok(secretkey) => {
            if secretkey.is_none() {
                return (axum::http::StatusCode::FORBIDDEN, b"").into_response();
            }
            secretkey.unwrap()
        }
        Err(_) => {
            return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, b"").into_response();
        }
    };
    let ret = crate::authorization::v4::get_v4_signature(
        &req,
        req.method().as_str(),
        &base_arg.region,
        &base_arg.service,
        req.url_path().as_str(),
        &secretkey,
        &base_arg.content_hash,
        &base_arg.signed_headers,
        query,
    );
    let circle_hasher = match ret {
        Ok((sig, circle_hasher)) => {
            if sig != base_arg.signature {
                log::info!(
                    "expect {sig} got {} args {:?} url_path {}",
                    base_arg.signature,
                    base_arg,
                    req.url_path().as_str()
                );
                return (axum::http::StatusCode::FORBIDDEN, b"").into_response();
            }
            circle_hasher
        }
        Err(err) => {
            log::error!("signature failed {err}");
            return (axum::http::StatusCode::FORBIDDEN, b"").into_response();
        }
    };
    let v4head = crate::authorization::v4::V4Head::new(
        base_arg.signature,
        base_arg.region,
        base_arg.access_key,
        circle_hasher,
    );
    let mut req: axum::http::Request<axum::body::Body> = req.into();
    req.extensions_mut().insert(v4head);
    next.run(req).await
}
mod bucket {

    #[derive(serde::Serialize, Debug)]
    #[serde(rename = "LocationConstraint", rename_all = "PascalCase")]
    pub struct LocationConstraint {
        #[serde(rename = "$value")]
        region: String,

        #[serde(rename = "xmlns")]
        _xmlns: &'static str,
    }
    impl LocationConstraint {
        pub fn new<T: Into<String>>(region: T) -> Self {
            Self {
                region: region.into(),
                _xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
            }
        }
    }
}
#[cfg(test)]
mod itest {
    use std::sync::Arc;

    use tokio::io::AsyncReadExt;

    #[derive(Default)]
    struct Target {}
    use crate::service::s3::*;
    impl CreateBucketHandler for Target {
        fn handle<'a>(
            &'a self,
            _opt: &'a CreateBucketOption,
            _bucket: &'a str,
        ) -> std::pin::Pin<Box<dyn 'a + Send + std::future::Future<Output = Result<(), String>>>>
        {
            Box::pin(async move {
                log::info!("create bucket {_bucket}");
                Ok(())
            })
        }
    }
    impl ListBucketHandler for Target {
        fn handle<'a>(
            &'a self,
            _opt: &'a ListBucketsOption,
        ) -> std::pin::Pin<
            Box<dyn 'a + Send + std::future::Future<Output = Result<Vec<Bucket>, String>>>,
        > {
            Box::pin(async move {
                let datetime = chrono::Utc::now().to_rfc3339();
                Ok(vec![Bucket {
                    name: "test1".to_string(),
                    creation_date: datetime,
                    bucket_region: "us-east-1".to_string(),
                }])
            })
        }
    }
    impl HeadHandler for Target {
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
                let mut ret: HeadObjectResult = Default::default();
                ret.checksum_sha256 = Some(
                    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824".to_string(),
                );
                ret.content_length = Some(5);
                ret.etag = Some("5d41402abc4b2a76b9719d911017c592".to_string());
                ret.last_modified = Some(
                    chrono::Utc::now()
                        .format("%a, %d %b %Y %H:%M:%S GMT")
                        .to_string(),
                );
                Ok(Some(ret))
            })
        }
    }
    impl PutObjectHandler for Target {
        fn handle<'a>(
            &'a self,
            opt: &PutObjectOption,
            bucket: &'a str,
            object: &'a str,
            body: &'a mut (dyn tokio::io::AsyncRead + Unpin + Send),
        ) -> std::pin::Pin<Box<dyn 'a + Send + std::future::Future<Output = Result<(), String>>>>
        {
            Box::pin(async move {
                log::info!("put bucket {bucket} object {object}");
                let mut buff = vec![];
                match body.read_to_end(&mut buff).await {
                    Ok(size) => {
                        log::info!("get {}", unsafe {
                            std::str::from_utf8_unchecked(&buff[..size])
                        });
                    }
                    Err(err) => {
                        log::error!("read error {err}");
                    }
                }
                Ok(())
            })
        }
    }
    impl DeleteBucketHandler for Target {
        fn handle<'a>(
            &'a self,
            _opt: &'a DeleteBucketOption,
            _bucket: &'a str,
        ) -> std::pin::Pin<Box<dyn 'a + Send + std::future::Future<Output = Result<(), String>>>>
        {
            Box::pin(async move {
                log::info!("delete bucket {_bucket}");
                Ok(())
            })
        }
    }
    impl DeleteObjectHandler for Target {
        fn handle<'a>(
            &'a self,
            _opt: &'a DeleteObjectOption,
            _object: &'a str,
        ) -> std::pin::Pin<Box<dyn 'a + Send + std::future::Future<Output = Result<(), String>>>>
        {
            Box::pin(async move {
                log::info!("delete object {_object}");
                Ok(())
            })
        }
    }
    impl crate::authorization::AccesskeyStore for Target {
        fn get<'a>(
            &'a self,
            _accesskey: &'a str,
        ) -> std::pin::Pin<
            Box<
                dyn 'a + Send + Sync + std::future::Future<Output = Result<Option<String>, String>>,
            >,
        > {
            Box::pin(async move { Ok(Some(format!("{_accesskey}12345"))) })
        }
    }
    impl crate::service::s3::GetObjectHandler for Target {
        fn handle<'a>(
            &'a self,
            bucket: &str,
            object: &str,
            opt: crate::service::s3::GetObjectOption,
            mut out: tokio::sync::Mutex<
                std::pin::Pin<
                    std::boxed::Box<(dyn crate::utils::io::PollWrite + Send + Unpin + 'a)>,
                >,
            >,
        ) -> std::pin::Pin<Box<dyn 'a + Send + std::future::Future<Output = Result<(), String>>>>
        {
            Box::pin(async move {
                let mut l = out.lock().await;
                let _ = l.poll_write(b"hello").await.map_err(|err| {
                    log::error!("write error {err}");
                });
                Ok(())
            })
        }
    }
    impl crate::service::s3::GetBucketLocationHandler for Target {}
    impl MultiUploadObjectHandler for Target {
        fn handle_create_session<'a>(
            &'a self,
            bucket: &'a str,
            key: &'a str,
        ) -> std::pin::Pin<Box<dyn 'a + Send + std::future::Future<Output = Result<String, ()>>>>
        {
            Box::pin(async move { Ok("ffffff".to_string()) })
        }

        fn handle_upload_part<'a>(
            &'a self,
            bucket: &'a str,
            key: &'a str,
            upload_id: &'a str,
            part_number: u32,
            body: &'a mut (dyn tokio::io::AsyncRead + Unpin + Send),
        ) -> std::pin::Pin<Box<dyn 'a + Send + std::future::Future<Output = Result<String, ()>>>>
        {
            Box::pin(async move {
                let mut buff = Vec::new();
                let size = body
                    .read_to_end(&mut buff)
                    .await
                    .map_err(|err| log::error!("read body error {err}"))?;
                println!(
                    "upload part upload_id={upload_id} part_number={part_number} bucket={bucket} key={key}\n{}",
                    unsafe { std::str::from_boxed_utf8_unchecked((&buff[..size]).into()) }
                );
                Ok("5d41402abc4b2a76b9719d911017c592".to_string())
            })
        }

        fn handle_complete<'a>(
            &'a self,
            bucket: &'a str,
            key: &'a str,
            upload_id: &'a str,
            //(etag,part number)
            data: &'a [(&'a str, u32)],
            opts: MultiUploadObjectCompleteOption,
        ) -> std::pin::Pin<Box<dyn 'a + Send + std::future::Future<Output = Result<String, ()>>>>
        {
            Box::pin(async move { Ok("69a329523ce1ec88bf63061863d9cb14".to_string()) })
        }

        fn handle_abort<'a>(
            &'a self,
            bucket: &'a str,
            key: &'a str,
            upload_id: &'a str,
        ) -> std::pin::Pin<Box<dyn 'a + Send + std::future::Future<Output = Result<(), ()>>>>
        {
            todo!()
        }
    }
    #[tokio::test]
    async fn test_server() -> Result<(), Box<dyn std::error::Error>> {
        let _ = tokio::fs::create_dir_all(".sys_bws").await;
        env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .init();
        let target = Arc::new(Target::default());
        let r = axum::Router::new()
            .layer(axum::middleware::from_fn(super::handle_fn))
            .layer(axum::middleware::from_fn(
                super::handle_authorization_middleware,
            ))
            .layer(axum::Extension(
                target.clone() as Arc<dyn PutObjectHandler + Send + Sync>
            ))
            .layer(axum::Extension(
                target.clone() as Arc<dyn HeadHandler + Send + Sync>
            ))
            .layer(axum::Extension(
                target.clone() as Arc<dyn ListBucketHandler + Send + Sync>
            ))
            .layer(axum::Extension(
                target.clone() as Arc<dyn CreateBucketHandler + Send + Sync>
            ))
            .layer(axum::Extension(
                target.clone() as Arc<dyn DeleteBucketHandler + Send + Sync>
            ))
            .layer(axum::Extension(
                target.clone() as Arc<dyn DeleteObjectHandler + Send + Sync>
            ))
            .layer(axum::Extension(
                target.clone() as Arc<dyn crate::authorization::AccesskeyStore + Send + Sync>
            ))
            .layer(axum::Extension(
                target.clone() as Arc<dyn GetObjectHandler + Send + Sync>
            ))
            .layer(axum::Extension(
                target.clone() as Arc<dyn GetBucketLocationHandler + Send + Sync>
            )).layer(axum::Extension(
                target.clone() as Arc<dyn MultiUploadObjectHandler + Send + Sync>
            ));
        let l = tokio::net::TcpListener::bind("0.0.0.0:9900").await?;
        axum::serve(l, r).await?;
        Ok(())
    }
}
