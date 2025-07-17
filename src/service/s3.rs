use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    io::Write,
    str::FromStr,
    sync::Mutex,
};
static OWNER_ID: &str = "ffffffffffffffff";
pub type DateTime = chrono::DateTime<chrono::Utc>;
pub struct Error(String);
impl From<String> for Error {
    fn from(value: String) -> Self {
        Self(value)
    }
}
impl From<&str> for Error {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Error").field(&self.0).finish()
    }
}
impl std::error::Error for Error {}
pub trait VRequest: crate::authorization::v4::VHeader {
    fn method(&self) -> String;
    fn url_path(&self) -> String;
    fn get_query(&self, k: &str) -> Option<String>;
    fn all_query(&self, cb: impl FnMut(&str, &str) -> bool);
}
pub trait BodyWriter {
    type BodyWriter<'a>: crate::utils::io::PollWrite + Send + Unpin
    where
        Self: 'a;
    fn get_body_writer<'b>(
        &'b mut self,
    ) -> std::pin::Pin<
        Box<dyn 'b + Send + std::future::Future<Output = Result<Self::BodyWriter<'_>, String>>>,
    >;
}
pub trait BodyReader {
    type BodyReader: crate::utils::io::PollRead + Send;
    fn get_body_reader<'b>(
        self,
    ) -> std::pin::Pin<
        Box<dyn 'b + Send + std::future::Future<Output = Result<Self::BodyReader, String>>>,
    >;
}
pub trait VResponse: crate::authorization::v4::VHeader + BodyWriter {
    fn set_status(&mut self, status: u16);
    fn send_header(&mut self);
}

#[derive(Default, Debug, Serialize)]
pub struct HeadObjectResult {
    #[serde(rename = "AcceptRanges")]
    pub accept_ranges: Option<String>,
    #[serde(rename = "ArchiveStatus")]
    pub archive_status: Option<String>, // 可用枚举替代
    #[serde(rename = "BucketKeyEnabled")]
    pub bucket_key_enabled: Option<bool>,
    #[serde(rename = "CacheControl")]
    pub cache_control: Option<String>,
    #[serde(rename = "ChecksumCRC32")]
    pub checksum_crc32: Option<String>,
    #[serde(rename = "ChecksumCRC32C")]
    pub checksum_crc32c: Option<String>,
    #[serde(rename = "ChecksumCRC64")]
    pub checksum_crc64: Option<String>,
    #[serde(rename = "ChecksumSHA1")]
    pub checksum_sha1: Option<String>,
    #[serde(rename = "ChecksumSHA256")]
    pub checksum_sha256: Option<String>,
    #[serde(rename = "ChecksumType")]
    pub checksum_type: Option<String>,
    #[serde(rename = "ContentDisposition")]
    pub content_disposition: Option<String>,
    #[serde(rename = "ContentEncoding")]
    pub content_encoding: Option<String>,
    #[serde(rename = "ContentLanguage")]
    pub content_language: Option<String>,
    #[serde(rename = "ContentLength")]
    pub content_length: Option<usize>,
    #[serde(rename = "ContentRange")]
    pub content_range: Option<String>,
    #[serde(rename = "ContentType")]
    pub content_type: Option<String>,
    #[serde(rename = "DeleteMarker")]
    pub delete_marker: Option<bool>,
    #[serde(rename = "ETag")]
    pub etag: Option<String>,
    #[serde(rename = "Expiration")]
    pub expiration: Option<String>,
    #[serde(rename = "Expires")]
    pub expires: Option<String>, // 原是 `time.Time`，可转换为 ISO8601 字符串
    #[serde(rename = "ExpiresString")]
    pub expires_string: Option<String>,
    #[serde(rename = "LastModified")]
    pub last_modified: Option<String>, // 可考虑使用 chrono::DateTime 类型
    #[serde(rename = "Metadata")]
    pub metadata: Option<HashMap<String, String>>,
    #[serde(rename = "MissingMeta")]
    pub missing_meta: Option<i32>,
    #[serde(rename = "ObjectLockLegalHoldStatus")]
    pub object_lock_legal_hold_status: Option<String>,
    #[serde(rename = "ObjectLockMode")]
    pub object_lock_mode: Option<String>,
    #[serde(rename = "ObjectLockRetainUntilDate")]
    pub object_lock_retain_until_date: Option<String>,
    #[serde(rename = "PartsCount")]
    pub parts_count: Option<i32>,
    #[serde(rename = "ReplicationStatus")]
    pub replication_status: Option<String>,
    #[serde(rename = "RequestCharged")]
    pub request_charged: Option<String>,
    #[serde(rename = "Restore")]
    pub restore: Option<String>,
    #[serde(rename = "SSECustomerAlgorithm")]
    pub sse_customer_algorithm: Option<String>,
    #[serde(rename = "SSECustomerKeyMD5")]
    pub sse_customer_key_md5: Option<String>,
    #[serde(rename = "SSEKMSKeyId")]
    pub sse_kms_key_id: Option<String>,
    #[serde(rename = "ServerSideEncryption")]
    pub server_side_encryption: Option<String>,
    #[serde(rename = "StorageClass")]
    pub storage_class: Option<String>,
    #[serde(rename = "VersionId")]
    pub version_id: Option<String>,
    #[serde(rename = "WebsiteRedirectLocation")]
    pub website_redirect_location: Option<String>,
}

pub trait HeadHandler {
    fn lookup<'a>(
        &self,
        bucket: &str,
        object: &str,
    ) -> std::pin::Pin<
        Box<
            dyn 'a
                + Send
                + Sync
                + std::future::Future<Output = Result<Option<HeadObjectResult>, Error>>,
        >,
    >;
}
#[derive(Default)]
pub struct GetObjectOption {
    // pub range:(Option<usize>,Option<usize>),
    // pub accept_encoding:Option<Vec<String>>,
}

pub trait GetObjectHandler: HeadHandler {
    fn handle<'a>(
        &'a self,
        bucket: &str,
        object: &str,
        opt: GetObjectOption,
        out: tokio::sync::Mutex<
            std::pin::Pin<Box<dyn 'a + Send + crate::utils::io::PollWrite + Unpin>>,
        >,
    ) -> std::pin::Pin<Box<dyn 'a + Send + std::future::Future<Output = Result<(), String>>>>;
}
extern crate serde;
use serde::Serialize;
use sha1::Digest;
use tokio::io::AsyncSeekExt;

use crate::utils::io::PollWrite;

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
#[serde(rename = "ListBucketResult")]
pub struct ListObjectResult {
    pub name: String,
    pub prefix: Option<String>,
    pub key_count: Option<u32>,
    pub max_keys: Option<u32>,
    pub delimiter: Option<String>,
    pub is_truncated: bool,
    #[serde(default)]
    pub contents: Vec<ListObjectContent>,
    #[serde(default)]
    pub common_prefixes: Vec<CommonPrefix>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ListObjectContent {
    pub key: String,
    pub last_modified: Option<String>,
    pub etag: Option<String>,
    pub size: u64,
    pub storage_class: Option<String>,
    pub owner: Option<Owner>,
}

#[derive(Debug, Serialize)]
#[serde(rename = "ListAllMyBucketsResult")]
#[serde(rename_all = "PascalCase")]
pub struct ListAllMyBucketsResult {
    #[serde(
        rename = "xmlns",
        default = "s3_namespace",
        skip_serializing_if = "String::is_empty"
    )]
    pub xmlns: String,

    pub owner: Owner,

    pub buckets: Buckets,
}
#[derive(Debug, Serialize)]
pub struct Buckets {
    #[serde(rename = "Bucket")]
    pub bucket: Vec<Bucket>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Bucket {
    pub name: String,
    pub creation_date: String,
    pub bucket_region: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Owner {
    pub id: String,
    pub display_name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CommonPrefix {
    pub prefix: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ListObjectOption {
    pub bucket: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation_token: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub delimiter: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding_type: Option<String>, // Usually "url"

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_bucket_owner: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fetch_owner: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_keys: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional_object_attributes: Option<Vec<String>>, // e.g. ["RestoreStatus"]

    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_payer: Option<String>, // e.g. "requester"

    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_after: Option<String>,
}

pub trait ListObjectHandler {
    fn handle<'a>(
        &'a self,
        opt: &'a ListObjectOption,
        bucket: &'a str,
    ) -> std::pin::Pin<
        Box<dyn 'a + Send + std::future::Future<Output = Result<Vec<ListObjectContent>, String>>>,
    >;
}
pub fn handle_head_object<T: VRequest, F: VResponse, E: HeadHandler>(
    req: &T,
    resp: &mut F,
    handler: &E,
) {
    todo!()
}
pub async fn handle_get_object<T: VRequest, F: VResponse>(
    req: T,
    resp: &mut F,
    handler: &std::sync::Arc<dyn GetObjectHandler + Send + Sync>,
) {
    use tokio::io::AsyncWriteExt;
    if req.method() != "GET" {
        resp.set_status(405);
        resp.send_header();
        return;
    }
    let rpath = req.url_path();
    let raw = rpath.trim_matches('/');
    let r = raw.find('/');
    if r.is_none() {
        resp.set_status(400);
        resp.send_header();
        return;
    }
    let opt = GetObjectOption::default();
    let next = r.unwrap();
    let bucket = &raw[..next];
    let object = &raw[next + 1..];

    let head = handler.lookup(bucket, object).await;
    if let Err(e) = head {
        log::error!("lookup {bucket} {object} error: {e}");
        resp.set_status(500);
        resp.send_header();
        return;
    }
    let head = head.unwrap();
    if head.is_none() {
        log::info!("not found {bucket} {object}");
        resp.set_status(404);
        resp.send_header();
        return;
    }
    //send header info to client
    let head = head.unwrap();
    if let Some(v) = head.content_length {
        resp.set_header("content-length", v.to_string().as_str())
    }
    if let Some(v) = head.etag {
        resp.set_header("etag", &v)
    }
    if let Some(v) = head.content_type {
        resp.set_header("content-type", &v)
    }
    if let Some(v) = head.last_modified {
        resp.set_header("last-modified", &v)
    }
    //
    resp.set_status(200);
    resp.send_header();
    let ret = {
        match resp.get_body_writer().await {
            Ok(body) => {
                let ret = handler
                    .handle(bucket, object, opt, tokio::sync::Mutex::new(Box::pin(body)))
                    .await;
                if let Err(err) = ret {
                    Err(err)
                } else {
                    Ok(())
                }
            }
            Err(err) => Err(err),
        }
    };
    if let Err(err) = ret {
        log::error!("body handle error {err}");
        resp.set_status(500);
    }
}

//query list-type=2, return ListObjectResult
pub async fn handle_get_list_object<T: VRequest, F: VResponse>(
    req: T,
    resp: &mut F,
    handler: &std::sync::Arc<dyn ListObjectHandler + Send + Sync>,
) {
    if req.method() != "GET" {
        resp.set_status(405);
        resp.send_header();
        return;
    }
    let rpath = req.url_path();
    let bucket = rpath.trim_matches('/').to_string();
    let opt = ListObjectOption {
        bucket: bucket.clone(),
        continuation_token: req.get_query("continuation-token"),
        delimiter: req.get_query("delimiter"),
        expected_bucket_owner: req.get_query("expected-bucket-owner"),
        max_keys: req
            .get_query("max-keys")
            .and_then(|v| v.parse::<i32>().ok()),
        optional_object_attributes: None, //todo: support option_object_attributes on v2
        request_payer: req.get_header("x-amz-request-layer"),
        start_after: req.get_query("start-after"),
        encoding_type: req.get_query("encoding-type"),
        fetch_owner: req.get_query("fetch-owner").and_then(|v| {
            if v == "true" {
                Some(true)
            } else if v == "false" {
                Some(false)
            } else {
                None
            }
        }),
        prefix: req.get_query("prefix"),
    };
    let ret = handler.handle(&opt, rpath.trim_matches('/')).await;
    match ret {
        Ok(ans) => {
            let result = ListObjectResult {
                name: bucket,
                prefix: opt.prefix,
                key_count: Some(ans.len() as u32),
                max_keys: opt.max_keys.map(|v| v as u32),
                delimiter: opt.delimiter,
                is_truncated: false,
                contents: ans,
                common_prefixes: vec![],
            };
            match quick_xml::se::to_string(&result) {
                Ok(data) => {
                    resp.set_header("content-type", "application/xml");
                    resp.set_header("content-length", data.len().to_string().as_str());
                    resp.set_status(200);
                    resp.send_header();
                    let ret = match resp.get_body_writer().await {
                        Ok(mut body) => {
                            if let Err(err) = body.poll_write(data.as_bytes()).await {
                                log::info!("write to response body error {err}");
                            }
                            Ok(())
                        }
                        Err(err) => Err(err),
                    };
                    if let Err(err) = ret {
                        log::error!("write body error {err}");
                        resp.set_status(500);
                        resp.send_header();
                        return;
                    }
                    // resp.get_body_writer().map_ok_or_else(
                    //     |e| log::error!("get_body_writer error:{e}"),
                    //     |mut bw| {
                    //         let _ = bw.write_all(data.as_bytes());
                    //     },
                    // );
                }
                Err(err) => {
                    log::error!("xml marshal failed {err}");
                }
            }
        }
        Err(err) => log::error!("get_list_object error {err}"),
    }
}

pub trait ListBucketHandler {
    fn handle<'a>(
        &'a self,
        opt: &'a ListBucketsOption,
    ) -> std::pin::Pin<Box<dyn 'a + Send + std::future::Future<Output = Result<Vec<Bucket>, String>>>>;
}
pub trait GetBucketLocationHandler {
    fn handle<'a>(
        &'a self,
        loc: Option<&'a str>,
    ) -> std::pin::Pin<
        Box<dyn 'a + Send + std::future::Future<Output = Result<Option<&'static str>, ()>>>,
    > {
        Box::pin(async { Ok(Some("us-west-1")) })
    }
}
#[derive(Debug)]
pub struct ListBucketsOption {
    pub bucket_region: Option<String>,
    pub continuation_token: Option<String>,
    pub max_buckets: Option<i32>,
    pub prefix: Option<String>,
}
pub async fn handle_get_list_buckets<T: VRequest, F: VResponse>(
    req: T,
    resp: &mut F,
    handler: &std::sync::Arc<dyn ListBucketHandler + Send + Sync>,
) {
    if req.method() != "GET" {
        resp.set_status(405);
        resp.send_header();
        return;
    }
    let opt = ListBucketsOption {
        bucket_region: req.get_query("bucket-region"),
        continuation_token: req.get_query("continuation-token"),
        max_buckets: req
            .get_query("max-buckets")
            .and_then(|v| v.parse::<i32>().ok()),
        prefix: req.get_query("prefix"),
    };
    match handler.handle(&opt).await {
        Ok(v) => {
            let res = ListAllMyBucketsResult {
                xmlns: r#"xmlns="http://s3.amazonaws.com/doc/2006-03-01/""#.to_string(),
                owner: Owner {
                    id: OWNER_ID.to_string(),
                    display_name: "bws".to_string(),
                },
                buckets: Buckets { bucket: v },
            };
            match quick_xml::se::to_string(&res) {
                Ok(v) => match resp.get_body_writer().await {
                    Ok(mut w) => {
                        if let Err(err) = w.poll_write(v.as_bytes()).await {
                            log::info!("write to client body error {err}");
                        }
                    }
                    Err(e) => log::error!("get_body_writer error: {e}"),
                },
                Err(e) => {
                    resp.set_status(500);
                    resp.send_header();
                    log::error!("xml serde error: {e}")
                }
            }
        }
        Err(e) => {
            log::info!("listbucket handle error: {e}");
            resp.set_status(500);
            resp.send_header();
        }
    }
}
#[derive(Default)]
pub struct PutObjectOption {
    // pub acl: ObjectCannedACL,
    pub cache_control: Option<String>,
    pub checksum_algorithm: Option<ChecksumAlgorithm>,
    pub checksum_crc32: Option<String>,
    pub checksum_crc32c: Option<String>,
    pub checksum_crc64nvme: Option<String>,
    pub checksum_sha1: Option<String>,
    pub checksum_sha256: Option<String>,
    pub content_disposition: Option<String>,
    pub content_encoding: Option<String>,
    pub content_language: Option<String>,
    pub content_length: Option<i64>,
    pub content_md5: Option<String>,
    pub content_type: Option<String>,
    pub expected_bucket_owner: Option<String>,
    pub expires: Option<DateTime>,
    pub grant_full_control: Option<String>,
    pub grant_read: Option<String>,
    pub if_match: Option<String>,
    pub if_none_match: Option<String>,
    // pub metadata: Option<HashMap<String, String>>,
    pub object_lock_legal_hold_status: Option<ObjectLockLegalHoldStatus>,
    pub object_lock_mode: Option<ObjectLockMode>,
    pub object_lock_retain_until_date: Option<DateTime>,
    pub request_payer: Option<RequestPayer>,
    pub storage_class: Option<String>,
    // pub tagging: Option<String>,
    // pub website_redirect_location: Option<String>,
    pub write_offset_bytes: Option<i64>,
}
impl PutObjectOption {
    pub fn invalid(&self) -> bool {
        if self.content_length.is_none() {
            return false;
        } else if self.content_md5.is_none() {
            return false;
        }
        true
    }
}

#[derive(Debug, PartialEq)]
pub enum ChecksumAlgorithm {
    Crc32,
    Crc32c,
    Sha1,
    Sha256,
    Crc64nvme,
}

impl std::str::FromStr for ChecksumAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "CRC32" => Ok(ChecksumAlgorithm::Crc32),
            "CRC32C" => Ok(ChecksumAlgorithm::Crc32c),
            "SHA1" => Ok(ChecksumAlgorithm::Sha1),
            "SHA256" => Ok(ChecksumAlgorithm::Sha256),
            "CRC64NVME" => Ok(ChecksumAlgorithm::Crc64nvme),
            _ => Err(format!("Invalid checksum algorithm: {}", s)),
        }
    }
}

#[derive(Debug)]
pub enum RequestPayer {
    Requester,
}
impl std::str::FromStr for RequestPayer {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "requester" => Ok(RequestPayer::Requester),
            _ => Err(Error(format!("Invalid RequestPayer value: {}", s))),
        }
    }
}
#[derive(Debug)]
pub enum ObjectLockMode {
    Governance,
    Compliance,
}
impl std::str::FromStr for ObjectLockMode {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "GOVERNANCE" => Ok(ObjectLockMode::Governance),
            "COMPLIANCE" => Ok(ObjectLockMode::Compliance),
            _ => Err(Error(format!("Invalid ObjectLockMode value: {}", s))),
        }
    }
}
#[derive(Debug)]
pub enum ObjectLockLegalHoldStatus {
    On,
    Off,
}
impl std::str::FromStr for ObjectLockLegalHoldStatus {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ON" => Ok(ObjectLockLegalHoldStatus::On),
            "OFF" => Ok(ObjectLockLegalHoldStatus::Off),
            _ => Err(Error(format!(
                "Invalid ObjectLockLegalHoldStatus value: {}",
                s
            ))),
        }
    }
}

pub trait PutObjectHandler {
    fn handle<'a>(
        &'a self,
        opt: &PutObjectOption,
        bucket: &'a str,
        object: &'a str,
        body: &'a mut (dyn tokio::io::AsyncRead + Unpin + Send),
    ) -> std::pin::Pin<Box<dyn 'a + Send + std::future::Future<Output = Result<(), String>>>>;
}
pub async fn handle_put_object<T: VRequest + BodyReader, F: VResponse>(
    mut v4head: crate::authorization::v4::V4Head,
    req: T,
    resp: &mut F,
    handler: &std::sync::Arc<dyn PutObjectHandler + Send + Sync>,
) {
    if req.method() != "PUT" {
        resp.set_status(405);
        resp.send_header();
        return;
    }
    let url_path = req.url_path();
    let url_path = url_path.trim_matches('/');
    let ret = url_path.find('/');
    if ret.is_none() {
        resp.set_status(400);
        resp.send_header();
        return;
    }
    let next = ret.unwrap();
    let bucket = &url_path[..next];
    let object = &url_path[next + 1..];
    let opt = PutObjectOption {
        cache_control: req.get_header("cache-control"),
        checksum_algorithm: req
            .get_header("checksum-algorithm")
            .and_then(|v| ChecksumAlgorithm::from_str(&v).ok()),
        checksum_crc32: req.get_header("x-amz-checksum-crc32"),
        checksum_crc32c: req.get_header("x-amz-checksum-crc32c"),
        checksum_crc64nvme: req.get_header("x-amz-checksum-crc64vme"),
        checksum_sha1: req.get_header("x-amz-checksum-sha1"),
        checksum_sha256: req.get_header("x-amz-checksum-sha256"),
        content_disposition: req.get_header("content-disposition"),
        content_encoding: req.get_header("cotent-encoding"),
        content_language: req.get_header("content-language"),
        content_length: req
            .get_header("content-length")
            .and_then(|v| v.parse::<i64>().map_or(Some(-1), Some)),
        content_md5: req.get_header("content-md5"),
        content_type: req.get_header("content-type"),
        expected_bucket_owner: req.get_header("x-amz-expected-bucket-owner"),
        expires: req.get_header("expire").and_then(|v| {
            chrono::NaiveDateTime::parse_from_str(&v, "%a, %d %b %Y %H:%M:%S GMT")
                .map_or(None, |v| {
                    Some(chrono::DateTime::from_naive_utc_and_offset(v, chrono::Utc))
                })
        }),
        grant_full_control: req.get_header("x-amz-grant-full-control"),
        grant_read: req.get_header("x-amz-grant-read"),
        if_match: req.get_header("if-match"),
        if_none_match: req.get_header("if-none-match"),
        // metadata: todo!(),
        object_lock_legal_hold_status: req
            .get_header("x-amz-object-lock-legal-hold-status")
            .and_then(|v| ObjectLockLegalHoldStatus::from_str(&v).ok()),
        object_lock_mode: req
            .get_header("x-amz-object-lock-mode")
            .and_then(|v| ObjectLockMode::from_str(&v).ok()),
        object_lock_retain_until_date: req
            .get_header("x-amz-object-lock-retain_until_date")
            .and_then(|v| {
                chrono::NaiveDateTime::parse_from_str(&v, "%a, %d %b %Y %H:%M:%S GMT")
                    .map_or(None, |v| {
                        Some(chrono::DateTime::from_naive_utc_and_offset(v, chrono::Utc))
                    })
            }),
        request_payer: req
            .get_header("x-amz-request-payer")
            .and_then(|v| RequestPayer::from_str(&v).ok()),
        storage_class: req.get_header("x-amz-storage-class"),
        // tagging: todo!(),
        // website_redirect_location: todo!(),
        write_offset_bytes: req
            .get_header("x-amz-write-offset-bytes")
            .and_then(|v| v.parse::<i64>().ok()),
    };

    //todo:parse from body,then derive into handle
    enum ContentSha256 {
        Hash(String),
        Streaming,
    }
    let content_sha256 = req.get_header("x-amz-content-sha256").map_or_else(
        || None,
        |content_sha256| {
            if content_sha256.as_str() == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
                Some(ContentSha256::Streaming)
            } else {
                Some(ContentSha256::Hash(content_sha256))
            }
        },
    );
    if content_sha256.is_none() {
        resp.set_status(403);
        return;
    }
    let content_sha256 = content_sha256.unwrap();
    let ret = req.get_body_reader().await;
    if let Err(err) = ret {
        resp.set_status(500);
        resp.send_header();
        log::error!("get body reader error: {err}");
        return;
    }
    let r = ret.unwrap();
    let ret: Result<(), String> = match content_sha256 {
        ContentSha256::Hash(cs) => {
            if opt.content_length.is_none() {
                resp.set_status(403);
                resp.send_header();
                return;
            }
            let content_length = opt.content_length.unwrap() as usize;
            if content_length <= 10 << 20 {
                let mut buff = vec![0u8; content_length];
                match parse_body(r, &mut buff, &cs, content_length).await {
                    Ok(_) => {
                        let mut buff = tokio::io::BufReader::new(std::io::Cursor::new(buff));
                        handler.handle(&opt, bucket, object, &mut buff).await
                    }
                    Err(err) => match err {
                        ParseBodyError::HashNoMatch => {
                            log::warn!("put object hash not match");
                            resp.set_status(400);
                            resp.send_header();
                            return;
                        }
                        ParseBodyError::ContentLengthIncorrect => {
                            log::warn!("content length invalid");
                            resp.set_status(400);
                            resp.send_header();
                            return;
                        }
                        ParseBodyError::Io(err) => {
                            log::error!("parse body io error {err}");
                            resp.set_status(500);
                            resp.send_header();
                            return;
                        }
                    },
                }
            } else {
                match tokio::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .read(true)
                    .mode(0o644)
                    .open(format!(".sys_bws/{}", cs))
                    .await
                {
                    Ok(mut fd) => match parse_body(r, &mut fd, &cs, content_length).await {
                        Ok(_) => {
                            if let Err(err) = fd.seek(std::io::SeekFrom::Start(0)).await {
                                log::error!("fd seek failed {err}");
                                resp.set_status(500);
                                resp.send_header();
                                return;
                            }
                            handler.handle(&opt, bucket, object, &mut fd).await
                        }
                        Err(err) => match err {
                            ParseBodyError::HashNoMatch => {
                                log::warn!("put object hash not match");
                                resp.set_status(400);
                                resp.send_header();
                                return;
                            }
                            ParseBodyError::ContentLengthIncorrect => {
                                log::warn!("content length invalid");
                                resp.set_status(400);
                                resp.send_header();
                                return;
                            }
                            ParseBodyError::Io(err) => {
                                log::error!("parse body io error {err}");
                                resp.set_status(500);
                                resp.send_header();
                                return;
                            }
                        },
                    },
                    Err(err) => {
                        log::error!("open local path error {err}");
                        resp.set_status(500);
                        resp.send_header();
                        return;
                    }
                }
            }
        }
        ContentSha256::Streaming => {
            let file_name = crate::random_str!(4);
            let file_name = format!(".sys_bws/{}", file_name);
            let ret = match tokio::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .read(true)
                .mode(0o644)
                .open(file_name.as_str())
                .await
            {
                Ok(mut fd) => crate::utils::chunk_parse(r, &mut fd, v4head.hasher()).await,
                Err(err) => {
                    log::error!("open local temp file error {err}");
                    resp.set_status(500);
                    resp.send_header();
                    return;
                }
            };
            if let Err(err) = ret {
                tokio::fs::remove_file(file_name.as_str())
                    .await
                    .unwrap_or_else(|err| log::error!("remove file {file_name} error {err}"));
                match err {
                    crate::utils::ChunkParseError::HashNoMatch => {
                        log::warn!("accept hash no match request");
                        resp.set_status(400);
                        resp.send_header();
                        return;
                    }
                    crate::utils::ChunkParseError::IllegalContent => {
                        log::warn!("accept illegal content request");
                        resp.set_status(400);
                        resp.send_header();
                        return;
                    }
                    crate::utils::ChunkParseError::Io(err) => {
                        log::error!("local io error {err}");
                        resp.set_status(500);
                        resp.send_header();
                        return;
                    }
                }
            }
            match tokio::fs::OpenOptions::new()
                .read(true)
                .open(file_name.as_str())
                .await
            {
                Ok(mut fd) => {
                    let ret = handler.handle(&opt, bucket, object, &mut fd).await;
                    tokio::fs::remove_file(file_name.as_str())
                        .await
                        .unwrap_or_else(|err| log::error!("remove file {file_name} error {err}"));
                    ret
                }
                Err(err) => {
                    log::error!("open file {file_name} error {err}");
                    resp.set_status(500);
                    resp.send_header();
                    tokio::fs::remove_file(file_name.as_str())
                        .await
                        .unwrap_or_else(|err| log::error!("remove file {file_name} error {err}"));
                    return;
                }
            }
        }
    };
    //
    match ret {
        Ok(_) => {
            resp.set_status(200);
            resp.send_header();
        }
        Err(err) => {
            resp.set_status(500);
            resp.send_header();
            log::error!("put object handle error: {err}");
        }
    }
}
pub struct DeleteObjectOption {}
pub trait DeleteObjectHandler {
    fn handle<'a>(
        &'a self,
        opt: &'a DeleteObjectOption,
        object: &'a str,
    ) -> std::pin::Pin<Box<dyn 'a + Send + std::future::Future<Output = Result<(), String>>>>;
}

pub async fn handle_delete_object<T: VRequest, F: VResponse>(
    req: T,
    resp: &mut F,
    handler: &std::sync::Arc<dyn DeleteObjectHandler + Send + Sync>,
) {
    let opt = DeleteObjectOption {};
    let url_path = req.url_path();
    if let Err(e) = handler.handle(&opt, url_path.trim_matches('/')).await {
        resp.set_status(500);
        log::info!("delete object handler error: {e}");
    } else {
        resp.set_status(204);
    }
}

pub struct CreateBucketOption {
    pub grant_full_control: Option<String>,
    pub grant_read: Option<String>,
    pub grant_read_acp: Option<String>,
    pub grant_write: Option<String>,
    pub grant_write_acp: Option<String>,
    pub object_lock_enabled_for_bucket: Option<bool>,
    pub object_ownership: Option<ObjectOwnership>,
}
pub enum ObjectOwnership {
    BucketOwnerPreferred,
    ObjectWriter,
    BucketOwnerEnforced,
}
impl FromStr for ObjectOwnership {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "BucketOwnerPreferred" => Ok(ObjectOwnership::BucketOwnerPreferred),
            "ObjectWriter" => Ok(ObjectOwnership::ObjectWriter),
            "BucketOwnerEnforced" => Ok(ObjectOwnership::BucketOwnerEnforced),
            _ => Err(Error(s.to_string())),
        }
    }
}
pub struct CreateBucketConfiguration {
    pub bucket: Option<BucketInfo>,
    pub location: Option<LocationInfo>,
    pub location_constraint: Option<BucketLocationConstraint>,
}
pub struct BucketInfo {
    pub data_redundancy: DataRedundancy,
    pub bucket_type: BucketType,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataRedundancy {
    SingleAvailabilityZone,
    SingleLocalZone,
    Unknown(String),
}

impl From<&str> for DataRedundancy {
    fn from(s: &str) -> Self {
        match s {
            "SingleAvailabilityZone" => Self::SingleAvailabilityZone,
            "SingleLocalZone" => Self::SingleLocalZone,
            other => Self::Unknown(other.to_string()),
        }
    }
}
impl Display for DataRedundancy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            match self {
                DataRedundancy::SingleAvailabilityZone => "SingleAvailabilityZone".to_string(),
                DataRedundancy::SingleLocalZone => "SingleLocalZone".to_string(),
                DataRedundancy::Unknown(s) => s.clone(),
            }
            .as_str(),
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BucketType {
    Directory,
    Unknown(String),
}

impl From<&str> for BucketType {
    fn from(s: &str) -> Self {
        match s {
            "Directory" => Self::Directory,
            other => Self::Unknown(other.to_string()),
        }
    }
}

impl Display for BucketType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            match self {
                Self::Directory => "Directory".to_string(),
                Self::Unknown(s) => s.clone(),
            }
            .as_str(),
        )
    }
}

pub struct LocationInfo {
    pub name: Option<String>,
    pub location_type: LocationType,
}

pub enum LocationType {
    AvailabilityZone,
    LocalZone,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BucketLocationConstraint {
    AfSouth1,
    ApEast1,
    ApNortheast1,
    ApNortheast2,
    ApNortheast3,
    ApSouth1,
    ApSouth2,
    ApSoutheast1,
    ApSoutheast2,
    ApSoutheast3,
    ApSoutheast4,
    ApSoutheast5,
    CaCentral1,
    CnNorth1,
    CnNorthwest1,
    Eu,
    EuCentral1,
    EuCentral2,
    EuNorth1,
    EuSouth1,
    EuSouth2,
    EuWest1,
    EuWest2,
    EuWest3,
    IlCentral1,
    MeCentral1,
    MeSouth1,
    SaEast1,
    UsEast2,
    UsGovEast1,
    UsGovWest1,
    UsWest1,
    UsWest2,
    Unknown(String),
}
impl From<&str> for BucketLocationConstraint {
    fn from(s: &str) -> Self {
        match s {
            "af-south-1" => Self::AfSouth1,
            "ap-east-1" => Self::ApEast1,
            "ap-northeast-1" => Self::ApNortheast1,
            "ap-northeast-2" => Self::ApNortheast2,
            "ap-northeast-3" => Self::ApNortheast3,
            "ap-south-1" => Self::ApSouth1,
            "ap-south-2" => Self::ApSouth2,
            "ap-southeast-1" => Self::ApSoutheast1,
            "ap-southeast-2" => Self::ApSoutheast2,
            "ap-southeast-3" => Self::ApSoutheast3,
            "ap-southeast-4" => Self::ApSoutheast4,
            "ap-southeast-5" => Self::ApSoutheast5,
            "ca-central-1" => Self::CaCentral1,
            "cn-north-1" => Self::CnNorth1,
            "cn-northwest-1" => Self::CnNorthwest1,
            "EU" => Self::Eu,
            "eu-central-1" => Self::EuCentral1,
            "eu-central-2" => Self::EuCentral2,
            "eu-north-1" => Self::EuNorth1,
            "eu-south-1" => Self::EuSouth1,
            "eu-south-2" => Self::EuSouth2,
            "eu-west-1" => Self::EuWest1,
            "eu-west-2" => Self::EuWest2,
            "eu-west-3" => Self::EuWest3,
            "il-central-1" => Self::IlCentral1,
            "me-central-1" => Self::MeCentral1,
            "me-south-1" => Self::MeSouth1,
            "sa-east-1" => Self::SaEast1,
            "us-east-2" => Self::UsEast2,
            "us-gov-east-1" => Self::UsGovEast1,
            "us-gov-west-1" => Self::UsGovWest1,
            "us-west-1" => Self::UsWest1,
            "us-west-2" => Self::UsWest2,
            other => Self::Unknown(other.to_string()),
        }
    }
}

impl Display for BucketLocationConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AfSouth1 => "af-south-1",
            Self::ApEast1 => "ap-east-1",
            Self::ApNortheast1 => "ap-northeast-1",
            Self::ApNortheast2 => "ap-northeast-2",
            Self::ApNortheast3 => "ap-northeast-3",
            Self::ApSouth1 => "ap-south-1",
            Self::ApSouth2 => "ap-south-2",
            Self::ApSoutheast1 => "ap-southeast-1",
            Self::ApSoutheast2 => "ap-southeast-2",
            Self::ApSoutheast3 => "ap-southeast-3",
            Self::ApSoutheast4 => "ap-southeast-4",
            Self::ApSoutheast5 => "ap-southeast-5",
            Self::CaCentral1 => "ca-central-1",
            Self::CnNorth1 => "cn-north-1",
            Self::CnNorthwest1 => "cn-northwest-1",
            Self::Eu => "EU",
            Self::EuCentral1 => "eu-central-1",
            Self::EuCentral2 => "eu-central-2",
            Self::EuNorth1 => "eu-north-1",
            Self::EuSouth1 => "eu-south-1",
            Self::EuSouth2 => "eu-south-2",
            Self::EuWest1 => "eu-west-1",
            Self::EuWest2 => "eu-west-2",
            Self::EuWest3 => "eu-west-3",
            Self::IlCentral1 => "il-central-1",
            Self::MeCentral1 => "me-central-1",
            Self::MeSouth1 => "me-south-1",
            Self::SaEast1 => "sa-east-1",
            Self::UsEast2 => "us-east-2",
            Self::UsGovEast1 => "us-gov-east-1",
            Self::UsGovWest1 => "us-gov-west-1",
            Self::UsWest1 => "us-west-1",
            Self::UsWest2 => "us-west-2",
            Self::Unknown(s) => s,
        })
    }
}

pub trait CreateBucketHandler {
    fn handle<'a>(
        &'a self,
        opt: &'a CreateBucketOption,
        bucket: &'a str,
    ) -> std::pin::Pin<Box<dyn 'a + Send + std::future::Future<Output = Result<(), String>>>>;
}
pub async fn handle_create_bucket<T: VRequest, F: VResponse>(
    req: T,
    resp: &mut F,
    handler: &std::sync::Arc<dyn CreateBucketHandler + Send + Sync>,
) {
    if req.method() != "PUT" {
        resp.set_status(405);
        resp.send_header();
        return;
    }

    let opt = CreateBucketOption {
        grant_full_control: req.get_header("x-amz-grant-full-control"),
        grant_read: req.get_header("x-amz-grant-read"),
        grant_read_acp: req.get_header("x-amz-grant-read-acp"),
        grant_write: req.get_header("x-amz-grant-write"),
        grant_write_acp: req.get_header("x-amz-grant-write-acp"),
        object_lock_enabled_for_bucket: req
            .get_header("x-amz-bucket-object-lock-enabled")
            .and_then(|v| {
                if v == "true" {
                    Some(true)
                } else if v == "false" {
                    Some(false)
                } else {
                    None
                }
            }),
        object_ownership: req
            .get_header("x-amz-object-ownership")
            .and_then(|v| v.parse().ok()),
    };
    let url_path = req.url_path();
    if let Err(e) = handler.handle(&opt, url_path.trim_matches('/')).await {
        resp.set_status(500);
        log::info!("delete object handler error: {e}")
    }
}

pub struct DeleteBucketOption {
    pub expected_owner: Option<String>,
}
pub trait DeleteBucketHandler {
    fn handle<'a>(
        &'a self,
        opt: &'a DeleteBucketOption,
        bucket: &'a str,
    ) -> std::pin::Pin<Box<dyn 'a + Send + std::future::Future<Output = Result<(), String>>>>;
}

pub async fn handle_delete_bucket<T: VRequest, F: VResponse>(
    req: T,
    resp: &mut F,
    handler: &std::sync::Arc<dyn DeleteBucketHandler + Send + Sync>,
) {
    if req.method() != "DELETE" {
        resp.set_status(405);
        resp.send_header();
        return;
    }
    let opt = DeleteBucketOption {
        expected_owner: req.get_header("x-amz-expected-bucket-owner"),
    };
    let url_path = req.url_path();
    match handler.handle(&opt, url_path.trim_matches('/')).await {
        Ok(_) => {
            resp.set_status(204);
            resp.send_header();
        }
        Err(e) => {
            resp.set_status(500);
            log::error!("delete object handler error: {e}")
        }
    }
}

//utils

enum ParseBodyError {
    HashNoMatch,
    ContentLengthIncorrect,
    Io(String),
}

async fn parse_body<
    T: crate::utils::io::PollRead + Send,
    E: tokio::io::AsyncWrite + Send + Unpin,
>(
    mut src: T,
    dst: &mut E,
    content_sha256: &str,
    mut content_length: usize,
) -> Result<(), ParseBodyError> {
    use tokio::io::AsyncWriteExt;
    let mut hsh = sha2::Sha256::new();
    // if content length > 10MB, it will store on disk instead memory
    while let Some(buff) = src.poll_read().await.map_err(ParseBodyError::Io)? {
        let buff_len = buff.len();
        if content_length < buff_len {
            return Err(ParseBodyError::ContentLengthIncorrect);
        }
        content_length -= buff_len;
        let _ = hsh.write_all(&buff);
        dst.write_all(&buff)
            .await
            .map_err(|err| ParseBodyError::Io(format!("write error {err}")))?;
    }
    let ret = hsh.finalize();
    let real_sha256 = hex::encode(ret);
    if real_sha256.as_str() != content_sha256 {
        Err(ParseBodyError::HashNoMatch)
    } else {
        Ok(())
    }
}

async fn parse_streaming_body<
    T: crate::utils::io::PollRead + Send,
    E: tokio::io::AsyncWrite + Send + Unpin,
>(
    mut src: T,
    dst: &mut E,
    content_sha256: &str,
) -> Result<(), ParseBodyError> {
    todo!()
}
// #[cfg(test)]
// mod req_test {
//     use std::{collections::HashMap, sync::RwLock};
//     static FAKE_ETAG: &str = "ffffffffffffffff";
//     struct HttpRequest {
//         url_path: String,
//         query: Vec<(String, String)>,
//         method: String,
//         headers: HashMap<String, String>,
//     }
//     impl crate::authorization::v4::VHeader for HttpRequest {
//         fn get_header(&self, key: &str) -> Option<String> {
//             self.headers
//                 .get(key)
//                 .map_or_else(|| None, |v| Some(v.clone()))
//         }

//         fn set_header(&mut self, key: &str, val: &str) {
//             self.headers.insert(key.to_string(), val.to_string());
//         }

//         fn delete_header(&mut self, key: &str) {
//             self.headers.remove(key);
//         }

//         fn rng_header(&self, mut cb: impl FnMut(&str, &str) -> bool) {
//             self.headers.iter().all(|(k, v)| cb(k, v));
//         }
//     }
//     impl super::VRequest for HttpRequest {
//         fn method(&self) -> String {
//             self.method.clone()
//         }

//         fn url_path(&self) -> String {
//             self.url_path.clone()
//         }

//         fn get_query(&self, target: &str) -> Option<String> {
//             let ans: Vec<_> = self.query.iter().filter(|(k, v)| k == target).collect();
//             if !ans.is_empty() {
//                 Some(ans.first().unwrap().1.clone())
//             } else {
//                 None
//             }
//         }

//         fn all_query(&self, mut cb: impl FnMut(&str, &str) -> bool) {
//             self.query.iter().all(|(k, v)| cb(k, v));
//         }
//     }
//     #[derive(Default)]
//     struct HttpResponse {
//         status: u16,
//         headers: HashMap<String, String>,
//         body: Vec<u8>,
//     }
//     impl crate::authorization::v4::VHeader for HttpResponse {
//         fn get_header(&self, key: &str) -> Option<String> {
//             self.headers
//                 .get(key)
//                 .map_or_else(|| None, |v| Some(v.clone()))
//         }

//         fn set_header(&mut self, key: &str, val: &str) {
//             self.headers.insert(key.to_string(), val.to_string());
//         }

//         fn delete_header(&mut self, key: &str) {
//             self.headers.remove(key);
//         }

//         fn rng_header(&self, mut cb: impl FnMut(&str, &str) -> bool) {
//             self.headers.iter().all(|(k, v)| cb(k, v));
//         }
//     }
//     struct VecWriter<'a>(&'a mut Vec<u8>);
//     impl<'a> std::io::Write for VecWriter<'_> {
//         fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
//             self.0.extend_from_slice(buf);
//             Ok(buf.len())
//         }

//         fn flush(&mut self) -> std::io::Result<()> {
//             Ok(())
//         }
//     }
//     impl super::BodyWriter for HttpResponse {
//         type BodyWriter<'a> = VecWriter<'a>;

//         fn get_body_writer(&mut self) -> Result<Self::BodyWriter<'_>, String> {
//             Ok(VecWriter(&mut self.body))
//         }
//     }
//     impl super::VResponse for HttpResponse {
//         fn set_status(&mut self, status: u16) {
//             if self.status != 0 {
//                 return;
//             }
//             self.status = status;
//         }

//         fn send_header(&mut self) {}
//     }

//     pub struct ListBucket(Vec<String>);
//     impl super::ListObjectHandler for ListBucket {
//         fn handle(
//             &self,
//             _: &super::ListObjectOption,
//             bucket: &str,
//         ) -> Result<Vec<super::ListObjectContent>, String> {
//             let last_modified = chrono::Utc::now().to_rfc2822();
//             Ok(self
//                 .0
//                 .iter()
//                 .filter_map(|v| {
//                     if v.starts_with(bucket) {
//                         return Some(super::ListObjectContent {
//                             key: v.trim_start_matches(bucket).to_string(),
//                             last_modified: Some(last_modified.clone()),
//                             etag: Some("801cbd6952577c28310fd5002670132a".to_string()),
//                             size: 20,
//                             owner: Some(super::Owner {
//                                 id: "123456789".to_string(),
//                                 display_name: "root".to_string(),
//                             }),
//                             storage_class: Some("standard".to_string()),
//                         });
//                     }
//                     None
//                 })
//                 .collect())
//         }
//     }

//     impl super::ListBucketHandler for ListBucket {
//         fn handle(
//             &self,
//             opt: &super::ListBucketsOption,
//         ) -> Result<Vec<super::Bucket>, String> {
//             let date = chrono::Utc::now().to_rfc2822();
//             Ok(self
//                 .0
//                 .iter()
//                 .map(|v| super::Bucket {
//                     name: v.find('/').map_or(v.clone(), |next| v[..next].to_string()),
//                     creation_date: date.clone(),
//                     bucket_region: "us-east-1".to_string(),
//                 })
//                 .collect())
//         }
//     }

//     #[test]
//     fn list_object() {
//         let lb = ListBucket(vec![
//             "test/hello.txt".to_string(),
//             "test/test.dat".to_string(),
//             "one/jack.json".to_string(),
//             "one/jim.json".to_string(),
//         ]);
//         let hm = HashMap::default();
//         let req = HttpRequest {
//             url_path: "/test".to_string(),
//             query: vec![],
//             method: "GET".to_string(),
//             headers: hm,
//         };
//         let mut resp = HttpResponse {
//             status: 0,
//             headers: HashMap::default(),
//             body: vec![],
//         };
//         super::handle_get_list_object(&req, &mut resp, &lb);
//         String::from_utf8(resp.body)
//             .map_or_else(|e| eprintln!("not ascii {e}"), |v| println!("{v}"));
//     }
//     #[test]
//     fn list_buckets() {
//         let hm = HashMap::default();
//         let req = HttpRequest {
//             url_path: "/".to_string(),
//             query: vec![],
//             method: "GET".to_string(),
//             headers: hm,
//         };
//         let mut resp = HttpResponse {
//             status: 0,
//             headers: HashMap::default(),
//             body: vec![],
//         };
//         let lb = ListBucket(vec![
//             "test/hello.txt".to_string(),
//             "test/test.dat".to_string(),
//             "one/jack.json".to_string(),
//             "one/jim.json".to_string(),
//         ]);
//         super::handle_get_list_buckets(&req, &mut resp, &lb);
//         String::from_utf8(resp.body)
//             .map_or_else(|e| eprintln!("not ascii {e}"), |v| println!("{v}"));
//     }

//     impl super::CreateBucketHandler for RwLock<ListBucket> {
//         fn handle(
//             &self,
//             opt: &super::CreateBucketOption,
//             bucket: &str,
//         ) -> Result<(), String> {
//             self.write().map_or(
//                 Err(Box::new(super::Error("write lock failed".to_string()))),
//                 |mut raw| {
//                     for v in raw.0.iter() {
//                         if v == bucket {
//                             return Ok(());
//                         }
//                     }
//                     raw.0.push(bucket.to_string());
//                     Ok(())
//                 },
//             )
//         }
//     }
//     impl super::DeleteBucketHandler for RwLock<ListBucket> {
//         fn handle(
//             &self,
//             opt: &super::DeleteBucketOption,
//             bucket: &str,
//         ) -> Result<(), String> {
//             self.write().map_or(
//                 Err(Box::new(super::Error("write lock failed".to_string()))),
//                 |mut v| {
//                     let mut index = 0;
//                     let mut remove_index = -1;
//                     for vv in v.0.iter() {
//                         if vv == bucket {
//                             remove_index = index;
//                             break;
//                         }
//                         index += 1;
//                     }
//                     if remove_index >= 0 {
//                         v.0.remove(remove_index as usize);
//                     }
//                     Ok(())
//                 },
//             )
//         }
//     }
//     #[test]
//     fn create_bucket() {
//         let hm = HashMap::default();
//         let mut req = HttpRequest {
//             url_path: "/t10".to_string(),
//             query: vec![],
//             method: "PUT".to_string(),
//             headers: hm,
//         };
//         let mut resp = HttpResponse {
//             status: 0,
//             headers: HashMap::default(),
//             body: vec![],
//         };
//         let lb = ListBucket(vec![]);
//         let lb = RwLock::new(lb);
//         super::handle_create_bucket(&req, &mut resp, &lb);
//         assert!(
//             lb.read().expect("read lock error").0.len() == 1,
//             "create bucket failed {}",
//             resp.status
//         );
//         req.method = "DELETE".to_string();
//         resp = HttpResponse {
//             status: 0,
//             headers: HashMap::default(),
//             body: vec![],
//         };
//         super::handle_delete_bucket(&req, &mut resp, &lb);
//         assert!(
//             lb.read().unwrap().0.is_empty(),
//             "delete failed {}",
//             resp.status
//         );
//     }
//     impl super::LookupHandler for HashMap<String, String> {
//         fn lookup(
//             &self,
//             bucket: &str,
//             object: &str,
//         ) -> Result<Option<super::HeadObjectResult>, super::Error> {
//             let ret = self.get(object);
//             if let None = ret {
//                 return Ok(None);
//             }
//             let info = ret.unwrap();
//             Ok(Some(super::HeadObjectResult {
//                 content_length: Some(info.len()),
//                 content_type: Some("text/plain".to_string()),
//                 etag: Some(FAKE_ETAG.to_string()),
//                 last_modified: Some(chrono::Utc::now().to_rfc2822().to_string()),
//                 ..Default::default()
//             }))
//         }
//     }
//     impl super::GetObjectHandler for HashMap<String, String> {
//         fn handle(
//             &self,
//             bucket: &str,
//             object: &str,
//             mut out: impl FnMut(&[u8]) -> Result<(), String>,
//         ) -> Result<(), String> {
//             let ret = self.get(object);
//             if let None = ret {
//                 return Err(Box::new(super::Error("content not found".to_string())));
//             }
//             let info = ret.unwrap();
//             out(info.as_bytes())
//         }
//     }

//     #[test]
//     fn get_object() {
//         let hm = HashMap::default();
//         let req = HttpRequest {
//             url_path: "/test/test.txt".to_string(),
//             query: vec![],
//             method: "GET".to_string(),
//             headers: hm,
//         };
//         let mut resp = HttpResponse::default();
//         let mut objstore = HashMap::default();
//         objstore.insert("test.txt".to_string(), "im test!".to_string());
//         super::handle_get_object(&req, &mut resp, &objstore);
//         assert!(
//             resp.status == 200,
//             "response status is not 200 {}",
//             resp.status
//         );
//         let val = String::from_utf8(resp.body).map_or("NoAscii".to_string(), |v| v);
//         assert!(
//             val == "im test!",
//             "response content is not 'im test!' got {}",
//             val
//         );

//         let mut resp = HttpResponse::default();
//         let mut objstore = HashMap::default();
//         objstore.insert("hello.txt".to_string(), "im test!".to_string());
//         super::handle_get_object(&req, &mut resp, &objstore);
//         assert!(
//             resp.status == 404,
//             "response status is not 404 {}",
//             resp.status
//         );
//     }
//     #[test]
//     fn put_and_delete_object() {}
// }
