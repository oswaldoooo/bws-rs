use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    io::Write,
    str::FromStr,
    sync::Mutex,
};
static OwnerId: &'static str = "ffffffffffffffff";
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
    type BodyWriter<'a>: std::io::Write
    where
        Self: 'a;
    fn get_body_writer(&mut self) -> Result<Self::BodyWriter<'_>, Box<dyn std::error::Error>>;
}
pub trait BodyReader {
    type BodyReader<'a>: std::io::Read
    where
        Self: 'a;
    fn get_body_reader(&mut self) -> Result<Self::BodyReader<'_>, Box<dyn std::error::Error>>;
}
pub trait VResponse: crate::authorization::v4::VHeader + BodyWriter {
    fn set_status(&mut self, status: i32);
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

pub trait LookupHandler {
    fn lookup(&self, bucket: &str, object: &str) -> Result<Option<HeadObjectResult>, Error>;
}

pub trait GetObjectHandler: LookupHandler {
    fn handle(
        &self,
        bucket: &str,
        object: &str,
        out: impl FnMut(&[u8]) -> Result<(), Box<dyn std::error::Error>>,
    ) -> Result<(), Box<dyn std::error::Error>>;
}
extern crate serde;
use serde::Serialize;

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
    fn handle(
        &self,
        opt: &ListObjectOption,
        bucket: &str,
    ) -> Result<Vec<ListObjectContent>, Box<dyn std::error::Error>>;
}
pub fn handle_head_object<T: VRequest, F: VResponse, E: LookupHandler>(
    req: &T,
    resp: &mut F,
    handler: &E,
) {
    todo!()
}
pub fn handle_get_object<T: VRequest, F: VResponse, E: GetObjectHandler>(
    req: &T,
    resp: &mut F,
    handler: &E,
) {
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
    let next = r.unwrap();
    let bucket = &raw[..next];
    let object = &raw[next + 1..];

    let head = handler.lookup(bucket, object);
    if let Err(e) = head {
        log::error!("lookup {bucket} {object} error: {e}");
        resp.set_status(500);
        resp.send_header();
        return;
    }
    let head = head.unwrap();
    if let None = head {
        log::info!("not found {bucket} {object}");
        resp.set_status(404);
        resp.send_header();
        return;
    }
    //send header info to client
    let head = head.unwrap();
    head.content_length
        .map(|v| resp.set_header("content-length", v.to_string().as_str()));
    head.etag.map(|v| resp.set_header("etag", &v));
    head.content_type
        .map(|v| resp.set_header("content-type", &v));
    head.last_modified
        .map(|v| resp.set_header("last-modified", &v));
    //
    resp.set_status(200);
    resp.send_header();
    let ret = handler.handle(bucket, object, |d| {
        let mut w = resp.get_body_writer()?;
        w.write_all(d)?;
        Ok(())
    });
    if let Err(err) = ret {
        log::error!("get_object handle return error: {err}");
        return;
    }
}

//query list-type=2, return ListObjectResult
pub fn handle_get_list_object<T: VRequest, F: VResponse, E: ListObjectHandler>(
    req: &T,
    resp: &mut F,
    handler: &E,
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
        max_keys: req.get_query("max-keys").map_or(None, |v| {
            i32::from_str_radix(&v, 10).map_or(None, |v| Some(v))
        }),
        optional_object_attributes: None, //todo: support option_object_attributes on v2
        request_payer: req.get_header("x-amz-request-layer"),
        start_after: req.get_query("start-after"),
        encoding_type: req.get_query("encoding-type"),
        fetch_owner: req.get_query("fetch-owner").map_or(None, |v| {
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
    let ret = handler.handle(&opt, rpath.trim_matches('/'));
    ret.map(|ans| {
        let result = ListObjectResult {
            name: bucket,
            prefix: opt.prefix,
            key_count: Some(ans.len() as u32),
            max_keys: opt.max_keys.map_or(None, |v| Some(v as u32)),
            delimiter: opt.delimiter,
            is_truncated: false,
            contents: ans,
            common_prefixes: vec![],
        };
        let _ = quick_xml::se::to_string(&result)
            .map(|data| {
                resp.set_header("content-type", "application/xml");
                resp.set_header("content-length", data.len().to_string().as_str());
                resp.set_status(200);
                resp.send_header();
                resp.get_body_writer().map_or_else(
                    |e| log::error!("get_body_writer error:{e}"),
                    |mut bw| {
                        let _ = bw.write_all(data.as_bytes());
                    },
                );
            })
            .map_err(|e| {
                println!("get error {e}");
                log::error!("to_utf8_io_writer error: {e}")
            });
    })
    .unwrap_or_else(|e| log::info!("list_bucket_handle error: {e}"));
}

pub trait ListBucketHandler {
    fn handle(&self, opt: &ListBucketsOption) -> Result<Vec<Bucket>, Box<dyn std::error::Error>>;
}
#[derive(Debug)]
pub struct ListBucketsOption {
    pub bucket_region: Option<String>,
    pub continuation_token: Option<String>,
    pub max_buckets: Option<i32>,
    pub prefix: Option<String>,
}
pub fn handle_get_list_buckets<T: VRequest, F: VResponse, E: ListBucketHandler>(
    req: &T,
    resp: &mut F,
    handler: &E,
) {
    if req.method() != "GET" {
        resp.set_status(405);
        resp.send_header();
        return;
    }
    let opt = ListBucketsOption {
        bucket_region: req.get_query("bucket-region"),
        continuation_token: req.get_query("continuation-token"),
        max_buckets: req.get_query("max-buckets").map_or(None, |v| {
            i32::from_str_radix(&v, 10).map_or(None, |v| Some(v))
        }),
        prefix: req.get_query("prefix"),
    };
    handler.handle(&opt).map_or_else(
        |e| log::info!("listbucket handle error: {e}"),
        |v| {
            let res = ListAllMyBucketsResult {
                xmlns: r#"xmlns="http://s3.amazonaws.com/doc/2006-03-01/""#.to_string(),
                owner: Owner {
                    id: OwnerId.to_string(),
                    display_name: "bws".to_string(),
                },
                buckets: Buckets { bucket: v },
            };
            quick_xml::se::to_string(&res).map_or_else(
                |e| log::error!("xml serde error: {e}"),
                |v| {
                    resp.get_body_writer().map_or_else(
                        |e| log::error!("get_body_writer error: {e}"),
                        |mut w| {
                            let _ = w.write_all(v.as_bytes());
                        },
                    );
                },
            );
        },
    );
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
    fn handle(
        &self,
        opt: &PutObjectOption,
        bucket: &str,
        object: &str,
        body: &mut dyn std::io::Read,
    ) -> Result<(), Box<dyn std::error::Error>>;
}
pub fn handle_put_object<T: VRequest + BodyReader, F: VResponse, E: PutObjectHandler>(
    mut req: &mut T,
    resp: &mut F,
    handler: &E,
) {
    if req.method() != "PUT" {
        resp.set_status(405);
        resp.send_header();
        return;
    }
    let url_path = req.url_path();
    let url_path = url_path.trim_matches('/');
    let ret = url_path.find('/');
    if let None = ret {
        resp.set_status(400);
        resp.send_header();
        return;
    }
    let next = ret.unwrap();
    let bucket = &url_path[..next];
    let object = &url_path[next + 1..];
    let opt = PutObjectOption {
        cache_control: req.get_header("cache-control"),
        checksum_algorithm: req.get_header("checksum-algorithm").map_or(None, |v| {
            ChecksumAlgorithm::from_str(&v).map_or(None, |v| Some(v))
        }),
        checksum_crc32: req.get_header("x-amz-checksum-crc32"),
        checksum_crc32c: req.get_header("x-amz-checksum-crc32c"),
        checksum_crc64nvme: req.get_header("x-amz-checksum-crc64vme"),
        checksum_sha1: req.get_header("x-amz-checksum-sha1"),
        checksum_sha256: req.get_header("x-amz-checksum-sha256"),
        content_disposition: req.get_header("content-disposition"),
        content_encoding: req.get_header("cotent-encoding"),
        content_language: req.get_header("content-language"),
        content_length: req.get_header("content-length").map_or(None, |v| {
            i64::from_str_radix(&v, 10).map_or(Some(-1), |v| Some(v))
        }),
        content_md5: req.get_header("content-md5"),
        content_type: req.get_header("content-type"),
        expected_bucket_owner: req.get_header("x-amz-expected-bucket-owner"),
        expires: req.get_header("expire").map_or(None, |v| {
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
            .map_or(None, |v| {
                ObjectLockLegalHoldStatus::from_str(&v).map_or(None, |v| Some(v))
            }),
        object_lock_mode: req.get_header("x-amz-object-lock-mode").map_or(None, |v| {
            ObjectLockMode::from_str(&v).map_or(None, |v| Some(v))
        }),
        object_lock_retain_until_date: req
            .get_header("x-amz-object-lock-retain_until_date")
            .map_or(None, |v| {
                chrono::NaiveDateTime::parse_from_str(&v, "%a, %d %b %Y %H:%M:%S GMT")
                    .map_or(None, |v| {
                        Some(chrono::DateTime::from_naive_utc_and_offset(v, chrono::Utc))
                    })
            }),
        request_payer: req.get_header("x-amz-request-payer").map_or(None, |v| {
            RequestPayer::from_str(&v).map_or(None, |v| Some(v))
        }),
        storage_class: req.get_header("x-amz-storage-class"),
        // tagging: todo!(),
        // website_redirect_location: todo!(),
        write_offset_bytes: req
            .get_header("x-amz-write-offset-bytes")
            .map_or(None, |v| {
                i64::from_str_radix(&v, 10).map_or(None, |v| Some(v))
            }),
    };
    let ret = req.get_body_reader();
    if let Err(err) = ret {
        resp.set_status(500);
        resp.send_header();
        log::error!("get body reader error: {err}");
        return;
    }
    let mut r = ret.unwrap();
    match handler.handle(&opt, bucket, object, &mut r) {
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
    fn handle(
        &self,
        opt: &DeleteObjectOption,
        object: &str,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

pub fn handle_delete_object<T: VRequest, F: VResponse, E: DeleteObjectHandler>(
    req: &T,
    resp: &mut F,
    handler: &E,
) {
    let opt = DeleteObjectOption {};
    let url_path = req.url_path();
    handler
        .handle(&opt, url_path.trim_matches('/'))
        .map_or_else(
            |e| {
                resp.set_status(500);
                log::info!("delete object handler error: {e}")
            },
            |_| {},
        );
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

impl ToString for DataRedundancy {
    fn to_string(&self) -> String {
        match self {
            Self::SingleAvailabilityZone => "SingleAvailabilityZone".to_string(),
            Self::SingleLocalZone => "SingleLocalZone".to_string(),
            Self::Unknown(s) => s.clone(),
        }
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

impl ToString for BucketType {
    fn to_string(&self) -> String {
        match self {
            Self::Directory => "Directory".to_string(),
            Self::Unknown(s) => s.clone(),
        }
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

impl ToString for BucketLocationConstraint {
    fn to_string(&self) -> String {
        match self {
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
        }
        .to_string()
    }
}

pub trait CreateBucketHandler {
    fn handle(
        &self,
        opt: &CreateBucketOption,
        bucket: &str,
    ) -> Result<(), Box<dyn std::error::Error>>;
}
fn handle_create_bucket<T: VRequest, F: VResponse, E: CreateBucketHandler>(
    req: &T,
    resp: &mut F,
    handler: &E,
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
        object_lock_enabled_for_bucket: req.get_header("x-amz-bucket-object-lock-enabled").map_or(
            None,
            |v| {
                if v == "true" {
                    Some(true)
                } else if v == "false" {
                    Some(false)
                } else {
                    None
                }
            },
        ),
        object_ownership: req
            .get_header("x-amz-object-ownership")
            .map_or(None, |v| v.parse().map_or(None, |f| Some(f))),
    };
    let url_path = req.url_path();
    let _ = handler
        .handle(&opt, url_path.trim_matches('/'))
        .map_err(|e| {
            resp.set_status(500);
            log::info!("delete object handler error: {e}")
        });
}

pub struct DeleteBucketOption {
    pub expected_owner: Option<String>,
}
pub trait DeleteBucketHandler {
    fn handle(
        &self,
        opt: &DeleteBucketOption,
        bucket: &str,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

fn handle_delete_bucket<T: VRequest, F: VResponse, E: DeleteBucketHandler>(
    req: &T,
    resp: &mut F,
    handler: &E,
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
    handler
        .handle(&opt, url_path.trim_matches('/'))
        .map_or_else(
            |e| {
                resp.set_status(500);
                log::info!("delete object handler error: {e}")
            },
            |_| {},
        );
}
#[cfg(test)]
mod req_test {
    use std::{collections::HashMap, str::Bytes, sync::RwLock};
    static FakeEtag: &'static str = "ffffffffffffffff";
    struct HttpRequest {
        url_path: String,
        query: Vec<(String, String)>,
        method: String,
        headers: HashMap<String, String>,
    }
    impl crate::authorization::v4::VHeader for HttpRequest {
        fn get_header(&self, key: &str) -> Option<String> {
            self.headers
                .get(key)
                .map_or_else(|| None, |v| Some(v.clone()))
        }

        fn set_header(&mut self, key: &str, val: &str) {
            self.headers.insert(key.to_string(), val.to_string());
        }

        fn delete_header(&mut self, key: &str) {
            self.headers.remove(key);
        }

        fn rng_header(&self, mut cb: impl FnMut(&str, &str) -> bool) {
            self.headers.iter().all(|(k, v)| cb(k, v));
        }
    }
    impl super::VRequest for HttpRequest {
        fn method(&self) -> String {
            self.method.clone()
        }

        fn url_path(&self) -> String {
            self.url_path.clone()
        }

        fn get_query(&self, target: &str) -> Option<String> {
            let ans: Vec<_> = self.query.iter().filter(|(k, v)| k == target).collect();
            if ans.len() > 0 {
                Some(ans.get(0).unwrap().1.clone())
            } else {
                None
            }
        }

        fn all_query(&self, mut cb: impl FnMut(&str, &str) -> bool) {
            self.query.iter().all(|(k, v)| cb(k, v));
        }
    }
    #[derive(Default)]
    struct HttpResponse {
        status: i32,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    }
    impl crate::authorization::v4::VHeader for HttpResponse {
        fn get_header(&self, key: &str) -> Option<String> {
            self.headers
                .get(key)
                .map_or_else(|| None, |v| Some(v.clone()))
        }

        fn set_header(&mut self, key: &str, val: &str) {
            self.headers.insert(key.to_string(), val.to_string());
        }

        fn delete_header(&mut self, key: &str) {
            self.headers.remove(key);
        }

        fn rng_header(&self, mut cb: impl FnMut(&str, &str) -> bool) {
            self.headers.iter().all(|(k, v)| cb(k, v));
        }
    }
    struct VecWriter<'a>(&'a mut Vec<u8>);
    impl<'a> std::io::Write for VecWriter<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl super::BodyWriter for HttpResponse {
        type BodyWriter<'a> = VecWriter<'a>;

        fn get_body_writer(&mut self) -> Result<Self::BodyWriter<'_>, Box<dyn std::error::Error>> {
            Ok(VecWriter(&mut self.body))
        }
    }
    impl super::VResponse for HttpResponse {
        fn set_status(&mut self, status: i32) {
            if self.status != 0 {
                return;
            }
            self.status = status;
        }

        fn send_header(&mut self) {}
    }

    pub struct ListBucket(Vec<String>);
    impl super::ListObjectHandler for ListBucket {
        fn handle(
            &self,
            _: &super::ListObjectOption,
            bucket: &str,
        ) -> Result<Vec<super::ListObjectContent>, Box<dyn std::error::Error>> {
            let last_modified = chrono::Utc::now().to_rfc2822();
            Ok(self
                .0
                .iter()
                .filter_map(|v| {
                    if v.starts_with(bucket) {
                        return Some(super::ListObjectContent {
                            key: v.trim_start_matches(bucket).to_string(),
                            last_modified: Some(last_modified.clone()),
                            etag: Some("801cbd6952577c28310fd5002670132a".to_string()),
                            size: 20,
                            owner: Some(super::Owner {
                                id: "123456789".to_string(),
                                display_name: "root".to_string(),
                            }),
                            storage_class: Some("standard".to_string()),
                        });
                    }
                    None
                })
                .collect())
        }
    }

    impl super::ListBucketHandler for ListBucket {
        fn handle(
            &self,
            opt: &super::ListBucketsOption,
        ) -> Result<Vec<super::Bucket>, Box<dyn std::error::Error>> {
            let date = chrono::Utc::now().to_rfc2822();
            Ok(self
                .0
                .iter()
                .map(|v| super::Bucket {
                    name: v
                        .find('/')
                        .map_or(v.clone(), |next| (&v[..next]).to_string()),
                    creation_date: date.clone(),
                    bucket_region: "us-east-1".to_string(),
                })
                .collect())
        }
    }

    #[test]
    fn list_object() {
        let lb = ListBucket(vec![
            "test/hello.txt".to_string(),
            "test/test.dat".to_string(),
            "one/jack.json".to_string(),
            "one/jim.json".to_string(),
        ]);
        let mut hm = HashMap::default();
        let req = HttpRequest {
            url_path: "/test".to_string(),
            query: vec![],
            method: "GET".to_string(),
            headers: hm,
        };
        let mut resp = HttpResponse {
            status: 0,
            headers: HashMap::default(),
            body: vec![],
        };
        super::handle_get_list_object(&req, &mut resp, &lb);
        String::from_utf8(resp.body)
            .map_or_else(|e| eprintln!("not ascii {e}"), |v| println!("{v}"));
    }
    #[test]
    fn list_buckets() {
        let mut hm = HashMap::default();
        let req = HttpRequest {
            url_path: "/".to_string(),
            query: vec![],
            method: "GET".to_string(),
            headers: hm,
        };
        let mut resp = HttpResponse {
            status: 0,
            headers: HashMap::default(),
            body: vec![],
        };
        let lb = ListBucket(vec![
            "test/hello.txt".to_string(),
            "test/test.dat".to_string(),
            "one/jack.json".to_string(),
            "one/jim.json".to_string(),
        ]);
        super::handle_get_list_buckets(&req, &mut resp, &lb);
        String::from_utf8(resp.body)
            .map_or_else(|e| eprintln!("not ascii {e}"), |v| println!("{v}"));
    }

    impl super::CreateBucketHandler for RwLock<ListBucket> {
        fn handle(
            &self,
            opt: &super::CreateBucketOption,
            bucket: &str,
        ) -> Result<(), Box<dyn std::error::Error>> {
            self.write().map_or(
                Err(Box::new(super::Error("write lock failed".to_string()))),
                |mut raw| {
                    for v in raw.0.iter() {
                        if v == bucket {
                            return Ok(());
                        }
                    }
                    raw.0.push(bucket.to_string());
                    Ok(())
                },
            )
        }
    }
    impl super::DeleteBucketHandler for RwLock<ListBucket> {
        fn handle(
            &self,
            opt: &super::DeleteBucketOption,
            bucket: &str,
        ) -> Result<(), Box<dyn std::error::Error>> {
            self.write().map_or(
                Err(Box::new(super::Error("write lock failed".to_string()))),
                |mut v| {
                    let mut index = 0;
                    let mut remove_index = -1;
                    for vv in v.0.iter() {
                        if vv == bucket {
                            remove_index = index as i32;
                            break;
                        }
                        index = index + 1;
                    }
                    if remove_index >= 0 {
                        v.0.remove(remove_index as usize);
                    }
                    Ok(())
                },
            )
        }
    }
    #[test]
    fn create_bucket() {
        let mut hm = HashMap::default();
        let mut req = HttpRequest {
            url_path: "/t10".to_string(),
            query: vec![],
            method: "PUT".to_string(),
            headers: hm,
        };
        let mut resp = HttpResponse {
            status: 0,
            headers: HashMap::default(),
            body: vec![],
        };
        let lb = ListBucket(vec![]);
        let lb = RwLock::new(lb);
        super::handle_create_bucket(&req, &mut resp, &lb);
        assert!(
            lb.read().expect("read lock error").0.len() == 1,
            "create bucket failed {}",
            resp.status
        );
        req.method = "DELETE".to_string();
        resp = HttpResponse {
            status: 0,
            headers: HashMap::default(),
            body: vec![],
        };
        super::handle_delete_bucket(&req, &mut resp, &lb);
        assert!(
            lb.read().unwrap().0.len() == 0,
            "delete failed {}",
            resp.status
        );
    }
    impl super::LookupHandler for HashMap<String, String> {
        fn lookup(
            &self,
            bucket: &str,
            object: &str,
        ) -> Result<Option<super::HeadObjectResult>, super::Error> {
            let ret = self.get(object);
            if let None = ret {
                return Ok(None);
            }
            let info = ret.unwrap();
            Ok(Some(super::HeadObjectResult {
                content_length: Some(info.len()),
                content_type: Some("text/plain".to_string()),
                etag: Some(FakeEtag.to_string()),
                last_modified: Some(chrono::Utc::now().to_rfc2822().to_string()),
                ..Default::default()
            }))
        }
    }
    impl super::GetObjectHandler for HashMap<String, String> {
        fn handle(
            &self,
            bucket: &str,
            object: &str,
            mut out: impl FnMut(&[u8]) -> Result<(), Box<dyn std::error::Error>>,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let ret = self.get(object);
            if let None = ret {
                return Err(Box::new(super::Error("content not found".to_string())));
            }
            let info = ret.unwrap();
            out(info.as_bytes())
        }
    }

    #[test]
    fn get_object() {
        let hm = HashMap::default();
        let req = HttpRequest {
            url_path: "/test/test.txt".to_string(),
            query: vec![],
            method: "GET".to_string(),
            headers: hm,
        };
        let mut resp = HttpResponse::default();
        let mut objstore = HashMap::default();
        objstore.insert("test.txt".to_string(), "im test!".to_string());
        super::handle_get_object(&req, &mut resp, &objstore);
        assert!(
            resp.status == 200,
            "response status is not 200 {}",
            resp.status
        );
        let val = String::from_utf8(resp.body).map_or("NoAscii".to_string(), |v| v);
        assert!(
            val == "im test!",
            "response content is not 'im test!' got {}",
            val
        );

        let mut resp = HttpResponse::default();
        let mut objstore = HashMap::default();
        objstore.insert("hello.txt".to_string(), "im test!".to_string());
        super::handle_get_object(&req, &mut resp, &objstore);
        assert!(
            resp.status == 404,
            "response status is not 404 {}",
            resp.status
        );
    }
    #[test]
    fn put_and_delete_object() {}
}
