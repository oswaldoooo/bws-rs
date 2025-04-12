use std::{io::Write, sync::Mutex};

pub trait VRequest: crate::authorization::v4::VHeader {
    fn method(&self) -> String;
    fn url_path(&self) -> String;
    fn get_query(&self, k: &str) -> Option<String>;
    fn all_query(&self, cb: impl FnMut(&str, &str) -> bool);
}

pub trait VResponse: crate::authorization::v4::VHeader {
    type BodyWriter<'a>: std::io::Write
    where
        Self: 'a;
    fn set_status(&mut self, status: i32);
    fn send_header(&mut self);
    fn get_body_writer(&mut self) -> Result<Self::BodyWriter<'_>, Box<dyn std::error::Error>>;
}

pub trait GetObjectHandler {
    fn handle(
        &self,
        rpath: &str,
        set_meta: impl FnMut(usize, &str, &str, chrono::DateTime<chrono::Utc>), /*content-length,content-type,etag,last-modified */
        out: impl FnMut(&[u8]) -> Result<usize, Box<dyn std::error::Error>>,
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

pub fn handle_get_object<T: VRequest, F: VResponse, E: GetObjectHandler>(
    req: &T,
    resp: &mut F,
    handler: &E,
) {
    let rpath = req.url_path();
    let resp2 = Mutex::new(resp);
    let ret = handler.handle(
        &rpath,
        |size, ct, etag, last_modified| {
            resp2
                .lock()
                .expect("lock failed")
                .set_header("content-type", ct);
            resp2
                .lock()
                .expect("lock failed")
                .set_header("content-length", size.to_string().as_str());
            resp2.lock().expect("lock failed").set_header("etag", etag);
            resp2
                .lock()
                .expect("lock failed")
                .set_header("last-modified", last_modified.to_rfc2822().as_str());
        },
        |d| {
            let mut writer = resp2.lock().expect("lock failed");
            let mut w = writer.get_body_writer()?;
            w.write_all(d)?;
            Ok(d.len())
        },
    );
    if let Err(err) = ret {
        log::info!("get_object handle return error: {err}");
        resp2.lock().expect("lock failed").set_status(400);
        resp2.lock().expect("lock failed").send_header();
        return;
    }
}

//query list-type=2, return ListObjectResult
pub fn handle_get_list_object<T: VRequest, F: VResponse, E: ListObjectHandler>(
    req: &T,
    resp: &mut F,
    handler: &E,
) {
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

pub struct PutObjectOption {}
pub trait PutObjectHandler {
    fn handle(
        &self,
        opt: &PutObjectOption,
        object: &str,
        body: &mut dyn std::io::Read,
    ) -> Result<(), Box<dyn std::error::Error>>;
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

pub struct CreateBucketOption {}
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
    let opt = CreateBucketOption {};
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

pub struct DeleteBucketOption {}
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
    let opt = DeleteBucketOption {};
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
    use std::{collections::HashMap, str::Bytes};

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
    impl super::VResponse for HttpResponse {
        fn set_status(&mut self, status: i32) {
            if status != 0 {
                return;
            }
            self.status = status;
        }

        fn send_header(&mut self) {}

        type BodyWriter<'a> = VecWriter<'a>;

        fn get_body_writer(&mut self) -> Result<Self::BodyWriter<'_>, Box<dyn std::error::Error>> {
            Ok(VecWriter(&mut self.body))
        }
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
    }
}
