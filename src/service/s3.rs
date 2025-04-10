use std::io::Write;

pub trait VRequest: crate::authorization::v4::VHeader {
    fn method(&self) -> String;
    fn url_path(&self) -> String;
    fn get_query(&self, k: &str) -> Option<String>;
    fn all_query(&self, cb: impl FnMut(&str, &str) -> bool);
}

pub trait VResponse: crate::authorization::v4::VHeader + std::io::Write {
    type BodyWriter: std::io::Write;
    fn set_status(&mut self, status: i32);
    fn send_header(&mut self);
    fn get_body_writer(&mut self) -> Result<Self::BodyWriter, Box<dyn std::error::Error>>;
}

pub trait GetObjectHandler {
    fn handle(
        &self,
        rpath: &str,
        set_meta: impl FnMut(usize, &str, &str, chrono::DateTime<chrono::Utc>), /*content-length,content-type,etag,last-modified */
        out: &mut dyn Write,
    ) -> Result<(), Box<dyn std::error::Error>>;
}
extern crate serde;
#[derive(Debug, self::serde::Serialize)]
pub struct ListBucketContent {
    #[serde(rename = "Key")]
    pub key: String,

    #[serde(rename = "LastModified")]
    pub last_modified: String,

    #[serde(rename = "ETag")]
    pub etag: String,

    #[serde(rename = "Size")]
    pub size: i32, // 如果有可能大于 i32::MAX，可以改成 i64 或 u64

    #[serde(rename = "Owner")]
    pub owner: Owner,

    #[serde(rename = "StorageClass")]
    pub storage_class: String,
}
#[derive(Debug, self::serde::Serialize)]
pub struct Owner {
    #[serde(rename = "ID")]
    pub id: String,

    #[serde(rename = "DisplayName")]
    pub display_name: String,
}

pub struct ListBucketOption {
    pub delimeter: Option<String>,
    pub fetch_owner: Option<bool>,
    pub list_type: Option<String>,
    pub prefix: String,
    pub encoding_type: String,
}
pub trait ListBucketHandler {
    fn handle(
        &self,
        opt: &ListBucketOption,
        bucket: &str,
    ) -> Result<Vec<ListBucketContent>, Box<dyn std::error::Error>>;
}

pub fn handle_get_object<T: VRequest, F: VResponse, E: GetObjectHandler>(
    req: &T,
    resp: &mut F,
    handler: &E,
) {
    let rpath = req.url_path();
    let bw = resp.get_body_writer();
    if let Err(err) = bw {
        log::error!("get_body_writer error: {err}");
        return;
    }
    let ret = handler.handle(
        &rpath,
        |size, ct, etag, last_modified| {
            resp.set_header("content-type", ct);
            resp.set_header("content-length", size.to_string().as_str());
            resp.set_header("etag", etag);
            resp.set_header("last-modified", last_modified.to_rfc2822().as_str());
        },
        &mut bw.unwrap(),
    );
    if let Err(err) = ret {
        log::info!("get_object handle return error: {err}");
        resp.set_status(400);
        resp.send_header();
        return;
    }
}

pub fn handle_get_list_bucket<T: VRequest, F: VResponse, E: ListBucketHandler>(
    req: &T,
    resp: &mut F,
    handler: &E,
) {
    let rpath = req.url_path();
    let bw = resp.get_body_writer();
    if let Err(err) = bw {
        log::error!("get_body_writer error: {err}");
        return;
    }
    let opt = ListBucketOption {
        delimeter: req.get_query("delimeter"),
        fetch_owner: req
            .get_query("fetch_owner")
            .map(|f| Some(if f == "true" { true } else { false }))
            .unwrap_or_else(|| None),
        list_type: req.get_query("list_type"),
        prefix: req
            .get_query("prefix")
            .map(|f| f)
            .unwrap_or_else(|| "".to_string()),
        encoding_type: req
            .get_query("encoding_type")
            .map(|f| f)
            .unwrap_or_else(|| "".to_string()),
    };
    let ret = handler.handle(&opt, rpath.trim_matches('/'));
    ret.map(|ans| {
        let _ = quick_xml::se::to_string(&ans)
            .map(|data| {
                resp.set_header("content-type", "application/xml");
                resp.set_header("content-length", data.len().to_string().as_str());
                resp.set_status(200);
                resp.send_header();
                let _ = bw.unwrap().write_all(data.as_bytes());
            })
            .map_err(|e| log::error!("to_utf8_io_writer error: {e}"));
    })
    .unwrap_or_else(|e| log::info!("list_bucket_handle error: {e}"));
}
