use std::io::Write;
extern crate hmac;
extern crate sha1;
use self::hmac::{Hmac, Mac};
use self::sha1::Digest;
pub trait VHeader {
    fn get_header(&self, key: &str) -> Option<String>;
    fn set_header(&mut self, key: &str, val: &str);
    fn delete_header(&mut self, key: &str);
    fn rng_header(&self, cb: impl FnMut(&str, &str) -> bool);
}
use crate::{error::Error, GenericResult};
#[derive(Debug)]
pub struct BaseArgs {
    pub region: String,
    pub service: String,
    pub access_key: String,
    pub content_hash: String,
    pub signed_headers: Vec<String>,
    pub signature: String,
    pub date: String,
}
pub fn extract_args<R: VHeader>(r: &R) -> Result<BaseArgs, ()> {
    let authorization = r.get_header("authorization").ok_or(())?;
    let authorization = authorization.trim();
    let heads = authorization.splitn(2, ' ').collect::<Vec<&str>>();
    if heads.len() != 2 {
        return Err(());
    }
    match heads[0] {
        "AWS4-HMAC-SHA256" => {
            let heads = heads[1].split(',').collect::<Vec<&str>>();
            if heads.len() != 3 {
                return Err(());
            }
            let mut credential = None;
            let mut singed_headers = None;
            let mut signature = None;
            for head in heads {
                let heads = head.trim().splitn(2, '=').collect::<Vec<&str>>();
                if heads.len() != 2 {
                    return Err(());
                }
                match heads[0] {
                    "Credential" => {
                        let heads = heads[1].split('/').collect::<Vec<&str>>();
                        if heads.len() != 5 {
                            return Err(());
                        }
                        credential = Some((heads[0], heads[1], heads[2], heads[3], heads[4]));
                    }
                    "SignedHeaders" => {
                        singed_headers = Some(heads[1].split(';').collect::<Vec<&str>>());
                    }
                    "Signature" => {
                        signature = Some(heads[1]);
                    }
                    _ => {
                        return Err(());
                    }
                }
            }
            if signature.is_none() || singed_headers.is_none() || credential.is_none() {
                return Err(());
            }
            let signature = signature.unwrap();
            let singed_headers = singed_headers.unwrap();
            let credential = credential.unwrap();
            Ok(BaseArgs {
                content_hash: r.get_header("x-amz-content-sha256").ok_or(())?,
                region: credential.2.to_string(),
                service: credential.3.to_string(),
                access_key: credential.0.to_string(),
                signed_headers: singed_headers.into_iter().map(|v| v.to_string()).collect(),
                signature: signature.to_string(),
                date: credential.1.to_string(),
            })
        }
        _ => Err(()),
    }
}
pub fn get_v4_signature<'a, T: VHeader, S: ToString>(
    req: &T,
    method: &str,
    region: &str,
    service: &str,
    url_path: &str,
    secretkey: &str,
    content_hash: &str,
    signed_headers: &[S],
    mut query: Vec<crate::utils::BaseKv<String, String>>,
) -> GenericResult<(String, HmacSha256CircleHasher)> {
    let xamz_date = req.get_header("x-amz-date");
    if xamz_date.is_none() {
        return Err(Error::Illegal.to_string());
    }
    let xamz_date = xamz_date.unwrap();
    let ans: Vec<String> = signed_headers
        .iter()
        .map(|v| {
            let v = v.to_string();
            let val = req.get_header(&v);
            match val {
                Some(val) => format!("{}:{val}", v),
                None => format!("{}:", v),
            }
        })
        .collect();
    query.sort_by(|a, b| a.key.cmp(&b.key));
    let query: Vec<String> = query
        .iter()
        .map(|v| format!("{}={}", v.key, v.val))
        .collect();
    let tosign = format!(
        "{method}\n{url_path}\n{}\n{}\n\n{}\n{}",
        query.join("&"),
        ans.join("\n"),
        signed_headers
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<String>>()
            .join(";"),
        content_hash
    );
    let ksign = get_v4_ksigning(secretkey, region, &xamz_date)?;
    let buff: &[u8] = &ksign;
    // println!("{tosign}");

    let mut hsh = sha2::Sha256::default();
    let _ = hsh.write_all(tosign.as_bytes());
    let ans = hsh.finalize();
    let canonical_hsh = hex::encode(ans);

    let tosign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}/{region}/{service}/aws4_request\n{canonical_hsh}",
        xamz_date,
        &xamz_date[..8]
    );
    // println!("tosign:{tosign}");
    let ret = Hmac::<sha2::Sha256>::new_from_slice(buff);
    if let Err(err) = ret {
        return Err(err.to_string());
    }
    let mut hsh = ret.unwrap();
    hsh.update(tosign.as_bytes());
    let ans = hsh.finalize().into_bytes();
    let hsh = hex::encode(ans);
    Ok((
        hsh.clone(),
        HmacSha256CircleHasher::new(ksign, hsh, xamz_date, region.to_string()),
    ))
}
fn get_v4_ksigning(secretkey: &str, region: &str, xamz_date: &str) -> GenericResult<[u8; 32]> {
    let mut ksign = [0u8; 32];
    circle_hmac_sha256(
        format!("AWS4{secretkey}").as_str(),
        vec![
            xamz_date[..8].as_bytes(),
            region.as_bytes(),
            "s3".as_bytes(),
            "aws4_request".as_bytes(),
        ]
        .as_slice(),
        &mut ksign,
    )?;
    Ok(ksign)
}
fn circle_hmac_sha256(initkey: &str, values: &[&[u8]], target: &mut [u8]) -> GenericResult<()> {
    let ret = Hmac::<sha2::Sha256>::new_from_slice(initkey.as_bytes());
    if let Err(err) = ret {
        return Err(err.to_string());
    }
    let mut hsh = ret.unwrap();
    hsh.update(values[0]);
    let mut next = hsh.finalize().into_bytes();
    for i in 1..values.len() {
        match Hmac::<sha2::Sha256>::new_from_slice(&next) {
            Ok(mut hsh) => {
                hsh.update(values[i]);
                next = hsh.finalize().into_bytes();
            }
            Err(err) => {
                return Err(err.to_string());
            }
        }
    }
    target[0..next.len()].copy_from_slice(&next);
    Ok(())
}
#[derive(Clone)]
pub struct HmacSha256CircleHasher {
    ksigning: [u8; 32],
    last_hash: String,
    xamz_date: String,
    region: String,
    date: String,
}
impl HmacSha256CircleHasher {
    pub fn new(ksigning: [u8; 32], lasthash: String, xamz_date: String, region: String) -> Self {
        Self {
            ksigning: ksigning,
            last_hash: lasthash,
            region: region,
            xamz_date: xamz_date.clone(),
            date: xamz_date[..8].to_string(),
        }
    }
    pub fn next(&mut self, curr_hsh: &str) -> Result<String, Error> {
        let ans = Hmac::<sha2::Sha256>::new_from_slice(&self.ksigning);
        if let Err(err) = ans {
            return Err(Error::Illegal);
        }
        let mut hsh = ans.unwrap();
        let tosign = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}/{}/s3/aws4_request\n{}\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n{}",
            self.xamz_date, self.date, self.region, self.last_hash, curr_hsh
        );
        hsh.update(tosign.as_bytes());
        let ans = hsh.finalize().into_bytes();
        let ans = hex::encode(ans);
        self.last_hash = ans.clone();
        Ok(ans)
    }
}
#[derive(Clone)]
pub struct V4Head {
    signature: String,
    region: String,
    accesskey: String,
    circle_hasher:HmacSha256CircleHasher,
}
impl V4Head {
    pub fn new(signature: String, region: String, accesskey: String,hasher:HmacSha256CircleHasher) -> Self {
        Self {
            signature,
            region,
            accesskey,
            circle_hasher:hasher,
        }
    }
    pub fn signature(&self) -> &str {
        &self.signature
    }
    pub fn region(&self) -> &str {
        &self.region
    }
    pub fn accesskey(&self) -> &str {
        &self.accesskey
    }
    pub fn hasher(&mut self)->&mut HmacSha256CircleHasher{
        &mut self.circle_hasher
    }
}
#[cfg(test)]
mod v4test {
    use std::{collections::HashMap, io::Write};
    extern crate sha1;
    use self::sha1::Digest;

    use crate::{utils::BaseKv, GenericResult};

    use super::VHeader;
    impl VHeader for HashMap<String, String> {
        fn get_header(&self, key: &str) -> Option<String> {
            let ans = self.get(key);
            ans.cloned()
        }

        fn set_header(&mut self, key: &str, val: &str) {
            self.insert(key.to_string(), val.to_string());
        }

        fn delete_header(&mut self, key: &str) {
            self.remove(key);
        }

        fn rng_header(&self, mut cb: impl FnMut(&str, &str) -> bool) {
            self.iter().all(|(k, v)| cb(k, v));
        }
    }
    #[test]
    fn v4_signature_test() -> GenericResult<()> {
        //case1
        let mut hm = HashMap::new();
        hm.insert("x-amz-date".to_string(), "20250407T021123Z".to_string());
        hm.insert(
            "x-amz-content-sha256".to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        );
        hm.insert("host".to_string(), "127.0.0.1:9000".to_string());
        let (signature,_) = super::get_v4_signature(
            &hm,
            "GET",
            "us-east-1",
            "s3",
            "/",
            "root12345",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            &["host", "x-amz-content-sha256", "x-amz-date"],
            vec![],
        )?;
        assert!(
            signature == "2e3e50b8ab771944088edcda925d886a078ec2442e8504f58e1ac3ef8a2f40fc",
            "expect 2e3e50b8ab771944088edcda925d886a078ec2442e8504f58e1ac3ef8a2f40fc, get {}",
            signature,
        );
        //case2
        let mut hm = HashMap::new();
        hm.insert("x-amz-date".to_string(), "20250407T060526Z".to_string());
        hm.insert(
            "x-amz-content-sha256".to_string(),
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".to_string(),
        );
        hm.insert("host".to_string(), "127.0.0.1:9000".to_string());
        hm.insert("x-amz-decoded-content-length".to_string(), "6".to_string());
        let (signature,_) = super::get_v4_signature(
            &hm,
            "PUT",
            "us-east-1",
            "s3",
            "/test/hello.txt",
            "root12345",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            &[
                "host",
                "x-amz-content-sha256",
                "x-amz-date",
                "x-amz-decoded-content-length",
            ],
            vec![],
        )?;
        assert!(
            signature == "ae05fb994613c1a72e9f1d3bf14de119155587b955ca7d5589a056e7ffab680f",
            "expect ae05fb994613c1a72e9f1d3bf14de119155587b955ca7d5589a056e7ffab680f,get {}",
            signature
        );
        //case3
        let mut hm = HashMap::new();
        hm.insert("x-amz-date".to_string(), "20250410T124056Z".to_string());
        hm.insert(
            "x-amz-content-sha256".to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        );
        hm.insert("host".to_string(), "127.0.0.1:9000".to_string());
        let (signature,_) = super::get_v4_signature(
            &hm,
            "GET",
            "us-east-1",
            "s3",
            "/test/",
            "root12345",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            &["host", "x-amz-content-sha256", "x-amz-date"],
            vec![BaseKv {
                key: "location".to_string(),
                val: "".to_string(),
            }],
        )?;
        assert!(
            signature == "f51cf31bf489474692475a74706f9382c7ba0e93e0d657dc9696efa83fc3906a",
            "expect f51cf31bf489474692475a74706f9382c7ba0e93e0d657dc9696efa83fc3906a, get {}",
            signature,
        );
        Ok(())
    }
    #[test]
    fn v4_chunk_signature_test() -> Result<(), Box<dyn std::error::Error>> {
        let mut hm = HashMap::new();
        hm.insert("x-amz-date".to_string(), "20250407T060526Z".to_string());
        hm.insert(
            "x-amz-content-sha256".to_string(),
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".to_string(),
        );
        hm.insert("host".to_string(), "127.0.0.1:9000".to_string());
        hm.insert("x-amz-decoded-content-length".to_string(), "6".to_string());
        let (headersignature,_) = super::get_v4_signature(
            &hm,
            "PUT",
            "us-east-1",
            "s3",
            "/test/hello.txt",
            "root12345",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            &[
                "host",
                "x-amz-content-sha256",
                "x-amz-date",
                "x-amz-decoded-content-length",
            ],
            vec![],
        )?;
        let ksigning = super::get_v4_ksigning("root12345", "us-east-1", "20250407T060526Z")?;

        let mut hsch = super::HmacSha256CircleHasher::new(
            ksigning,
            headersignature,
            "20250407T060526Z".to_string(),
            "us-east-1".to_string(),
        );
        let mut hsh = sha2::Sha256::default();
        let _ = hsh.write_all("hello\n".as_bytes());
        let ans = hsh.finalize();
        let hsh = hsch.next(hex::encode(ans).as_str())?;
        assert!(
            hsh == "fe78329ef4be9a33af1ffb23c435cf9d985c79dc65911ac78a66317f5a0521bb",
            "expect fe78329ef4be9a33af1ffb23c435cf9d985c79dc65911ac78a66317f5a0521bb,get {}",
            hsh
        );
        let final_chunk_hsh =
            hsch.next("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")?;
        assert!(
            final_chunk_hsh == "9095844b0da3ae2e9fe65b372662c4beadfc38ebe5a709b16ea9b03d427d03ad",
            "expect 9095844b0da3ae2e9fe65b372662c4beadfc38ebe5a709b16ea9b03d427d03ad,get {}",
            final_chunk_hsh
        );
        Ok(())
    }
}
