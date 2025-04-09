use std::io::Write;

use hmac::{Hmac, Mac};
use sha1::Digest;
pub trait VHeader {
    fn get(&self, key: &str) -> Option<String>;
    fn set(&mut self, key: &str, val: &str);
    fn delete(&mut self, key: &str);
    fn rng(&self, cb: impl FnMut(&str, &str) -> bool);
}
use crate::{GenericResult, error::Error};

fn get_v4_signature<T: VHeader>(
    req: &T,
    method: &str,
    region: &str,
    url_path: &str,
    secretkey: &str,
    content_hash: &str,
) -> GenericResult<String> {
    let xamz_date = req.get("x-amz-date");
    if xamz_date.is_none() {
        return Err(Box::new(Error::Illegal));
    }
    let xamz_date = xamz_date.unwrap();
    let (ans, keyans) = get_sorted_headers(req);
    let tosign = format!(
        "{method}\n{url_path}\n\n{}\n\n{}\n{}",
        ans.join("\n").to_string(),
        keyans.join(";").to_string(),
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
        "AWS4-HMAC-SHA256\n{}\n{}/{region}/s3/aws4_request\n{canonical_hsh}",
        xamz_date,
        xamz_date[..8].to_string()
    );
    // println!("tosign:{tosign}");
    let ret = Hmac::<sha2::Sha256>::new_from_slice(buff);
    if let Err(err) = ret {
        return Err(Box::new(Error::Other(format!("{err}"))));
    }
    let mut hsh = ret.unwrap();
    hsh.update(tosign.as_bytes());
    let ans = hsh.finalize().into_bytes();
    Ok(hex::encode(ans))
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
        return Err(Box::new(Error::Other(format!("{err}"))));
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
                return Err(Box::new(Error::Other(format!("{err}"))));
            }
        }
    }
    (&mut target[0..next.len()]).copy_from_slice(&next);
    Ok(())
}
fn get_sorted_headers<T: VHeader>(headers: &T) -> (Vec<String>, Vec<String>) {
    let mut ans = vec![];
    let mut keyans = vec![];
    let keyansref = &mut keyans;
    headers.rng(|k, _| {
        if k != "host" && !k.starts_with("x-amz-") {
            return true;
        }
        keyansref.push(k.to_string());
        true
    });
    keyans.sort();
    for k in keyans.iter() {
        let val = headers.get(&k).unwrap();
        ans.push(format!("{k}:{val}"));
    }
    (ans, keyans)
}

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

#[cfg(test)]
mod v4test {
    use std::{collections::HashMap, io::Write};

    use sha1::Digest;

    use crate::GenericResult;

    use super::VHeader;
    impl VHeader for HashMap<String, String> {
        fn get(&self, key: &str) -> Option<String> {
            let ans = self.get(key);
            match ans {
                Some(ans) => Some(ans.clone()),
                None => None,
            }
        }

        fn set(&mut self, key: &str, val: &str) {
            self.insert(key.to_string(), val.to_string());
        }

        fn delete(&mut self, key: &str) {
            self.remove(key);
        }

        fn rng(&self, mut cb: impl FnMut(&str, &str) -> bool) {
            self.iter().all(|(k, v)| cb(&k, &v));
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
        let signature = super::get_v4_signature(
            &hm,
            "GET",
            "us-east-1",
            "/",
            "root12345",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )?;
        assert!(
            signature == "2e3e50b8ab771944088edcda925d886a078ec2442e8504f58e1ac3ef8a2f40fc",
            "expect 2e3e50b8ab771944088edcda925d886a078ec2442e8504f58e1ac3ef8a2f40fc, get {signature}"
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
        let signature = super::get_v4_signature(
            &hm,
            "PUT",
            "us-east-1",
            "/test/hello.txt",
            "root12345",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        )?;
        assert!(
            signature == "ae05fb994613c1a72e9f1d3bf14de119155587b955ca7d5589a056e7ffab680f",
            "expect ae05fb994613c1a72e9f1d3bf14de119155587b955ca7d5589a056e7ffab680f,get {signature}"
        );
        Ok(())
    }
    #[test]
    fn v4_chunk_signature_test() -> GenericResult<()> {
        let mut hm = HashMap::new();
        hm.insert("x-amz-date".to_string(), "20250407T060526Z".to_string());
        hm.insert(
            "x-amz-content-sha256".to_string(),
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".to_string(),
        );
        hm.insert("host".to_string(), "127.0.0.1:9000".to_string());
        hm.insert("x-amz-decoded-content-length".to_string(), "6".to_string());
        let headersignature = super::get_v4_signature(
            &hm,
            "PUT",
            "us-east-1",
            "/test/hello.txt",
            "root12345",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
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
            "expect fe78329ef4be9a33af1ffb23c435cf9d985c79dc65911ac78a66317f5a0521bb,get {hsh}"
        );
        let final_chunk_hsh =
            hsch.next("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")?;
        assert!(
            final_chunk_hsh == "9095844b0da3ae2e9fe65b372662c4beadfc38ebe5a709b16ea9b03d427d03ad",
            "expect 9095844b0da3ae2e9fe65b372662c4beadfc38ebe5a709b16ea9b03d427d03ad,get {final_chunk_hsh}"
        );
        Ok(())
    }
}
