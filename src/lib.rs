pub mod authorization;pub mod error;mod utils;pub mod service;

pub type GenericResult<T>=Result<T,Box<dyn std::error::Error>>;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
