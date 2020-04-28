use crate::regex_builder::compile_re;

use std::boxed::Box;

use std::borrow::Cow;

use regex::Regex;

#[derive(Debug, PartialEq, Eq)]
pub enum HashIOC<'a> {
    MD5(&'a str),
    SHA1(&'a str),
    SHA256(&'a str),
    SHA512(&'a str),
    SSDEEP(&'a str)
}

const MD5_PATTERN: &'static str = r#"\b[A-Fa-f0-9]{32}\b"#;

pub fn parse_md5(input: &str) -> Vec<HashIOC> {
    lazy_static! {
        static ref MD5_RE: Box<Regex>= compile_re(Cow::from(MD5_PATTERN));
    }
    return MD5_RE.find_iter(input)
    .map(|x|HashIOC::MD5(x.as_str()))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_md5() {
        assert_eq!(parse_md5("this ioc 08f2eb5f1bcbaf25ba97aef26593ed96"), 
        vec![HashIOC::MD5("08f2eb5f1bcbaf25ba97aef26593ed96")])
    }
}