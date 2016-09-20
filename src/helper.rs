#![allow(dead_code)]

//! Helper functions allowing you to avoid writing boilerplate code for common operations, such as
//! parsing JSON or reading files.

// Copyright (c) 2016 Google Inc (lewinb@google.com).
//
// Refer to the project root for licensing information.

use serde_json;

use std::io::{self, Read};
use std::fs;

use service_account::ServiceAccountKey;
use types::{ConsoleApplicationSecret, ApplicationSecret};

pub fn read_application_secret(file: &String) -> io::Result<ApplicationSecret> {
    use std::io::Read;

    let mut secret = String::new();
    let mut file = try!(fs::OpenOptions::new().read(true).open(file));
    try!(file.read_to_string(&mut secret));

    parse_application_secret(&secret)
}

pub fn parse_application_secret(secret: &String) -> io::Result<ApplicationSecret> {
    let result: serde_json::Result<ConsoleApplicationSecret> = serde_json::from_str(secret);
    match result {
        Err(e) => {
            Err(io::Error::new(io::ErrorKind::InvalidData,
                               format!("Bad application secret: {}", e)))
        }
        Ok(decoded) => {
            if decoded.web.is_some() {
                Ok(decoded.web.unwrap())
            } else if decoded.installed.is_some() {
                Ok(decoded.installed.unwrap())
            } else {
                Err(io::Error::new(io::ErrorKind::InvalidData,
                                   "Unknown application secret format"))
            }
        }
    }
}

pub fn service_account_key_from_file(path: &String) -> io::Result<ServiceAccountKey> {
    let mut key = String::new();
    let mut file = try!(fs::OpenOptions::new().read(true).open(path));
    try!(file.read_to_string(&mut key));

    match serde_json::from_str(&key) {
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}", e))),
        Ok(decoded) => Ok(decoded),
    }
}
