//! Just run this program: It will ask you for authorization to view metadata,
//! and then display you the contents of your Google Drive root directory.
//!
//! This example demonstrates how to use the [interactive OAuth 2 flow for installed
//! applications.](https://developers.google.com/identity/protocols/OAuth2InstalledApp)
//!
//! Copyright (c) 2016 Google, Inc. (Lewin Bormann <lbo@spheniscida.de>)

extern crate hyper;
extern crate yup_oauth2;
extern crate serde_json;
extern crate google_drive3;

use std::path::Path;

use yup_oauth2::{Authenticator, FlowType, ApplicationSecret, DiskTokenStorage,
                 DefaultAuthenticatorDelegate, read_application_secret};
use google_drive3::Drive;

const CLIENT_SECRET_FILE: &'static str = "example_client_secret.json";

// reads the provided example client secret, the quick and dirty way.
fn read_client_secret(file: String) -> ApplicationSecret {
    read_application_secret(Path::new(&file)).unwrap()
}

fn main() {
    let secret = read_client_secret(CLIENT_SECRET_FILE.to_string());
    let authenticator = Authenticator::new(&secret,
                                           DefaultAuthenticatorDelegate,
                                           hyper::Client::new(),
                                           DiskTokenStorage::new(&"token_store.json".to_string())
                                               .unwrap(),
                                           Some(FlowType::InstalledInteractive));
    let hub = Drive::new(hyper::Client::new(), authenticator);

    let (_resp, list_result) = hub.files().list().q("'root' in parents and trashed = false").doit().unwrap();

    for file in list_result.files.unwrap_or(vec![]) {
        println!("{} ({})",
                 file.name.unwrap_or(String::new()),
                 file.mime_type.unwrap_or(String::new()));
    }
}
