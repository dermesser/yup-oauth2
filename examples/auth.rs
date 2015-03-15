#![feature(collections, old_io, std_misc, exit_status)]
#![allow(deprecated)]
extern crate "yup-oauth2" as oauth2;
extern crate "yup-hyper-mock" as mock;
extern crate hyper;
extern crate chrono;
extern crate getopts;
extern crate open;

use oauth2::GetToken;
use chrono::{Local};
use getopts::{HasArg,Options,Occur,Fail};
use std::env;
use std::default::Default;
use std::time::Duration;
use std::old_io::timer::sleep;


fn usage(program: &str, opts: &Options, err: Option<Fail>) {
    if err.is_some() {
        println!("{}", err.unwrap());
        env::set_exit_status(1);
    }
    println!("{}", opts.short_usage(program) + " SCOPE [SCOPE ...]");
    println!("{}", opts.usage("A program to authenticate against oauthv2 services.\n\
              See https://developers.google.com/youtube/registering_an_application\n\
              and https://developers.google.com/youtube/v3/guides/authentication#devices"));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let prog = args[0].clone();

    let mut opts = Options::new();
    opts.opt("c", "id", "oauthv2 ID of your application", "CLIENT_ID", HasArg::Yes, Occur::Req)
        .opt("s", "secret", "oauthv2 secret of your application", "CLIENT_SECRET", HasArg::Yes, Occur::Req);

    let m = match opts.parse(args.tail()) {
        Ok(m) => m,
        Err(e) => {
            usage(&prog, &opts, Some(e));
            return
        }
    };

    if m.free.len() == 0 {
        let msg = Fail::ArgumentMissing("you must provide one or more authorization scopes as free options".to_string());
        usage(&prog, &opts, Some(msg));
        return
    }

    let secret = oauth2::ApplicationSecret {
        client_id: m.opt_str("c").unwrap(),
        client_secret: m.opt_str("s").unwrap(),
        token_uri: Default::default(),
        auth_uri: Default::default(),
        redirect_uris: Default::default(),
        client_email: None,
        auth_provider_x509_cert_url: None,
        client_x509_cert_url: None
    };

    println!("THIS PROGRAM PRINTS ALL COMMUNICATION TO STDERR !!!");

    struct StdoutHandler;
    impl oauth2::AuthenticatorDelegate for StdoutHandler {
        fn present_user_code(&mut self, pi: oauth2::PollInformation) {
            println!("Please enter '{}' at {} and authenticate the application for the\n\
                      given scopes. This is not a test !\n\
                      You have time until {} to do that.
                      Do not terminate the program until you deny or grant access !",
                      pi.user_code, pi.verification_url, pi.expires_at.with_timezone(&Local));
            let delay = Duration::seconds(5);
            println!("Browser opens automatically in {} seconds", delay);
            sleep(delay);
            open::that(&pi.verification_url).ok();
            println!("DONE - waiting for authorization ...");
        }
    }

    let client = hyper::Client::with_connector(mock::TeeConnector {
                        connector: hyper::net::HttpConnector(None) 
                    });

    if let Some(t) = oauth2::Authenticator::new(&secret, StdoutHandler, client, 
                        oauth2::NullStorage, None)
                    .token(&m.free) {
            println!("Authentication granted !");
            println!("You should store the following information for use, or revoke it.");
            println!("All dates are given in UTC.");
            println!("{:?}", t);
    } else {
        println!("Invalid client id, invalid scope, user denied access or request expired");
        env::set_exit_status(10);
    }
}