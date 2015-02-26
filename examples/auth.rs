extern crate "yup-oauth2" as oauth2;
extern crate "yup-hyper-mock" as mock;
extern crate hyper;
extern crate getopts;

use getopts::{HasArg,Options,Occur,Fail};
use std::os;
use std::old_io::{File, FileMode, FileAccess};
use std::old_path::Path;

fn usage(program: &str, opts: &Options, err: Option<Fail>) {
    if err.is_some() {
        println!("{}", err.unwrap());
        os::set_exit_status(1);
    }
    println!("{}", opts.short_usage(program) + " SCOPE [SCOPE ...]");
    println!("{}", opts.usage("A program to authenticate against oauthv2 services.\n\
              See https://developers.google.com/youtube/registering_an_application\n\
              and https://developers.google.com/youtube/v3/guides/authentication#devices"));
}

fn main() {
    let args = os::args();
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

    let client_id = m.opt_str("c").unwrap();
    let client_secret = m.opt_str("s").unwrap();

    println!("THIS PROGRAM PRINTS ALL COMMUNICATION TO STDERR !!!");

    struct StdoutHandler;
    impl oauth2::DeviceFlowHelperDelegate for StdoutHandler {
        fn present_user_code(&mut self, pi: oauth2::PollInformation) {
            println!("Please enter '{}' at {} and authenticate the application for the\n\
                      given scopes. This is not a test !\n\
                      You have time until {} to do that.
                      Do not terminate the program until you deny or grant access !",
                      pi.user_code, pi.verification_url, pi.expires_at);
        }
    }

    let client = hyper::Client::with_connector(mock::TeeConnector {
                        connector: hyper::net::HttpConnector(None) 
                    });
    if let Some(t) = oauth2::DeviceFlowHelper::new(&mut StdoutHandler)
                    .retrieve_token(client, &client_id, &client_secret, &m.free) {
            println!("Authentication granted !");
            println!("You should store the following information for use, or revoke it.");
            println!("{:?}", t);
    } else {
        println!("Invalid client id, invalid scope, user denied access or request expired");
        os::set_exit_status(10);
    }
}