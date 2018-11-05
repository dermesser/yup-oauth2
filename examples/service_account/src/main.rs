//! Demonstrates the use of service accounts and the Google Cloud Pubsub API.
//!
//! Run this binary as .../service_account pub 'your message' in order to publish messages,
//! and as .../service_account sub in order to subscribe to those messages. This will look like the
//! following:
//!
//! ```
//! $ target/debug/service_account pub 'Hello oh wonderful world' &
//! $ target/debug/service_account sub
//! Published message #95491011619126
//! message <95491011619126> 'Hello oh wonderful world' at 2016-09-21T20:04:47.040Z
//! Published message #95491011620879
//! message <95491011620879> 'Hello oh wonderful world' at 2016-09-21T20:04:49.086Z
//! Published message #95491011622600
//! message <95491011622600> 'Hello oh wonderful world' at 2016-09-21T20:04:51.132Z
//! Published message #95491011624393
//! message <95491011624393> 'Hello oh wonderful world' at 2016-09-21T20:04:53.187Z
//! Published message #95491011626206
//! message <95491011626206> 'Hello oh wonderful world' at 2016-09-21T20:04:55.233Z
//! ```
//!
//! (note that this program won't work as-is, because the credentials are invalid; it will work if
//! you supply a valid client secret)
//!
//! Copyright (c) 2016 Google, Inc. (Lewin Bormann <lbo@spheniscida.de>)
//!
extern crate base64;
extern crate yup_oauth2 as oauth;
extern crate google_pubsub1 as pubsub;
extern crate hyper;
extern crate hyper_native_tls;

use std::env;
use std::time;
use std::thread;

use hyper::net::HttpsConnector;
use hyper_native_tls::NativeTlsClient;
use pubsub::{Topic, Subscription};

// The prefixes are important!
const SUBSCRIPTION_NAME: &'static str = "projects/sanguine-rhythm-105020/subscriptions/rust_authd_sub_1";
const TOPIC_NAME: &'static str = "projects/sanguine-rhythm-105020/topics/topic-01";

type PubsubMethods<'a> = pubsub::ProjectMethods<'a,
                                                hyper::Client,
                                                oauth::ServiceAccountAccess<hyper::Client>>;

// Verifies that the topic TOPIC_NAME exists, or creates it.
fn check_or_create_topic(methods: &PubsubMethods) -> Topic {
    let result = methods.topics_get(TOPIC_NAME).doit();

    if result.is_err() {
        println!("Assuming topic doesn't exist; creating topic");
        let topic = pubsub::Topic { name: Some(TOPIC_NAME.to_string()), labels: None };
        let result = methods.topics_create(topic, TOPIC_NAME).doit().unwrap();
        result.1
    } else {
        result.unwrap().1
    }
}

fn check_or_create_subscription(methods: &PubsubMethods) -> Subscription {
    // check if subscription exists
    let result = methods.subscriptions_get(SUBSCRIPTION_NAME).doit();

    if result.is_err() {
        println!("Assuming subscription doesn't exist; creating subscription");
        let sub = pubsub::Subscription {
            topic: Some(TOPIC_NAME.to_string()),
            ack_deadline_seconds: Some(30),
            push_config: None,
            message_retention_duration: None,
            retain_acked_messages: None,
            name: Some(SUBSCRIPTION_NAME.to_string()),
            labels: None,
        };
        let (_resp, sub) = methods.subscriptions_create(sub, SUBSCRIPTION_NAME).doit().unwrap();

        sub
    } else {
        result.unwrap().1
    }
}

fn ack_message(methods: &PubsubMethods, id: String) {
    let request = pubsub::AcknowledgeRequest { ack_ids: Some(vec![id]) };
    let result = methods.subscriptions_acknowledge(request, SUBSCRIPTION_NAME).doit();

    match result {
        Err(e) => {
            println!("Ack error: {:?}", e);
        }
        Ok(_) => (),
    }
}

// Wait for new messages. Print and ack any new messages.
fn subscribe_wait(methods: &PubsubMethods) {
    check_or_create_subscription(&methods);

    let request = pubsub::PullRequest {
        return_immediately: Some(false),
        max_messages: Some(1),
    };


    loop {
        let result = methods.subscriptions_pull(request.clone(), SUBSCRIPTION_NAME).doit();

        match result {
            Err(e) => {
                println!("Pull error: {}", e);
            }
            Ok((_response, pullresponse)) => {
                for msg in pullresponse.received_messages.unwrap_or(Vec::new()) {
                    let ack_id = msg.ack_id.unwrap_or(String::new());
                    let message = msg.message.unwrap_or(Default::default());
                    println!("message <{}> '{}' at {}",
                             message.message_id.unwrap_or(String::new()),
                             String::from_utf8(base64::decode(&message.data
                                         .unwrap_or(String::new()))
                                     .unwrap())
                                 .unwrap(),
                             message.publish_time.unwrap_or(String::new()));

                    if ack_id != "" {
                        ack_message(methods, ack_id);
                    }
                }
            }
        }
    }
}

// Publish some message every 2 seconds.
fn publish_stuff(methods: &PubsubMethods, message: &str) {
    check_or_create_topic(&methods);

    let message = pubsub::PubsubMessage {
        // Base64 encoded!
        data: Some(base64::encode(message.as_bytes())),
        ..Default::default()
    };
    let request = pubsub::PublishRequest { messages: Some(vec![message]) };


    loop {
        let result = methods.topics_publish(request.clone(), TOPIC_NAME).doit();

        match result {
            Err(e) => {
                println!("Publish error: {}", e);
            }
            Ok((_response, pubresponse)) => {
                for msg in pubresponse.message_ids.unwrap_or(Vec::new()) {
                    println!("Published message #{}", msg);
                }
            }
        }

        thread::sleep(time::Duration::new(2, 0));
    }
}

// If called as '.../service_account pub', act as publisher; if called as '.../service_account
// sub', act as subscriber.
fn main() {
    let client_secret = oauth::service_account_key_from_file(&"pubsub-auth.json".to_string())
        .unwrap();
    let client = hyper::Client::with_connector(HttpsConnector::new(NativeTlsClient::new().unwrap()));
    let mut access = oauth::ServiceAccountAccess::new(client_secret, client);

    use oauth::GetToken;
    println!("{:?}",
             access.token(&vec!["https://www.googleapis.com/auth/pubsub"]).unwrap());

    let client = hyper::Client::with_connector(HttpsConnector::new(NativeTlsClient::new().unwrap()));
    let hub = pubsub::Pubsub::new(client, access);
    let methods = hub.projects();

    let mode = env::args().nth(1).unwrap_or(String::new());

    if mode == "pub" {
        let message = env::args().nth(2).unwrap_or("Hello World!".to_string());
        publish_stuff(&methods, &message);
    } else if mode == "sub" {
        subscribe_wait(&methods);
    } else {
        println!("Please use either of 'pub' or 'sub' as first argument to this binary!");
    }
}
