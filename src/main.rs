extern crate rand;
extern crate mio_uds;
extern crate tiny_http;
extern crate acme_client;
extern crate sozu_lib as sozu;
extern crate sozu_command_lib as sozu_command;

use std::thread;
use std::net::SocketAddr;
use mio_uds::UnixStream;
use rand::{thread_rng, Rng};
use tiny_http::{Server, Response};
use acme_client::error::Error;
use acme_client::{Account,Challenge,Directory};
use sozu::channel::Channel;
use sozu::messages::{Order, Instance, HttpFront, HttpsFront, CertificateAndKey, CertFingerprint, TcpFront};
use sozu_command::data::{AnswerData,ConfigCommand,ConfigMessage,ConfigMessageAnswer,ConfigMessageStatus,RunState};
use sozu_command::config::Config;

fn main() {
  let domain      = "example.com";
  let email       = "example@example.com";
  let certificate = "certificate.pem";
  let key         = "key.pem";
  let config_file = "./config.toml";

  let config = Config::load_from_path(config_file).expect("could not parse configuration file");
  let stream = UnixStream::connect(&config.command_socket).expect("could not connect to the command unix socket");
  let mut channel: Channel<ConfigMessage,ConfigMessageAnswer> = Channel::new(stream, 10000, 20000);
  channel.set_blocking(true);



  let account       = generate_account(email).expect("could not generate account");
  let authorization = account.authorization(domain).expect("could not generate authorization");
  let challenge     = authorization.get_http_challenge().expect("HTTP challenge not found");

  println!("HTTP challenge token: {} key: {}", challenge.token(), challenge.key_authorization());

  let path              = format!(".well-known/acme-challenge/{}", challenge.token());
  let key_authorization = challenge.key_authorization().to_string();

  let server = Server::http("127.0.0.1:0").expect("could not create HTTP server");
  let address = server.server_addr();

  let server_thread = thread::spawn(move || {
    loop {
      let request = match server.recv() {
        Ok(rq) => rq,
        Err(e) => { println!("error: {}", e); break }
      };

      println!("got request to URL: {}", request.url());
      if request.url() == path {
        request.respond(Response::from_data(key_authorization.as_bytes()).with_status_code(200));
        return true;
      } else {
        request.respond(Response::from_data(&b"not found"[..]).with_status_code(404));
      }
    }

    false
  });

  challenge.validate().expect("could not launch HTTP challenge request");
  let res = server_thread.join().expect("HTTP server thread failed");

  if res {
    sign_and_save(&account, domain, certificate, key).expect("could not save certificate");
  } else {
    println!("did not receive challenge request");
  }
}

fn generate_account(email: &str) -> Result<Account,Error> {
  let directory = Directory::from_url("https://acme-staging.api.letsencrypt.org/directory")?;

  directory.account_registration()
           .email(email)
           .register()
}

fn sign_and_save(account: &Account, domain: &str, certificate: &str, key: &str) -> Result<(),Error> {
  let cert = account.certificate_signer(&[domain]).sign_certificate()?;
  cert.save_signed_certificate(certificate)?;
  cert.save_private_key(key)
}

fn generate_id() -> String {
  let s: String = thread_rng().gen_ascii_chars().take(6).collect();
  format!("ID-{}", s)
}

fn set_up_proxying(channel: &mut Channel<ConfigMessage,ConfigMessageAnswer>, app_id: &str, hostname: &str, path_begin: &str, server_address: SocketAddr) -> bool {

  order_command(channel, Order::AddHttpFront(HttpFront {
    app_id: String::from(app_id),
    hostname: String::from(hostname),
    path_begin: String::from(path_begin)
  })) && order_command(channel, Order::AddInstance(Instance {
    app_id: String::from(app_id),
    ip_address: server_address.ip().to_string(),
    port: server_address.port()
  }))
}

fn remove_proxying(channel: &mut Channel<ConfigMessage,ConfigMessageAnswer>, app_id: &str, hostname: &str, path_begin: &str, server_address: SocketAddr) -> bool {
  order_command(channel, Order::RemoveHttpFront(HttpFront {
    app_id: String::from(app_id),
    hostname: String::from(hostname),
    path_begin: String::from(path_begin)
  })) && order_command(channel, Order::RemoveInstance(Instance {
    app_id: String::from(app_id),
    ip_address: server_address.ip().to_string(),
    port: server_address.port()
  }))
}

fn order_command(channel: &mut Channel<ConfigMessage,ConfigMessageAnswer>, order: Order) -> bool {
  let id = generate_id();
  channel.write_message(&ConfigMessage::new(
    id.clone(),
    ConfigCommand::ProxyConfiguration(order.clone()),
    None,
  ));

  loop {
    match channel.read_message() {
      None          => println!("the proxy didn't answer"),
      Some(message) => {
        if id != message.id {
          panic!("received message with invalid id: {:?}", message);
        }
        match message.status {
          ConfigMessageStatus::Processing => {
            // do nothing here
            // for other messages, we would loop over read_message
            // until an error or ok message was sent
          },
          ConfigMessageStatus::Error => {
            println!("could not execute order: {}", message.message);
            return false;
          },
          ConfigMessageStatus::Ok => {
            match order {
              Order::AddInstance(_) => println!("backend added : {}", message.message),
              Order::RemoveInstance(_) => println!("backend removed : {} ", message.message),
              Order::AddCertificate(_) => println!("certificate added: {}", message.message),
              Order::RemoveCertificate(_) => println!("certificate removed: {}", message.message),
              Order::AddHttpFront(_) => println!("front added: {}", message.message),
              Order::RemoveHttpFront(_) => println!("front removed: {}", message.message),
              _ => {
                // do nothing for now 
              }
            }
            return true;
          }
        }
      }
    }
  }
}
