#[macro_use] extern crate clap;
extern crate rand;
extern crate mio_uds;
extern crate tiny_http;
extern crate acme_client;
extern crate sozu_lib as sozu;
extern crate sozu_command_lib as sozu_command;

use std::thread;
use std::fs::File;
use std::net::SocketAddr;
use clap::{App,Arg};
use mio_uds::UnixStream;
use rand::{thread_rng, Rng};
use tiny_http::{Server, Response};
use acme_client::error::Error;
use acme_client::{Account,Directory};
use sozu::channel::Channel;
use sozu::messages::{Order, Instance, HttpFront, HttpsFront, CertificateAndKey, CertFingerprint};
use sozu_command::certificate::{calculate_fingerprint,split_certificate_chain};
use sozu_command::data::{ConfigCommand,ConfigMessage,ConfigMessageAnswer,ConfigMessageStatus};
use sozu_command::config::Config;

fn main() {

  let matches = App::new("sozu-acme")
                        .version(crate_version!())
                        .about("ACME (Let's Encrypt) configuration tool for sozu")
                        .arg(Arg::with_name("config")
                            .short("c")
                            .long("config")
                            .value_name("FILE")
                            .help("Sets a custom config file")
                            .takes_value(true)
                            .required(true))
                        .arg(Arg::with_name("domain")
                            .long("domain")
                            .value_name("domain name")
                            .help("application's domain name")
                            .takes_value(true)
                            .required(true))
                        .arg(Arg::with_name("email")
                            .long("email")
                            .value_name("registration email")
                            .help("registration email")
                            .takes_value(true)
                            .required(true))
                        .arg(Arg::with_name("id")
                            .long("id")
                            .value_name("Application id")
                            .help("application identifier")
                            .takes_value(true)
                            .required(true))
                        .arg(Arg::with_name("cert")
                            .long("certificate")
                            .value_name("certificate path")
                            .help("certificate path")
                            .takes_value(true)
                            .required(true))
                        .arg(Arg::with_name("chain")
                            .long("chain")
                            .value_name("certificate chain path")
                            .help("certificate chain path")
                            .takes_value(true)
                            .required(true))
                        .arg(Arg::with_name("key")
                            .long("key")
                            .value_name("key path")
                            .help("key path")
                            .takes_value(true)
                            .required(true))
                        .get_matches();

  let config_file = matches.value_of("config").expect("required config file");
  let app_id      = matches.value_of("id").expect("required application id");
  let certificate = matches.value_of("cert").expect("required certificate path");
  let chain       = matches.value_of("chain").expect("required certificate chain path");
  let key         = matches.value_of("key").expect("required key path");
  let domain      = matches.value_of("domain").expect("required domain name");
  let email       = matches.value_of("email").expect("required registration email");


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

  if !set_up_proxying(&mut channel, app_id, domain, &path, address) {
    panic!("could not set up proxying to HTTP challenge server");
  }

  let path2 = path.clone();
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
    if !remove_proxying(&mut channel, app_id, domain, &path2, address) {
      println!("could not deactivate proxying");
    }

    sign_and_save(&account, domain, certificate, chain, key).expect("could not save certificate");
    if !add_certificate(&mut channel, app_id, domain, "", certificate, chain, key) {
      println!("could not add new certificate");
    } else {
      println!("new certificate set up");
    }
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

fn sign_and_save(account: &Account, domain: &str, certificate: &str, chain: &str, key: &str) -> Result<(),Error> {
  let cert = account.certificate_signer(&[domain]).sign_certificate()?;
  cert.save_signed_certificate(certificate)?;
  let mut file = File::create(chain)?;
  cert.write_intermediate_certificate(None, &mut file)?;
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

fn add_certificate(channel: &mut Channel<ConfigMessage,ConfigMessageAnswer>, app_id: &str, hostname: &str, path_begin: &str, certificate_path: &str, chain_path: &str, key_path: &str) -> bool {
  match Config::load_file(certificate_path) {
    Ok(certificate) => {
      match calculate_fingerprint(certificate.as_bytes()) {
        Err(e)          => println!("could not calculate fingerprint for certificate: {:?}", e),
        Ok(fingerprint) => {
          match Config::load_file(chain_path).map(split_certificate_chain) {
            Err(e) => println!("could not load certificate chain: {:?}", e),
            Ok(certificate_chain) => {
              match Config::load_file(key_path) {
                Err(e) => println!("could not load key: {:?}", e),
                Ok(key) => {
                  return order_command(channel, Order::AddCertificate(CertificateAndKey {
                    certificate: certificate,
                    certificate_chain: certificate_chain,
                    key: key
                  })) && order_command(channel, Order::AddHttpsFront(HttpsFront {
                    app_id: String::from(app_id),
                    hostname: String::from(hostname),
                    path_begin: String::from(path_begin),
                    fingerprint: CertFingerprint(fingerprint)
                  }));
                }
              }
            }
          }
        },
      }
    },
    Err(e) => println!("could not load file: {:?}", e)
  };

  false
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
