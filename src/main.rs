#[macro_use] extern crate log;
#[macro_use] extern crate clap;
extern crate rand;
extern crate mio_uds;
extern crate tiny_http;
extern crate acme_client;
extern crate pretty_env_logger;
extern crate sozu_command_lib as sozu_command;

use std::fs::File;
use std::{thread,time};
use std::net::SocketAddr;
use clap::{App,Arg};
use mio_uds::UnixStream;
use rand::{thread_rng, Rng};
use tiny_http::{Server, Response};
use acme_client::error::Error;
use acme_client::{Account,Directory};
use sozu_command::channel::Channel;
use sozu_command::proxy::{ProxyRequestData, Backend, HttpFront,
  CertificateAndKey, CertFingerprint, AddCertificate, RemoveBackend,
  ReplaceCertificate};
use sozu_command::certificate::{calculate_fingerprint,split_certificate_chain};
use sozu_command::command::{CommandRequestData,CommandRequest,CommandResponse,CommandStatus};
use sozu_command::config::Config;

fn main() {
  pretty_env_logger::init();
  info!("starting up");

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
                        .arg(Arg::with_name("old-cert")
                            .long("old-certificate")
                            .value_name("previous certificate path")
                            .help("path to the previous certificate")
                            .takes_value(true))
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
                        .arg(Arg::with_name("http")
                            .long("http")
                            .value_name("HTTP frontend address")
                            .help("format: IP:port")
                            .takes_value(true)
                            .required(true))
                        .arg(Arg::with_name("https")
                            .long("https")
                            .value_name("HTTPS frontend address")
                            .help("format: IP:port")
                            .takes_value(true)
                            .required(true))
                        .get_matches();

  let config_file = matches.value_of("config").expect("required config file");
  let app_id      = matches.value_of("id").expect("required application id");
  let certificate = matches.value_of("cert").expect("required certificate path");
  let old_cert    = matches.value_of("old-cert");
  let chain       = matches.value_of("chain").expect("required certificate chain path");
  let key         = matches.value_of("key").expect("required key path");
  let domain      = matches.value_of("domain").expect("required domain name");
  let email       = matches.value_of("email").expect("required registration email");
  let http        = matches.value_of("http").expect("required HTTP frontend address").parse::<SocketAddr>().expect("invalid HTTP frontend address format");
  let https       = matches.value_of("https").expect("required HTTPS frontend address").parse::<SocketAddr>().expect("invalid HTTPS frontend address format");

  let old_fingerprint = old_cert.and_then(|path| Config::load_file_bytes(path).ok())
    .and_then(|file| calculate_fingerprint(&file));

  let config = Config::load_from_path(config_file).expect("could not parse configuration file");
  let stream = UnixStream::connect(&config.command_socket).expect(&format!("could not connect to the command unix socket: {}", config.command_socket));
  let mut channel: Channel<CommandRequest,CommandResponse> = Channel::new(stream, 10000, 20000);
  channel.set_blocking(true);

  info!("got channel, connecting to Let's Encrypt");

  let account       = generate_account(email).expect("could not generate account");
  let authorization = account.authorization(domain).expect("could not generate authorization");
  let challenge     = authorization.get_http_challenge().expect("HTTP challenge not found");

  debug!("HTTP challenge token: {} key: {}", challenge.token(), challenge.key_authorization());

  let path              = format!("/.well-known/acme-challenge/{}", challenge.token());
  let key_authorization = challenge.key_authorization().to_string();

  let server = Server::http("127.0.0.1:0").expect("could not create HTTP server");
  let address = server.server_addr();
  let acme_app_id = generate_app_id(&app_id);

  debug!("setting up proxying");
  if !set_up_proxying(&mut channel, &http, &acme_app_id, domain, &path, address) {
    panic!("could not set up proxying to HTTP challenge server");
  }

  let path2 = path.clone();
  let server_thread = thread::spawn(move || {
    info!("HTTP server started");
    loop {
      let request = match server.recv() {
        Ok(rq) => rq,
        Err(e) => { error!("error: {}", e); break }
      };

      info!("got request to URL: {}", request.url());
      if request.url() == path {
        request.respond(Response::from_data(key_authorization.as_bytes()).with_status_code(200));
        info!("challenge request answered, stopping HTTP server");
        return true;
      } else {
        request.respond(Response::from_data(&b"not found"[..]).with_status_code(404));
      }
    }

    false
  });

  thread::sleep(time::Duration::from_millis(100));
  info!("launching validation");
  challenge.validate().expect("could not launch HTTP challenge request");
  let res = server_thread.join().expect("HTTP server thread failed");

  if res {
    if !remove_proxying(&mut channel, &http, &acme_app_id, domain, &path2, address) {
      error!("could not deactivate proxying");
    }

    sign_and_save(&account, domain, certificate, chain, key).expect("could not save certificate");
    info!("new certificate saved to {}", certificate);
    if !add_certificate(&mut channel, &https, domain, certificate, chain, key, old_fingerprint) {
      error!("could not add new certificate");
    } else {
      info!("new certificate set up");
    }
  } else {
    error!("did not receive challenge request");
  }
}

fn generate_account(email: &str) -> Result<Account,Error> {
  //let directory = Directory::from_url("https://acme-staging.api.letsencrypt.org/directory")?;
  let directory = Directory::lets_encrypt()?;

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

fn generate_app_id(app_id: &str) -> String {
  let s: String = thread_rng().gen_ascii_chars().take(6).collect();
  format!("{}-ACME-{}", app_id, s)
}

fn set_up_proxying(channel: &mut Channel<CommandRequest,CommandResponse>, frontend: &SocketAddr, app_id: &str, hostname: &str, path_begin: &str,
  server_address: SocketAddr) -> bool {

  order_command(channel, ProxyRequestData::AddHttpFront(HttpFront {
    address: frontend.clone(),
    app_id: String::from(app_id),
    hostname: String::from(hostname),
    path_begin: String::from(path_begin)
  })) && order_command(channel, ProxyRequestData::AddBackend(Backend {
    app_id: String::from(app_id),
    backend_id: format!("{}-0", app_id),
    address: server_address,
    load_balancing_parameters: None,
    sticky_id: None,
    backup: None,
  }))
}

fn remove_proxying(channel: &mut Channel<CommandRequest,CommandResponse>, frontend: &SocketAddr, app_id: &str, hostname: &str, path_begin: &str,
  server_address: SocketAddr) -> bool {
  order_command(channel, ProxyRequestData::RemoveHttpFront(HttpFront {
    address: frontend.clone(),
    app_id: String::from(app_id),
    hostname: String::from(hostname),
    path_begin: String::from(path_begin)
  })) && order_command(channel, ProxyRequestData::RemoveBackend(RemoveBackend {
    app_id: String::from(app_id),
    backend_id: format!("{}-0", app_id),
    address: server_address,
  }))
}

fn add_certificate(channel: &mut Channel<CommandRequest,CommandResponse>,
  frontend: &SocketAddr, hostname: &str,
  certificate_path: &str, chain_path: &str, key_path: &str,
  old_fingerprint: Option<Vec<u8>>) -> bool {

  let certificate = match Config::load_file(certificate_path) {
    Err(e) => {
      error!("could not load certificate: {:?}", e);
      return false;
    },
    Ok(c) => c,
  };
  let key = match Config::load_file(key_path) {
    Err(e) => {
      error!("could not load key: {:?}", e);
      return false;
    },
    Ok(k) => k,
  };
  let certificate_chain = match Config::load_file(chain_path).map(split_certificate_chain) {
    Err(e) => {
      error!("could not load certificate chain: {:?}", e);
      return false;
    },
    Ok(c) => c,
  };

  match old_fingerprint {
    None => return order_command(channel, ProxyRequestData::AddCertificate(AddCertificate {
      front: frontend.clone(),
      certificate: CertificateAndKey {
        certificate: certificate,
        certificate_chain: certificate_chain,
        key: key
      },
      names: vec!(hostname.to_string()),
    })),
    Some(f) => return order_command(channel, ProxyRequestData::ReplaceCertificate(ReplaceCertificate {
      front: frontend.clone(),
      new_certificate: CertificateAndKey {
        certificate: certificate,
        certificate_chain: certificate_chain,
        key: key
      },
      old_fingerprint: CertFingerprint(f),
      old_names: vec!(hostname.to_string()),
      new_names: vec!(hostname.to_string()),
    })),
  }
}

fn order_command(channel: &mut Channel<CommandRequest,CommandResponse>, order: ProxyRequestData) -> bool {
  let id = generate_id();
  channel.write_message(&CommandRequest::new(
    id.clone(),
    CommandRequestData::Proxy(order.clone()),
    None,
  ));

  loop {
    match channel.read_message() {
      None          => error!("the proxy didn't answer"),
      Some(message) => {
        if id != message.id {
          panic!("received message with invalid id: {:?}", message);
        }
        match message.status {
          CommandStatus::Processing => {
            // do nothing here
            // for other messages, we would loop over read_message
            // until an error or ok message was sent
          },
          CommandStatus::Error => {
            error!("could not execute order: {}", message.message);
            return false;
          },
          CommandStatus::Ok => {
            match order {
              ProxyRequestData::AddBackend(_) => info!("backend added : {}", message.message),
              ProxyRequestData::RemoveBackend(_) => info!("backend removed : {} ", message.message),
              ProxyRequestData::AddCertificate(_) => info!("certificate added: {}", message.message),
              ProxyRequestData::RemoveCertificate(_) => info!("certificate removed: {}", message.message),
              ProxyRequestData::AddHttpFront(_) => info!("front added: {}", message.message),
              ProxyRequestData::RemoveHttpFront(_) => info!("front removed: {}", message.message),
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
