#[macro_use] extern crate log;
#[macro_use] extern crate clap;
extern crate sozu_command_lib as sozu_command;

use std::{
  iter, thread, time,
  fs::File,
  net::SocketAddr,
  io::Write,
};
use clap::{App, Arg};
use rand::{thread_rng, Rng, distributions::Alphanumeric};
use tiny_http::{Server, Response};
use acme_lib::{Directory, DirectoryUrl};
use acme_lib::persist::FilePersist;
use acme_lib::create_p384_key;
use sozu_command::channel::Channel;
use sozu_command::{
  config::Config,
  certificate::{calculate_fingerprint, split_certificate_chain},
  command::{CommandRequestData, CommandRequest, CommandResponse, CommandStatus},
  proxy::{ProxyRequestData, Backend, HttpFrontend, CertificateAndKey, CertificateFingerprint,
    AddCertificate, RemoveBackend, ReplaceCertificate, Route, PathRule, RulePosition},
};

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
  let stream = mio::net::UnixStream::connect(&config.command_socket).expect(&format!("could not connect to the command unix socket: {}", config.command_socket));
  let mut channel: Channel<CommandRequest,CommandResponse> = Channel::new(stream, 10000, 20000);
  channel.set_blocking(true);

  info!("got channel, connecting to Let's Encrypt");

  // Use DirectoryUrl::LetsEncrypStaging for dev/testing
  //let url = DirectoryUrl::LetsEncryptStaging;
  let url = DirectoryUrl::LetsEncrypt;

  let persist = FilePersist::new(".");
  // Create a directory entrypoint.
  let dir = Directory::from_url(persist, url).unwrap();
  // Reads the private account key from persistence, or
  // creates a new one before accessing the API to establish
  // that it's there.
  let acc = dir.account(email).unwrap();

  // Order a new TLS certificate for a domain.
  let mut ord_new = acc.new_order(domain, &[]).unwrap();

  // If the ownership of the domain(s) have already been
  // authorized in a previous order, you might be able to
  // skip validation. The ACME API provider decides.
  let ord_csr = loop {
    // are we done?
    if let Some(ord_csr) = ord_new.confirm_validations() {
      break ord_csr;
    }

    // Get the possible authorizations (for a single domain
    // this will only be one element).
    let auths = ord_new.authorizations().unwrap();
    let auth = &auths[0];
    let challenge = auth.http_challenge();
    let challenge_token = challenge.http_token();

    let path = format!("/.well-known/acme-challenge/{}", challenge_token);
    let key_authorization = challenge.http_proof();
    debug!("HTTP challenge token: {} key: {}", challenge_token, key_authorization);

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
          info!("challenge request answered");
          // the challenge can be called multiple times
          //return true;
        } else {
          request.respond(Response::from_data(&b"not found"[..]).with_status_code(404));
        }
      }

      false
    });

    thread::sleep(time::Duration::from_millis(100));

    challenge.validate(2000).unwrap();
    info!("challenge validated");
    ord_new.refresh().unwrap();

    //let res = server_thread.join().expect("HTTP server thread failed");
    //if res {
      if !remove_proxying(&mut channel, &http, &acme_app_id, domain, &path2, address) {
        error!("could not deactivate proxying");
        panic!();
      }
    //}
  };

  // Ownership is proven. Create a private key for
  // the certificate. These are provided for convenience, you
  // can provide your own keypair instead if you want.
  let pkey_pri = create_p384_key();

  // Submit the CSR. This causes the ACME provider to enter a
  // state of "processing" that must be polled until the
  // certificate is either issued or rejected. Again we poll
  // for the status change.
  let ord_cert =
    ord_csr.finalize_pkey(pkey_pri, 5000).unwrap();

  // Now download the certificate. Also stores the cert in
  // the persistence.
  let cert = ord_cert.download_and_save_cert().unwrap();

  info!("got cert: \n{}", cert.certificate());
  let certificates = sozu_command::certificate::split_certificate_chain(cert.certificate().to_string());
  let mut file = File::create(certificate).unwrap();
  file.write_all(certificates[0].as_bytes());
  //FIXME: there may be more than 1 cert in the chain
  let mut file = File::create(chain).unwrap();
  file.write_all(certificates[1].as_bytes());
  let mut file = File::create(key).unwrap();
  file.write_all(cert.private_key().as_bytes());

  info!("saved cert and key");
  if !add_certificate(&mut channel, &https, domain, certificate, chain, key, old_fingerprint) {
    error!("could not add new certificate");
  } else {
    info!("added new certificate");
  }

  info!("DONE");
}

fn generate_id() -> String {
  let s: String = iter::repeat(()).map(|()| thread_rng().sample(Alphanumeric)).take(6).map(|c| c as char).collect();
  format!("ID-{}", s)
}

fn generate_app_id(app_id: &str) -> String {
  let s: String = iter::repeat(()).map(|()| thread_rng().sample(Alphanumeric)).take(6).map(|c| c as char).collect();
  format!("{}-ACME-{}", app_id, s)
}

fn set_up_proxying(channel: &mut Channel<CommandRequest,CommandResponse>, frontend: &SocketAddr, cluster_id: &str, hostname: &str, path_begin: &str,
  server_address: SocketAddr) -> bool {

  order_command(channel, ProxyRequestData::AddHttpFrontend(HttpFrontend {
    address: frontend.clone(),
    route: Route::ClusterId(String::from(cluster_id)),
    hostname: String::from(hostname),
    path: PathRule::Prefix(String::from(path_begin)),
    method: None,
    position: RulePosition::Tree,
  })) && order_command(channel, ProxyRequestData::AddBackend(Backend {
    cluster_id: String::from(cluster_id),
    backend_id: format!("{}-0", cluster_id),
    address: server_address,
    load_balancing_parameters: None,
    sticky_id: None,
    backup: None,
  }))
}

fn remove_proxying(channel: &mut Channel<CommandRequest,CommandResponse>, frontend: &SocketAddr, cluster_id: &str, hostname: &str, path_begin: &str,
  server_address: SocketAddr) -> bool {
  order_command(channel, ProxyRequestData::RemoveHttpFrontend(HttpFrontend {
    address: frontend.clone(),
    route: Route::ClusterId(String::from(cluster_id)),
    hostname: String::from(hostname),
    path: PathRule::Prefix(String::from(path_begin)),
    method: None,
    position: RulePosition::Tree,
  })) && order_command(channel, ProxyRequestData::RemoveBackend(RemoveBackend {
    cluster_id: String::from(cluster_id),
    backend_id: format!("{}-0", cluster_id),
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
      address: frontend.clone(),
      certificate: CertificateAndKey {
        certificate,
        certificate_chain,
        key,
        versions: vec![],
      },
      names: vec!(hostname.to_string()),
      expired_at: None,
    })),
    Some(f) => return order_command(channel, ProxyRequestData::ReplaceCertificate(ReplaceCertificate {
      address: frontend.clone(),
      new_certificate: CertificateAndKey {
        certificate,
        certificate_chain,
        key,
        versions: vec![],
      },
      old_fingerprint: CertificateFingerprint(f),
      new_names: vec!(hostname.to_string()),
      new_expired_at: None,
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
              ProxyRequestData::AddHttpFrontend(_) => info!("front added: {}", message.message),
              ProxyRequestData::RemoveHttpFrontend(_) => info!("front removed: {}", message.message),
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
