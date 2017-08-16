extern crate tiny_http;
extern crate acme_client;
extern crate sozu_command_lib as sozu_command;

use std::thread;
use tiny_http::{Server, Response};
use acme_client::{Account,Challenge,Directory};
use acme_client::error::Error;

fn main() {
  let domain = "example.com";
  let email  = "example@example.com";
  let certificate = "certificate.pem";
  let key         = "key.pem";

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
