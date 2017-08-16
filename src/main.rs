extern crate acme_client;
extern crate sozu_command_lib as sozu_command;

use acme_client::{Account,Challenge,Directory};
use acme_client::error::Error;

fn main() {
  let domain = "example.com";
  let email  = "example@example.com";

  let account       = generate_account(domain, email).expect("could not generate account");
  let authorization = account.authorization(domain).expect("could not generate authorization");
  let challenge     = authorization.get_http_challenge().ok_or("HTTP challenge not found");
}

fn generate_account(domain: &str, email: &str) -> Result<Account,Error> {
  let directory = Directory::from_url("https://acme-staging.api.letsencrypt.org/directory")?;

  directory.account_registration()
           .email(email)
           .register()
}

