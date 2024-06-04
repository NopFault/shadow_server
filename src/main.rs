use reqwest::blocking::Client;
use reqwest::header::HeaderMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::time::Duration;
use serde_json::Value;
use std::fmt::Write as FmtWrite;
use std::process;
use colored::*;
use std::str;
use std::env;
use std::fs;
use std::io;

/**
* FIX:
* Writting fast do not looking at beuty :)
*/

type HmacSha256 = Hmac<Sha256>;

fn read(config: String) -> Result<String, io::Error> {
    let content = fs::read_to_string(config)?;
    Ok(content)
}

fn api_call(method: String, query: String, config: HashMap<String, String>) -> Result<String, Box<dyn std::error::Error>> {
    let api_uri = config["uri"].clone();
    let api_key = config["key"].clone();
    let api_secret = config["secret"].clone();

    let url = format!("{}{}", api_uri, method);


let mut request: Value = serde_json::from_str(query.as_str())?;
    if let Value::Object(ref mut map) = request {
        map.insert("apikey".to_string(), Value::String(api_key.to_string()));
    } else {
        return Err("Query must be a JSON object".into());
    }

    let request_string = serde_json::to_string(&request)?;

    let mut mac = HmacSha256::new_from_slice(api_secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(request_string.as_bytes());
    let result = mac.finalize();
    let hmac2 = hex::encode(result.into_bytes());

    let client = Client::new();
    let mut headers = HeaderMap::new();
    headers.insert("HMAC2", hmac2.parse()?);

    let response = client.post(&url)
        .headers(headers)
        .body(request_string)
        .timeout(Duration::from_secs(30)) // TIMEOUT equivalent
        .send()?
        .text()?;

    let response_json:Value = serde_json::from_str(&response)?;
    let prettier = serde_json::to_string_pretty(&response_json)?;
    let pretty_colorfull = colorize_json(&prettier)?;

    Ok(pretty_colorfull)
}

fn colorize_json(json: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut result = String::new();
    for line in json.lines() {
        let line = line.trim();
        if line.starts_with('{') || line.starts_with('}') {
            writeln!(result, "{}", line.cyan())?;
        } else if line.starts_with('[') || line.starts_with(']') {
            writeln!(result, "{}", line.magenta())?;
        } else if line.contains(':') {
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            let key = parts[0].trim();
            let value = parts[1].trim();
            writeln!(result, "{}: {}", key.green(), value.yellow())?;
        } else {
            writeln!(result, "{}", line)?;
        }
    }
    Ok(result)
}



fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 4 {
        println!("USAGE: \n\nshadow key_file method query \n\n");
        process::exit(1);
    }

    let key_file: String = String::from(&args[1]);
    let method: String = String::from(&args[2]);
    let query: String = String::from(&args[3]);

    let conf_content: String = read(key_file).unwrap_or_else(|_| String::from(""));

    let mut config_data: HashMap<String, String> = HashMap::new();

    for conf_line in conf_content.lines() {
        let split: Vec<&str> = conf_line.split("=").collect();
        if split.len() == 2 {
            let key = split[0].trim().to_string();
            let value = split[1].trim().to_string();
            config_data.insert(key, value);
        }
    }



    match api_call(method, query, config_data) {
        Ok(response) => println!("{}", response),
        Err(err) => eprintln!("Error: {}", err)
    }
}
