use std::fs;
use std::io::Write;
use flate2::write::GzEncoder;
use flate2::Compression;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};

fn main() {
    let original_bytes = fs::read("sample.exe").expect("Unable to read sample.exe");

    // 1. AES Encryption (AES-256-GCM)
    let key_bytes = b"616e2d65787472656d656c792d736563";
    let key = Key::<Aes256Gcm>::from_slice(key_bytes); 
    let nonce = Nonce::from_slice(b"616e2d657874");
    let cipher = Aes256Gcm::new(key);
    
    let encrypted_bytes = cipher.encrypt(nonce, original_bytes.as_ref())
        .expect("encryption failure!");

    // 2. Compression
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&encrypted_bytes).unwrap();
    let compressed_bytes = encoder.finish().unwrap();

    // 3. Save to OUT_DIR
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = std::path::Path::new(&out_dir).join("payload.packed");
    fs::write(&dest_path, compressed_bytes).unwrap();

    println!("cargo:rerun-if-changed=sample.exe");
}