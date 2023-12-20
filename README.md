# BasicHollowing
64 bits (only) Rust Process Hollowing DLL

# Whats that ?
A basic Rust dll that performs process hollowing 

Target process is set in lib.rs : 
```
let pe_to_exec = "C:\\Windows\\System32\\systeminfo.exe";
```

PE to inject is also set in lib.rs :
```
let file_to_load = "sample.exe";
```

sample.exe is provided, it's just a basic c programm displaying a messagebox once injected.

# How to use it
1. Compilation 
```
cargo build --release
```
2. Test it
```
rundll32.exe .\target\release\process_hollow.dll,main
```
![Alt text](/assets/hello.png)

# Note 
I don't know why, but it doesn't work on all target processes. 
systeminfo.exe seems to be work with all my payloads.

# How to debug ?
1. Rename lib.rs as main.rs
2. In main.rs : remove #[no_mangle], rename "pub extern "C" fn main()" as "fn main()"
3. cargo run will print all debug logs
4. Cargo build --release will build an exe that displays only informational steps
![Alt text](/assets/logs.png)

# References
    - https://www.timdbg.com/posts/writing-a-debugger-from-scratch-part-2/
    - https://github.com/2vg/blackcat-rs
    - https://github.com/m0n0ph1/Process-Hollowing