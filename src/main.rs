use std::os::raw::c_void;
use std::time::Duration;
use windows_sys::core::PCWSTR;
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleHandleA, GetModuleHandleW, GetProcAddress, LoadLibraryW,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MessageBoxA, MessageBoxW, MB_OK, MESSAGEBOX_RESULT, MESSAGEBOX_STYLE,
};

pub fn install_hook(dll_name: &str, func_name: &str, target: usize) {
    unsafe {
        //获取原始函数的地址
        let address = GetProcAddress(
            GetModuleHandleW(dll_name.as_ptr() as _),
            func_name.as_ptr() as _,
        )
        .expect(&(String::from(func_name) + " not found in " + dll_name + " !"));
        //保存原始Sleep函数的第一条指令，即头5个字节
        let mut old_bytes: [u16; 5] = [0, 0, 0, 0, 0];
        let old_pointer = std::ptr::null_mut();
        ReadProcessMemory(
            GetCurrentProcess(),
            &address as *const _ as *const c_void,
            &mut old_bytes as *mut _ as *mut c_void,
            5,
            old_pointer,
        );
        //构造jmp指令
        let mut new_bytes: [u8; 5] = [b'\xE9', 0, 0, 0, 0];
        let bytes: [u16; 4] = std::mem::transmute(address as usize - target - 5);
        new_bytes[1] = bytes[0] as u8;
        new_bytes[2] = bytes[1] as u8;
        new_bytes[3] = bytes[2] as u8;
        new_bytes[4] = bytes[3] as u8;
        //替换原始指令
        WriteProcessMemory(
            GetCurrentProcess(),
            &address as *const _ as *const c_void,
            &new_bytes as *const _ as *const c_void,
            5,
            old_pointer,
        );
    }
}

#[no_mangle]
pub extern "system" fn MyMessageBoxA(
    hwnd: HWND,
    lptext: PCWSTR,
    lpcaption: PCWSTR,
    utype: MESSAGEBOX_STYLE,
) -> MESSAGEBOX_RESULT {
    println!("succeed");
    return 0;
}

fn main() {
    unsafe {
        MessageBoxA(0, "test".as_ptr() as _, "test".as_ptr() as _, MB_OK);
    }
    //fixme not work fine here
    install_hook("user32.dll", "MessageBoxA", MyMessageBoxA as usize);
    unsafe {
        MessageBoxA(0, "test".as_ptr() as _, "test".as_ptr() as _, MB_OK);
    }
}
