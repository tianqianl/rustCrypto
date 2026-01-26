use libc::{c_char, c_int, size_t};
use std::ffi::{CStr, CString};
use std::ptr;
use std::slice;
use crate::crypto::{CryptoEngine, EncryptedData};

#[repr(C)]
pub struct CKeyPair {
    pub public_key: *mut c_char,
    pub private_key: *mut c_char,
}

#[repr(C)]
pub struct CEncryptedData {
    pub ciphertext: *mut c_char,
    pub nonce: *mut c_char,
    pub tag: *mut c_char,
}

#[repr(C)]
pub struct CByteArray {
    pub data: *mut u8,
    pub len: size_t,
}

#[no_mangle]
pub extern "C" fn crypto_generate_rsa_keypair(bits: c_int) -> *mut CKeyPair {
    match CryptoEngine::generate_rsa_keypair(bits as u32) {
        Ok(keypair) => {
            let public_key = CString::new(keypair.public_key).unwrap().into_raw();
            let private_key = CString::new(keypair.private_key).unwrap().into_raw();
            
            let c_keypair = Box::new(CKeyPair {
                public_key,
                private_key,
            });
            
            Box::into_raw(c_keypair)
        }
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn crypto_rsa_encrypt(
    public_key: *const c_char,
    plaintext: *const u8,
    plaintext_len: size_t,
    out_len: *mut size_t,
) -> *mut CByteArray {
    if public_key.is_null() || plaintext.is_null() {
        return ptr::null_mut();
    }

    let public_key_str = unsafe { CStr::from_ptr(public_key) }
        .to_str()
        .unwrap_or("");
    
    let plaintext_slice = unsafe { slice::from_raw_parts(plaintext, plaintext_len) };

    match CryptoEngine::rsa_encrypt(public_key_str, plaintext_slice) {
        Ok(encrypted) => {
            let mut data = encrypted;
            data.shrink_to_fit();
            let len = data.len();
            
            if !out_len.is_null() {
                unsafe { *out_len = len };
            }
            
            let ptr = data.as_mut_ptr();
            std::mem::forget(data);
            
            Box::into_raw(Box::new(CByteArray { data: ptr, len }))
        }
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn crypto_rsa_decrypt(
    private_key: *const c_char,
    ciphertext: *const u8,
    ciphertext_len: size_t,
    out_len: *mut size_t,
) -> *mut CByteArray {
    if private_key.is_null() || ciphertext.is_null() {
        return ptr::null_mut();
    }

    let private_key_str = unsafe { CStr::from_ptr(private_key) }
        .to_str()
        .unwrap_or("");
    
    let ciphertext_slice = unsafe { slice::from_raw_parts(ciphertext, ciphertext_len) };

    match CryptoEngine::rsa_decrypt(private_key_str, ciphertext_slice) {
        Ok(decrypted) => {
            let mut data = decrypted;
            data.shrink_to_fit();
            let len = data.len();
            
            if !out_len.is_null() {
                unsafe { *out_len = len };
            }
            
            let ptr = data.as_mut_ptr();
            std::mem::forget(data);
            
            Box::into_raw(Box::new(CByteArray { data: ptr, len }))
        }
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn crypto_aes_gcm_encrypt(
    key: *const u8,
    key_len: size_t,
    plaintext: *const u8,
    plaintext_len: size_t,
) -> *mut CEncryptedData {
    if key.is_null() || plaintext.is_null() {
        return ptr::null_mut();
    }

    let key_slice = unsafe { slice::from_raw_parts(key, key_len) };
    let plaintext_slice = unsafe { slice::from_raw_parts(plaintext, plaintext_len) };

    match CryptoEngine::aes_gcm_encrypt(key_slice, plaintext_slice) {
        Ok(encrypted) => {
            let ciphertext = CString::new(encrypted.ciphertext).unwrap().into_raw();
            let nonce = CString::new(encrypted.nonce).unwrap().into_raw();
            let tag = CString::new(encrypted.tag).unwrap().into_raw();
            
            Box::into_raw(Box::new(CEncryptedData {
                ciphertext,
                nonce,
                tag,
            }))
        }
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn crypto_aes_gcm_decrypt(
    key: *const u8,
    key_len: size_t,
    encrypted_data: *const CEncryptedData,
    out_len: *mut size_t,
) -> *mut CByteArray {
    if key.is_null() || encrypted_data.is_null() {
        return ptr::null_mut();
    }

    let key_slice = unsafe { slice::from_raw_parts(key, key_len) };
    
    let ciphertext = unsafe {
        CStr::from_ptr((*encrypted_data).ciphertext)
            .to_str()
            .unwrap_or("")
    };
    
    let nonce = unsafe {
        CStr::from_ptr((*encrypted_data).nonce)
            .to_str()
            .unwrap_or("")
    };
    
    let tag = unsafe {
        CStr::from_ptr((*encrypted_data).tag)
            .to_str()
            .unwrap_or("")
    };

    let encrypted = EncryptedData {
        ciphertext: ciphertext.to_string(),
        nonce: nonce.to_string(),
        tag: tag.to_string(),
    };

    match CryptoEngine::aes_gcm_decrypt(key_slice, &encrypted) {
        Ok(decrypted) => {
            let mut data = decrypted;
            data.shrink_to_fit();
            let len = data.len();
            
            if !out_len.is_null() {
                unsafe { *out_len = len };
            }
            
            let ptr = data.as_mut_ptr();
            std::mem::forget(data);
            
            Box::into_raw(Box::new(CByteArray { data: ptr, len }))
        }
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn crypto_generate_aes_key(out_len: *mut size_t) -> *mut CByteArray {
    match CryptoEngine::generate_aes_key() {
        Ok(key) => {
            let mut data = key;
            data.shrink_to_fit();
            let len = data.len();
            
            if !out_len.is_null() {
                unsafe { *out_len = len };
            }
            
            let ptr = data.as_mut_ptr();
            std::mem::forget(data);
            
            Box::into_raw(Box::new(CByteArray { data: ptr, len }))
        }
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn crypto_free_keypair(keypair: *mut CKeyPair) {
    if !keypair.is_null() {
        unsafe {
            let kp = Box::from_raw(keypair);
            if !kp.public_key.is_null() {
                let _ = CString::from_raw(kp.public_key);
            }
            if !kp.private_key.is_null() {
                let _ = CString::from_raw(kp.private_key);
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn crypto_free_encrypted_data(data: *mut CEncryptedData) {
    if !data.is_null() {
        unsafe {
            let ed = Box::from_raw(data);
            if !ed.ciphertext.is_null() {
                let _ = CString::from_raw(ed.ciphertext);
            }
            if !ed.nonce.is_null() {
                let _ = CString::from_raw(ed.nonce);
            }
            if !ed.tag.is_null() {
                let _ = CString::from_raw(ed.tag);
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn crypto_free_byte_array(array: *mut CByteArray) {
    if !array.is_null() {
        unsafe {
            let ba = Box::from_raw(array);
            let _ = Vec::from_raw_parts(ba.data, ba.len, ba.len);
        }
    }
}

#[no_mangle]
pub extern "C" fn crypto_get_version() -> *const c_char {
    CString::new(env!("CARGO_PKG_VERSION")).unwrap().into_raw()
}