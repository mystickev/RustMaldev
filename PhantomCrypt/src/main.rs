use aes::{Aes128, cipher::{KeyInit, generic_array::GenericArray}};
use std::fs::File;
use std::io::{self, Read};
use aes::cipher::BlockEncrypt;

struct Rc4Encrypt {
    i: u8,
    j: u8,
    s: [u8; 256],
}

impl Rc4Encrypt {
    fn new(key: &[u8]) -> Rc4Encrypt {
        let mut s: [u8; 256] = [0; 256];
        let mut j: u8 = 0;

        for i in 0..256 {
            s[i] = i as u8;
        }

        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }

        Rc4Encrypt { i: 0, j: 0, s }
    }

    fn next(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s[self.i as usize]);

        self.s.swap(self.i as usize, self.j as usize);

        self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize]
    }

    pub fn encrypt(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            *byte ^= self.next();
        }
    }
}

// Padding for AES
fn pad_data(data: &mut Vec<u8>) {
    let block_size = 16;
    let padding_needed = block_size - (data.len() % block_size);
    data.extend(std::iter::repeat(padding_needed as u8).take(padding_needed));
}

// Function to encrypt with AES
fn aes_encrypt(data: &[u8], cipher: &Aes128) -> Vec<u8> {
    let mut encrypted_data = Vec::new();
    for chunk in data.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        encrypted_data.extend_from_slice(&block);
    }
    encrypted_data
}

// Function to encrypt with XOR
fn xor_encrypt(shellcode: &mut [u8], key: &[u8]) {
    for (i, byte) in shellcode.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

//function to turn shellcode to mac addresses
fn print_shellcode_as_mac(shellcode: &[u8]) {
    for chunk in shellcode.chunks(6) {
        let mac: Vec<String> = chunk.iter().map(|byte| format!("{:02X}", byte)).collect();
        println!("{}", mac.join(":"));
    }
}

//function to turn shellcode to ipv4
fn print_shellcode_as_ipv4(shellcode: &[u8]) {
    for chunk in shellcode.chunks(4) {
        let segment: Vec<String> = chunk.iter().map(|byte| byte.to_string()).collect();
        println!("{}.{}.{}.{}", segment.get(0).unwrap_or(&"0".to_string()), segment.get(1).unwrap_or(&"0".to_string()), segment.get(2).unwrap_or(&"0".to_string()), segment.get(3).unwrap_or(&"0".to_string()));
    }
}

fn main() -> io::Result<()> {
    let mut input = String::new();

    println!("Enter the path to the RAW shellcode file:");
    io::stdin().read_line(&mut input)?;
    let path = input.trim();
    let mut file = File::open(path)?;
    let mut shellcode = Vec::new();
    file.read_to_end(&mut shellcode)?;

    println!("Choose Encryption/Obfuscation type (RC4, XOR, AES) || (IPV4, MAC):");
    input.clear();
    io::stdin().read_line(&mut input)?;
    let encryption_type = input.trim().to_uppercase();

    match encryption_type.as_str() {
        "RC4" => {
            println!("Enter RC4 Key:");
            input.clear();
            io::stdin().read_line(&mut input)?;
            let key = input.trim().as_bytes();
            let mut rc4 = Rc4Encrypt::new(key);
            rc4.encrypt(&mut shellcode);
            println!("RC4 Encrypted shellcode: {:?}", shellcode);
        },
        "XOR" => {
            println!("Enter XOR Key:");
            input.clear();
            io::stdin().read_line(&mut input)?;
            let key = input.trim().as_bytes();
            xor_encrypt(&mut shellcode, key);
            println!("XOR Encrypted shellcode: {:?}", shellcode);
        },
        "AES" => {
            println!("Enter AES Key (16 bytes):");
            input.clear();
            io::stdin().read_line(&mut input)?;
            let key_bytes = input.trim().as_bytes();
            if key_bytes.len() != 16 {
                println!("AES key must be exactly 16 bytes.");
                return Ok(());
            }
            let key = GenericArray::from_slice(key_bytes);
            let cipher = Aes128::new(&key); // Assuming KeyInit trait is in use
            pad_data(&mut shellcode);
            let encrypted_data = aes_encrypt(&shellcode, &cipher);
            println!("AES Encrypted shellcode: {:?}", encrypted_data);
        },
        "IPV4" => {
            println!("Shellcode as IPv4 addresses:");
            print_shellcode_as_ipv4(&shellcode);
        },
        "MAC" => {
            println!("Shellcode as MAC addresses:");
            print_shellcode_as_mac(&shellcode);
        },
        _ => {
            println!("Invalid encryption/obfuscation type selected.");
        }
    }

    Ok(())
}
