use sha2::{Digest, Sha256};

const SOURCE_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~+";

struct MixBase64 {
    chars: [u8; 65],

    decode_map: [i8; 256],
}

impl MixBase64 {
    fn new(password: &str) -> Self {
        let secret: String = init_ksa(&format!("{}mix64", password));
        let secret_bytes: &[u8] = secret.as_bytes();

        let mut chars: [u8; 65] = [b'+'; 65];

        let mut decode_map: [i8; 256] = [-1i8; 256];

        for i in 0..64usize {
            chars[i] = secret_bytes[i];
        }

        if secret_bytes.len() > 64 {
            chars[64] = secret_bytes[64];
        } else {
            chars[64] = b'+';
        }

        for i in 0..65usize {
            decode_map[chars[i] as usize] = i as i8;
        }

        Self { chars, decode_map }
    }

    fn encode(&self, data: &[u8]) -> String {
        if data.is_empty() {
            return String::new();
        }

        let mut result: String = String::with_capacity((data.len() * 4 + 2) / 3);
        let pad: u8 = self.chars[64];

        let mut i: usize = 0;

        while i + 3 <= data.len() {
            let b0: u8 = data[i];
            let b1: u8 = data[i + 1];
            let b2: u8 = data[i + 2];
            result.push(self.chars[(b0 >> 2) as usize] as char);
            result.push(self.chars[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
            result.push(self.chars[(((b1 & 15) << 2) | (b2 >> 6)) as usize] as char);
            result.push(self.chars[(b2 & 63) as usize] as char);
            i += 3;
        }

        let remaining: usize = data.len() - i;
        if remaining == 1 {
            let b0: u8 = data[i];
            result.push(self.chars[(b0 >> 2) as usize] as char);
            result.push(self.chars[((b0 & 3) << 4) as usize] as char);
            result.push(pad as char);
            result.push(pad as char);
        } else if remaining == 2 {
            let b0: u8 = data[i];
            let b1: u8 = data[i + 1];
            result.push(self.chars[(b0 >> 2) as usize] as char);
            result.push(self.chars[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
            result.push(self.chars[((b1 & 15) << 2) as usize] as char);
            result.push(pad as char);
        }

        result
    }

    fn decode(&self, s: &str) -> Result<Vec<u8>, String> {
        let bytes: &[u8] = s.as_bytes();
        if bytes.is_empty() {
            return Ok(Vec::new());
        }

        if bytes.len() % 4 != 0 {
            return Err("invalid base64 string length".into());
        }

        let pad: u8 = self.chars[64];

        let mut size: usize = (bytes.len() / 4) * 3;
        if bytes.len() >= 2 && bytes[bytes.len() - 2] == pad && bytes[bytes.len() - 1] == pad {
            size = size.saturating_sub(2);
        } else if !bytes.is_empty() && bytes[bytes.len() - 1] == pad {
            size = size.saturating_sub(1);
        }

        let mut buf: Vec<u8> = vec![0u8; size];
        let mut j: usize = 0;

        for chunk in bytes.chunks(4) {
            let idx: [i8; 4] = [
                self.decode_map[chunk[0] as usize],
                self.decode_map[chunk[1] as usize],
                self.decode_map[chunk[2] as usize],
                self.decode_map[chunk[3] as usize],
            ];

            if idx[0] < 0 || idx[1] < 0 || idx[2] < 0 || idx[3] < 0 {
                return Err("invalid base64 character".into());
            }
            let enc: [u8; 4] = [idx[0] as u8, idx[1] as u8, idx[2] as u8, idx[3] as u8];

            buf[j] = (enc[0] << 2) | (enc[1] >> 4);
            j += 1;
            if enc[2] < 64 {
                buf[j] = (enc[1] << 4) | (enc[2] >> 2);
                j += 1;
            }
            if enc[3] < 64 {
                buf[j] = (enc[2] << 6) | enc[3];
                j += 1;
            }
        }

        buf.truncate(j);

        Ok(buf)
    }
}

fn init_ksa(password: &str) -> String {
    let mut hasher: Sha256 = Sha256::new();
    hasher.update(password.as_bytes());
    let key: [u8; 32] = hasher.finalize().into();

    let source: &[u8] = SOURCE_CHARS.as_bytes();
    let n: usize = source.len();

    let mut sbox: Vec<usize> = (0..n).collect();

    let mut k: Vec<u8> = vec![0u8; n];
    for idx in 0..n {
        k[idx] = key[idx % key.len()];
    }

    let mut j: usize = 0;
    for idx in 0..n {
        j = (j + sbox[idx] + k[idx] as usize) % n;
        sbox.swap(idx, j);
    }

    let mut secret: String = String::with_capacity(n);
    for &idx in &sbox {
        secret.push(source[idx] as char);
    }
    secret
}

pub struct FileNameConverter {
    password: String,

    enc_type: String,

    enc_suffix: Option<String>,
}

impl FileNameConverter {
    pub fn new(password: &str, enc_type: &str, enc_suffix: Option<&str>) -> Self {
        let normalized: Option<String> = enc_suffix
            .map(|s: &str| s.trim().trim_start_matches('.').to_string())
            .filter(|s: &String| !s.is_empty());
        Self {
            password: password.to_string(),
            enc_type: enc_type.to_string(),
            enc_suffix: normalized,
        }
    }

    pub fn encrypt_path(&self, display_path: &str) -> String {
        if display_path.ends_with('/') {
            return display_path.to_string();
        }

        let path: &std::path::Path = std::path::Path::new(display_path);
        let file_name: &str = path
            .file_name()
            .and_then(|n: &std::ffi::OsStr| n.to_str())
            .unwrap_or(display_path);
        let dir: &str = path.parent().and_then(|p: &std::path::Path| p.to_str()).unwrap_or("");

        let ext: &str = std::path::Path::new(file_name)
            .extension()
            .and_then(|e: &std::ffi::OsStr| e.to_str())
            .unwrap_or("");

        let enc_name: String = encode_name(&self.password, &self.enc_type, file_name);

        let suffix: String = match &self.enc_suffix {
            Some(s) => s.clone(),
            None => ext.to_string(),
        };
        let encrypted_name: String = if suffix.is_empty() {
            enc_name
        } else {
            format!("{}.{}", enc_name, suffix)
        };

        let dir_trim: &str = dir.trim_end_matches('/');
        if dir_trim.is_empty() {
            format!("/{}", encrypted_name)
        } else {
            format!("{}/{}", dir_trim, encrypted_name)
        }
    }

    pub fn decrypt_path(&self, encrypted_path: &str) -> String {
        if encrypted_path.ends_with('/') {
            return encrypted_path.to_string();
        }

        let path: &std::path::Path = std::path::Path::new(encrypted_path);
        let file_name: &str = path
            .file_name()
            .and_then(|n: &std::ffi::OsStr| n.to_str())
            .unwrap_or(encrypted_path);
        let dir: &str = path.parent().and_then(|p: &std::path::Path| p.to_str()).unwrap_or("");

        let enc_name: String = match &self.enc_suffix {
            Some(sfx) => {
                let dot: String = format!(".{}", sfx);
                let dotdot: String = format!("..{}", sfx);
                if let Some(b) = file_name.strip_suffix(&dotdot) {
                    b.to_string()
                } else if let Some(b) = file_name.strip_suffix(&dot) {
                    b.to_string()
                } else {
                    return encrypted_path.to_string();
                }
            }
            None => {
                let ext: &str = std::path::Path::new(file_name)
                    .extension()
                    .and_then(|e: &std::ffi::OsStr| e.to_str())
                    .unwrap_or("");
                if ext.is_empty() {
                    file_name.to_string()
                } else {
                    let with_dot: String = format!(".{}", ext);
                    file_name
                        .strip_suffix(&with_dot)
                        .unwrap_or(file_name)
                        .to_string()
                }
            }
        };

        let show_name: String = decode_name(&self.password, &self.enc_type, &enc_name);

        if show_name.is_empty() {
            return encrypted_path.to_string();
        }

        let dir_trim: &str = dir.trim_end_matches('/');
        if dir_trim.is_empty() {
            format!("/{}", show_name)
        } else {
            format!("{}/{}", dir_trim, show_name)
        }
    }
}

pub fn encode_name(password: &str, enc_type: &str, plain_name: &str) -> String {
    let mb: MixBase64 = MixBase64::new(&format!("{}{}", password, enc_type));
    mb.encode(plain_name.as_bytes())
}

pub fn decode_name(password: &str, enc_type: &str, encrypted_name: &str) -> String {
    let mb: MixBase64 = MixBase64::new(&format!("{}{}", password, enc_type));
    match mb.decode(encrypted_name) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
        Err(_) => String::new(),
    }
}