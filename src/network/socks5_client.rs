/// SOCKS5 HTTP Client for Tor
///
/// Implements SOCKS5 protocol to route HTTP requests through Tor proxy (127.0.0.1:9050)
/// Supports .onion addresses and standard HTTP GET/POST operations

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NO_AUTH: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const RESERVED: u8 = 0x00;

/// Result type for SOCKS5 operations
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// SOCKS5 HTTP client
pub struct Socks5Client {
    proxy_host: String,
    proxy_port: u16,
    timeout: Duration,
}

impl Socks5Client {
    /// Create a new SOCKS5 client
    pub fn new(proxy_host: String, proxy_port: u16) -> Self {
        Self {
            proxy_host,
            proxy_port,
            timeout: Duration::from_secs(30),
        }
    }

    /// Create default Tor SOCKS5 client (127.0.0.1:9050)
    pub fn tor_default() -> Self {
        Self::new("127.0.0.1".to_string(), 9050)
    }

    /// Set connection timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Perform HTTP GET request through SOCKS5
    pub fn http_get(&self, url: &str) -> Result<String> {
        let (host, port, path) = parse_url(url)?;
        let mut stream = self.connect_socks5(&host, port)?;

        // Send HTTP GET request
        let request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: SecureLegion/2.0\r\n\
             Accept: */*\r\n\
             Connection: close\r\n\
             \r\n",
            path, host
        );

        stream.write_all(request.as_bytes())?;
        stream.flush()?;

        // Read response
        let response = read_http_response(&mut stream)?;
        Ok(response)
    }

    /// Perform HTTP POST request through SOCKS5
    pub fn http_post(&self, url: &str, body: &str, content_type: &str) -> Result<String> {
        let (host, port, path) = parse_url(url)?;
        let mut stream = self.connect_socks5(&host, port)?;

        // Send HTTP POST request
        let request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: SecureLegion/2.0\r\n\
             Accept: */*\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            path, host, content_type, body.len(), body
        );

        stream.write_all(request.as_bytes())?;
        stream.flush()?;

        // Read response
        let response = read_http_response(&mut stream)?;
        Ok(response)
    }

    /// Perform HTTP POST request with binary body through SOCKS5
    pub fn http_post_binary(&self, url: &str, body: &[u8], content_type: &str) -> Result<String> {
        let (host, port, path) = parse_url(url)?;
        let mut stream = self.connect_socks5(&host, port)?;

        // Send HTTP POST headers
        let headers = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: SecureLegion/2.0\r\n\
             Accept: */*\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            path, host, content_type, body.len()
        );

        stream.write_all(headers.as_bytes())?;
        // Write binary body separately (not formatted into string)
        stream.write_all(body)?;
        stream.flush()?;

        // Read response
        let response = read_http_response(&mut stream)?;
        Ok(response)
    }

    /// Connect to target host via SOCKS5 proxy
    fn connect_socks5(&self, target_host: &str, target_port: u16) -> Result<TcpStream> {
        // Connect to SOCKS5 proxy
        let proxy_addr = format!("{}:{}", self.proxy_host, self.proxy_port);
        let mut stream = TcpStream::connect_timeout(
            &proxy_addr.parse()?,
            self.timeout,
        )?;

        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;

        // SOCKS5 handshake: Client greeting
        // +----+----------+----------+
        // |VER | NMETHODS | METHODS |
        // +----+----------+----------+
        // | 1 | 1 | 1 to 255 |
        // +----+----------+----------+
        let greeting = [SOCKS5_VERSION, 0x01, AUTH_NO_AUTH];
        stream.write_all(&greeting)?;
        stream.flush()?;

        // Read server response
        let mut response = [0u8; 2];
        stream.read_exact(&mut response)?;

        if response[0] != SOCKS5_VERSION {
            return Err(format!("Invalid SOCKS version: {}", response[0]).into());
        }

        if response[1] != AUTH_NO_AUTH {
            return Err("SOCKS5 authentication required but not supported".into());
        }

        // SOCKS5 connection request
        // +----+-----+-------+------+----------+----------+
        // |VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT |
        // +----+-----+-------+------+----------+----------+
        // | 1 | 1 | X'00' | 1 | Variable | 2 |
        // +----+-----+-------+------+----------+----------+

        let host_bytes = target_host.as_bytes();
        let host_len = host_bytes.len();

        if host_len > 255 {
            return Err("Hostname too long".into());
        }

        let mut request = Vec::with_capacity(7 + host_len);
        request.push(SOCKS5_VERSION);
        request.push(CMD_CONNECT);
        request.push(RESERVED);
        request.push(ATYP_DOMAIN);
        request.push(host_len as u8);
        request.extend_from_slice(host_bytes);
        request.push((target_port >> 8) as u8);
        request.push((target_port & 0xFF) as u8);

        stream.write_all(&request)?;
        stream.flush()?;

        // Read connection response
        let mut response = [0u8; 4];
        stream.read_exact(&mut response)?;

        if response[0] != SOCKS5_VERSION {
            return Err(format!("Invalid SOCKS version in response: {}", response[0]).into());
        }

        if response[1] != 0x00 {
            let error_msg = match response[1] {
                0x01 => "General SOCKS server failure",
                0x02 => "Connection not allowed by ruleset",
                0x03 => "Network unreachable",
                0x04 => "Host unreachable",
                0x05 => "Connection refused",
                0x06 => "TTL expired",
                0x07 => "Command not supported",
                0x08 => "Address type not supported",
                _ => "Unknown SOCKS error",
            };
            return Err(format!("SOCKS5 connection failed: {}", error_msg).into());
        }

        // Read bound address (we don't need it, but must read it)
        let atyp = response[3];
        match atyp {
            0x01 => {
                // IPv4: 4 bytes + 2 bytes port
                let mut addr = [0u8; 6];
                stream.read_exact(&mut addr)?;
            }
            0x03 => {
                // Domain: 1 byte length + domain + 2 bytes port
                let mut len_byte = [0u8; 1];
                stream.read_exact(&mut len_byte)?;
                let len = len_byte[0] as usize;
                let mut addr = vec![0u8; len + 2];
                stream.read_exact(&mut addr)?;
            }
            0x04 => {
                // IPv6: 16 bytes + 2 bytes port
                let mut addr = [0u8; 18];
                stream.read_exact(&mut addr)?;
            }
            _ => {
                return Err(format!("Unknown address type: {}", atyp).into());
            }
        }

        log::info!("SOCKS5 connection established to {}:{}", target_host, target_port);
        Ok(stream)
    }
}

/// Parse URL into (host, port, path)
fn parse_url(url: &str) -> Result<(String, u16, String)> {
    let url = url.trim();

    // Strip http:// or https://
    let url = if url.starts_with("http://") {
        &url[7..]
    } else if url.starts_with("https://") {
        &url[8..]
    } else {
        url
    };

    // Find first slash (path start)
    let (host_port, path) = if let Some(slash_idx) = url.find('/') {
        (&url[..slash_idx], &url[slash_idx..])
    } else {
        (url, "/")
    };

    // Split host and port
    let (host, port) = if let Some(colon_idx) = host_port.rfind(':') {
        let host = &host_port[..colon_idx];
        let port_str = &host_port[colon_idx + 1..];
        let port = port_str.parse::<u16>()
            .map_err(|_| format!("Invalid port: {}", port_str))?;
        (host.to_string(), port)
    } else {
        (host_port.to_string(), 80)
    };

    Ok((host, port, path.to_string()))
}

/// Read HTTP response from stream
fn read_http_response(stream: &mut TcpStream) -> Result<String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];

    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break, // EOF
            Ok(n) => {
                buffer.extend_from_slice(&chunk[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Timeout or no more data
                break;
            }
            Err(e) => return Err(e.into()),
        }
    }

    let response = String::from_utf8_lossy(&buffer).to_string();
    Ok(response)
}

/// Extract body from HTTP response
pub fn extract_http_body(response: &str) -> Option<String> {
    // Find double CRLF (end of headers)
    if let Some(pos) = response.find("\r\n\r\n") {
        return Some(response[pos + 4..].to_string());
    }

    // Try single LF (some servers use this)
    if let Some(pos) = response.find("\n\n") {
        return Some(response[pos + 2..].to_string());
    }

    None
}

/// Extract status code from HTTP response
pub fn extract_status_code(response: &str) -> Option<u16> {
    let first_line = response.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() >= 2 && parts[0].starts_with("HTTP/") {
        return parts[1].parse().ok();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_url() {
        let (host, port, path) = parse_url("http://example.onion:8080/contact-card").unwrap();
        assert_eq!(host, "example.onion");
        assert_eq!(port, 8080);
        assert_eq!(path, "/contact-card");

        let (host, port, path) = parse_url("http://example.onion/test").unwrap();
        assert_eq!(host, "example.onion");
        assert_eq!(port, 80);
        assert_eq!(path, "/test");

        let (host, port, path) = parse_url("example.onion:9151").unwrap();
        assert_eq!(host, "example.onion");
        assert_eq!(port, 9151);
        assert_eq!(path, "/");
    }

    #[test]
    fn test_extract_status_code() {
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(extract_status_code(response), Some(200));

        let response = "HTTP/1.1 404 Not Found\r\n\r\n";
        assert_eq!(extract_status_code(response), Some(404));
    }

    #[test]
    fn test_extract_body() {
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(extract_http_body(response), Some("hello".to_string()));

        let response = "HTTP/1.1 200 OK\n\nworld";
        assert_eq!(extract_http_body(response), Some("world".to_string()));
    }
}
