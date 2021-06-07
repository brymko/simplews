use anyhow::Result;
use rustls::{ClientConfig, ClientConnection, ServerName, StreamClonabel};

use std::net::TcpStream;
use std::sync::Arc;

#[derive(Debug)]
struct TcpStreamClone {
    pub stream: TcpStream,
}

impl Clone for TcpStreamClone {
    fn clone(&self) -> Self {
        Self {
            stream: self.stream.try_clone().unwrap(),
        }
    }
}

impl std::io::Read for TcpStreamClone {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }
}

impl std::io::Write for TcpStreamClone {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

#[derive(Debug, Clone)]
pub struct Stream {
    stream: StreamClonabel<ClientConnection, TcpStreamClone>,
}

impl Stream {
    pub fn new<S: AsRef<str>>(io: TcpStream, hostname: S) -> Self {
        use std::convert::TryFrom;

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        let trusted_ct_logs = &[];
        let config = rustls::ConfigBuilder::with_safe_defaults()
            .for_client()
            .unwrap()
            .with_root_certificates(root_store, trusted_ct_logs)
            .with_no_client_auth();

        let cc = ClientConnection::new(
            Arc::new(config),
            ServerName::try_from(hostname.as_ref()).expect("invalid DNS name"),
        )
        .unwrap();

        Self {
            stream: StreamClonabel::new(cc, TcpStreamClone { stream: io }),
        }
    }

    pub fn do_handshake(&mut self) -> Result<()> {
        Ok(())
    }
}

impl std::io::Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // TODO(brymko):
        self.stream.read(buf)
    }
}

impl std::io::Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

#[derive(Debug)]
pub struct Listener {}

#[cfg(test)]
mod test {
    use super::*;
    use rustls::Connection;
    use std::convert::TryInto;
    use std::io::{stdout, Read, Write};

    #[test]
    fn tls_check() {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        let config = rustls::ConfigBuilder::with_safe_defaults()
            .for_client()
            .unwrap()
            .with_root_certificates(root_store, &[])
            .with_no_client_auth();

        let server_name = "www.google.com".try_into().unwrap();
        let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut sock = TcpStream::connect("www.google.com:443").unwrap();
        let mut sock = TcpStreamClone { stream: sock };
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        let mut plaintext = Vec::new();
        let _ = tls
            .write(
                concat!(
                    "GET / HTTP/1.1\r\n",
                    "Host: www.google.com\r\n",
                    "Connection: close\r\n",
                    "Accept-Encoding: identity\r\n",
                    "\r\n"
                )
                .as_bytes(),
            )
            .unwrap();
        let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
        tls.read_to_end(&mut plaintext).unwrap();
        let plain = String::from_utf8(plaintext[..100].to_vec()).unwrap();
        assert!(plain.contains("200 OK"));
    }

    #[test]
    fn struct_tls_check() {
        let sock = TcpStream::connect("www.google.com:443").unwrap();
        let mut s = Stream::new(sock, "www.google.com");
        let _ = s
            .write(
                concat!(
                    "GET / HTTP/1.1\r\n",
                    "Host: www.google.com\r\n",
                    "Connection: close\r\n",
                    "Accept-Encoding: identity\r\n",
                    "\r\n"
                )
                .as_bytes(),
            )
            .unwrap();
        let mut plaintext = Vec::new();
        s.read_to_end(&mut plaintext).unwrap();
        let plain = String::from_utf8(plaintext[..100].to_vec()).unwrap();
        assert!(plain.contains("200 OK"));
    }

    #[test]
    fn manual_ws_echo_tls() {
        let mut s = TcpStream::connect("stream.data.alpaca.markets:443").unwrap();
        let mut s = Stream::new(s, "stream.data.alpaca.markets");
        let _ = s.write(&[32, 49, 51, 13, 10, 13, 10]);
        let mut plaintext = Vec::new();
        s.read_to_end(&mut plaintext).unwrap();
        let plain = String::from_utf8(plaintext[..].to_vec()).unwrap();
        assert!(plain.contains("Bad Request"))
    }
}
