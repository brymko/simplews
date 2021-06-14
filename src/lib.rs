#![allow(unused)]

use anyhow::{anyhow, bail, Context, Result};

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

mod dns;
mod http;
mod ssl;

#[derive(Clone, Debug)]
pub enum Message {
    Close(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Text(String),
    Binary(Vec<u8>),
}

#[derive(Clone, Copy, Debug)]
enum WebsocketOpcode {
    Continuation = 0,
    Text = 1,
    Binary = 2,
    NonControl1 = 3,
    NonControl2 = 4,
    NonControl3 = 5,
    NonControl4 = 6,
    NonControl5 = 7,
    Close = 8,
    Ping = 9,
    Pong = 10,
    Control1 = 11,
    Control2 = 12,
    Control3 = 13,
    Control4 = 14,
    Control5 = 15,
}

impl WebsocketOpcode {
    pub fn to_int(self) -> u8 {
        self as u8
    }
}

impl WebsocketOpcode {
    pub fn from_int(opcode: u8) -> Option<Self> {
        match opcode {
            0 => Some(Self::Continuation),
            1 => Some(Self::Text),
            2 => Some(Self::Binary),
            3 => Some(Self::NonControl1),
            4 => Some(Self::NonControl2),
            5 => Some(Self::NonControl3),
            6 => Some(Self::NonControl4),
            7 => Some(Self::NonControl5),
            8 => Some(Self::Close),
            9 => Some(Self::Ping),
            10 => Some(Self::Pong),
            11 => Some(Self::Control1),
            12 => Some(Self::Control2),
            13 => Some(Self::Control3),
            14 => Some(Self::Control4),
            15 => Some(Self::Control5),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct Frame {
    fin: u8,
    rsv1: u8,
    rsv2: u8,
    rsv3: u8,
    opcode: WebsocketOpcode,
    mask: u8,
    payload_len: u64,
    mask_key: [u8; 4],
    payload: Vec<u8>,
}

impl Frame {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ret = Vec::with_capacity(self.payload.len() + 16);

        let first = (self.fin & 1) << 7
            | (self.rsv1 & 1) << 6
            | (self.rsv2 & 1) << 5
            | (self.rsv3 & 1) << 4
            | (self.opcode.to_int() & 0xf);

        ret.push(first);

        let payload_len = self.payload.len();
        let first_payload_len = if payload_len > 0xffff {
            127
        } else if payload_len > 125 {
            126
        } else {
            payload_len as u8
        };

        let second = ((self.mask & 1) << 7) | first_payload_len;
        ret.push(second);

        if first_payload_len == 126 {
            ret.extend_from_slice(&(payload_len as u16).to_be_bytes()[..]);
        } else if first_payload_len == 127 {
            ret.extend_from_slice(&payload_len.to_be_bytes()[..]);
        }

        if self.mask == 1 {
            ret.extend_from_slice(&self.mask_key[..]);
        }

        ret.extend_from_slice(self.payload.as_slice());

        ret
    }
}

#[derive(Clone, Copy, Debug)]
enum ConnectionStatus {
    Connecting,
    Open,
    Closing,
    Close,
}

#[derive(Debug)]
pub struct Writer {
    is_socket_active: Arc<AtomicBool>,
    peer_name: String,
    should_mask: bool,
    next_mask: u32,
    io: TcpStream,
    ssl: Option<ssl::Stream>,
}

impl Clone for Writer {
    fn clone(&self) -> Self {
        Self {
            is_socket_active: self.is_socket_active.clone(),
            next_mask: self.next_mask,
            should_mask: self.should_mask,
            peer_name: self.peer_name.clone(),
            io: self.io.try_clone().unwrap(),
            ssl: self.ssl.clone(),
        }
    }
}

impl Writer {
    fn raw_send<B: AsRef<[u8]>>(&mut self, bytes: B) -> Result<()> {
        use std::io::Write;
        use std::sync::atomic::Ordering;

        if !self.is_socket_active.load(Ordering::SeqCst) {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe).into());
        }

        let res = if let Some(ssl) = &mut self.ssl {
            ssl.write_all(bytes.as_ref())
        } else {
            self.io.write_all(bytes.as_ref())
        }
        .context("Failed to write bytes to stream");

        if res.is_err() {
            log::trace!("Stream send error: {:?}", res);
            self.is_socket_active.store(false, Ordering::SeqCst);
        }

        res?;

        Ok(())
    }

    pub fn send_message(&mut self, msg: Message) -> Result<()> {
        log::trace!("trying to send to {:?} message: {:?}", self.name(), msg);

        let (opcode, payload) = match msg {
            Message::Ping(p) => (WebsocketOpcode::Ping, p),
            Message::Pong(p) => (WebsocketOpcode::Pong, p),
            Message::Close(p) => (WebsocketOpcode::Close, p),
            Message::Text(p) => (WebsocketOpcode::Text, p.as_bytes().to_vec()),
            Message::Binary(p) => (WebsocketOpcode::Binary, p),
        };

        let mut mask_key = 0;
        let mask = self.next_mask.to_be_bytes();
        let payload = if self.should_mask {
            payload
                .into_iter()
                .map(|b| {
                    let encoded = b ^ mask[mask_key % 4];
                    mask_key += 1;
                    encoded
                })
                .collect::<Vec<_>>()
        } else {
            payload
        };

        let frame = Frame {
            fin: 1,
            rsv1: 0,
            rsv2: 0,
            rsv3: 0,
            opcode,
            payload_len: payload.len() as u64,
            payload,
            mask_key: mask,
            mask: if self.should_mask { 1 } else { 0 },
        };

        self.next_mask.wrapping_add(1);

        self.raw_send(frame.to_bytes())
    }

    pub fn name(&self) -> &str {
        self.peer_name.as_str()
    }
}

fn setup_socket(sock: &TcpStream) -> Result<()> {
    sock.set_nodelay(true)?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(600)));
    sock.set_write_timeout(Some(std::time::Duration::from_secs(600)));
    Ok(())
}

#[derive(Debug)]
pub struct Client {
    current_fragment: Option<Frame>,
    status: ConnectionStatus,
    url: url::Url,
    writer: Writer,
}

impl Client {
    fn do_handshake(&mut self) -> Result<()> {
        if let Some(ssl) = &mut self.writer.ssl {
            ssl.do_handshake().context("Failed SSL handshake")?;
        }

        let random_token = "AQIDBAUGBwgJCgsMDQ4PEC==";
        let open_handshake = http::ReqBuilder::from_url(self.url.clone())
            .version(http::HttpVersion::Http11)
            .method(http::HttpMethod::GET)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Key", random_token)
            .header("Sec-WebSocket-Version", "13")
            .build();

        self.raw_send(open_handshake)
            .context("Failed to send opening handshake")?;
        let response = self.raw_recv().context("Failed to read opening response")?;

        let response = http::parse_response(response).context("Failed to parse http response")?;

        match response.status {
            http::HttpStatus::Informal(http::StatusInformal::SwitchingProtocols) => {
                let upgrade_field = response.headers.get("upgrade");
                if !upgrade_field.map(|val| val.to_lowercase() == *"websocket").unwrap_or(false) {
                    // failure according to spec
                    bail!("Server failed to send 'Upgrade' header according to RFC 6455 (must be case-insensitive 'websocket': {:?}", response);
                }

                let connection_field = response.headers.get("connection");
                if !connection_field.map(|val| val.to_lowercase() == *"upgrade").unwrap_or(false) {
                    // failure according to spec
                    bail!("Server failed to send 'Connection' header according to RFC 6455 (must be case-insensitive 'upgrade': {:?}", response);
                }

                let accept_token = response.headers.get("sec-websocket-accept");
                if !accept_token.map(|val| true).unwrap_or(false) {
                    // TODO: fail if token isn't correct but we don't really care, not even a security
                    // issue in this usecase.
                    bail!("Server failed to send 'Sec-WebSocket-Accept' according to RFC 6455: {:?}", response);
                }

                let extensions = response.headers.get("sec-websocket-extensions");
                if extensions.map(|ex| !ex.is_empty()).unwrap_or(false) {
                    bail!("Server required websocket extension which we don't provide: {:?}", response);
                }

                let extensions = response.headers.get("sec-websocket-protocol");
                if extensions.map(|ex| !ex.is_empty()).unwrap_or(false) {
                    bail!("Server required websocket protocol which we don't provide: {:?}", response);
                }

                // TODO: cookies i guess ?
            }
            // TODO(brymko):
            _ => bail!("Server send different status than 101 SwitchingProtocols, not handling right now: {:?}", response),
        }

        self.status = ConnectionStatus::Open;

        Ok(())
    }

    fn raw_send<B: AsRef<[u8]>>(&mut self, bytes: B) -> Result<()> {
        self.writer.raw_send(bytes)
    }

    fn recv_some(&mut self, size: usize) -> Result<Vec<u8>> {
        assert!(size != 0);

        use std::sync::atomic::Ordering;

        if !self.writer.is_socket_active.load(Ordering::SeqCst) {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe).into());
        }

        let mut ret = vec![0; size];
        let amount = match if let Some(ssl) = &mut self.writer.ssl {
            ssl.read(&mut ret)
        } else {
            self.writer.io.read(&mut ret)
        }
        .context("Failed to read bytes from stream")
        {
            Err(e) => {
                log::trace!("Stream recv error: {:?}", e);
                self.writer.is_socket_active.store(false, Ordering::SeqCst);
                self.writer.io.shutdown(std::net::Shutdown::Both);
                return Err(e);
            }
            // In this case we have to be reaaaaally careful to not make a call to this function
            // with size == 0, see assert at the beginning. if the returend value is 0 this
            // indicates an unexpected eof
            Ok(o) if o == 0 => {
                log::trace!("Stream unexpected EOF {:?}", self.name());
                self.writer.is_socket_active.store(false, Ordering::SeqCst);
                self.writer.io.shutdown(std::net::Shutdown::Both);
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe).into());
            }
            Ok(o) => o,
        };

        ret.truncate(amount);

        Ok(ret)
    }

    fn raw_recv_exact(&mut self, mut bytes: usize) -> Result<Vec<u8>> {
        let mut ret = Vec::with_capacity(bytes);

        loop {
            let buf = self.recv_some(bytes)?;
            ret.extend_from_slice(&buf);

            if ret.len() >= bytes {
                break;
            }

            bytes -= buf.len();
        }

        Ok(ret)
    }

    fn raw_recv(&mut self) -> Result<Vec<u8>> {
        const CHUNK_SIZE: usize = 0x1000;
        let mut ret = Vec::with_capacity(CHUNK_SIZE);

        loop {
            let buf = self.recv_some(CHUNK_SIZE)?;
            ret.extend_from_slice(&buf);

            if buf.len() != CHUNK_SIZE {
                break;
            }
        }

        Ok(ret)
    }

    fn recv_frame(&mut self) -> Result<Frame> {
        use std::convert::TryInto;

        let meta = self.raw_recv_exact(2)?;
        let fin = (meta[0] >> 7) & 1;
        let rsv1 = (meta[0] >> 6) & 1;
        let rsv2 = (meta[0] >> 5) & 1;
        let rsv3 = (meta[0] >> 4) & 1;
        let opcode = meta[0] & 0xf;
        let mask = (meta[1] >> 7) & 1;
        let payload_len = (meta[1] & 0x7f) as u64;

        let payload_len = if payload_len == 126 {
            u16::from_be_bytes(self.raw_recv_exact(2)?.as_slice().try_into()?) as u64
        } else if payload_len == 127 {
            u64::from_be_bytes(self.raw_recv_exact(8)?.as_slice().try_into()?)
        } else {
            payload_len
        };

        let mask_key = if mask == 1 {
            self.raw_recv_exact(4)?
        } else {
            vec![0; 4]
        };

        let mask_key = [mask_key[0], mask_key[1], mask_key[2], mask_key[3]];

        let mut mask_idx = 0;
        let payload = self
            .raw_recv_exact(payload_len as usize)?
            .iter()
            .map(|&byte| {
                let decoded = byte ^ mask_key[mask_idx % 4];
                mask_idx += 1;
                decoded
            })
            .collect();

        Ok(Frame {
            fin,
            rsv1,
            rsv2,
            rsv3,
            mask,
            // UNWRAP: only 4 bits are used from the stream
            opcode: WebsocketOpcode::from_int(opcode).unwrap(),
            payload_len,
            mask_key,
            payload,
        })
    }

    fn next_full_fragment(&mut self) -> Result<Frame> {
        let mut frame = self.current_fragment.take().unwrap_or(self.recv_frame()?);

        if frame.fin == 1 {
            return Ok(frame);
        }

        loop {
            let next = self.recv_frame()?;

            if frame.fin == 1
                && matches!(
                    frame.opcode,
                    WebsocketOpcode::Control1
                        | WebsocketOpcode::Control2
                        | WebsocketOpcode::Control3
                        | WebsocketOpcode::Control4
                        | WebsocketOpcode::Control5
                        | WebsocketOpcode::Ping
                        | WebsocketOpcode::Pong
                        | WebsocketOpcode::Close
                )
            {
                // short cut control frame to reader
                self.current_fragment = Some(frame);
                return Ok(next);
            }

            // don't care if opcode isn't continuation
            frame.payload.extend_from_slice(next.payload.as_slice());
            frame.fin = next.fin;

            if frame.fin == 1 {
                return Ok(frame);
            }
        }
    }

    fn from_socket(io: TcpStream, addr: SocketAddr, ssl: Option<ssl::Stream>) -> Self {
        let url_string = format!("wss://{:?}", addr);
        Self {
            writer: Writer {
                peer_name: addr.to_string(),
                is_socket_active: Arc::new(AtomicBool::new(true)),
                io,
                ssl,
                should_mask: false,
                next_mask: 0,
            },
            url: url::Url::parse(url_string.as_str()).unwrap_or_else(|_| {
                url::Url::parse("wss://dummy.url.this.should.not.happen/").unwrap()
            }),
            current_fragment: None,
            status: ConnectionStatus::Connecting,
        }
    }

    pub fn create_writer(&self) -> Writer {
        self.writer.clone()
    }

    pub fn recv_message(&mut self) -> Result<Message> {
        use std::sync::atomic::Ordering;

        match self.status {
            ConnectionStatus::Close | ConnectionStatus::Closing => {
                log::trace!("WebSocket Connection has been closed");
                self.writer.is_socket_active.store(false, Ordering::SeqCst);
                self.writer.io.shutdown(std::net::Shutdown::Both);
                bail!("WebSocket connection has been closed");
            }
            _ => {}
        }

        let full_frame = self.next_full_fragment()?;

        let msg = match full_frame.opcode {
            WebsocketOpcode::Text => Ok(Message::Text(String::from_utf8(full_frame.payload)?)),
            WebsocketOpcode::Ping => Ok(Message::Ping(full_frame.payload)),
            WebsocketOpcode::Pong => Ok(Message::Pong(full_frame.payload)),
            WebsocketOpcode::Binary => Ok(Message::Binary(full_frame.payload)),
            WebsocketOpcode::Close => {
                self.status = ConnectionStatus::Close;
                Ok(Message::Close(full_frame.payload))
            }
            _ => bail!("Opcode unhandled: {:?}", full_frame),
        };

        log::trace!("received from {:?} message: {:?}", self.name(), msg);

        msg
    }

    pub fn send_message(&mut self, msg: Message) -> Result<()> {
        match self.status {
            ConnectionStatus::Close | ConnectionStatus::Closing => {
                log::trace!("WS Connection has been closed");
                self.writer.io.shutdown(std::net::Shutdown::Both);
                bail!("WebSocket connection has been closed");
            }
            _ => {}
        }
        if let Message::Close(_) = &msg {
            self.status = ConnectionStatus::Closing
        }
        self.writer.send_message(msg)
    }

    pub fn connect<Uri: AsRef<str>>(server_uri: Uri) -> Result<Self> {
        let url = url::Url::parse(server_uri.as_ref())?;

        let host = url.host_str().ok_or_else(|| anyhow!("missing host"))?;
        let connect_url = match url.scheme() {
            "wss" => format!("{}:{}", host, url.port().unwrap_or(443)),
            "ws" => format!("{}:{}", host, url.port().unwrap_or(80)),
            _ => bail!("Invalid or missing shema"),
        };

        let stream = TcpStream::connect(connect_url)?;
        let io = stream.try_clone().context("Failed to clone TcpStream")?;
        let ssl = if url.scheme() == "wss" {
            Some(ssl::Stream::new(stream, host))
        } else {
            None
        };

        let mut this = Self {
            current_fragment: None,
            writer: Writer {
                peer_name: host.to_string(),
                should_mask: true,
                is_socket_active: Arc::new(AtomicBool::new(true)),
                io,
                ssl,
                next_mask: 1,
            },
            status: ConnectionStatus::Connecting,
            url,
        };

        setup_socket(&this.writer.io);
        this.do_handshake()?;

        Ok(this)
    }

    pub fn name(&self) -> &str {
        self.writer.name()
    }
}

#[derive(Debug)]
pub struct Server {
    listener: TcpListener,
    ssl: Option<ssl::Listener>,
}

impl Server {
    fn do_handshake(client: &mut Client) -> Result<()> {
        let client_handshake = client.raw_recv().context("Failed to received handshake")?;
        let req =
            http::parse_request(client_handshake).context("Failed to parse handshake request")?;
        let token = req
            .headers
            .get("sec-websocket-key")
            .ok_or_else(|| anyhow!("Client didn't send us the challenge token"))?;

        let mut to_sha = token.as_bytes().to_vec();
        to_sha.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");

        let sha = sha1::Sha1::from(to_sha).digest();
        let encoded = base64::encode(sha.bytes());

        let mut resp = http::RespBuilder::new(
            http::HttpVersion::Http11,
            http::HttpStatus::Informal(http::StatusInformal::SwitchingProtocols),
        )
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Accept", encoded)
        .build();

        client
            .raw_send(resp)
            .context("Failed to send handshake response")?;

        client.status = ConnectionStatus::Open;

        Ok(())
    }

    pub fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(addr)?,
            ssl: None,
        })
    }

    pub fn accept(&mut self) -> Result<Client> {
        let (mut s, addr) = self.listener.accept()?;
        log::info!("New connection request from {:?}", addr);

        setup_socket(&s);

        let mut this = Client::from_socket(s, addr, None);
        Self::do_handshake(&mut this)?;

        log::info!("New client {:?}", this.name());

        Ok(this)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::thread;

    #[test]
    fn it_works() {
        let d = 2 + 2;
        assert_eq!(d, 4);
    }

    #[test]
    fn system_resolver() {
        let mut c = Client::connect("ws://google.com:80");
        assert!(c.is_err())
    }

    #[test]
    fn websocket_handshake_no_ssl() {
        let mut c = Client::connect("ws://echo.websocket.org").unwrap();
    }

    #[test]
    fn frame_to_bytes_small_payload() {
        let msg = Message::Binary(vec![8; 42]);

        let (opcode, payload) = match msg {
            Message::Ping(p) => (WebsocketOpcode::Ping, p),
            Message::Pong(p) => (WebsocketOpcode::Pong, p),
            Message::Close(p) => (WebsocketOpcode::Close, p),
            Message::Text(p) => (WebsocketOpcode::Text, p.as_bytes().to_vec()),
            Message::Binary(p) => (WebsocketOpcode::Binary, p),
        };

        let mut mask_key = 0;
        let mask = [1, 1, 1, 1];
        let payload = payload
            .into_iter()
            .map(|b| {
                let encoded = b ^ mask[mask_key % 4];
                mask_key += 1;
                encoded
            })
            .collect::<Vec<_>>();

        let frame = Frame {
            fin: 1,
            rsv1: 0,
            rsv2: 0,
            rsv3: 0,
            opcode,
            payload_len: payload.len() as u64,
            payload,
            mask_key: mask,
            mask: 1,
        };

        assert!(
            frame.to_bytes()
                == [
                    130, 170, 1, 1, 1, 1, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9
                ]
        );
    }

    #[test]
    fn frame_to_bytes_medium_payload() {
        let msg = Message::Binary(vec![8; 0x200]);

        let (opcode, payload) = match msg {
            Message::Ping(p) => (WebsocketOpcode::Ping, p),
            Message::Pong(p) => (WebsocketOpcode::Pong, p),
            Message::Close(p) => (WebsocketOpcode::Close, p),
            Message::Text(p) => (WebsocketOpcode::Text, p.as_bytes().to_vec()),
            Message::Binary(p) => (WebsocketOpcode::Binary, p),
        };

        let mut mask_key = 0;
        let mask = [1, 1, 1, 1];
        let payload = payload
            .into_iter()
            .map(|b| {
                let encoded = b ^ mask[mask_key % 4];
                mask_key += 1;
                encoded
            })
            .collect::<Vec<_>>();

        let frame = Frame {
            fin: 1,
            rsv1: 0,
            rsv2: 0,
            rsv3: 0,
            opcode,
            payload_len: payload.len() as u64,
            payload,
            mask_key: mask,
            mask: 1,
        };

        assert!(
            frame.to_bytes()
                == [
                    130, 254, 2, 0, 1, 1, 1, 1, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                    9
                ]
        );
    }

    #[test]
    fn frame_to_bytes_large_payload() {
        let msg = Message::Binary(vec![8; 0x20000]);

        let (opcode, payload) = match msg {
            Message::Ping(p) => (WebsocketOpcode::Ping, p),
            Message::Pong(p) => (WebsocketOpcode::Pong, p),
            Message::Close(p) => (WebsocketOpcode::Close, p),
            Message::Text(p) => (WebsocketOpcode::Text, p.as_bytes().to_vec()),
            Message::Binary(p) => (WebsocketOpcode::Binary, p),
        };

        let mut mask_key = 0;
        let mask = [1, 1, 1, 1];
        let payload = payload
            .into_iter()
            .map(|b| {
                let encoded = b ^ mask[mask_key % 4];
                mask_key += 1;
                encoded
            })
            .collect::<Vec<_>>();

        let frame = Frame {
            fin: 1,
            rsv1: 0,
            rsv2: 0,
            rsv3: 0,
            opcode,
            payload_len: payload.len() as u64,
            payload,
            mask_key: mask,
            mask: 1,
        };

        let mut wanted = vec![130, 255, 0, 0, 0, 0, 0, 2, 0, 0, 1, 1, 1, 1];
        wanted.append(&mut vec![9; 0x20000]);
        assert!(frame.to_bytes() == wanted);
    }

    #[test]
    fn echo_test() {
        let mut c = Client::connect("ws://echo.websocket.org").unwrap();
        c.send_message(Message::Text("hello world".to_string()))
            .unwrap();
        let msg = c.recv_message().unwrap();
        if let Message::Text(e) = msg {
            assert!(e == *"hello world");
        } else {
            panic!("response not a text message");
        }
    }

    #[test]
    fn server_test() {
        let addr = "ws://127.0.0.1:33456";
        let bind_addr = "127.0.0.1:33456";
        let mut s = Server::bind(bind_addr).unwrap();
        thread::spawn(move || {
            let mut c = Client::connect(addr).unwrap();
            c.send_message(Message::Ping(b"loool".to_vec())).unwrap();
        });
        let mut c = s.accept().unwrap();
        if let Message::Ping(s) = c.recv_message().unwrap() {
            assert!(s == b"loool");
        } else {
            panic!("not ping received");
        }
    }
}
