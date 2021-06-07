use anyhow::{anyhow, Context, Result};
use url::Url;

use std::collections::HashMap;

#[derive(Clone, Copy, Debug)]
pub enum StatusInformal {
    Continue = 100,
    SwitchingProtocols = 101,
    Processing = 102,
    EarlyHints = 103,
}

impl StatusInformal {
    #[inline]
    pub fn to_int(self) -> usize {
        self as usize
    }

    #[inline]
    pub fn from_int(status: usize) -> Option<Self> {
        match status {
            100 => Some(Self::Continue),
            101 => Some(Self::SwitchingProtocols),
            102 => Some(Self::Processing),
            103 => Some(Self::EarlyHints),
            _ => None,
        }
    }

    #[inline]
    pub fn from_str<S: AsRef<str>>(status: S) -> Option<Self> {
        match status.as_ref() {
            "100" | "100 Continue" => Some(Self::Continue),
            "101" | "101 Switching Protocols" => Some(Self::SwitchingProtocols),
            "102" | "102 Processing" => Some(Self::Processing),
            "103" | "103 Early Hints" => Some(Self::EarlyHints),
            _ => None,
        }
    }

    #[inline]
    pub fn to_str(self) -> &'static str {
        match self {
            Self::Continue => "100 Continue",
            Self::SwitchingProtocols => "101 Switching Protocols",
            Self::Processing => "102 Processing",
            Self::EarlyHints => "103 Early Hints",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum StatusSuccess {
    // Success
    OK = 200,
    Created = 201,
    Accepted = 202,
    NonAuthoritativeResponse = 203,
    NoContent = 204,
    ResetContent = 205,
    PartialContent = 206,
    MutliStatus = 207,
    AlreadyReported = 208,
    IMUsed = 226,
}

impl StatusSuccess {
    #[inline]
    pub fn to_int(self) -> usize {
        self as usize
    }

    #[inline]
    pub fn from_int(status: usize) -> Option<Self> {
        match status {
            200 => Some(Self::OK),
            201 => Some(Self::Created),
            202 => Some(Self::Accepted),
            203 => Some(Self::NonAuthoritativeResponse),
            204 => Some(Self::NoContent),
            205 => Some(Self::ResetContent),
            206 => Some(Self::PartialContent),
            207 => Some(Self::MutliStatus),
            208 => Some(Self::AlreadyReported),
            226 => Some(Self::IMUsed),
            _ => None,
        }
    }

    #[inline]
    pub fn from_str<S: AsRef<str>>(status: S) -> Option<Self> {
        match status.as_ref() {
            "200" | "200 OK" => Some(Self::OK),
            "201" | "201 Created" => Some(Self::Created),
            "202" | "202 Accepted" => Some(Self::Accepted),
            "203" | "203 Non-Authoritative Information" => Some(Self::NonAuthoritativeResponse),
            "204" | "204 No Content" => Some(Self::NoContent),
            "205" | "205 Reset Content" => Some(Self::ResetContent),
            "206" | "206 Partial Content" => Some(Self::PartialContent),
            "207" | "207 Multi-Status" => Some(Self::MutliStatus),
            "208" | "208 Already Reported" => Some(Self::AlreadyReported),
            "226" | "226 IM Used" => Some(Self::IMUsed),
            _ => None,
        }
    }

    #[inline]
    pub fn to_str(self) -> &'static str {
        match self {
            Self::OK => "200 OK",
            Self::Created => "201 Created",
            Self::Accepted => "202 Accepted",
            Self::NonAuthoritativeResponse => "203 Non-Authoritative Information",
            Self::NoContent => "204 No Content",
            Self::ResetContent => "205 Reset Content",
            Self::PartialContent => "206 Partial Content",
            Self::MutliStatus => "207 Multi-Status",
            Self::AlreadyReported => "208 Already Reported",
            Self::IMUsed => "226 IM Used",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum StatusRedirect {
    MultipleChoices = 300,
    MovedPermanently = 301,
    Found = 302,
    SeeOther = 303,
    NotModified = 304,
    UseProxy = 305,
    SwitchProxy = 306,
    TemporaryRedirect = 307,
    PermanentRedirect = 308,
}

impl StatusRedirect {
    #[inline]
    pub fn to_int(self) -> usize {
        self as usize
    }

    #[inline]
    pub fn from_int(status: usize) -> Option<Self> {
        match status {
            300 => Some(Self::MultipleChoices),
            301 => Some(Self::MovedPermanently),
            302 => Some(Self::Found),
            303 => Some(Self::SeeOther),
            304 => Some(Self::NotModified),
            305 => Some(Self::UseProxy),
            306 => Some(Self::SwitchProxy),
            307 => Some(Self::TemporaryRedirect),
            308 => Some(Self::PermanentRedirect),
            _ => None,
        }
    }

    #[inline]
    pub fn from_str<S: AsRef<str>>(status: S) -> Option<Self> {
        match status.as_ref() {
            "300" | "300 Multiple Choices" => Some(Self::MultipleChoices),
            "301" | "301 Moved Permanently" => Some(Self::MovedPermanently),
            "302" | "302 Found" => Some(Self::Found),
            "303" | "303 See Other" => Some(Self::SeeOther),
            "304" | "304 Not Modified" => Some(Self::NotModified),
            "305" | "305 Use Proxy" => Some(Self::UseProxy),
            "306" | "306 Switch Proxy" => Some(Self::SwitchProxy),
            "307" | "307 Temporary Redirect" => Some(Self::TemporaryRedirect),
            "308" | "308 Permanent Redirect" => Some(Self::PermanentRedirect),
            _ => None,
        }
    }

    #[inline]
    pub fn to_str(self) -> &'static str {
        match self {
            Self::MultipleChoices => "300 Multiple Choices",
            Self::MovedPermanently => "301 Moved Permanently",
            Self::Found => "302 Found",
            Self::SeeOther => "303 See Other",
            Self::NotModified => "304 Not Modified",
            Self::UseProxy => "305 Use Proxy",
            Self::SwitchProxy => "306 Switch Proxy",
            Self::TemporaryRedirect => "307 Temporary Redirect",
            Self::PermanentRedirect => "308 Permanent Redirect",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum StatusClientError {
    BadRequest = 400,
    Unauthorized = 401,
    PaymentRequired = 402,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    NotAcceptable = 406,
    ProxyAuthenticationRequired = 407,
    RequestTimeout = 408,
    Conflict = 409,
    Gone = 410,
    LengthRequired = 411,
    PreconditionFailed = 412,
    PayloadTooLarge = 413,
    URITooLong = 414,
    UnsupportedMediaType = 415,
    RangeNotSatisfiable = 416,
    ExpectationFailed = 417,
    ImATeaPot = 418,
    MisdirectedRequest = 421,
    UnprocessabelEntity = 422,
    Locked = 423,
    FailedDependency = 424,
    TooEarly = 425,
    UpgradeRequired = 426,
    PreconditionRequired = 428,
    TooManyRequest = 429,
    RequestHeaderFieldsTooLarge = 431,
    UnavailableForLegalReasons = 451,
}

impl StatusClientError {
    #[inline]
    pub fn to_int(self) -> usize {
        self as usize
    }

    #[inline]
    pub fn from_int(status: usize) -> Option<Self> {
        match status {
            400 => Some(Self::BadRequest),
            401 => Some(Self::Unauthorized),
            402 => Some(Self::PaymentRequired),
            403 => Some(Self::Forbidden),
            404 => Some(Self::NotFound),
            405 => Some(Self::MethodNotAllowed),
            406 => Some(Self::NotAcceptable),
            407 => Some(Self::ProxyAuthenticationRequired),
            408 => Some(Self::RequestTimeout),
            409 => Some(Self::Conflict),
            410 => Some(Self::Gone),
            411 => Some(Self::LengthRequired),
            412 => Some(Self::PreconditionFailed),
            413 => Some(Self::PayloadTooLarge),
            414 => Some(Self::URITooLong),
            415 => Some(Self::UnsupportedMediaType),
            416 => Some(Self::RangeNotSatisfiable),
            417 => Some(Self::ExpectationFailed),
            418 => Some(Self::ImATeaPot),
            421 => Some(Self::MisdirectedRequest),
            422 => Some(Self::UnprocessabelEntity),
            423 => Some(Self::Locked),
            424 => Some(Self::FailedDependency),
            425 => Some(Self::TooEarly),
            426 => Some(Self::UpgradeRequired),
            428 => Some(Self::PreconditionRequired),
            429 => Some(Self::TooManyRequest),
            431 => Some(Self::RequestHeaderFieldsTooLarge),
            451 => Some(Self::UnavailableForLegalReasons),
            _ => None,
        }
    }

    #[inline]
    pub fn from_str<S: AsRef<str>>(status: S) -> Option<Self> {
        match status.as_ref() {
            "400" | "400 Bad Request" => Some(Self::BadRequest),
            "401" | "401 Unauthorized" => Some(Self::Unauthorized),
            "402" | "402 Payment Required" => Some(Self::PaymentRequired),
            "403" | "403 Forbidden" => Some(Self::Forbidden),
            "404" | "404 Not Found" => Some(Self::NotFound),
            "405" | "405 Method Not Allowed" => Some(Self::MethodNotAllowed),
            "406" | "406 Not Acceptable" => Some(Self::NotAcceptable),
            "407" | "407 Proxy Authentication Required" => Some(Self::ProxyAuthenticationRequired),
            "408" | "408 Request Timeout" => Some(Self::RequestTimeout),
            "409" | "409 Conflict" => Some(Self::Conflict),
            "410" | "410 Gone" => Some(Self::Gone),
            "411" | "411 Length Required" => Some(Self::LengthRequired),
            "412" | "412 Precondition Failed" => Some(Self::PreconditionFailed),
            "413" | "413 Payload Too Large" => Some(Self::PayloadTooLarge),
            "414" | "414 URI Too Long" => Some(Self::URITooLong),
            "415" | "415 Unsupported Media Type" => Some(Self::UnsupportedMediaType),
            "416" | "416 Range Not Satisfiable" => Some(Self::RangeNotSatisfiable),
            "417" | "417 Expectation Failed" => Some(Self::ExpectationFailed),
            "418" | "418 I'm a teapot" => Some(Self::ImATeaPot),
            "421" | "421 Misdirected Request" => Some(Self::MisdirectedRequest),
            "422" | "422 Unprocessable Entity" => Some(Self::UnprocessabelEntity),
            "423" | "423 Locked" => Some(Self::Locked),
            "424" | "424 Failed Dependency" => Some(Self::FailedDependency),
            "425" | "425 Too Early" => Some(Self::TooEarly),
            "426" | "426 Upgrade Required" => Some(Self::UpgradeRequired),
            "428" | "428 Precondition Required" => Some(Self::PreconditionRequired),
            "429" | "429 Too Many Requests" => Some(Self::TooManyRequest),
            "431" | "431 Request Header Fields Too Large" => {
                Some(Self::RequestHeaderFieldsTooLarge)
            }
            "451" | "451 Unavailable For Legal Reasons" => Some(Self::UnavailableForLegalReasons),
            _ => None,
        }
    }

    #[inline]
    pub fn to_str(self) -> &'static str {
        match self {
            Self::BadRequest => "400 Bad Request",
            Self::Unauthorized => "401 Unauthorized",
            Self::PaymentRequired => "402 Payment Required",
            Self::Forbidden => "403 Forbidden",
            Self::NotFound => "404 Not Found",
            Self::MethodNotAllowed => "405 Method Not Allowed",
            Self::NotAcceptable => "406 Not Acceptable",
            Self::ProxyAuthenticationRequired => "407 Proxy Authentication Required",
            Self::RequestTimeout => "408 Request Timeout",
            Self::Conflict => "409 Conflict",
            Self::Gone => "410 Gone",
            Self::LengthRequired => "411 Length Required",
            Self::PreconditionFailed => "412 Precondition Failed",
            Self::PayloadTooLarge => "413 Payload Too Large",
            Self::URITooLong => "414 URI Too Long",
            Self::UnsupportedMediaType => "415 Unsupported Media Type",
            Self::RangeNotSatisfiable => "416 Range Not Satisfiable",
            Self::ExpectationFailed => "417 Expectation Failed",
            Self::ImATeaPot => "418 I'm a teapot",
            Self::MisdirectedRequest => "421 Misdirected Request",
            Self::UnprocessabelEntity => "422 Unprocessable Entity",
            Self::Locked => "423 Locked",
            Self::FailedDependency => "424 Failed Dependency",
            Self::TooEarly => "425 Too Early",
            Self::UpgradeRequired => "426 Upgrade Required",
            Self::PreconditionRequired => "428 Precondition Required",
            Self::TooManyRequest => "429 Too Many Requests",
            Self::RequestHeaderFieldsTooLarge => "431 Request Header Fields Too Large",
            Self::UnavailableForLegalReasons => "451 Unavailable For Legal Reasons",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum StatusServerError {
    InternalServerError = 500,
    NotImplemented = 501,
    BadGateway = 502,
    ServiceUnavailable = 503,
    GatewayTimeout = 504,
    HTTPVersionNotSupported = 505,
    VariantAlsoNegotiats = 506,
    InsufficientStorage = 507,
    LoopDetected = 508,
    NotExtended = 510,
    NetworkAuthenticationRequired = 511,
}

impl StatusServerError {
    #[inline]
    fn to_int(self) -> usize {
        self as usize
    }

    #[inline]
    fn from_int(status: usize) -> Option<Self> {
        match status {
            500 => Some(Self::InternalServerError),
            501 => Some(Self::NotImplemented),
            502 => Some(Self::BadGateway),
            503 => Some(Self::ServiceUnavailable),
            504 => Some(Self::GatewayTimeout),
            505 => Some(Self::HTTPVersionNotSupported),
            506 => Some(Self::VariantAlsoNegotiats),
            507 => Some(Self::InsufficientStorage),
            508 => Some(Self::LoopDetected),
            510 => Some(Self::NotExtended),
            511 => Some(Self::NetworkAuthenticationRequired),
            _ => None,
        }
    }

    #[inline]
    fn from_str<S: AsRef<str>>(status: S) -> Option<Self> {
        match status.as_ref() {
            "500" | "500 Internal Server Error" => Some(Self::InternalServerError),
            "501" | "501 Not Implemented" => Some(Self::NotImplemented),
            "502" | "502 Bad Gateway" => Some(Self::BadGateway),
            "503" | "503 Service Unavailable" => Some(Self::ServiceUnavailable),
            "504" | "504 Gateway Timeout" => Some(Self::GatewayTimeout),
            "505" | "505 HTTP Version Not Supported" => Some(Self::HTTPVersionNotSupported),
            "506" | "506 Variant Also Negotiates" => Some(Self::VariantAlsoNegotiats),
            "507" | "507 Insufficient Storage" => Some(Self::InsufficientStorage),
            "508" | "508 Loop Detected" => Some(Self::LoopDetected),
            "510" | "510 Not Extended" => Some(Self::NotExtended),
            "511" | "511 Network Authentication Required" => {
                Some(Self::NetworkAuthenticationRequired)
            }
            _ => None,
        }
    }

    #[inline]
    fn to_str(self) -> &'static str {
        match self {
            Self::InternalServerError => "500 Internal Server Error",
            Self::NotImplemented => "501 Not Implemented",
            Self::BadGateway => "502 Bad Gateway",
            Self::ServiceUnavailable => "503 Service Unavailable",
            Self::GatewayTimeout => "504 Gateway Timeout",
            Self::HTTPVersionNotSupported => "505 HTTP Version Not Supported",
            Self::VariantAlsoNegotiats => "506 Variant Also Negotiates",
            Self::InsufficientStorage => "507 Insufficient Storage",
            Self::LoopDetected => "508 Loop Detected",
            Self::NotExtended => "510 Not Extended",
            Self::NetworkAuthenticationRequired => "511 Network Authentication Required",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum HttpStatus {
    Informal(StatusInformal),
    Success(StatusSuccess),
    Redirect(StatusRedirect),
    ClientError(StatusClientError),
    ServerError(StatusServerError),
    Unknown(usize),
}

impl HttpStatus {
    #[inline]
    pub fn to_int(self) -> usize {
        match self {
            Self::Unknown(s) => s,
            Self::Informal(i) => i.to_int(),
            Self::Success(i) => i.to_int(),
            Self::Redirect(i) => i.to_int(),
            Self::ClientError(i) => i.to_int(),
            Self::ServerError(i) => i.to_int(),
        }
    }

    #[inline]
    pub fn from_int(status: usize) -> Self {
        if let Some(s) = StatusInformal::from_int(status) {
            return Self::Informal(s);
        }
        if let Some(s) = StatusSuccess::from_int(status) {
            return Self::Success(s);
        }
        if let Some(s) = StatusRedirect::from_int(status) {
            return Self::Redirect(s);
        }
        if let Some(s) = StatusClientError::from_int(status) {
            return Self::ClientError(s);
        }
        if let Some(s) = StatusServerError::from_int(status) {
            return Self::ServerError(s);
        }

        Self::Unknown(status)
    }

    #[inline]
    /// Parses a "<Number> [<Explanation>]" string. Explanation is not mandatory. Must be seperated
    /// by ascii whitespace. will return Error if no standard status was found and the string does
    /// not start with a number, as the string -> number parsing will fail.
    pub fn from_str<S: AsRef<str>>(status: S) -> Result<Self> {
        if let Some(s) = StatusInformal::from_str(status.as_ref()) {
            return Ok(Self::Informal(s));
        }
        if let Some(s) = StatusSuccess::from_str(status.as_ref()) {
            return Ok(Self::Success(s));
        }
        if let Some(s) = StatusRedirect::from_str(status.as_ref()) {
            return Ok(Self::Redirect(s));
        }
        if let Some(s) = StatusClientError::from_str(status.as_ref()) {
            return Ok(Self::ClientError(s));
        }
        if let Some(s) = StatusServerError::from_str(status.as_ref()) {
            return Ok(Self::ServerError(s));
        }

        return Ok(Self::Unknown(
            status
                .as_ref()
                .split_ascii_whitespace()
                .next()
                .unwrap_or("")
                .parse::<usize>()?,
        ));
    }

    #[inline]
    pub fn to_str(self) -> &'static str {
        match self {
            Self::Informal(p) => p.to_str(),
            Self::Success(p) => p.to_str(),
            Self::Redirect(p) => p.to_str(),
            Self::ClientError(p) => p.to_str(),
            Self::ServerError(p) => p.to_str(),
            Self::Unknown(_) => "",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum HttpVersion {
    Http10,
    Http11,
    Http2,
}

impl HttpVersion {
    pub fn from_str<S: AsRef<str>>(version: S) -> Option<Self> {
        match version.as_ref() {
            "HTTP/1.0" => Some(Self::Http10),
            "HTTP/1.1" => Some(Self::Http11),
            "HTTP/2" => Some(Self::Http2),
            _ => None,
        }
    }

    pub fn to_str(self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
            Self::Http2 => "HTTP/2",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResponseResult {
    pub headers: HashMap<String, String>,
    pub status: HttpStatus,
    pub version: HttpVersion,
}

pub fn parse_response(packet: Vec<u8>) -> Result<ResponseResult> {
    let raw = String::from_utf8_lossy(packet.as_slice());
    let raw = raw
        .split("\r\n\r\n")
        .next()
        .ok_or_else(|| anyhow!("Invalid http header: {:?}", packet))?;

    let mut lines = raw.split_terminator("\r\n");

    let meta = lines
        .next()
        .ok_or_else(|| anyhow!("Status Line missing: {:?}", raw))?;
    let mut meta_split = meta.split_ascii_whitespace();
    let raw_version = meta_split.next().unwrap_or("");
    let version = HttpVersion::from_str(raw_version)
        .ok_or_else(|| anyhow!("Unknown version {:?}", raw_version))?;
    let raw_status = meta_split.next().unwrap_or("");
    let status = HttpStatus::from_str(raw_status).context("Invalid status code")?;

    let mut headers = HashMap::new();
    for line in lines {
        let mut parts = line.splitn(2, ':');
        if let (Some(header), Some(value)) = (parts.next(), parts.next()) {
            headers.insert(header.to_lowercase(), value.trim_start().to_string());
        } else {
            break;
        }
    }

    Ok(ResponseResult {
        headers,
        status,
        version,
    })
}

#[derive(Clone, Debug)]
pub struct RequestResult {
    pub headers: HashMap<String, String>,
    pub path: String,
    pub version: HttpVersion,
}

pub fn parse_request(packet: Vec<u8>) -> Result<RequestResult> {
    let raw = String::from_utf8_lossy(packet.as_slice());
    let raw = raw
        .split("\r\n\r\n")
        .next()
        .ok_or_else(|| anyhow!("Invalid http header: {:?}", packet))?;

    let mut lines = raw.split_terminator("\r\n");

    let meta = lines
        .next()
        .ok_or_else(|| anyhow!("Request Line missing: {:?}", raw))?;
    let mut meta_split = meta.split_ascii_whitespace();
    let method = meta_split
        .next()
        .ok_or_else(|| anyhow!("No method found"))?;
    let path = meta_split.next().ok_or_else(|| anyhow!("No path found"))?;
    let raw_version = meta_split.next().unwrap_or("");
    let version = HttpVersion::from_str(raw_version)
        .ok_or_else(|| anyhow!("Unknown version {:?}", raw_version))?;

    let mut headers = HashMap::new();
    for line in lines {
        let mut parts = line.splitn(2, ':');
        if let (Some(header), Some(value)) = (parts.next(), parts.next()) {
            headers.insert(header.to_lowercase(), value.trim_start().to_string());
        } else {
            break;
        }
    }

    Ok(RequestResult {
        headers,
        path: path.to_string(),
        version,
    })
}

#[derive(Clone, Copy, Debug)]
pub enum HttpMethod {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    CONNECT,
    OPTIONS,
    TRACE,
    PATCH,
}

impl HttpMethod {
    fn to_str(self) -> &'static str {
        match self {
            Self::GET => "GET",
            Self::HEAD => "HEAD",
            Self::POST => "POST",
            Self::PUT => "PUT",
            Self::DELETE => "DELETE",
            Self::CONNECT => "CONNECT",
            Self::OPTIONS => "OPTIONS",
            Self::TRACE => "TRACE",
            Self::PATCH => "PATCH",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ReqBuilder {
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    url: Url,
    version: Option<HttpVersion>,
    method: Option<HttpMethod>,
}

impl ReqBuilder {
    pub fn new<S: AsRef<str>>(url: S) -> Result<Self> {
        Ok(Self {
            headers: Vec::new(),
            url: Url::parse(url.as_ref()).context("Invalid Url")?,
            version: None,
            method: None,
            body: Vec::new(),
        })
    }

    pub fn from_url(url: url::Url) -> Self {
        Self {
            headers: Vec::new(),
            url,
            version: None,
            method: None,
            body: Vec::new(),
        }
    }

    pub fn header<S: ToString, D: ToString>(mut self, header: S, value: D) -> Self {
        self.headers.push((header.to_string(), value.to_string()));
        self
    }

    pub fn version(mut self, version: HttpVersion) -> Self {
        self.version = Some(version);
        self
    }

    pub fn method(mut self, method: HttpMethod) -> Self {
        self.method = Some(method);
        self
    }

    pub fn body<B: AsRef<[u8]>>(mut self, body: B) -> Self {
        self.body = body.as_ref().to_vec();
        self
    }

    pub fn build(mut self) -> Vec<u8> {
        let request_line = format!(
            "{} {} {}\r\n",
            self.method.unwrap_or(HttpMethod::GET).to_str(),
            self.url.path(),
            self.version.unwrap_or(HttpVersion::Http11).to_str()
        );

        let host_line = if let Some(host) = self.url.host_str() {
            if let Some(port) = self.url.port() {
                format!("Host: {}:{}\r\n", host, port)
            } else {
                format!("Host: {}\r\n", host,)
            }
        } else {
            String::new()
        };

        let mut headers = String::new();
        for (header, value) in self.headers {
            headers.push_str(format!("{}: {}\r\n", header, value).as_str());
        }

        let complete = format!("{}{}{}\r\n", request_line, host_line, headers);

        let mut res = complete.as_bytes().to_vec();
        res.append(self.body.as_mut());

        res
    }
}

#[derive(Clone, Debug)]
pub struct RespBuilder {
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    version: HttpVersion,
    status: HttpStatus,
}

impl RespBuilder {
    pub fn new(version: HttpVersion, status: HttpStatus) -> Self {
        Self {
            headers: Vec::new(),
            body: Vec::new(),
            version,
            status,
        }
    }

    pub fn header<S: ToString, D: ToString>(mut self, header: S, value: D) -> Self {
        self.headers.push((header.to_string(), value.to_string()));
        self
    }

    pub fn body<B: AsRef<[u8]>>(mut self, body: B) -> Self {
        self.body = body.as_ref().to_vec();
        self
    }

    pub fn build(mut self) -> Vec<u8> {
        let status_line = format!("{} {}\r\n", self.version.to_str(), self.status.to_str());
        let mut headers = String::new();
        for (header, value) in self.headers {
            headers.push_str(format!("{}: {}\r\n", header, value).as_str());
        }

        let complete = format!("{}{}\r\n", status_line, headers);

        let mut res = complete.as_bytes().to_vec();
        res.append(self.body.as_mut());

        res
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn http_response1() {
        let http = b"
HTTP/1.1 101 Switching Protocols\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r
Sec-WebSocket-Protocol: chat\r
\r\n";

        let parsed = parse_response(http.as_ref().into()).unwrap();
        assert!(matches!(parsed.version, HttpVersion::Http11));
        assert!(matches!(parsed.status, HttpStatus::Informal(_)));
        assert!(parsed.status.to_int() == 101);
        assert!(parsed.headers["upgrade"] == *"websocket");
        assert!(parsed.headers["connection"] == *"Upgrade");
        assert!(parsed.headers["sec-websocket-accept"] == *"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert!(parsed.headers["sec-websocket-protocol"] == *"chat");
    }

    #[test]
    fn http_build1() {
        let builder = ReqBuilder::new("wss://server.example.com/chat")
            .unwrap()
            .version(HttpVersion::Http11)
            .method(HttpMethod::GET)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Origin", "http://example.com")
            .header("Sec-WebSocket-Protocol", "chat, superchat")
            .header("Sec-WebSocket-Version", "13");

        let complete = builder.build();
        let wanted = b"GET /chat HTTP/1.1\r
Host: server.example.com\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r
Origin: http://example.com\r
Sec-WebSocket-Protocol: chat, superchat\r
Sec-WebSocket-Version: 13\r
\r\n";

        assert!(wanted == complete.as_slice());
    }
}
