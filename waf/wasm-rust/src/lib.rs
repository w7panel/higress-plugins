mod config;

use std::rc::Rc;

use coraza::{
    transaction::{Interruption, Transaction},
    Waf,
};
use proxy_wasm::{
    hostcalls,
    traits::{Context, HttpContext, RootContext},
    types::{Action, BufferType, ContextType, LogLevel},
};

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(Root { waf: None })
    });
}}

struct Root {
    waf: Option<Rc<Waf>>,
}

impl Context for Root {}

impl RootContext for Root {
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn on_configure(&mut self, size: usize) -> bool {
        let bytes = match hostcalls::get_buffer(BufferType::PluginConfiguration, 0, size) {
            Ok(Some(bytes)) => bytes,
            _ => return false,
        };
        match config::compile(&bytes) {
            Ok(waf) => {
                self.waf = Some(Rc::new(waf));
                true
            }
            Err(error) => {
                proxy_wasm::hostcalls::log(LogLevel::Error, &format!("waf-rust config: {error}"))
                    .ok();
                false
            }
        }
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(Stream {
            waf: self.waf.clone(),
            tx: None,
            request_done: false,
            response_done: false,
            protocol: "HTTP/2.0".to_owned(),
        }))
    }
}

struct Stream {
    waf: Option<Rc<Waf>>,
    tx: Option<Transaction>,
    request_done: bool,
    response_done: bool,
    protocol: String,
}

impl Stream {
    fn refuse(status: u32) -> Action {
        if let Err(error) = hostcalls::send_http_response(status, vec![], None) {
            hostcalls::log(LogLevel::Error, &format!("waf-rust reply: {error:?}")).ok();
        }
        Action::Pause
    }

    fn verdict(interruption: Option<Interruption>) -> Action {
        if let Some(item) = interruption {
            return Self::refuse(if item.status == 0 {
                403
            } else {
                u32::from(item.status)
            });
        }
        Action::Continue
    }

    fn request_body(&mut self, size: usize) -> Action {
        if self.request_done {
            return Action::Continue;
        }
        if size > 16 * 1024 * 1024 {
            return Self::refuse(413);
        }
        self.request_done = true;
        let body = match hostcalls::get_buffer(BufferType::HttpRequestBody, 0, size) {
            Ok(Some(body)) => body,
            Ok(None) if size == 0 => Vec::new(),
            _ => return Self::refuse(500),
        };
        Self::verdict(
            self.tx
                .as_mut()
                .and_then(|tx| tx.process_request_body(&body)),
        )
    }

    fn response_body(&mut self, size: usize) -> Action {
        if self.response_done {
            return Action::Continue;
        }
        if size > 1024 * 1024 {
            return Self::refuse(502);
        }
        self.response_done = true;
        let body = match hostcalls::get_buffer(BufferType::HttpResponseBody, 0, size) {
            Ok(Some(body)) => body,
            Ok(None) if size == 0 => Vec::new(),
            _ => return Self::refuse(500),
        };
        Self::verdict(
            self.tx
                .as_mut()
                .and_then(|tx| tx.process_response_body(&body)),
        )
    }
}

impl Context for Stream {
    fn on_done(&mut self) -> bool {
        if let Some(tx) = &mut self.tx {
            if let Err(error) = tx.finish() {
                hostcalls::log(LogLevel::Error, &format!("waf-rust finish: {error}")).ok();
            }
        }
        true
    }
}

impl HttpContext for Stream {
    fn on_http_request_headers(&mut self, _num_headers: usize, end_of_stream: bool) -> Action {
        let Some(waf) = &self.waf else {
            return Self::refuse(503);
        };
        let mut tx = waf.new_transaction();
        let Ok(Some(path)) = self.get_http_request_header(":path") else {
            return Self::refuse(500);
        };
        let Ok(Some(method)) = self.get_http_request_header(":method") else {
            return Self::refuse(500);
        };
        if let Ok(Some(protocol)) = hostcalls::get_property(vec!["request", "protocol"]) {
            self.protocol = String::from_utf8_lossy(&protocol).into_owned();
        }
        tx.process_uri(path.as_bytes(), &method, &self.protocol);
        let Ok(headers) = self.get_http_request_headers() else {
            return Self::refuse(500);
        };
        for (name, value) in headers {
            tx.add_request_header(&name, value.as_bytes());
        }
        if let Ok(Some(authority)) = self.get_http_request_header(":authority") {
            tx.add_request_header("Host", authority.as_bytes());
            tx.set_server_name(authority.as_bytes());
        }
        let verdict = tx.process_request_headers();
        self.tx = Some(tx);
        let action = Self::verdict(verdict);
        if action == Action::Pause {
            return action;
        }
        if end_of_stream {
            self.request_body(0)
        } else {
            action
        }
    }

    fn on_http_request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        if body_size > 16 * 1024 * 1024 {
            return Self::refuse(413);
        }
        if !end_of_stream {
            return Action::Pause;
        }
        self.request_body(body_size)
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, end_of_stream: bool) -> Action {
        if !self.request_done {
            let action = self.request_body(0);
            if action == Action::Pause {
                return action;
            }
        }
        let Ok(headers) = self.get_http_response_headers() else {
            return Self::refuse(500);
        };
        let status = self
            .get_http_response_header(":status")
            .ok()
            .flatten()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(200);
        let Some(tx) = self.tx.as_mut() else {
            return Self::refuse(500);
        };
        for (name, value) in headers {
            tx.add_response_header(&name, value.as_bytes());
        }
        let action = Self::verdict(tx.process_response_headers(status, &self.protocol));
        if action == Action::Pause {
            return action;
        }
        if end_of_stream {
            self.response_body(0)
        } else {
            action
        }
    }

    fn on_http_response_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        if body_size > 1024 * 1024 {
            return Self::refuse(502);
        }
        if !end_of_stream {
            return Action::Pause;
        }
        self.response_body(body_size)
    }
}
