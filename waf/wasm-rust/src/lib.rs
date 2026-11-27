mod config;

use std::rc::Rc;

use coraza::{
    transaction::{Interruption, Transaction},
    types::RuleEngineStatus,
};
use proxy_wasm::{
    hostcalls,
    traits::{Context, HttpContext, RootContext},
    types::{Action, BufferType, ContextType, LogLevel},
};

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(Root { policies: None })
    });
}}

struct Root {
    policies: Option<Rc<config::Policies>>,
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
        match config::compile_policies(&bytes) {
            Ok(policies) => {
                self.policies = Some(Rc::new(policies));
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
            policies: self.policies.clone(),
            tx: None,
            disabled: false,
            request_done: false,
            response_done: false,
            request_memory_limit: 0,
            protocol: "HTTP/2.0".to_owned(),
        }))
    }
}

struct Stream {
    policies: Option<Rc<config::Policies>>,
    tx: Option<Transaction>,
    disabled: bool,
    request_done: bool,
    response_done: bool,
    request_memory_limit: usize,
    protocol: String,
}

impl Stream {
    fn inspects_request_body(&self) -> bool {
        self.tx
            .as_ref()
            .is_some_and(|tx| tx.request_body_access() && tx.rule_engine() != RuleEngineStatus::Off)
    }

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
        if self.inspects_request_body() && size > self.request_memory_limit {
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
        let mut body = match hostcalls::get_buffer(BufferType::HttpResponseBody, 0, size) {
            Ok(Some(body)) => body,
            Ok(None) if size == 0 => Vec::new(),
            _ => return Self::refuse(500),
        };
        if self
            .tx
            .as_mut()
            .and_then(|tx| tx.process_response_body(&body))
            .is_some()
        {
            body.fill(0);
            if let Err(error) = hostcalls::set_buffer(BufferType::HttpResponseBody, 0, size, &body)
            {
                hostcalls::log(
                    LogLevel::Error,
                    &format!("waf-rust redact response: {error:?}"),
                )
                .ok();
                return Self::refuse(502);
            }
        }
        Action::Continue
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
        let Some(policies) = &self.policies else {
            return Self::refuse(503);
        };
        let route = hostcalls::get_property(vec!["route_name"])
            .ok()
            .flatten()
            .map(|name| String::from_utf8_lossy(&name).into_owned());
        let Some(waf) = route
            .as_ref()
            .and_then(|name| policies.routes.get(name))
            .or(policies.default.as_ref())
        else {
            self.disabled = true;
            return Action::Continue;
        };
        let mut tx = waf.new_transaction();
        let configured_memory = waf.config().request_body_in_memory_limit;
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
        self.request_memory_limit = usize::try_from(if configured_memory == 0 {
            tx.request_body_limit()
        } else {
            configured_memory
        })
        .unwrap_or(0);
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
        if self.disabled {
            return Action::Continue;
        }
        if body_size > 16 * 1024 * 1024 {
            return Self::refuse(413);
        }
        if self.inspects_request_body() && body_size > self.request_memory_limit {
            return Self::refuse(413);
        }
        if !end_of_stream {
            return Action::Pause;
        }
        self.request_body(body_size)
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, end_of_stream: bool) -> Action {
        if self.disabled {
            return Action::Continue;
        }
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
        if self.disabled {
            return Action::Continue;
        }
        if body_size > 1024 * 1024 {
            return Self::refuse(502);
        }
        if !end_of_stream {
            return Action::Pause;
        }
        self.response_body(body_size)
    }
}
