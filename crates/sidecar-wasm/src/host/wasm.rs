use sidecar_core::{SidecarError, SidecarFuture};

use super::{BoundHostTransport, MAX_WASM_REQUEST_BYTES, MAX_WASM_RESPONSE_BYTES};

impl<'a> BoundHostTransport<'a> {
    pub(super) fn fetch_json<Request, Response>(
        self,
        method: &'a str,
        path: &'a str,
        request: Option<&'a Request>,
    ) -> SidecarFuture<'a, Response>
    where
        Request: serde::Serialize + 'a,
        Response: serde::de::DeserializeOwned + 'a,
    {
        Box::pin(async move { self.fetch_json_value(method, path, request).await })
    }

    pub(super) async fn fetch_json_value<Request, Response>(
        &self,
        method: &str,
        path: &str,
        request: Option<&Request>,
    ) -> Result<Response, SidecarError>
    where
        Request: serde::Serialize,
        Response: serde::de::DeserializeOwned,
    {
        let body = request
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| transport_error("wasm host request could not be encoded"))?;
        if body
            .as_deref()
            .is_some_and(|body| body.len() > MAX_WASM_REQUEST_BYTES)
        {
            return Err(transport_error(
                "wasm host request exceeds the configured byte limit",
            ));
        }
        let response = self
            .fetch_text(method, path, body.as_deref(), "application/json")
            .await?;
        serde_json::from_str(&response)
            .map_err(|_| transport_error("wasm host response could not be decoded"))
    }

    pub(super) fn fetch_form<Response>(
        self,
        path: &'static str,
        form_fields: &'a [(&'a str, String)],
    ) -> SidecarFuture<'a, Response>
    where
        Response: serde::de::DeserializeOwned + 'a,
    {
        Box::pin(async move {
            let body = form_fields
                .iter()
                .map(|(name, value)| {
                    format!(
                        "{}={}",
                        js_sys::encode_uri_component(name),
                        js_sys::encode_uri_component(value)
                    )
                })
                .collect::<Vec<_>>()
                .join("&");
            if body.len() > MAX_WASM_REQUEST_BYTES {
                return Err(transport_error(
                    "wasm host request exceeds the configured byte limit",
                ));
            }
            let response = self
                .fetch_text(
                    "POST",
                    path,
                    Some(&body),
                    "application/x-www-form-urlencoded",
                )
                .await?;
            serde_json::from_str(&response)
                .map_err(|_| transport_error("wasm host response could not be decoded"))
        })
    }

    async fn fetch_text(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        content_type: &str,
    ) -> Result<String, SidecarError> {
        use wasm_bindgen::{JsCast, JsValue};

        let global = js_sys::global();
        let fetch = &self.transport.fetch;
        let (options, abort_controller) = self.build_request_options(method, body, content_type)?;
        let url = format!("{}{}", self.config.base_url.trim_end_matches('/'), path);
        let promise = fetch
            .call2(&global, &JsValue::from_str(&url), &options)
            .map_err(|_| transport_error("wasm host fetch call failed"))?
            .dyn_into::<js_sys::Promise>()
            .map_err(|_| transport_error("wasm host fetch did not return a promise"))?;
        let response = await_fetch_with_timeout(promise, abort_controller.clone())
            .await
            .map_err(|_| transport_error("wasm host fetch rejected or timed out"))?;
        read_fetch_response(response, abort_controller, path).await
    }
    fn build_request_headers(&self, content_type: &str) -> Result<js_sys::Object, SidecarError> {
        let config = self.config;
        let context = self.context;
        let headers = js_sys::Object::new();
        set_property(&headers, "content-type", content_type)?;
        if !config.api_key.is_empty() {
            set_property(&headers, "x-api-key", &config.api_key)?;
        }
        if let Some(value) = config.tenant_domain.as_deref() {
            set_property(&headers, "x-tenant-domain", value)?;
        }
        if let Some(value) = context.authorization.as_deref() {
            set_property(&headers, "authorization", value)?;
        }
        if let Some(value) = context.client_ip.as_deref() {
            set_property(&headers, "x-forwarded-for", value)?;
        }
        if let Some(value) = context.traceparent.as_deref() {
            set_property(&headers, "traceparent", value)?;
        }
        if let Some(value) = context.tracestate.as_deref() {
            set_property(&headers, "tracestate", value)?;
        }

        Ok(headers)
    }

    fn build_request_options(
        &self,
        method: &str,
        body: Option<&str>,
        content_type: &str,
    ) -> Result<(js_sys::Object, Option<wasm_bindgen::JsValue>), SidecarError> {
        use wasm_bindgen::JsValue;
        let abort_controller = abort_controller();
        let options = js_sys::Object::new();
        set_property(&options, "method", method)?;
        // Cloudflare Workers does not implement the Fetch `error` redirect
        // mode. `manual` preserves the no-follow contract; non-2xx responses
        // (including redirects) are rejected below before their body is
        // consumed.
        set_property(&options, "redirect", "manual")?;
        js_sys::Reflect::set(
            &options,
            &JsValue::from_str("headers"),
            self.build_request_headers(content_type)?.as_ref(),
        )
        .map_err(|_| transport_error("wasm host request headers could not be configured"))?;
        if let Some(body) = body {
            set_property(&options, "body", body)?;
        }
        if let Some(controller) = abort_controller.as_ref()
            && let Ok(signal) = js_sys::Reflect::get(controller, &JsValue::from_str("signal"))
        {
            js_sys::Reflect::set(&options, &JsValue::from_str("signal"), &signal).map_err(
                |_| transport_error("wasm host request timeout could not be configured"),
            )?;
        }

        Ok((options, abort_controller))
    }
}

async fn read_fetch_response(
    response: wasm_bindgen::JsValue,
    abort_controller: Option<wasm_bindgen::JsValue>,
    path: &str,
) -> Result<String, SidecarError> {
    use wasm_bindgen::JsValue;
    let ok = js_sys::Reflect::get(&response, &JsValue::from_str("ok"))
        .ok()
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    if !ok {
        let status = js_sys::Reflect::get(&response, &JsValue::from_str("status"))
            .ok()
            .and_then(|value| value.as_f64())
            .map(|value| value as u16)
            .unwrap_or(0);
        if path == "/runtime/local/sync" && matches!(status, 404 | 405) {
            return Err(SidecarError::bad_gateway(
                "runtime_sync_unavailable",
                "upstream does not expose runtime synchronization",
            ));
        }
        return Err(SidecarError::bad_gateway(
            "wasm_host_transport_failed",
            format!("wasm host returned non-success status {status}"),
        ));
    }
    let body = read_response_body(&response, abort_controller).await?;
    String::from_utf8(body)
        .map_err(|_| transport_error("wasm host response body was not valid UTF-8"))
}

async fn await_fetch_with_timeout(
    promise: js_sys::Promise,
    abort_controller: Option<wasm_bindgen::JsValue>,
) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue> {
    use std::{cell::RefCell, rc::Rc};

    use wasm_bindgen::{JsCast, JsValue, closure::Closure};
    use wasm_bindgen_futures::JsFuture;

    let global = js_sys::global();
    let Some(set_timeout) = js_sys::Reflect::get(&global, &JsValue::from_str("setTimeout"))
        .ok()
        .and_then(|value| value.dyn_into::<js_sys::Function>().ok())
    else {
        return Err(JsValue::from_str("setTimeout is unavailable"));
    };
    let clear_timeout = js_sys::Reflect::get(&global, &JsValue::from_str("clearTimeout"))
        .ok()
        .and_then(|value| value.dyn_into::<js_sys::Function>().ok())
        .ok_or_else(|| JsValue::from_str("clearTimeout is unavailable"))?;
    let timer_id = Rc::new(RefCell::new(None::<JsValue>));
    let timer_callback = Rc::new(RefCell::new(None::<Closure<dyn FnMut()>>));
    let timeout = {
        let timeout_global = global.clone();
        let timer_id = Rc::clone(&timer_id);
        let timer_callback = Rc::clone(&timer_callback);
        js_sys::Promise::new(&mut move |resolve, _reject| {
            let controller = abort_controller.clone();
            let callback_resolve = resolve.clone();
            let callback = Closure::wrap(Box::new(move || {
                if let Some(controller) = controller.as_ref()
                    && let Ok(value) = js_sys::Reflect::get(controller, &JsValue::from_str("abort"))
                    && let Ok(abort) = value.dyn_into::<js_sys::Function>()
                {
                    let _ = abort.call0(controller);
                }
                let _ = callback_resolve.call0(&JsValue::UNDEFINED);
            }) as Box<dyn FnMut()>);
            match set_timeout.call2(
                &timeout_global,
                callback.as_ref().unchecked_ref(),
                &JsValue::from_f64(crate::constants::WASM_REQUEST_TIMEOUT_MILLIS),
            ) {
                Ok(value) => {
                    timer_id.borrow_mut().replace(value);
                    timer_callback.borrow_mut().replace(callback);
                }
                Err(_) => {
                    let _ = resolve.call0(&JsValue::UNDEFINED);
                }
            }
        })
    };
    let promises = js_sys::Array::new();
    promises.push(&promise);
    promises.push(&timeout);
    let result = JsFuture::from(js_sys::Promise::race(promises.as_ref())).await;
    if let Some(timer_id) = timer_id.borrow_mut().take() {
        let _ = clear_timeout.call1(&global, &timer_id);
    }
    timer_callback.borrow_mut().take();
    result
}

fn abort_controller() -> Option<wasm_bindgen::JsValue> {
    use wasm_bindgen::{JsCast, JsValue};

    let global = js_sys::global();
    let constructor = js_sys::Reflect::get(&global, &JsValue::from_str("AbortController"))
        .ok()?
        .dyn_into::<js_sys::Function>()
        .ok()?;
    js_sys::Reflect::construct(&constructor, &js_sys::Array::new()).ok()
}

async fn read_response_body(
    response: &wasm_bindgen::JsValue,
    abort_controller: Option<wasm_bindgen::JsValue>,
) -> Result<Vec<u8>, SidecarError> {
    use wasm_bindgen::{JsCast, JsValue};

    let headers = js_sys::Reflect::get(response, &JsValue::from_str("headers"))
        .map_err(|_| transport_error("wasm host response headers are unavailable"))?;
    let get_header = js_sys::Reflect::get(&headers, &JsValue::from_str("get"))
        .ok()
        .and_then(|value| value.dyn_into::<js_sys::Function>().ok())
        .ok_or_else(|| transport_error("wasm host response headers are unavailable"))?;
    let content_length = get_header
        .call1(&headers, &JsValue::from_str("content-length"))
        .ok()
        .and_then(|value| value.as_string())
        .and_then(|value| value.parse::<usize>().ok());
    if content_length.is_some_and(|length| length > MAX_WASM_RESPONSE_BYTES) {
        return Err(transport_error(
            "wasm host response exceeds the configured byte limit",
        ));
    }

    let body = js_sys::Reflect::get(response, &JsValue::from_str("body"))
        .map_err(|_| transport_error("wasm host response body is unavailable"))?;
    let reader_factory = js_sys::Reflect::get(&body, &JsValue::from_str("getReader"))
        .ok()
        .and_then(|value| value.dyn_into::<js_sys::Function>().ok())
        .ok_or_else(|| transport_error("wasm host response does not provide a body stream"))?;
    let reader = reader_factory
        .call0(&body)
        .map_err(|_| transport_error("wasm host response stream could not be opened"))?;
    let read = js_sys::Reflect::get(&reader, &JsValue::from_str("read"))
        .ok()
        .and_then(|value| value.dyn_into::<js_sys::Function>().ok())
        .ok_or_else(|| transport_error("wasm host response stream is unreadable"))?;

    let mut bytes = Vec::with_capacity(content_length.unwrap_or_default());
    loop {
        let result = read
            .call0(&reader)
            .map_err(|_| transport_error("wasm host response stream read failed"))?
            .dyn_into::<js_sys::Promise>()
            .map_err(|_| transport_error("wasm host response stream read was not async"))?;
        let result = await_fetch_with_timeout(result, abort_controller.clone())
            .await
            .map_err(|_| transport_error("wasm host response stream read rejected"))?;
        if js_sys::Reflect::get(&result, &JsValue::from_str("done"))
            .ok()
            .and_then(|value| value.as_bool())
            .unwrap_or(false)
        {
            break;
        }
        let chunk = js_sys::Reflect::get(&result, &JsValue::from_str("value"))
            .map_err(|_| transport_error("wasm host response stream chunk is unavailable"))?;
        let chunk = js_sys::Uint8Array::new(&chunk);
        let chunk_len = chunk.length() as usize;
        if bytes.len().saturating_add(chunk_len) > MAX_WASM_RESPONSE_BYTES {
            return Err(transport_error(
                "wasm host response exceeds the configured byte limit",
            ));
        }
        let start = bytes.len();
        bytes.resize(start + chunk_len, 0);
        chunk.copy_to(&mut bytes[start..]);
    }
    Ok(bytes)
}

fn set_property(object: &js_sys::Object, name: &str, value: &str) -> Result<(), SidecarError> {
    use wasm_bindgen::JsValue;
    js_sys::Reflect::set(object, &JsValue::from_str(name), &JsValue::from_str(value))
        .map(|_| ())
        .map_err(|_| transport_error("wasm host request could not be configured"))
}

fn transport_error(message: &'static str) -> SidecarError {
    SidecarError::bad_gateway("wasm_host_transport_failed", message)
}
