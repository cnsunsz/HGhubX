//! Edge envelope POST with system-DNS then AliDNS DoH fallback for line probes.
use crate::net::{client_for, client_for_dns, edge_redirect_target, err_text, heal_client, mark_public_dns, prefers_public_dns, proxy_active};
use crate::network_policy;
use serde_json::Value;
use std::time::Instant;

async fn send_edge_json(
    target_url: &url::Url,
    referer: &str,
    payload: &Value,
    token: Option<&str>,
    public_json: bool,
    public_dns: bool,
) -> Result<(url::Url, reqwest::Response), String> {
    let (target, client) = if public_dns { client_for_dns(target_url.as_str(), true).await? } else { client_for(target_url.as_str()).await? };
    let mut req = client.post(target.clone()).header("Accept", "application/json").header("Referer", referer).json(payload);
    if public_json { req = req.header("X-HG-Public-JSON", "1"); }
    if let Some(t) = token.filter(|t| !t.is_empty()) {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    Ok((target, req.send().await.map_err(|e| err_text(&e))?))
}

pub(crate) async fn post_edge_json(
    url: &str,
    referer: &str,
    payload: &Value,
    token: Option<&str>,
    public_json: bool,
    guest_get: bool,
    started: Instant,
) -> Result<crate::edge_crypto::HttpReply, String> {
    let mut next = network_policy::parse_target(url)?;
    for hop in 0..=5 {
        let host = next.host_str().unwrap_or("").to_string();
        let proxy = proxy_active(&next);
        let mut use_public = !proxy && prefers_public_dns(&host);
        for attempt in 0..2 {
            match send_edge_json(&next, referer, payload, token, public_json, use_public).await {
                Ok((target, resp)) => {
                    if use_public { mark_public_dns(&host, true); }
                    let status = resp.status();
                    let headers_ms = started.elapsed().as_millis() as u64;
                    if status.is_redirection() {
                        if hop == 5 { return Err("重定向次数超过限制".into()); }
                        let location = resp.headers().get(reqwest::header::LOCATION).and_then(|h| h.to_str().ok()).ok_or("重定向缺少有效 Location")?;
                        next = edge_redirect_target(&target, status.as_u16(), location, guest_get)?;
                        break;
                    }
                    let ctype = resp.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                    let gateway = if resp.headers().contains_key("x-amz-cf-id") { "cloudfront" } else if resp.headers().contains_key("cf-ray") { "cloudflare" } else { "other" };
                    let has_pub_hdr = resp.headers().get("X-HG-Public-JSON").and_then(|v| v.to_str().ok()) == Some("1");
                    let text = resp.text().await.map_err(|e| err_text(&e))?;
                    return Ok(crate::edge_crypto::HttpReply { status: status.as_u16(), ctype, gateway, public_json: has_pub_hdr, target_host: target.host_str().unwrap_or("").to_string(), headers_ms, text });
                }
                Err(error) => {
                    if use_public { mark_public_dns(&host, false); }
                    heal_client(&error);
                    if attempt == 0 && !proxy && crate::media_dns::eligible(&next, &error) {
                        use_public = !use_public;
                        continue;
                    }
                    return Err(error);
                }
            }
        }
    }
    Err("重定向次数超过限制".into())
}

