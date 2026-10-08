//! `OpenRouter` price snapshots for the run budget.
//!
//! Keel books the worst-case cost of every model request before sending it, so
//! a run needs a price for its model. `OpenRouter` publishes per-provider
//! prices; the snapshot takes the highest input-side and output-side price
//! across every provider endpoint and long-context override, rounded up to
//! whole micro-USD per token. Trusted admission shows it to the operator.

use super::CliError;
use serde_json::Value;
use std::process::Command;

const API: &str = "https://openrouter.ai/api/v1";
/// Prices charged per input-side token: prompt and cache traffic.
const INPUT_FIELDS: &[&str] = &[
    "prompt",
    "input_cache_read",
    "input_cache_write",
    "input_cache_write_1h",
    "audio",
    "input_audio_cache",
];
/// Prices charged per output-side token.
const OUTPUT_FIELDS: &[&str] = &["completion", "internal_reasoning"];

/// The conservative `(input, output)` price of `model` in micro-USD per token.
///
/// # Errors
///
/// Returns an error when the price list cannot be fetched, the model is
/// unknown, or a price cannot be bounded per token.
pub fn price_snapshot(model: &str) -> Result<(u64, u64), CliError> {
    let endpoints = fetch(&format!("{API}/models/{model}/endpoints"))?;
    let listing = fetch(&format!("{API}/models"))?;
    let mut pricings = endpoints
        .pointer("/data/endpoints")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|endpoint| endpoint.get("pricing").cloned())
        .collect::<Vec<_>>();
    if pricings.is_empty() {
        return Err(CliError::new(format!(
            "OpenRouter lists no provider endpoint for `{model}`"
        )));
    }
    if let Some(listed) = listing
        .get("data")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|entry| entry.get("id").and_then(Value::as_str) == Some(model))
        .and_then(|entry| entry.get("pricing"))
    {
        pricings.push(listed.clone());
    }
    snapshot(&pricings).map_err(|error| CliError::new(format!("`{model}`: {error}")))
}

fn fetch(url: &str) -> Result<Value, CliError> {
    let output = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "20",
            url,
        ])
        .output()
        .map_err(|error| CliError::new(format!("cannot run curl: {error}")))?;
    if !output.status.success() {
        return Err(CliError::new(format!(
            "cannot fetch OpenRouter prices from {url}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| CliError::new(format!("OpenRouter price list is not JSON: {error}")))
}

/// The highest input-side and output-side price across `pricings` and their
/// long-context overrides.
fn snapshot(pricings: &[Value]) -> Result<(u64, u64), String> {
    let mut tiers = Vec::new();
    for pricing in pricings {
        tiers.push(pricing);
        tiers.extend(
            pricing
                .get("overrides")
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        );
    }
    let (mut input, mut output) = (0, 0);
    for tier in tiers {
        if price(tier, "request")? > 0 {
            return Err("a per-request fee cannot be bounded per token".to_owned());
        }
        for field in INPUT_FIELDS {
            input = input.max(price(tier, field)?);
        }
        for field in OUTPUT_FIELDS {
            output = output.max(price(tier, field)?);
        }
    }
    Ok((input, output))
}

/// One price field as micro-USD per token, rounded up; absent is zero.
fn price(pricing: &Value, field: &str) -> Result<u64, String> {
    let Some(value) = pricing.get(field) else {
        return Ok(0);
    };
    let text = value
        .as_str()
        .ok_or_else(|| format!("price `{field}` is not a decimal string"))?;
    micro_usd_ceiling(text).ok_or_else(|| format!("price `{field}` = `{text}` is not usable"))
}

/// Converts a non-negative decimal USD amount to micro-USD, rounding up.
fn micro_usd_ceiling(text: &str) -> Option<u64> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty() && fraction.is_empty()
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let whole = if whole.is_empty() {
        0
    } else {
        whole.parse::<u64>().ok()?
    };
    let (micro, rest) = fraction.split_at(fraction.len().min(6));
    let micro = format!("{micro:0<6}").parse::<u64>().ok()?;
    let round_up = u64::from(rest.bytes().any(|byte| byte != b'0'));
    whole.checked_mul(1_000_000)?.checked_add(micro + round_up)
}

#[cfg(test)]
mod tests {
    use super::{micro_usd_ceiling, snapshot};

    #[test]
    fn prices_round_up_to_whole_micro_usd() {
        assert_eq!(micro_usd_ceiling("0.000003"), Some(3));
        assert_eq!(micro_usd_ceiling("0.0000033"), Some(4));
        assert_eq!(micro_usd_ceiling("0"), Some(0));
        assert_eq!(micro_usd_ceiling("1.5"), Some(1_500_000));
        assert_eq!(micro_usd_ceiling("-1"), None);
        assert_eq!(micro_usd_ceiling("1e-6"), None);
    }

    #[test]
    fn the_snapshot_takes_the_worst_provider_and_tier() {
        let pricings = [
            serde_json::json!({"prompt": "0.000003", "completion": "0.000015",
                "input_cache_write_1h": "0.000006"}),
            serde_json::json!({"prompt": "0.0000033", "completion": "0.0000165",
                "overrides": [{"min_prompt_tokens": 200_000, "prompt": "0.000006",
                    "completion": "0.0000225"}]}),
        ];
        assert_eq!(snapshot(&pricings), Ok((6, 23)));
        let per_request = [serde_json::json!({"prompt": "0.000001", "request": "0.01"})];
        assert!(snapshot(&per_request).is_err());
    }
}

#[cfg(test)]
mod live_tests {
    #[test]
    #[ignore = "fetches the live OpenRouter price list"]
    fn live_snapshots_price_known_models() {
        for model in ["anthropic/claude-sonnet-4.6", "openai/gpt-5"] {
            let (input, output) = super::price_snapshot(model).expect(model);
            assert!(input > 0 && output > input, "{model}: {input} {output}");
            println!("{model}: input {input} output {output}");
        }
        assert!(super::price_snapshot("keel/no-such-model").is_err());
    }
}
