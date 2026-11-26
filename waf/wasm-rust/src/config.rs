use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use coraza::{rule_data::Memory, seclang::Parser, Waf};
use include_dir::{include_dir, Dir, DirEntry};
use regex::Regex;
use serde_json::Value;

static RULES: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../wasm/wasmplugin/rules");

fn files(dir: &Dir<'_>, out: &mut Vec<(String, Vec<u8>)>) {
    for entry in dir.entries() {
        match entry {
            DirEntry::Dir(child) => files(child, out),
            DirEntry::File(file) => {
                let path = file.path().to_string_lossy().replace('\\', "/");
                let name = match path.as_str() {
                    "coraza-demo.conf" => "@demo-conf".to_owned(),
                    "crs-setup.conf.example" => "@crs-setup-conf".to_owned(),
                    _ if path.starts_with("crs/") => format!("@owasp_crs/{}", &path[4..]),
                    _ => path,
                };
                out.push((name, file.contents().to_vec()));
            }
        }
    }
}

fn rule_files() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    files(&RULES, &mut out);
    out
}

fn detection(name: &str) -> bool {
    (name.starts_with("REQUEST-9") || name.starts_with("RESPONSE-9")) && !required(name)
}

fn required(name: &str) -> bool {
    [
        "REQUEST-901-",
        "REQUEST-905-",
        "REQUEST-949-",
        "REQUEST-999-",
        "RESPONSE-959-",
        "RESPONSE-980-",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

fn object<'a>(
    value: &'a Value,
    key: &str,
) -> Result<Option<&'a serde_json::Map<String, Value>>, String> {
    match value.get(key) {
        None => Ok(None),
        Some(Value::Object(items)) => Ok(Some(items)),
        Some(_) => Err(format!("{key} must be an object")),
    }
}

pub fn directives(config: &Value) -> Result<String, String> {
    let mode = config
        .get("engineMode")
        .and_then(Value::as_str)
        .unwrap_or("On");
    if !["On", "Off", "DetectionOnly"].contains(&mode) {
        return Err(format!("invalid engine mode {mode}"));
    }
    let level = config
        .get("paranoiaLevel")
        .and_then(Value::as_i64)
        .unwrap_or(1);
    if !(1..=4).contains(&level) {
        return Err(format!("invalid paranoia level {level}"));
    }
    let mut lines = Vec::new();
    if config
        .get("useCRS")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        let categories = object(config, "categories")?;
        let rules = rule_files();
        let available: BTreeMap<String, &[u8]> = rules
            .iter()
            .filter_map(|(path, bytes)| {
                let name = path.strip_prefix("@owasp_crs/")?;
                (name.ends_with(".conf") && (detection(name) || required(name)))
                    .then_some((name.to_owned(), bytes.as_slice()))
            })
            .collect();
        if let Some(categories) = categories {
            for (name, enabled) in categories {
                let file = format!("{name}.conf");
                if !detection(&file) || !available.contains_key(&file) || !enabled.is_boolean() {
                    return Err(format!("invalid CRS category {name}"));
                }
            }
        }
        let active = |name: &str| {
            categories
                .and_then(|items| items.get(name.trim_end_matches(".conf")))
                .and_then(Value::as_bool)
                .unwrap_or(true)
        };
        let id_pattern = Regex::new(r"(?i)\bid\s*:\s*(\d+)").map_err(|error| error.to_string())?;
        let mut known_ids = BTreeSet::new();
        let mut active_ids = BTreeSet::new();
        for (name, bytes) in &available {
            if !detection(name) {
                continue;
            }
            for line in String::from_utf8_lossy(bytes).lines() {
                if line.trim_start().starts_with('#') {
                    continue;
                }
                if let Some(id) = id_pattern.captures(line).and_then(|match_| match_.get(1)) {
                    known_ids.insert(id.as_str().to_owned());
                    if active(name) {
                        active_ids.insert(id.as_str().to_owned());
                    }
                }
            }
        }
        lines.extend([
            "Include @demo-conf".to_owned(),
            "Include @crs-setup-conf".to_owned(),
        ]);
        lines.push(format!(
            "SecAction \"id:900000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level={level}\""
        ));
        lines.push(format!(
            "SecAction \"id:900001,phase:1,pass,nolog,setvar:tx.detection_paranoia_level={level}\""
        ));
        for (name, bytes) in &available {
            if name.starts_with("REQUEST-999-") {
                for line in String::from_utf8_lossy(bytes).lines() {
                    let parts: Vec<_> = line.split_whitespace().collect();
                    if parts.len() >= 3
                        && parts[0] == "SecRuleUpdateTargetById"
                        && active_ids.contains(parts[1])
                    {
                        lines.push(line.to_owned());
                    }
                }
            } else if required(name) || active(name) {
                lines.push(format!("Include @owasp_crs/{name}"));
            }
        }
        if let Some(states) = object(config, "ruleStates")? {
            for (id, enabled) in states {
                if !enabled.is_boolean() {
                    return Err(format!("invalid CRS rule state {id}"));
                }
                if enabled == false {
                    if id.parse::<u32>().is_err() || !known_ids.contains(id) {
                        return Err(format!("invalid CRS rule ID {id}"));
                    }
                    if active_ids.contains(id) {
                        lines.push(format!("SecRuleRemoveById {id}"));
                    }
                }
            }
        }
    }
    if config
        .get("requestBodyAccess")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        lines.push("SecRequestBodyAccess On".to_owned());
    }
    if let Some(custom) = config.get("customRules") {
        let items = custom.as_array().ok_or("customRules must be an array")?;
        for item in items {
            let rule = item
                .get("rule")
                .and_then(Value::as_str)
                .ok_or("customRules must contain rules")?;
            if item
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                lines.push(rule.to_owned());
            }
        }
    }
    lines.push(format!("SecRuleEngine {mode}"));
    Ok(lines.join("\n"))
}

pub fn compile(bytes: &[u8]) -> Result<Waf, String> {
    let config: Value = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if !config.is_object() {
        return Err("configuration must be an object".to_owned());
    }
    let text = directives(&config)?;
    let mut parser = Parser::new().with_rule_data(Arc::new(Memory::new(rule_files())));
    parser
        .from_string(&text)
        .map_err(|error| error.to_string())?;
    if let Some(skipped) = parser.skipped().first() {
        return Err(format!("skipped rule: {skipped}"));
    }
    parser.compile().map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_controls() {
        let config = serde_json::json!({"useCRS":true,"categories":{"REQUEST-941-APPLICATION-ATTACK-XSS":false},"ruleStates":{"942100":false},"customRules":[{"enabled":true,"rule":"SecRule REQUEST_URI \"@streq /probe\" \"id:1000000,phase:1,deny,status:403\""}]});
        let text = directives(&config).unwrap();
        assert!(!text.contains("Include @owasp_crs/REQUEST-941-APPLICATION-ATTACK-XSS.conf"));
        assert!(text.contains("SecRuleRemoveById 942100"));
        assert!(text.contains("id:1000000"));
        assert!(
            directives(&serde_json::json!({"useCRS":true,"ruleStates":{"999999":false}})).is_err()
        );
    }

    #[test]
    fn full_crs_compiles() {
        let full = compile(br#"{"useCRS":true,"engineMode":"On","paranoiaLevel":1}"#).unwrap();
        let reduced = compile(br#"{"useCRS":true,"categories":{"REQUEST-941-APPLICATION-ATTACK-XSS":false},"ruleStates":{"942100":false}}"#).unwrap();
        assert!(reduced.rule_count() < full.rule_count());
    }

    #[test]
    fn body_switch_without_crs() {
        let off = compile(br#"{"requestBodyAccess":false}"#).unwrap();
        let on = compile(br#"{"requestBodyAccess":true}"#).unwrap();
        assert!(!off.config().request_body_access);
        assert!(on.config().request_body_access);
    }
}
