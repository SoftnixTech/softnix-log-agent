use crate::config::Condition;
use crate::event::{value_to_string, Event};
use anyhow::{Context, Result};
use regex::Regex;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Conditions
// ---------------------------------------------------------------------------

/// A `Condition` with its regex compiled once, instead of on every
/// evaluation (which is what made `matches` the one hot-path regex in this
/// file that wasn't pre-compiled — at even moderate event rates with a
/// `when: {op: matches}` condition, this alone falsified the "<1% CPU" claim).
pub struct CompiledCondition {
    field: String,
    op: String,
    value: Option<serde_json::Value>,
    /// `value` run through `value_to_string` once, at compile time, instead of
    /// on every evaluation. Lets the string operators compare `&str` to `&str`
    /// without allocating either side per event. `None` when there is no
    /// value, or when the value is a `Value::Null` (which `value_to_string`
    /// also declines) — both cases the operators below handle explicitly.
    value_str: Option<String>,
    regex: Option<Regex>,
}

impl CompiledCondition {
    pub fn compile(c: &Condition) -> Result<Self> {
        let regex = if c.op == "matches" {
            match &c.value {
                Some(Value::String(pat)) => Some(
                    Regex::new(pat)
                        .with_context(|| format!("invalid regex in condition on {}", c.field))?,
                ),
                _ => None,
            }
        } else {
            None
        };
        Ok(CompiledCondition {
            field: c.field.clone(),
            op: c.op.clone(),
            value_str: c.value.as_ref().and_then(value_to_string),
            value: c.value.clone(),
            regex,
        })
    }
}

/// Evaluate a compiled condition.
///
/// Split into a borrowing fast path and the original owned-`Value` path. The
/// old implementation started with `ev.get_field(&cond.field)`, which clones
/// the whole event body for `message`/`raw_message`, and then
/// `value_to_string` cloned it again — twice per output per event for the two
/// most natural fields to filter on. `Event::get_str` borrows instead.
///
/// The fallback is what makes this a pure refactor: the fast path runs only
/// when `get_str` answers, i.e. only for string-valued fields, and every
/// other field (numeric core fields, `timestamp`, `collector_version`,
/// non-string `fields` entries, absent fields) goes through `eval_value_op`,
/// which is the previous code verbatim.
pub fn eval_condition(cond: &CompiledCondition, ev: &Event) -> bool {
    match cond.op.as_str() {
        "exists" => field_present(cond, ev),
        "not_exists" => !field_present(cond, ev),
        "eq" | "ne" | "contains" | "matches" => match eval_str_op(cond, ev) {
            Some(hit) => hit,
            None => eval_value_op(cond, ev),
        },
        "gt" | "lt" => {
            // Numeric comparison keeps the owned path: it needs the field's
            // `Value` to distinguish a number from a numeric string, and the
            // clone is of a `Number`, not of a body.
            let field_val = ev.get_field(&cond.field);
            let (Some(a), Some(b)) = (&field_val, &cond.value) else {
                return false;
            };
            let (Some(a), Some(b)) = (value_to_f64(a), value_to_f64(b)) else {
                return false;
            };
            if cond.op == "gt" {
                a > b
            } else {
                a < b
            }
        }
        _ => false,
    }
}

/// Presence check without the clone.
///
/// `Event::get_str` returning `Some` implies `get_field` would too (it covers
/// a subset of the same names, and the only `fields` entries it answers for
/// are present ones), so this is exactly `get_field(..).is_some()` with the
/// copy skipped whenever the field is a string.
fn field_present(cond: &CompiledCondition, ev: &Event) -> bool {
    ev.get_str(&cond.field).is_some() || ev.get_field(&cond.field).is_some()
}

/// Allocation-free path for the string operators. `Some(result)` when the
/// field is one `get_str` can borrow; `None` when the caller must fall back
/// to `eval_value_op`.
///
/// Each arm reproduces the corresponding arm of the old implementation for the
/// case where the field resolved to a `Value::String`:
/// - `contains`/`eq`: the old code needed `value_to_string` to succeed on both
///   sides, so a non-stringifiable literal (`null`, or no literal at all)
///   answered `false`.
/// - `ne`: the old code answered `!values_eq(..)`, which is `true` when the
///   literal is present but does not stringify, and `false` when there is no
///   literal at all (that fell through to the catch-all `_ => false`).
/// - `matches`: `regex` is only ever `Some` for `op == "matches"` with a
///   string literal, and the old code answered `false` otherwise.
fn eval_str_op(cond: &CompiledCondition, ev: &Event) -> Option<bool> {
    let a = ev.get_str(&cond.field)?;
    match cond.op.as_str() {
        "contains" => Some(match &cond.value_str {
            Some(b) => a.contains(b.as_str()),
            None => false,
        }),
        "eq" => Some(match &cond.value_str {
            Some(b) => a == b.as_str(),
            None => false,
        }),
        "ne" => Some(match (&cond.value, &cond.value_str) {
            (Some(_), Some(b)) => a != b.as_str(),
            (Some(_), None) => true,
            (None, _) => false,
        }),
        "matches" => Some(match &cond.regex {
            Some(re) => re.is_match(a),
            None => false,
        }),
        _ => None,
    }
}

/// The original owned-`Value` comparison, unchanged. Used for every field
/// `get_str` cannot borrow as a string.
fn eval_value_op(cond: &CompiledCondition, ev: &Event) -> bool {
    let field_val = ev.get_field(&cond.field);
    match cond.op.as_str() {
        "eq" => match (&field_val, &cond.value) {
            (Some(a), Some(b)) => values_eq(a, b),
            _ => false,
        },
        "ne" => match (&field_val, &cond.value) {
            (Some(a), Some(b)) => !values_eq(a, b),
            (None, Some(_)) => true,
            _ => false,
        },
        "contains" => match (&field_val, &cond.value) {
            (Some(a), Some(b)) => {
                let (Some(a), Some(b)) = (value_to_string(a), value_to_string(b)) else {
                    return false;
                };
                a.contains(&b)
            }
            _ => false,
        },
        "matches" => match (&field_val, &cond.regex) {
            (Some(a), Some(re)) => match value_to_string(a) {
                Some(a) => re.is_match(&a),
                None => false,
            },
            _ => false,
        },
        _ => false,
    }
}

fn values_eq(a: &Value, b: &Value) -> bool {
    if a == b {
        return true;
    }
    match (value_to_string(a), value_to_string(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

fn value_to_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_condition_matches_like_the_interpreted_one() {
        let cond = Condition {
            field: "message".to_string(),
            op: "matches".to_string(),
            value: Some(serde_json::Value::String(r"error \d+".to_string())),
        };
        let compiled = CompiledCondition::compile(&cond).unwrap();
        let mut hit = Event::new("s", "test", "error 42 occurred");
        hit.message = "error 42 occurred".to_string();
        let mut miss = Event::new("s", "test", "all good");
        miss.message = "all good".to_string();
        assert!(eval_condition(&compiled, &hit));
        assert!(!eval_condition(&compiled, &miss));
    }

    #[test]
    fn an_invalid_regex_is_rejected_at_compile_time_not_per_event() {
        let cond = Condition {
            field: "message".to_string(),
            op: "matches".to_string(),
            value: Some(serde_json::Value::String("(unclosed".to_string())),
        };
        assert!(CompiledCondition::compile(&cond).is_err());
    }

    fn compile(field: &str, op: &str, value: Option<Value>) -> CompiledCondition {
        CompiledCondition::compile(&Condition {
            field: field.to_string(),
            op: op.to_string(),
            value,
        })
        .unwrap()
    }

    fn s(v: &str) -> Option<Value> {
        Some(Value::String(v.to_string()))
    }

    /// R-5: the condition's own literal is stringified once at compile time
    /// instead of by `value_to_string` on every evaluation.
    #[test]
    fn the_condition_literal_is_stringified_once_at_compile_time() {
        assert_eq!(
            compile("message", "contains", s("ERROR"))
                .value_str
                .as_deref(),
            Some("ERROR")
        );
        assert_eq!(
            compile("severity", "eq", Some(serde_json::json!(3)))
                .value_str
                .as_deref(),
            Some("3"),
            "numeric literals must stringify exactly as value_to_string did"
        );
        assert_eq!(
            compile("flag", "eq", Some(Value::Bool(true)))
                .value_str
                .as_deref(),
            Some("true")
        );
        assert_eq!(compile("message", "exists", None).value_str, None);
        assert_eq!(
            compile("message", "eq", Some(Value::Null)).value_str,
            None,
            "null does not stringify, matching value_to_string"
        );
    }

    /// R-5 equivalence table, populated event. Every expectation here is the
    /// answer the pre-fix `get_field` + `value_to_string` implementation gave,
    /// so the borrowing fast path must reproduce all of it: string fields,
    /// numeric fields, `fields`-map lookups (string and non-string), formatted
    /// core fields, and a missing field, across every operator.
    #[test]
    fn eval_condition_is_unchanged_on_a_populated_event() {
        let mut ev = Event::new("src-1", "test", "database ERROR code 42");
        ev.hostname = Some("host-a".to_string());
        ev.application = Some("app".to_string());
        ev.process_id = Some("123".to_string());
        ev.severity = Some(3);
        ev.raw_message = Some("<11>database ERROR code 42".to_string());
        ev.fields
            .insert("env".to_string(), Value::String("prod".to_string()));
        ev.fields
            .insert("retries".to_string(), Value::Number(7.into()));

        let cases: Vec<(&str, &str, Option<Value>, bool)> = vec![
            // --- borrowed string core field ---
            ("message", "contains", s("ERROR"), true),
            ("message", "contains", s("WARN"), false),
            ("message", "eq", s("database ERROR code 42"), true),
            ("message", "eq", s("other"), false),
            ("message", "ne", s("database ERROR code 42"), false),
            ("message", "ne", s("other"), true),
            ("message", "matches", s(r"code \d+"), true),
            ("message", "matches", s(r"^code"), false),
            ("message", "exists", None, true),
            ("message", "not_exists", None, false),
            // gt/lt keep the owned numeric path; a non-numeric body is false
            ("message", "gt", Some(serde_json::json!(5)), false),
            ("message", "lt", Some(serde_json::json!(5)), false),
            // a null / absent literal must answer exactly as before
            ("message", "eq", Some(Value::Null), false),
            ("message", "ne", Some(Value::Null), true),
            ("message", "eq", None, false),
            ("message", "ne", None, false),
            ("message", "contains", Some(Value::Null), false),
            ("message", "matches", None, false),
            ("message", "frobnicate", s("x"), false),
            // --- other borrowed core fields ---
            ("raw_message", "contains", s("<11>"), true),
            ("hostname", "eq", s("host-a"), true),
            ("hostname", "contains", s("host"), true),
            ("hostname", "not_exists", None, false),
            ("application", "eq", s("app"), true),
            ("source", "eq", s("src-1"), true),
            ("source_type", "eq", s("test"), true),
            // cross-type eq stringifies both sides, before and after
            ("process_id", "eq", s("123"), true),
            ("process_id", "eq", Some(serde_json::json!(123)), true),
            // --- numeric core field: owned fallback ---
            ("severity", "eq", Some(serde_json::json!(3)), true),
            ("severity", "eq", s("3"), true),
            ("severity", "eq", Some(serde_json::json!(4)), false),
            ("severity", "ne", Some(serde_json::json!(4)), true),
            ("severity", "contains", s("3"), true),
            ("severity", "exists", None, true),
            ("severity", "not_exists", None, false),
            ("severity", "gt", Some(serde_json::json!(2)), true),
            ("severity", "lt", Some(serde_json::json!(2)), false),
            // --- formatted core field: owned fallback ---
            ("timestamp", "contains", s("T"), true),
            ("timestamp", "exists", None, true),
            ("collector_version", "exists", None, true),
            // --- fields map, string entry: borrowed ---
            ("env", "eq", s("prod"), true),
            ("env", "ne", s("dev"), true),
            ("env", "contains", s("pro"), true),
            ("env", "matches", s("^pr"), true),
            ("env", "exists", None, true),
            ("env", "not_exists", None, false),
            // --- fields map, non-string entry: owned fallback ---
            ("retries", "eq", Some(serde_json::json!(7)), true),
            ("retries", "eq", s("7"), true),
            ("retries", "contains", s("7"), true),
            ("retries", "exists", None, true),
            ("retries", "gt", Some(serde_json::json!(6)), true),
            // --- missing field ---
            ("nope", "exists", None, false),
            ("nope", "not_exists", None, true),
            ("nope", "eq", s("x"), false),
            ("nope", "ne", s("x"), true),
            ("nope", "contains", s("x"), false),
            ("nope", "matches", s("x"), false),
            ("nope", "gt", Some(serde_json::json!(1)), false),
        ];

        for (field, op, value, expected) in cases {
            let compiled = compile(field, op, value.clone());
            assert_eq!(
                eval_condition(&compiled, &ev),
                expected,
                "field={field} op={op} value={value:?}"
            );
        }
    }

    /// R-5 equivalence table, event with every optional field absent.
    #[test]
    fn eval_condition_is_unchanged_when_optional_fields_are_absent() {
        let ev = Event::new("s", "t", "body");

        let cases: Vec<(&str, &str, Option<Value>, bool)> = vec![
            ("hostname", "exists", None, false),
            ("hostname", "not_exists", None, true),
            ("hostname", "eq", s("x"), false),
            ("hostname", "ne", s("x"), true),
            ("hostname", "contains", s("x"), false),
            ("hostname", "matches", s("x"), false),
            ("raw_message", "exists", None, false),
            ("raw_message", "contains", s("x"), false),
            ("application", "not_exists", None, true),
            ("process_id", "eq", s("1"), false),
            ("severity", "exists", None, false),
            ("severity", "gt", Some(serde_json::json!(1)), false),
            ("severity", "ne", Some(serde_json::json!(1)), true),
            ("message", "eq", s("body"), true),
            ("source", "eq", s("s"), true),
        ];

        for (field, op, value, expected) in cases {
            let compiled = compile(field, op, value.clone());
            assert_eq!(
                eval_condition(&compiled, &ev),
                expected,
                "field={field} op={op} value={value:?}"
            );
        }
    }

    /// R-5 regression: a `fields` entry shadowing one of the five names
    /// `get_field` reserves for core fields (severity/facility/timestamp/
    /// received_at/collector_version) must not change `eval_condition`'s
    /// answer -- see the corresponding test in `src/event.rs` for why this
    /// can happen from ordinary parser input.
    #[test]
    fn eval_condition_ignores_a_fields_entry_that_shadows_a_reserved_core_field_name() {
        let mut ev = Event::new("s", "t", "body");
        ev.fields.insert(
            "severity".to_string(),
            Value::String("not-a-real-severity".to_string()),
        );
        ev.fields
            .insert("facility".to_string(), Value::String("local0".to_string()));

        // ev.severity and ev.facility are both None: get_field must say so,
        // completely ignoring the shadowing fields entries.
        assert!(!eval_condition(&compile("severity", "exists", None), &ev));
        assert!(!eval_condition(&compile("facility", "exists", None), &ev));
        assert!(!eval_condition(
            &compile("severity", "eq", s("not-a-real-severity")),
            &ev
        ));
        assert!(!eval_condition(
            &compile("facility", "eq", s("local0")),
            &ev
        ));
    }
}
