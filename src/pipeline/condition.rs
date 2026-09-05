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
            value: c.value.clone(),
            regex,
        })
    }
}

pub fn eval_condition(cond: &CompiledCondition, ev: &Event) -> bool {
    let field_val = ev.get_field(&cond.field);
    match cond.op.as_str() {
        "exists" => field_val.is_some(),
        "not_exists" => field_val.is_none(),
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
        "gt" | "lt" => {
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
}
