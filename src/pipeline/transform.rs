use crate::config::{Condition, PipelineConfig, TransformStep};
use crate::event::{value_to_string, Event};
use anyhow::Result;
use regex::Regex;
use serde_json::Value;

use super::condition::{eval_condition, CompiledCondition};

// ---------------------------------------------------------------------------
// Transforms
// ---------------------------------------------------------------------------

/// Pre-compiled transform chain.
pub struct Transformer {
    steps: Vec<CompiledStep>,
}

enum CompiledStep {
    AddField {
        field: String,
        value: Value,
        when: Option<CompiledCondition>,
    },
    RemoveField {
        field: String,
        when: Option<CompiledCondition>,
    },
    RenameField {
        from: String,
        to: String,
        when: Option<CompiledCondition>,
    },
    Convert {
        field: String,
        to: String,
        when: Option<CompiledCondition>,
    },
    Mask {
        field: String,
        re: Regex,
        replacement: String,
        when: Option<CompiledCondition>,
    },
    Drop {
        when: CompiledCondition,
    },
    Keep {
        when: CompiledCondition,
    },
}

/// Compile an optional `when:` condition, propagating an invalid regex as a
/// startup error instead of silently accepting a condition that would never
/// match at runtime.
fn compile_when(when: Option<Condition>) -> Result<Option<CompiledCondition>> {
    when.as_ref().map(CompiledCondition::compile).transpose()
}

impl Transformer {
    pub fn compile(cfg: &PipelineConfig) -> Result<Self> {
        let mut steps = Vec::new();
        for t in &cfg.transforms {
            steps.push(match t.clone() {
                TransformStep::AddField { field, value, when } => CompiledStep::AddField {
                    field,
                    value,
                    when: compile_when(when)?,
                },
                TransformStep::RemoveField { field, when } => CompiledStep::RemoveField {
                    field,
                    when: compile_when(when)?,
                },
                TransformStep::RenameField { from, to, when } => CompiledStep::RenameField {
                    from,
                    to,
                    when: compile_when(when)?,
                },
                TransformStep::Convert { field, to, when } => CompiledStep::Convert {
                    field,
                    to,
                    when: compile_when(when)?,
                },
                TransformStep::Mask {
                    field,
                    pattern,
                    replacement,
                    when,
                } => CompiledStep::Mask {
                    field,
                    re: Regex::new(&pattern)?,
                    replacement,
                    when: compile_when(when)?,
                },
                TransformStep::Drop { when } => CompiledStep::Drop {
                    when: CompiledCondition::compile(&when)?,
                },
                TransformStep::Keep { when } => CompiledStep::Keep {
                    when: CompiledCondition::compile(&when)?,
                },
            });
        }
        Ok(Transformer { steps })
    }

    /// Apply all steps; returns false if the event should be dropped.
    pub fn apply(&self, ev: &mut Event) -> bool {
        for step in &self.steps {
            match step {
                CompiledStep::AddField { field, value, when } => {
                    if when.as_ref().is_none_or(|w| eval_condition(w, ev)) {
                        ev.set_field(field, value.clone());
                    }
                }
                CompiledStep::RemoveField { field, when } => {
                    if when.as_ref().is_none_or(|w| eval_condition(w, ev)) {
                        ev.remove_field(field);
                    }
                }
                CompiledStep::RenameField { from, to, when } => {
                    if when.as_ref().is_none_or(|w| eval_condition(w, ev)) {
                        if let Some(v) = ev.get_field(from) {
                            ev.remove_field(from);
                            ev.set_field(to, v);
                        }
                    }
                }
                CompiledStep::Convert { field, to, when } => {
                    if when.as_ref().is_none_or(|w| eval_condition(w, ev)) {
                        if let Some(v) = ev.get_field(field) {
                            if let Some(converted) = convert_value(&v, to) {
                                ev.set_field(field, converted);
                            }
                        }
                    }
                }
                CompiledStep::Mask {
                    field,
                    re,
                    replacement,
                    when,
                } => {
                    if when.as_ref().is_none_or(|w| eval_condition(w, ev)) {
                        // R-5: the old chain was get_field (clones the body)
                        // -> value_to_string (clones it again) -> replace_all
                        // (a third copy) -> set_field. `get_str` borrows the
                        // body, so a masked string field costs one copy.
                        // Fields `get_str` cannot borrow — numbers, bools,
                        // non-string `fields` entries — keep the original
                        // stringify-then-set path, including its long-standing
                        // coercion of the masked field to a string.
                        let masked: Option<String> = match ev.get_str(field) {
                            Some(s) => Some(re.replace_all(s, replacement.as_str()).into_owned()),
                            None => ev
                                .get_field(field)
                                .as_ref()
                                .and_then(value_to_string)
                                .map(|s| re.replace_all(&s, replacement.as_str()).into_owned()),
                        };
                        if let Some(s) = masked {
                            ev.set_field(field, Value::String(s));
                        }
                        // `raw_message` retains the original unparsed line, so
                        // masking only `message` would leak the secret through
                        // raw_message on outputs that emit every field (e.g.
                        // json). Apply the same masking to raw_message whenever
                        // we mask message, so no sensitive data escapes.
                        if field == "message" {
                            if let Some(raw) = ev.raw_message.take() {
                                let masked = re.replace_all(&raw, replacement.as_str());
                                ev.raw_message = Some(masked.into_owned());
                            }
                        }
                    }
                }
                CompiledStep::Drop { when } => {
                    if eval_condition(when, ev) {
                        return false;
                    }
                }
                CompiledStep::Keep { when } => {
                    if !eval_condition(when, ev) {
                        return false;
                    }
                }
            }
        }
        true
    }
}

fn convert_value(v: &Value, to: &str) -> Option<Value> {
    match to {
        "string" => value_to_string(v).map(Value::String),
        "int" => match v {
            Value::Number(n) => n.as_i64().map(|x| Value::Number(x.into())),
            Value::String(s) => s
                .trim()
                .parse::<i64>()
                .ok()
                .map(|x| Value::Number(x.into())),
            Value::Bool(b) => Some(Value::Number(i64::from(*b).into())),
            _ => None,
        },
        "float" => match v {
            Value::Number(n) => n
                .as_f64()
                .and_then(serde_json::Number::from_f64)
                .map(Value::Number),
            Value::String(s) => s
                .trim()
                .parse::<f64>()
                .ok()
                .and_then(serde_json::Number::from_f64)
                .map(Value::Number),
            _ => None,
        },
        "bool" => match v {
            Value::Bool(b) => Some(Value::Bool(*b)),
            Value::String(s) => match s.to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" => Some(Value::Bool(true)),
                "false" | "0" | "no" => Some(Value::Bool(false)),
                _ => None,
            },
            Value::Number(n) => Some(Value::Bool(n.as_f64() != Some(0.0))),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ParserConfig;
    use crate::pipeline::parser::Parser;

    fn raw_parser() -> Parser {
        Parser::compile(&ParserConfig::default()).unwrap()
    }

    #[test]
    fn transforms_apply() {
        let cfg: PipelineConfig = serde_yaml::from_str(
            r#"
transforms:
  - type: add_field
    field: dc
    value: bkk-1
  - type: rename_field
    from: dc
    to: datacenter
  - type: mask
    field: message
    pattern: "\\b\\d{13,16}\\b"
    replacement: "[CARD]"
  - type: drop
    when: { field: severity, op: gt, value: 6 }
"#,
        )
        .unwrap();
        let t = Transformer::compile(&cfg).unwrap();

        // PIPE-006 needs raw_message populated to exercise the scrub-both-copies
        // path; keep_raw_message defaults to false since R-2, so opt in here.
        let mut ev = Parser::compile(&ParserConfig {
            keep_raw_message: true,
            ..Default::default()
        })
        .unwrap()
        .parse("card 4111111111111111 charged", "f", "file");
        ev.severity = Some(3);
        assert!(t.apply(&mut ev));
        assert_eq!(ev.fields["datacenter"], Value::String("bkk-1".into()));
        assert!(ev.message.contains("[CARD]"));
        assert!(!ev.message.contains("4111111111111111"));
        // PIPE-006 regression: masking `message` must also scrub raw_message so
        // the secret can't leak through outputs that emit every field (json).
        let raw = ev.raw_message.as_deref().unwrap();
        assert!(raw.contains("[CARD]"), "raw_message not masked: {raw}");
        assert!(
            !raw.contains("4111111111111111"),
            "secret leaked in raw_message: {raw}"
        );

        let mut debug_ev = raw_parser().parse("noise", "f", "file");
        debug_ev.severity = Some(7);
        assert!(!t.apply(&mut debug_ev), "debug event should be dropped");
    }

    #[test]
    fn convert_types() {
        assert_eq!(
            convert_value(&Value::String("42".into()), "int"),
            Some(Value::Number(42.into()))
        );
        assert_eq!(
            convert_value(&Value::String("yes".into()), "bool"),
            Some(Value::Bool(true))
        );
    }

    /// R-5: the mask step did get_field (clone) -> value_to_string (clone) ->
    /// replace_all (clone) -> set_field (move): three full copies of the
    /// message per masked event. It now borrows the body for string fields.
    /// Non-string fields must keep working exactly as before, including the
    /// coercion to a string that masking them has always done.
    #[test]
    fn mask_covers_string_and_non_string_fields() {
        let cfg: PipelineConfig = serde_yaml::from_str(
            r#"
transforms:
  - type: mask
    field: message
    pattern: "\\d{4}"
    replacement: "[X]"
  - type: mask
    field: env
    pattern: "prod"
    replacement: "[ENV]"
  - type: mask
    field: retries
    pattern: "7"
    replacement: "9"
  - type: mask
    field: absent
    pattern: "x"
    replacement: "y"
"#,
        )
        .unwrap();
        let t = Transformer::compile(&cfg).unwrap();

        let mut ev = Event::new("s", "test", "code 1234 here");
        ev.fields
            .insert("env".to_string(), Value::String("prod".to_string()));
        ev.fields
            .insert("retries".to_string(), Value::Number(7.into()));
        assert!(t.apply(&mut ev));

        assert_eq!(ev.message, "code [X] here", "core string field");
        assert_eq!(
            ev.fields["env"],
            Value::String("[ENV]".to_string()),
            "fields-map string entry"
        );
        // Unchanged behaviour: a non-string field is stringified, masked and
        // written back as a string.
        assert_eq!(
            ev.fields["retries"],
            Value::String("9".to_string()),
            "non-string fields entry must still be masked via the owned path"
        );
        assert!(
            !ev.fields.contains_key("absent"),
            "masking a missing field must not create it"
        );

        // A pattern that does not match must leave the value byte-identical.
        let mut untouched = Event::new("s", "test", "no digits here");
        assert!(t.apply(&mut untouched));
        assert_eq!(untouched.message, "no digits here");
    }
}
