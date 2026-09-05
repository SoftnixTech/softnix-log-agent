//! The event pipeline: parse → transform → normalize → enrich → route.
//!
//! One file per stage, following the section banners the original file already
//! used. `route` itself lives in engine.rs, which owns the destination fan-out.

mod condition;
mod enrich;
mod parser;
mod syslog;
mod transform;

pub use condition::{eval_condition, CompiledCondition};
pub use enrich::Enricher;
pub use parser::Parser;
pub use syslog::parse_syslog_into;
pub use transform::Transformer;
