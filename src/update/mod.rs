//! Self-update: signed-manifest verification, staging, platform-specific
//! atomic swap, and rollback. See
//! `docs/superpowers/specs/2026-09-09-self-update-mechanism.md` for the
//! full design and the constraints every function here must uphold.

pub mod manifest;
pub mod watermark;
pub mod verify;
