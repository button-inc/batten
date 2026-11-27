//! The config model's invariants (CLOUD-2789): every section's validator.
//!
//! A section's rules are facts about the model, not about the feature that
//! later reads the section, so they sit beside [`crate::config_model`] and
//! below the loader. [`crate::config`] parses a file into the model and runs
//! these; a feature that loads the config therefore no longer sits underneath
//! the loader that validates it. Each feature's rules keep their own module
//! here, named for the feature, which re-exports them under their old names.

pub mod action;

pub mod advisory;

pub mod budget;

pub mod forge_query;

pub mod githook;

pub mod handler;

pub mod hookcost;

pub mod markers;

pub mod mcp;

pub mod mint;

pub mod outputs;

pub mod provision;

pub mod receipt;

pub mod record;

pub mod recorder;

pub mod redirect;

pub mod refusal;

pub mod rules;

pub mod startup;

pub mod transcript;

pub mod waiver;
