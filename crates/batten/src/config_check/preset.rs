use crate::config_check::verdict::declared_from;

use crate::preset_catalog::MANIFESTS;

use crate::config_model::DeclaredVerdict;

/// Every verdict row the vendored presets declare, as the registry carries them.
///
/// Chained onto the native rows by [`vendored`]. Derived rather
/// than declared a second time: before this, adding a preset class meant editing
/// a table in another module under a comment, and nothing tied the two together.
#[must_use]
pub fn verdict_rows() -> Vec<DeclaredVerdict> {
    MANIFESTS
        .iter()
        .flat_map(|manifest| manifest.verdicts.iter())
        .map(declared_from)
        .collect()
}
