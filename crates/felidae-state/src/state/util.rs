use super::*;

/// Helper function to pad block heights for lexicographic ordering.
///
/// Uses 20 digits to accommodate the full u64 range.
pub fn pad_height(height: Height) -> String {
    format!("{:020}", height.value())
}
