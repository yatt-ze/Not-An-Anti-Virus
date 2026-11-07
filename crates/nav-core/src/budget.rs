//! Read-back accounting shared by the container readers (§6.2): an
//! archive-wide total and the current entry's equal share of what remains.

/// Work spent reading one archive's entries, charged against the archive
/// total and the current entry's allowance together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShareBudget {
    remaining: usize,
    entry_remaining: usize,
}

impl ShareBudget {
    /// A fresh budget of `total`; until [`ShareBudget::start_share`] the
    /// whole of it is the entry allowance.
    pub(crate) fn new(total: usize) -> Self {
        ShareBudget {
            remaining: total,
            entry_remaining: total,
        }
    }

    /// Bytes still available across the archive.
    pub(crate) fn remaining(&self) -> usize {
        self.remaining
    }

    /// Bytes still available to the current entry.
    pub(crate) fn entry_remaining(&self) -> usize {
        self.entry_remaining
    }

    /// Gives the next entry one of `parts` equal shares of what remains.
    /// Called cheapest entry first, unused allowance carries to later ones.
    pub(crate) fn start_share(&mut self, parts: usize) {
        self.entry_remaining = self.remaining / parts.max(1);
    }

    /// Charges `n` against the total and the current allowance. Saturates at zero.
    pub(crate) fn charge(&mut self, n: usize) {
        self.remaining = self.remaining.saturating_sub(n);
        self.entry_remaining = self.entry_remaining.saturating_sub(n);
    }
}
