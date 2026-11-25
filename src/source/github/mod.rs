//! github as a source.
//!
//! [`capture`] reads an organisation or one repository and returns the
//! transcripts. a repository is read with its tickets and changes.
//! [`facts::derive`] turns transcripts into statements and makes no requests.

mod capture;
pub mod facts;
mod findings;
mod releases;
mod updates;
mod work;

pub use capture::{
    capture, client, token, ACTIVITY, BRANCH_PROTECTION, BRANCH_RULES, CHECK_RUNS, CODE_SCANNING,
    DEPENDABOT, FILES, ORGANISATION, PULL_REQUEST, RELEASES, REPOSITORIES, REPOSITORY,
    SECRET_SCANNING, STATUSES, TIMELINE, WORK_ITEMS,
};

use crate::source::build::Host;

pub(crate) static HOST: Host = Host {
    id: "github.com",
    name: "github",
};

crate::source::source!(
    /// github.com as a [`Source`](crate::source::Source).
    Github,
    "github:<organisation>, github:<organisation>/<repository>"
);
