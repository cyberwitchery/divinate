//! gitlab as a source.
//!
//! [`capture`] reads a group and its subgroups, or one project with its
//! issues and merge requests, with one credential, and returns the
//! transcripts. [`facts::derive`] turns transcripts into statements and makes
//! no requests.

mod capture;
pub mod facts;
mod work;

pub use capture::{
    capture, client, token, APPROVALS, APPROVAL_RULES, APPROVAL_SETTINGS, CLOSED_BY, GROUP, ISSUES,
    MERGED, MERGE_REQUESTS, NOTES, PIPELINES, PROJECT, PROJECTS, PROTECTED_BRANCHES, PUSHES,
    STATE_EVENTS,
};

use crate::source::build::Host;

pub(crate) static HOST: Host = Host {
    id: "gitlab.com",
    name: "gitlab",
};

crate::source::source!(
    /// gitlab.com as a [`Source`](crate::source::Source).
    Gitlab,
    "gitlab:<group>, gitlab:<group>/<project>"
);
