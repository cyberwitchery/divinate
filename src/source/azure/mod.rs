//! azure devops as a source.
//!
//! [`capture`] reads an organisation or one project and returns the
//! transcripts. a project is read with its work items and pull requests.
//! [`facts::derive`] turns transcripts into statements and makes no requests.

mod capture;
pub mod facts;
mod work;

pub use capture::{
    capture, client, token, BRANCH_POLICIES, COMPLETED, EVALUATIONS, ORGANISATION, PROJECT,
    PROJECTS, PULL_REQUESTS, PUSHES, REPOSITORIES, THREADS, WORK_ITEM_LINKS, WORK_ITEM_REVISIONS,
    WORK_ITEM_STATES,
};

use crate::source::build::Host;

pub(crate) static HOST: Host = Host {
    id: "dev.azure.com",
    name: "azure",
};

crate::source::source!(
    /// dev.azure.com as a [`Source`](crate::source::Source).
    Azure,
    "azure:<organisation>, azure:<organisation>/<project>"
);
