//! reading an azure devops organisation or project.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::error::{Error, Result};
use crate::source::reading::{self, diagnostic, failure, percent_encode, Api, Reader};
use crate::source::{Clock, Fetch, Period, Roots};
use crate::transcript::{HttpExchange, Termination, Transcript};

const ORIGIN: &str = "https://dev.azure.com";
static API: Api = Api {
    origin: ORIGIN,
    classify,
    next: next_page,
};
/// the resource azure's own sign-in issues tokens for azure devops under.
const TOKEN_RESOURCE: &str = "499b84ac-1321-427f-aa17-267ca6975798";
/// how many items a list page is asked for.
const PAGE: u64 = 100;
/// how many work items one reading of links asks for; the source allows 200.
const BATCH: usize = 200;

/// the organisation, as the connection it gives this credential.
pub const ORGANISATION: &str = "azure/organisation/v1";
/// every project of the organisation that the credential can see.
pub const PROJECTS: &str = "azure/projects/v1";
/// one project.
pub const PROJECT: &str = "azure/project/v1";
/// every git repository of one project that the credential can see.
pub const REPOSITORIES: &str = "azure/repositories/v1";
/// the policies that apply to one branch of one repository.
pub const BRANCH_POLICIES: &str = "azure/branch-policies/v1";
/// the pull requests of one project opened in a period.
pub const PULL_REQUESTS: &str = "azure/pull-requests/v1";
/// the comment, vote, and status threads of one pull request.
pub const THREADS: &str = "azure/pull-request-threads/v1";
/// the pull requests of one project completed in a period.
pub const COMPLETED: &str = "azure/completed-pull-requests/v1";
/// how each policy judged one pull request.
pub const EVALUATIONS: &str = "azure/policy-evaluations/v1";
/// the pushes to one branch of one repository in a period.
pub const PUSHES: &str = "azure/pushes/v1";
/// every revision of the work items of one project changed since a time.
pub const WORK_ITEM_REVISIONS: &str = "azure/work-item-revisions/v1";
/// the states of one work item type, and the category of each.
pub const WORK_ITEM_STATES: &str = "azure/work-item-states/v1";
/// a batch of work items with the links the source keeps for them.
pub const WORK_ITEM_LINKS: &str = "azure/work-item-links/v1";

/// the work item fields a revision is read with.
const FIELDS: &str = "System.Id,System.Rev,System.WorkItemType,System.State,System.Title,\
                      System.Tags,System.CreatedDate,System.CreatedBy,System.ChangedDate,\
                      System.ChangedBy,System.CommentCount";

/// read an organisation or a project.
///
/// an organisation is read with its projects, their repositories, and the
/// policies on the default branch of each. a project is read with the same,
/// and with the pull requests and work items opened in the period and what
/// happened to each.
///
/// a reading that fails is returned as a transcript that says how it ended,
/// not as an error.
///
/// # Errors
///
/// returns an error when the path is not `<organisation>` or
/// `<organisation>/<project>`, or a transcript cannot be sealed.
pub fn capture(
    path: &str,
    period: &Period,
    clock: &Clock,
    fetch: &mut Fetch,
) -> Result<Vec<Transcript>> {
    let allowed = |name: &str, extra: &[u8]| {
        !name.is_empty()
            && !name.starts_with(['.', ' '])
            && !name.ends_with(['.', ' '])
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || extra.contains(&byte))
    };
    let (organisation, project) = match path.split_once('/') {
        Some((organisation, project)) => (organisation, Some(project)),
        None => (path, None),
    };
    if !allowed(organisation, b"-") || project.is_some_and(|project| !allowed(project, b"-_. ")) {
        return Err(Error::Invalid(format!(
            "{path:?} is not an azure devops organisation or organisation/project"
        )));
    }
    let mut reader = Reader::new(&API, clock, fetch);
    let root = format!("{ORIGIN}/{organisation}");
    let mut transcripts = vec![reader.read(
        ORGANISATION,
        &format!("azure:{organisation}"),
        &[],
        format!("{root}/_apis/connectionData?api-version=7.1-preview.1"),
    )?];
    if let Some(project) = project {
        one_project(&mut reader, organisation, project, period, &mut transcripts)?;
        return Ok(transcripts);
    }
    let listing = reader.read(
        PROJECTS,
        &format!("azure:{organisation}"),
        &[],
        format!("{root}/_apis/projects?%24top={PAGE}&api-version=7.1"),
    )?;
    let projects = super::facts::values(&listing);
    transcripts.push(listing);
    for project in projects {
        if let Some(name) = project["name"].as_str() {
            repositories(&mut reader, organisation, name, &mut transcripts)?;
        }
    }
    Ok(transcripts)
}

/// the repositories of one project, and the policies on the default branch of each.
fn repositories(
    reader: &mut Reader,
    organisation: &str,
    project: &str,
    transcripts: &mut Vec<Transcript>,
) -> Result<Vec<super::facts::Listed>> {
    let subject = format!("azure:{organisation}/{project}");
    let base = format!("{ORIGIN}/{organisation}/{}/_apis", percent_encode(project));
    let listing = reader.read(
        REPOSITORIES,
        &subject,
        &[],
        format!("{base}/git/repositories?api-version=7.1"),
    )?;
    let listed = super::facts::listed(&listing);
    transcripts.push(listing);
    for repository in &listed {
        let Some(branch) = &repository.default_branch else {
            continue;
        };
        transcripts.push(branch_policies(
            reader,
            &base,
            &format!("{subject}/{}", repository.name),
            &repository.id,
            branch,
        )?);
    }
    Ok(listed)
}

/// the pushes to one branch of one repository in the period.
fn pushes(
    reader: &mut Reader,
    base: &str,
    repository: &str,
    repository_id: &str,
    branch: &str,
    period: &Period,
) -> Result<Transcript> {
    reader.read(
        PUSHES,
        repository,
        &[("from", &period.from), ("until", &period.until), ("branch", branch)],
        format!(
            "{base}/git/repositories/{repository_id}/pushes?searchCriteria.refName={}&searchCriteria.fromDate={}&searchCriteria.toDate={}&searchCriteria.includeRefUpdates=true&%24top={PAGE}&%24skip=0&api-version=7.1",
            percent_encode(&format!("refs/heads/{branch}")),
            percent_encode(&period.from),
            percent_encode(&period.until)
        ),
    )
}

/// the policies that apply to one branch of one repository.
fn branch_policies(
    reader: &mut Reader,
    base: &str,
    repository: &str,
    repository_id: &str,
    branch: &str,
) -> Result<Transcript> {
    let reference = percent_encode(&format!("refs/heads/{branch}"));
    reader.read(
        BRANCH_POLICIES,
        repository,
        &[("branch", branch)],
        format!(
            "{base}/git/policy/configurations?repositoryId={repository_id}&refName={reference}&%24top={PAGE}&api-version=7.1"
        ),
    )
}

/// one project: its repositories, and the pull requests and work items
/// opened in the period with what happened to each.
fn one_project(
    reader: &mut Reader,
    organisation: &str,
    project: &str,
    period: &Period,
    transcripts: &mut Vec<Transcript>,
) -> Result<()> {
    let subject = format!("azure:{organisation}/{project}");
    let encoded = percent_encode(project);
    let about = reader.read(
        PROJECT,
        &subject,
        &[],
        format!("{ORIGIN}/{organisation}/_apis/projects/{encoded}?api-version=7.1"),
    )?;
    let project_id = super::facts::project_id(&about);
    transcripts.push(about);
    let Some(project_id) = project_id else {
        return Ok(());
    };
    let repositories = repositories(reader, organisation, project, transcripts)?;
    let base = format!("{ORIGIN}/{organisation}/{encoded}/_apis");
    for repository in &repositories {
        let Some(branch) = &repository.default_branch else {
            continue;
        };
        let about = format!("{subject}/{}", repository.name);
        transcripts.push(pushes(
            reader,
            &base,
            &about,
            &repository.id,
            branch,
            period,
        )?);
    }
    changes(
        reader,
        &base,
        &subject,
        &project_id,
        &repositories,
        period,
        transcripts,
    )?;
    tickets(reader, &base, &subject, period, transcripts)
}

/// the pull requests opened or completed in the period, and what happened to each.
fn changes(
    reader: &mut Reader,
    base: &str,
    subject: &str,
    project_id: &str,
    repositories: &[super::facts::Listed],
    period: &Period,
    transcripts: &mut Vec<Transcript>,
) -> Result<()> {
    let (from, until) = (percent_encode(&period.from), percent_encode(&period.until));
    let parameters = [("from", period.from.as_str()), ("until", &period.until)];
    let search = |status: &str, range: &str| {
        format!(
            "{base}/git/pullrequests?searchCriteria.status={status}&searchCriteria.minTime={from}&searchCriteria.maxTime={until}&searchCriteria.queryTimeRangeType={range}&%24top={PAGE}&%24skip=0&api-version=7.1"
        )
    };
    let opened = reader.read(
        PULL_REQUESTS,
        subject,
        &parameters,
        search("all", "created"),
    )?;
    let completed = reader.read(
        COMPLETED,
        subject,
        &parameters,
        search("completed", "closed"),
    )?;
    let mut pulls = super::work::pull_requests(&opened, "creationDate");
    pulls.extend(super::work::pull_requests(&completed, "closedDate"));
    pulls.sort_by_key(|pull| pull.number);
    pulls.dedup_by_key(|pull| pull.number);
    transcripts.extend([opened, completed]);
    // the policies of every other branch a pull request of the period goes into.
    let mut targets = std::collections::BTreeSet::new();
    for pull in pulls {
        targets.extend(pull.target.clone().map(|target| {
            (
                pull.repository_name.clone(),
                pull.repository_id.clone(),
                target,
            )
        }));
        let number = pull.number.to_string();
        let about = format!("{subject}/{}!{number}", pull.repository_name);
        let artifact = format!("vstfs:///CodeReview/CodeReviewId/{project_id}/{number}");
        for (resource, url) in [
            (
                THREADS,
                format!(
                    "{base}/git/repositories/{}/pullRequests/{number}/threads?api-version=7.1",
                    pull.repository_id
                ),
            ),
            (
                EVALUATIONS,
                format!(
                    "{base}/policy/evaluations?artifactId={}&includeNotApplicable=true&%24top={PAGE}&%24skip=0&api-version=7.1-preview.1",
                    percent_encode(&artifact)
                ),
            ),
        ] {
            transcripts.push(reader.read(resource, &about, &[("number", &number)], url)?);
        }
    }
    for (name, id, target) in targets {
        let default = repositories
            .iter()
            .find(|repository| repository.id == id)
            .and_then(|repository| repository.default_branch.as_ref());
        if default != Some(&target) {
            let repository = format!("{subject}/{name}");
            transcripts.push(branch_policies(reader, base, &repository, &id, &target)?);
            transcripts.push(pushes(reader, base, &repository, &id, &target, period)?);
        }
    }
    Ok(())
}

/// the work items opened in the period, the states of their types, and their links.
fn tickets(
    reader: &mut Reader,
    base: &str,
    subject: &str,
    period: &Period,
    transcripts: &mut Vec<Transcript>,
) -> Result<()> {
    let from = percent_encode(&period.from);
    let parameters = [("from", period.from.as_str()), ("until", &period.until)];
    // the source selects revisions by when they were made. every revision of
    // an item opened in the period was made in it or later.
    let revisions = reader.read(
        WORK_ITEM_REVISIONS,
        subject,
        &parameters,
        format!(
            "{base}/wit/reporting/workitemrevisions?fields={}&startDateTime={from}&includeIdentityRef=true&%24maxPageSize=200&api-version=7.1",
            percent_encode(FIELDS)
        ),
    )?;
    let tickets = super::work::tickets(&revisions);
    transcripts.push(revisions);
    for kind in &tickets.types {
        transcripts.push(reader.read(
            WORK_ITEM_STATES,
            subject,
            &[("type", kind)],
            format!(
                "{base}/wit/workitemtypes/{}/states?api-version=7.1",
                percent_encode(kind)
            ),
        )?);
    }
    for (batch, ids) in tickets.ids.chunks(BATCH).enumerate() {
        let ids = ids.iter().map(u64::to_string).collect::<Vec<_>>().join(",");
        transcripts.push(reader.read(
            WORK_ITEM_LINKS,
            subject,
            &[("batch", &(batch + 1).to_string()), ("ids", &ids)],
            format!("{base}/wit/workitems?ids={ids}&%24expand=relations&api-version=7.1"),
        )?);
    }
    Ok(())
}

/// where the next page is. azure devops has three ways of saying so: a link
/// in the body of a revision batch, a continuation token in a header, and a
/// full page of a list that is read by skipping.
fn next_page(exchange: &HttpExchange) -> Option<String> {
    let url = &exchange.request.url;
    let body = serde_json::from_str::<Value>(&exchange.response.body).ok()?;
    if let Some(last) = body["isLastBatch"].as_bool() {
        return (!last)
            .then(|| body["nextLink"].as_str().map(str::to_owned))
            .flatten();
    }
    if let Some(token) = exchange.response.headers.get("x-ms-continuationtoken") {
        let base = url.split("&continuationToken=").next().unwrap_or(url);
        return Some(format!(
            "{base}&continuationToken={}",
            percent_encode(token)
        ));
    }
    let marker = "%24skip=";
    let start = url.find(marker)? + marker.len();
    let end = url[start..].find('&').map_or(url.len(), |end| start + end);
    let skipped = url[start..end].parse::<u64>().ok()?;
    let listed = u64::try_from(body["value"].as_array()?.len()).ok()?;
    (listed == PAGE).then(|| format!("{}{}{}", &url[..start], skipped + PAGE, &url[end..]))
}

/// find the local azure devops credential: the `az` sign-in, then
/// `AZURE_DEVOPS_EXT_PAT`. with neither, the reading is made without one,
/// which azure devops allows for parts of public projects.
///
/// # Errors
///
/// returns an error when the `az` command prints something that is not text.
pub fn token() -> Result<String> {
    let signed_in = [
        "az",
        "account",
        "get-access-token",
        "--resource",
        TOKEN_RESOURCE,
        "--query",
        "accessToken",
        "--output",
        "tsv",
    ];
    if let Some(token) = reading::command_credential(&signed_in)? {
        return Ok(format!("bearer {token}"));
    }
    if let Some(token) = reading::variable_credential("AZURE_DEVOPS_EXT_PAT") {
        return Ok(format!("pat {token}"));
    }
    eprintln!(
        "no azure devops credential (`az login` or AZURE_DEVOPS_EXT_PAT); reading without one, \
         which shows only parts of public projects"
    );
    Ok(String::new())
}

/// a fetch function that reads azure devops with what [`token`] found.
pub fn client(token: &str, roots: &Roots) -> Box<Fetch<'static>> {
    let (authorization, secrets) = match token.split_once(' ') {
        Some(("bearer", secret)) => (Some(format!("Bearer {secret}")), vec![secret.to_owned()]),
        Some(("pat", secret)) => {
            let basic = base64(format!(":{secret}").as_bytes());
            (
                Some(format!("Basic {basic}")),
                vec![secret.to_owned(), basic],
            )
        }
        _ => (None, Vec::new()),
    };
    reading::client(
        ORIGIN,
        authorization,
        secrets,
        &[
            ("accept", "application/json"),
            // answer an unauthenticated request with 401, not a sign-in page.
            ("x-tfs-fedauthredirect", "Suppress"),
        ],
        &[
            "date",
            "etag",
            "location",
            "retry-after",
            "x-ms-continuationtoken",
            "x-ratelimit-limit",
            "x-ratelimit-remaining",
            "x-ratelimit-reset",
            "x-ratelimit-resource",
            "x-vss-e2eid",
        ],
        roots,
    )
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let group = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |group, (index, byte)| {
                group | u32::from(*byte) << (16 - 8 * index)
            });
        for position in 0..4 {
            if position <= chunk.len() {
                let index = (group >> (18 - 6 * position)) & 63;
                encoded.push(char::from(ALPHABET[index as usize]));
            } else {
                encoded.push('=');
            }
        }
    }
    encoded
}

fn classify(status: u16, body: &str, headers: &BTreeMap<String, String>) -> Termination {
    match status {
        // azure devops answers some unauthenticated requests with a sign-in page.
        203 => Termination::Unauthenticated {
            diagnostic: diagnostic(status, body),
        },
        _ => failure(status, body, headers, "x-ratelimit-reset"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript::exchange;

    fn answered(url: &str, headers: &[(&str, &str)], body: &str) -> HttpExchange {
        let headers = headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        exchange(url, 200, headers, body.into())
    }

    #[test]
    fn a_path_names_an_organisation_or_one_project() {
        let period = Period {
            from: "2026-01-01T00:00:00Z".into(),
            until: "2026-04-01T00:00:00Z".into(),
            files: true,
        };
        let read = |path: &str| {
            capture(
                path,
                &period,
                &|| Ok("2026-11-24T10:00:00Z".to_owned()),
                &mut |_: &str| Err(Error::Collection("offline".into())),
            )
        };
        // the organisation and its project listing; the organisation and the project.
        assert_eq!(read("example").unwrap().len(), 2);
        assert_eq!(read("example/Platform Team").unwrap().len(), 2);
        assert!(read("example/a/b").is_err());
        assert!(read("example/..").is_err());
        assert!(read("example?x=1").is_err());
    }

    #[test]
    fn the_next_page_is_found_three_ways() {
        let batch =
            "https://dev.azure.com/o/p/_apis/wit/reporting/workitemrevisions?api-version=7.1";
        let more = r#"{"values":[],"nextLink":"https://dev.azure.com/o/p/_apis/wit/reporting/workItemRevisions?continuationToken=7","isLastBatch":false}"#;
        assert_eq!(
            next_page(&answered(batch, &[], more)).as_deref(),
            Some("https://dev.azure.com/o/p/_apis/wit/reporting/workItemRevisions?continuationToken=7")
        );
        // the last batch still names a link, for a later reading to resume from.
        let last = more.replace("false", "true");
        assert_eq!(next_page(&answered(batch, &[], &last)), None);

        let listed = "https://dev.azure.com/o/_apis/projects?%24top=100&api-version=7.1";
        let token = [("x-ms-continuationtoken", "a b")];
        assert_eq!(
            next_page(&answered(listed, &token, r#"{"value":[]}"#)).as_deref(),
            Some("https://dev.azure.com/o/_apis/projects?%24top=100&api-version=7.1&continuationToken=a%20b")
        );

        let skipping = "https://dev.azure.com/o/p/_apis/git/pullrequests?%24top=100&%24skip=100&api-version=7.1";
        let full = format!(r#"{{"value":[{}]}}"#, vec!["{}"; 100].join(","));
        assert_eq!(
            next_page(&answered(skipping, &[], &full)).as_deref(),
            Some("https://dev.azure.com/o/p/_apis/git/pullrequests?%24top=100&%24skip=200&api-version=7.1")
        );
        assert_eq!(
            next_page(&answered(skipping, &[], r#"{"value":[{}]}"#)),
            None
        );
    }

    #[test]
    fn a_sign_in_page_is_not_an_answer() {
        let none = BTreeMap::new();
        assert!(matches!(
            classify(203, "<html>", &none),
            Termination::Unauthenticated { .. }
        ));
        assert!(matches!(
            classify(401, r#"{"message":"TF400813: not authorized"}"#, &none),
            Termination::Unauthenticated { diagnostic } if diagnostic == "HTTP 401: TF400813: not authorized"
        ));
    }

    #[test]
    fn a_token_is_sent_the_way_its_kind_needs() {
        assert_eq!(base64(b":pat"), "OnBhdA==");
        assert_eq!(base64(b":token"), "OnRva2Vu");
        assert_eq!(base64(b"ab"), "YWI=");
    }
}
