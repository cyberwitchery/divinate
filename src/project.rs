//! declarative repository configuration.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::workflow::{ProjectConfig, SourceConfig, SourceContext, SourceProvider};

/// the repository-root configuration filename.
pub const PROJECT_FILE: &str = "divinate.yaml";

#[derive(Debug, Clone)]
/// a validated project configuration and the exact bytes it came from.
pub struct LoadedProject {
    pub config: ProjectConfig,
    pub bytes: Vec<u8>,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
/// the checked-in project configuration.
pub struct ProjectFile {
    pub repository: RepositoryConfig,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub packs: BTreeMap<String, PackFileConfig>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sources: BTreeMap<String, SourceFileConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// repository identity and branch intent.
pub struct RepositoryConfig {
    pub identity: String,
    pub branch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
/// one external pack installed for this project.
pub struct PackFileConfig {
    pub executable: PathBuf,
    #[serde(
        default = "empty_object",
        rename = "config",
        skip_serializing_if = "is_empty_object"
    )]
    pub configuration: Value,
    #[serde(
        default = "default_timeout",
        skip_serializing_if = "is_default_timeout"
    )]
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
/// one enabled evidence source.
pub struct SourceFileConfig {
    pub provider: SourceFileProvider,
    #[serde(default = "required_source")]
    pub required: bool,
    #[serde(default, skip_serializing_if = "is_repository_context")]
    pub context: SourceContext,
    #[serde(
        default = "empty_object",
        rename = "config",
        skip_serializing_if = "is_empty_object"
    )]
    pub configuration: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
/// a built-in source or one collector from an external pack.
pub enum SourceFileProvider {
    Builtin(BuiltinProvider),
    Pack(PackProvider),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// a built-in source provider.
pub struct BuiltinProvider {
    pub builtin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// an external pack collector provider.
pub struct PackProvider {
    pub pack: String,
    pub collector: String,
}

/// load and validate `divinate.yaml` from a repository root.
///
/// # Errors
///
/// returns an error for missing or malformed configuration, invalid repository
/// identity, unsafe settings, or unresolved executables.
pub fn load(repository_root: &Path) -> Result<LoadedProject> {
    let path = repository_root.join(PROJECT_FILE);
    if !path.is_file() {
        return Err(Error::Invalid(format!(
            "missing {}; run divinate init or add the repository's committed configuration",
            path.display()
        )));
    }
    let bytes = fs::read(&path).map_err(|source| Error::Io {
        path: path.clone(),
        source,
    })?;
    let file: ProjectFile = serde_yaml_ng::from_slice(&bytes).map_err(|source| Error::Yaml {
        path: path.clone(),
        source,
    })?;
    validate_repository(&file.repository)?;
    let actual = crate::release::repository_identity(repository_root)?;
    if actual != file.repository.identity {
        return Err(Error::Provenance(format!(
            "repository path resolves to {actual}, not divinate.yaml repository identity {}",
            file.repository.identity
        )));
    }
    let config = resolve(repository_root, file)?;
    Ok(LoadedProject {
        config,
        sha256: crate::hex_digest(&bytes),
        bytes,
    })
}

/// write a starter project configuration unless one already exists.
///
/// # Errors
///
/// returns an error when the file cannot be serialized or written.
pub fn initialize(repository_root: &Path, repository: &str, branch: &str) -> Result<bool> {
    let path = repository_root.join(PROJECT_FILE);
    if path.exists() {
        load(repository_root)?;
        return Ok(false);
    }
    let file = ProjectFile {
        repository: RepositoryConfig {
            identity: repository.into(),
            branch: branch.into(),
        },
        packs: BTreeMap::new(),
        sources: BTreeMap::new(),
    };
    store(repository_root, &file)?;
    Ok(true)
}

/// write a project configuration in canonical YAML form.
///
/// # Errors
///
/// returns an error when serialization or writing fails.
pub fn store(repository_root: &Path, file: &ProjectFile) -> Result<()> {
    let path = repository_root.join(PROJECT_FILE);
    let bytes = serde_yaml_ng::to_string(file)
        .map_err(|source| Error::Yaml {
            path: path.clone(),
            source,
        })?
        .into_bytes();
    fs::write(&path, bytes).map_err(|source| Error::Io { path, source })?;
    Ok(())
}

/// convert the pre-YAML project configuration for one-time migration.
#[must_use]
pub fn from_legacy(config: &ProjectConfig) -> ProjectFile {
    let packs = config
        .packs
        .iter()
        .map(|(id, pack)| {
            (
                id.clone(),
                PackFileConfig {
                    executable: pack.executable.clone(),
                    configuration: normalized_configuration(&pack.configuration),
                    timeout_seconds: pack.timeout_seconds,
                },
            )
        })
        .collect();
    let sources = config
        .sources
        .iter()
        .map(|(id, source)| {
            let provider = match &source.provider {
                SourceProvider::Builtin { source } => {
                    SourceFileProvider::Builtin(BuiltinProvider {
                        builtin: source.clone(),
                    })
                }
                SourceProvider::Pack { pack, collector } => {
                    SourceFileProvider::Pack(PackProvider {
                        pack: pack.clone(),
                        collector: collector.clone(),
                    })
                }
            };
            (
                id.clone(),
                SourceFileConfig {
                    provider,
                    required: source.required,
                    context: source.context,
                    configuration: normalized_configuration(&source.configuration),
                },
            )
        })
        .collect();
    ProjectFile {
        repository: RepositoryConfig {
            identity: config.repository.clone(),
            branch: config.branch.clone(),
        },
        packs,
        sources,
    }
}

fn normalized_configuration(value: &Value) -> Value {
    if value.is_null() {
        empty_object()
    } else {
        value.clone()
    }
}

fn resolve(repository_root: &Path, file: ProjectFile) -> Result<ProjectConfig> {
    let mut packs = BTreeMap::new();
    for (id, pack) in file.packs {
        validate_value(&format!("packs.{id}.config"), &pack.configuration)?;
        let executable = resolve_executable(repository_root, &pack.executable)
            .map_err(|error| Error::Invalid(format!("packs.{id}.executable: {error}")))?;
        packs.insert(
            id,
            crate::pack::PackConfig {
                executable,
                configuration: pack.configuration,
                timeout_seconds: pack.timeout_seconds,
            },
        );
    }
    let mut sources = BTreeMap::new();
    for (id, mut source) in file.sources {
        validate_value(&format!("sources.{id}.config"), &source.configuration)?;
        let (provider, context) = match source.provider {
            SourceFileProvider::Builtin(provider) => {
                if provider.builtin != "release-sbom" {
                    return Err(Error::Invalid(format!(
                        "sources.{id}.provider.builtin: unknown built-in provider {:?}",
                        provider.builtin
                    )));
                }
                crate::release::validate_source_configuration(&source.configuration)
                    .map_err(|error| Error::Invalid(format!("sources.{id}.config: {error}")))?;
                let executable = source
                    .configuration
                    .get("executable")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        Error::Invalid(format!("sources.{id}.config.executable must be a string"))
                    })?;
                let executable = resolve_executable(repository_root, Path::new(executable))
                    .map_err(|error| {
                        Error::Invalid(format!("sources.{id}.config.executable: {error}"))
                    })?;
                source.configuration["executable"] =
                    Value::String(executable.to_string_lossy().into_owned());
                (
                    SourceProvider::Builtin {
                        source: provider.builtin,
                    },
                    SourceContext::Release,
                )
            }
            SourceFileProvider::Pack(provider) => {
                if !packs.contains_key(&provider.pack) {
                    return Err(Error::Invalid(format!(
                        "sources.{id}.provider.pack: pack {:?} is not configured",
                        provider.pack
                    )));
                }
                (
                    SourceProvider::Pack {
                        pack: provider.pack,
                        collector: provider.collector,
                    },
                    source.context,
                )
            }
        };
        sources.insert(
            id,
            SourceConfig {
                provider,
                configuration: source.configuration,
                context,
                enabled: true,
                required: source.required,
            },
        );
    }
    Ok(ProjectConfig {
        repository: file.repository.identity,
        branch: file.repository.branch,
        packs,
        sources,
    })
}

fn validate_repository(repository: &RepositoryConfig) -> Result<()> {
    if repository.identity.trim().is_empty() {
        return Err(Error::Invalid(
            "repository.identity must not be empty".into(),
        ));
    }
    if repository.branch.trim().is_empty() {
        return Err(Error::Invalid("repository.branch must not be empty".into()));
    }
    Ok(())
}

fn validate_value(path: &str, value: &Value) -> Result<()> {
    if !value.is_object() {
        return Err(Error::Invalid(format!("{path} must be a mapping")));
    }
    crate::pack::validate_configuration(value)
        .map_err(|error| Error::Invalid(format!("{path}: {error}")))
}

fn resolve_executable(repository_root: &Path, executable: &Path) -> Result<PathBuf> {
    if executable.components().count() > 1 || executable.is_absolute() {
        let path = if executable.is_absolute() {
            executable.to_owned()
        } else {
            repository_root.join(executable)
        };
        return executable_file(path);
    }
    let Some(paths) = env::var_os("PATH") else {
        return Err(Error::Invalid(format!(
            "cannot resolve executable {:?}: PATH is not set",
            executable.display()
        )));
    };
    for directory in env::split_paths(&paths) {
        let candidate = directory.join(executable);
        if candidate.is_file() {
            return executable_file(candidate);
        }
    }
    Err(Error::Invalid(format!(
        "executable {:?} was not found in PATH",
        executable.display()
    )))
}

fn executable_file(path: PathBuf) -> Result<PathBuf> {
    if !path.is_file() {
        return Err(Error::Invalid(format!(
            "executable does not exist: {}",
            path.display()
        )));
    }
    fs::canonicalize(&path).map_err(|source| Error::Io { path, source })
}

fn is_empty_object(value: &Value) -> bool {
    value.as_object().is_some_and(serde_json::Map::is_empty)
}

fn empty_object() -> Value {
    serde_json::json!({})
}

const fn required_source() -> bool {
    true
}

const fn default_timeout() -> u64 {
    30
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_default_timeout(value: &u64) -> bool {
    *value == 30
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_repository_context(value: &SourceContext) -> bool {
    matches!(value, SourceContext::Repository)
}
