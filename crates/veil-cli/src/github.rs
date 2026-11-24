use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};

use crate::update;

pub struct ReleaseSource {
    repository: String,
    agent: ureq::Agent,
}

impl ReleaseSource {
    pub fn configured() -> Result<Self> {
        Self::new(env!("CARGO_PKG_REPOSITORY"))
    }

    pub fn new(repository: &str) -> Result<Self> {
        let path = repository
            .strip_prefix("https://github.com/")
            .context("Release source must be a public HTTPS GitHub repository")?;
        let parts: Vec<_> = path.split('/').collect();
        ensure!(
            parts.len() == 2
                && parts.iter().all(|part| {
                    !part.is_empty()
                        && !matches!(*part, "." | "..")
                        && part.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                        })
                }),
            "Invalid GitHub release repository"
        );
        Ok(Self {
            repository: path.to_owned(),
            agent: ureq::AgentBuilder::new()
                .redirects(0)
                .timeout_connect(Duration::from_secs(30))
                .timeout_read(Duration::from_secs(60))
                .build(),
        })
    }

    pub fn latest_tag(&self) -> Result<String> {
        let bytes = self.fetch(
            format!(
                "https://api.github.com/repos/{}/releases/latest",
                self.repository
            ),
            update::MAX_MANIFEST,
        )?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("Invalid GitHub release discovery response"))?;
        Ok(value["tag_name"]
            .as_str()
            .context("GitHub release discovery did not provide a tag")?
            .to_owned())
    }

    pub fn asset(&self, version: &str, file: &str, limit: u64) -> Result<Vec<u8>> {
        self.fetch(self.asset_url(version, file)?, limit)
    }

    fn asset_url(&self, version: &str, file: &str) -> Result<String> {
        ensure!(
            semver::Version::parse(version)?.to_string() == version,
            "Release version must be canonical"
        );
        ensure!(
            !file.is_empty()
                && !file.starts_with('.')
                && !file.contains("..")
                && file.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+')
                }),
            "Invalid release asset filename"
        );
        Ok(format!(
            "https://github.com/{}/releases/download/v{version}/{file}",
            self.repository
        ))
    }

    fn fetch(&self, url: String, limit: u64) -> Result<Vec<u8>> {
        self.fetch_with(url, limit, |url| {
            self.agent
                .get(url)
                .set("User-Agent", concat!("veil/", env!("CARGO_PKG_VERSION")))
                .call()
                .map_err(|error| match error {
                    ureq::Error::Status(status, _) => anyhow::anyhow!(
                        "Public release service returned HTTP {status}; check release availability or the GitHub API rate limit"
                    ),
                    ureq::Error::Transport(_) => anyhow::anyhow!(
                        "Cannot reach the public release service; check connectivity and TLS"
                    ),
                })
        })
    }

    fn fetch_with(
        &self,
        mut url: String,
        limit: u64,
        mut send: impl FnMut(&str) -> Result<ureq::Response>,
    ) -> Result<Vec<u8>> {
        for redirects in 0..=5 {
            ensure!(
                allowed_url(&url),
                "Release redirect has an untrusted destination"
            );
            let response = send(&url)?;
            match response.status() {
                200 => return update::bounded_read(response.into_reader(), limit),
                301 | 302 | 303 | 307 | 308 => {
                    ensure!(redirects < 5, "Too many release redirects");
                    url = response
                        .header("Location")
                        .context("Release redirect has no destination")?
                        .to_owned();
                }
                status => {
                    bail!("Public release service returned an incomplete response ({status})")
                }
            }
        }
        unreachable!()
    }
}

fn allowed_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or_default();
    matches!(
        host,
        "github.com"
            | "api.github.com"
            | "release-assets.githubusercontent.com"
            | "objects.githubusercontent.com"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> ReleaseSource {
        ReleaseSource::new("https://github.com/example/veil").unwrap()
    }

    fn redirect(location: &str) -> ureq::Response {
        format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\n\r\n")
            .parse()
            .unwrap()
    }

    #[test]
    fn repository_and_asset_paths_cannot_inject_another_origin() {
        for repository in [
            "http://github.com/example/veil",
            "https://github.com/example/veil/extra",
            "https://github.com/example/veil?token=value",
            "https://github.com/../veil",
            "https://github.com/example/veil#fragment",
        ] {
            assert!(ReleaseSource::new(repository).is_err());
        }
        for file in [
            "../manifest.json",
            "manifest.json?query",
            "//other.invalid/file",
            "",
        ] {
            assert!(source().asset_url("0.4.2", file).is_err());
        }
        assert_eq!(
            source().asset_url("0.4.2", "manifest.json").unwrap(),
            "https://github.com/example/veil/releases/download/v0.4.2/manifest.json"
        );
    }

    #[test]
    fn redirects_are_https_only_and_use_exact_allowed_hosts() {
        for url in [
            "http://github.com/file",
            "https://github.com.evil.invalid/file",
            "https://github.com@evil.invalid/file",
            "https://github.com:443/file",
            "https://evil.invalid/file",
            "/relative-path",
        ] {
            let mut requests = 0;
            let result = source().fetch_with("https://github.com/file".into(), 10, |_| {
                requests += 1;
                Ok(redirect(url))
            });
            assert!(result.is_err(), "{url}");
            assert_eq!(
                requests, 1,
                "must refuse before contacting the redirect target"
            );
        }
    }

    #[test]
    fn a_public_asset_redirect_streams_only_a_bounded_complete_body() {
        let mut requests = Vec::new();
        let bytes = source()
            .fetch_with("https://github.com/file".into(), 4, |url| {
                requests.push(url.to_owned());
                if requests.len() == 1 {
                    Ok(redirect(
                        "https://release-assets.githubusercontent.com/file?signature=value",
                    ))
                } else {
                    Ok(ureq::Response::new(200, "OK", "data")?)
                }
            })
            .unwrap();
        assert_eq!(bytes, b"data");
        assert_eq!(requests.len(), 2);
        assert!(
            source()
                .fetch_with("https://github.com/file".into(), 3, |_| {
                    Ok(ureq::Response::new(200, "OK", "data")?)
                })
                .is_err()
        );
        assert!(
            source()
                .fetch_with("https://github.com/file".into(), 4, |_| {
                    Ok(ureq::Response::new(206, "Partial Content", "data")?)
                })
                .is_err()
        );
    }

    #[test]
    fn redirect_loops_and_missing_locations_are_refused() {
        let mut requests = 0;
        assert!(
            source()
                .fetch_with("https://github.com/file".into(), 4, |_| {
                    requests += 1;
                    Ok(redirect("https://github.com/file"))
                })
                .is_err()
        );
        assert_eq!(requests, 6);
        assert!(
            source()
                .fetch_with("https://github.com/file".into(), 4, |_| {
                    Ok(ureq::Response::new(302, "Found", "")?)
                })
                .is_err()
        );
    }
}
