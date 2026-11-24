//! HTTP error envelope.
//!
//! Errors leave the service as `application/problem+json` ([RFC 9457]), built from
//! [`veil_proto::ProblemDetails`]. Handlers return [`ApiError`]; the `IntoResponse` impl is
//! the single place that decides status, media type, and body shape.
//!
//! [RFC 9457]: https://www.rfc-editor.org/rfc/rfc9457

use axum::{
    Json,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};

use veil_proto::ProblemDetails;

const TYPE_PREFIX: &str = "https://veil.example.com/problems/";

/// An error returned by an HTTP handler.
#[derive(Debug, thiserror::Error)]
#[error("{title}")]
pub struct ApiError {
    status: StatusCode,
    kind: &'static str,
    title: &'static str,
    detail: Option<String>,
    retry_after: Option<u64>,
}

impl ApiError {
    fn new(
        status: StatusCode,
        kind: &'static str,
        title: &'static str,
        detail: Option<String>,
    ) -> Self {
        Self {
            status,
            kind,
            title,
            detail,
            retry_after: None,
        }
    }

    /// `429 Too Many Requests` with `Retry-After`: too many failed sign-ins.
    pub fn too_many_requests(retry_after: u64) -> Self {
        Self {
            retry_after: Some(retry_after),
            ..Self::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too-many-requests",
                "Too many failed sign-ins",
                Some(format!("try again in {retry_after} seconds")),
            )
        }
    }

    /// `400 Bad Request`.
    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "bad-request",
            "Malformed request",
            Some(detail.into()),
        )
    }

    /// `401 Unauthorized`. The detail never says whether the account exists.
    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Authentication required",
            None,
        )
    }

    /// `403 Forbidden`.
    pub fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", "Not permitted", None)
    }

    /// `409 Conflict`. The detail carries the current revision when one exists.
    pub fn conflict(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "conflict",
            "Object changed",
            Some(detail.into()),
        )
    }

    /// `404 Not Found`.
    pub fn not_found() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "not-found",
            "Resource not found",
            None,
        )
    }

    /// `500 Internal Server Error`. The detail is returned to the client, so it must not
    /// contain secrets, SQL, or filesystem paths.
    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "Internal error",
            Some(detail.into()),
        )
    }

    /// `426 Upgrade Required`: the client speaks another protocol version. The body adds a
    /// `supported` member listing the versions this service speaks.
    pub fn protocol_mismatch() -> Response {
        let problem = Self::new(
            StatusCode::UPGRADE_REQUIRED,
            "protocol",
            "Unsupported protocol version",
            None,
        )
        .into_problem();
        let mut body = match serde_json::to_value(&problem) {
            Ok(body) => body,
            Err(_) => return Self::internal("problem document unavailable").into_response(),
        };
        if let Some(object) = body.as_object_mut() {
            object.insert(
                "supported".to_owned(),
                serde_json::json!([veil_proto::PROTOCOL_VERSION]),
            );
        }
        (
            StatusCode::UPGRADE_REQUIRED,
            [(header::CONTENT_TYPE, "application/problem+json")],
            Json(body),
        )
            .into_response()
    }

    /// Builds the problem document without converting it into a response.
    pub fn into_problem(self) -> ProblemDetails {
        let mut problem = ProblemDetails::new(
            format!("{TYPE_PREFIX}{}", self.kind),
            self.title,
            self.status.as_u16(),
        );
        if let Some(detail) = self.detail {
            problem = problem.with_detail(detail);
        }
        problem
    }
}

impl From<crate::store::StoreError> for ApiError {
    fn from(error: crate::store::StoreError) -> Self {
        use crate::store::StoreError;
        match error {
            StoreError::NotFound => Self::not_found(),
            StoreError::Conflict => Self::conflict("the object changed since it was read"),
            StoreError::Forbidden => Self::forbidden(),
            StoreError::Invalid(detail) => Self::bad_request(detail),
            StoreError::IncompatibleSchema(_) => {
                tracing::error!(error = %error, "storage failure");
                Self::internal("storage unavailable")
            }
            StoreError::Database(error) => {
                tracing::error!(error = %error, "storage failure");
                Self::internal("storage unavailable")
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status;
        let retry_after = self.retry_after;
        let problem = self.into_problem();
        let mut response = (
            status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            Json(problem),
        )
            .into_response();
        if let Some(seconds) = retry_after {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, seconds.into());
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_becomes_a_problem_document() {
        let problem = ApiError::not_found().into_problem();

        assert_eq!(problem.status, 404);
        assert_eq!(problem.kind, "https://veil.example.com/problems/not-found");
        assert_eq!(problem.detail, None);
    }

    #[test]
    fn bad_request_is_problem_json() {
        let response = ApiError::bad_request("missing id").into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/problem+json"
        );
    }
}
