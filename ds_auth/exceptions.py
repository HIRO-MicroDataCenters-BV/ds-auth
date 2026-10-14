"""Custom exceptions. All inherit from AuthError so a service can catch
one base class if it wants to."""


class AuthError(Exception):
    """Base for every auth/authz error raised by this middleware."""

    status_code: int = 401

    def __init__(self, detail: str, status_code: int | None = None):
        super().__init__(detail)
        self.detail = detail
        if status_code is not None:
            self.status_code = status_code


class MissingTokenError(AuthError):
    status_code = 401


class InvalidTokenError(AuthError):
    status_code = 401


class PolicyDeniedError(AuthError):
    status_code = 403


class PolicyEngineUnavailableError(AuthError):
    status_code = 503
