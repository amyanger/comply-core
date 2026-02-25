"""Custom exceptions for ComplyCore."""

from __future__ import annotations


class ComplyError(Exception):
    """Base exception for all ComplyCore errors."""


class ComplyConfigError(ComplyError):
    """Missing or invalid configuration."""


class ComplyAuthError(ComplyError):
    """Authentication or permission failure."""


class ComplyCollectionError(ComplyError):
    """API call failure during evidence collection."""


class ComplyIntegrityError(ComplyError):
    """Evidence hash chain violation."""
