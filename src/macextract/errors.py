"""Error hierarchy for macextract."""


class MacExtractError(Exception):
    """Base class for all macextract errors."""


class UnsupportedError(MacExtractError):
    """The data is not a recognised archive, or the format is not supported."""


class CorruptError(MacExtractError):
    """A recognised archive is damaged (bad lengths, bad CRCs, truncation)."""


class PasswordRequiredError(MacExtractError):
    """The archive is encrypted and no password was supplied."""


class BadPasswordError(PasswordRequiredError):
    """A password was supplied but it does not decrypt the archive."""
