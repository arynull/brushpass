"""The provider plugin interface for credential rotation.

A provider is the only part of brushpass that talks to a third-party
service. Keeping it behind a two-method interface means the rotation
engine in :mod:`brushpass.rotate` is provider-agnostic and testable with a
fake, and adding a service means adding one file here — no changes to the
engine, the store, or the CLI.

The contract:

``rotate(old_secret, config) -> str``
    Return the new secret. Raise :class:`ProviderError` if the upstream
    service refused; never return an empty string and never return the
    old secret back.

``revoke(secret, config) -> None``
    Make the secret unusable at the provider. Raise
    :class:`ProviderError` on failure. A provider that has no revocation
    API returns ``None`` from :meth:`Provider.supports_revoke` being
    ``False`` — brushpass then documents the fact instead of pretending
    the old secret died.

Two rules every provider inherits:

1. **Config is validated before the network is touched.** A typo in a
   config key must fail as a config error, not as a confusing HTTP 401.
2. **Secrets never travel through argv or an exception message.** They go
   in request headers or bodies, and a :class:`ProviderError` is phrased
   so that interpolating it into a log cannot leak one.
"""

from dataclasses import dataclass, field


class ProviderError(Exception):
    """A provider could not rotate or revoke a secret.

    Messages are written to be safe to print: they name the config key
    or the endpoint that failed, never the secret itself.
    """


class ConfigError(ProviderError):
    """Provider configuration is missing, mistyped, or unusable.

    Distinct from :class:`ProviderError` so the CLI can say "fix your
    config" instead of "the upstream service failed".
    """


@dataclass(frozen=True)
class Step:
    """One human-readable step in a rotation plan.

    Shown by ``rotate --dry-run`` and in the dry-run plan output, so an
    operator can see what *would* happen before it happens.
    """

    description: str
    destructive: bool = False

    def render(self, index: int | None = None) -> str:
        prefix = f"{index}. " if index is not None else "- "
        marker = " (irreversible)" if self.destructive else ""
        return f"{prefix}{self.description}{marker}"


@dataclass(frozen=True)
class RotationResult:
    """What a provider hands back from a successful rotation."""

    new_secret: str
    expires_at: str | None = None
    detail: str = ""
    metadata: dict = field(default_factory=dict)


class Provider:
    """Base class for rotation providers.

    Subclasses must set :attr:`name`, :attr:`description`, and
    :attr:`required_config`; the registry uses them for ``provider list``
    and for validating a credential's stored config before use.
    """

    name: str = ""
    description: str = ""
    # Config keys that must be present. Optional keys go in
    # `optional_config` so `provider list` can show what is tunable.
    required_config: tuple[str, ...] = ()
    optional_config: tuple[str, ...] = ()
    supports_revoke: bool = True
    revoke_note: str = ""
    # Bound by the rotation engine before `rotate` is called, so a
    # provider that needs the label (only `manual`, for its prompt
    # wording) can read it without widening the two-method interface.
    label: str | None = None

    def validate_config(self, config: dict | None) -> dict:
        """Check a credential's config against this provider's schema.

        Subclasses extend :meth:`check_config` for type and value checks;
        the required-key check here is common to all of them.

        Raises:
            ConfigError: if a required key is missing or the value is
                unusable. The message names the key and says what is
                expected, and never echoes a secret-shaped value.
        """
        values = dict(config or {})
        missing = [key for key in self.required_config if not values.get(key)]
        if missing:
            raise ConfigError(
                f"Provider '{self.name}' is missing required config: "
                f"{', '.join(missing)}. Expected: {self.describe_config()}"
            )
        self.check_config(values)
        return values

    def check_config(self, config: dict) -> None:
        """Provider-specific type/value validation. Override as needed."""

    def plan(self, context) -> list[Step]:
        """Steps this provider will perform, for ``rotate --dry-run``.

        The default plan is the shape of every rotation; providers add
        their own specifics. Never performs I/O.
        """
        return [
            Step(f"Ask provider '{self.name}' for a new secret"),
            Step("Store the new secret encrypted, replacing the old one"),
        ]

    def rotate(self, old_secret: str, config: dict) -> RotationResult:
        """Perform the upstream rotation. Subclasses must implement."""
        raise NotImplementedError

    def revoke(self, secret: str, config: dict) -> None:
        """Revoke a secret upstream.

        The default refuses: a provider that cannot honestly revoke must
        say so rather than silently succeeding.
        """
        raise ProviderError(
            f"Provider '{self.name}' does not implement upstream revocation"
        )

    def describe_config(self) -> str:
        """One-line description of the expected config, for error text."""
        parts = list(self.required_config)
        parts += [f"{key} (optional)" for key in self.optional_config]
        return ", ".join(parts) if parts else "no configuration"

    def instructions(self, context) -> list[str]:
        """Operator-facing steps. Only ``manual`` really needs these."""
        return []
