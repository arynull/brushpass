"""Provider registry.

A plain name -> instance mapping. Registration is explicit and happens at
import time, so ``provider list`` reflects exactly what is compiled in and
a typo'd provider name fails immediately rather than at rotation time.

Third-party providers can register through :func:`register` (see the
authoring guide in the README); the shipped three are registered by the
:mod:`brushpass.providers` package itself.
"""

from .base import (
    ConfigError,
    Provider,
    ProviderError,
    RotationResult,
    Step,
)

_REGISTRY: dict[str, Provider] = {}


def register(provider: Provider) -> None:
    """Register a provider under its own :attr:`Provider.name`.

    Raises:
        ProviderError: if the name is empty or already taken, or if the
            object does not implement the interface. Registration is the
            one place where a half-implemented plugin can be caught before
            it is asked to rotate a live credential.
    """
    name = (provider.name or "").strip()
    if not name:
        raise ProviderError(
            f"Cannot register {type(provider).__name__}: it has no name"
        )
    if name in _REGISTRY:
        raise ProviderError(f"Provider '{name}' is already registered")
    for method in ("rotate", "revoke", "validate_config"):
        if not callable(getattr(provider, method, None)):
            raise ProviderError(
                f"Cannot register '{name}': missing required method '{method}'"
            )
    _REGISTRY[name] = provider


def get_provider(name: str) -> Provider:
    """Look up a provider by name.

    Raises:
        ConfigError: if no such provider is registered. The message lists
            what is available, so the fix is visible in the error.
    """
    try:
        return _REGISTRY[name]
    except KeyError:
        available = ", ".join(sorted(_REGISTRY)) or "none"
        raise ConfigError(
            f"Unknown provider '{name}'. Available: {available}"
        ) from None


def available_providers() -> list[Provider]:
    """Every registered provider, name-sorted."""
    return [_REGISTRY[name] for name in sorted(_REGISTRY)]


def provider_names() -> list[str]:
    """Registered provider names, sorted."""
    return sorted(_REGISTRY)


__all__ = [
    "ConfigError",
    "Provider",
    "ProviderError",
    "RotationResult",
    "Step",
    "available_providers",
    "get_provider",
    "provider_names",
    "register",
]
