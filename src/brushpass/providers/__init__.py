"""Provider plugins for brushpass credential rotation.

Importing this package registers the three shipped providers:

* ``github-app``  — GitHub App installation tokens via the Apps API
* ``generic-http`` — any internal secret service reachable over HTTP
* ``manual``      — human-driven rotation for credentials with no API

Third-party providers register with :func:`register`. See the authoring
guide in the README for the full interface.
"""

from .base import (
    ConfigError,
    Provider,
    ProviderError,
    RotationResult,
    Step,
)
from .generic_http import GenericHttpProvider
from .github_app import GitHubAppProvider
from .manual import ManualProvider
from .registry import (
    available_providers,
    get_provider,
    provider_names,
    register,
)

register(GitHubAppProvider())
register(GenericHttpProvider())
register(ManualProvider())

__all__ = [
    "ConfigError",
    "GenericHttpProvider",
    "GitHubAppProvider",
    "ManualProvider",
    "Provider",
    "ProviderError",
    "RotationResult",
    "Step",
    "available_providers",
    "get_provider",
    "provider_names",
    "register",
]
