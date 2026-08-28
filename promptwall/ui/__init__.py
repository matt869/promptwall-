"""The operator console.

Two pages, both static HTML with no build step and no third-party assets:

  /dashboard   what the gateway is doing right now
  /playground  what the gateway would do to a request you type

The pages ship no data. Every number in them is fetched from /admin at
runtime with a key the operator supplies, which keeps the console on the same
side of the auth boundary as the API it reads -- serving the HTML does not
disclose anything /  does not already disclose.
"""

from .router import router

__all__ = ["router"]
