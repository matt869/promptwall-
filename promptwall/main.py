"""The ASGI application and its CLI entry point.

Startup order matters and is not arbitrary:

  1. logging, so every later failure is legible
  2. settings, which fail loudly on bad config rather than at first request
  3. policy, which must validate before any traffic is accepted
  4. layers, which load models and compile patterns
  5. the HTTP surface

Anything that would leave PromptWall running but not actually protecting
should stop the process here, at deploy time, rather than surfacing as a
quiet gap in production.
"""

from __future__ import annotations

import argparse
import sys
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from . import __version__
from .admin.router import router as admin_router
from .config import Settings, get_settings, load_dotenv, reset_settings_cache
from .exceptions import ConfigError
from .middleware.auth import AuthMiddleware
from .middleware.error_handler import install as install_error_handlers
from .middleware.rate_limit import RateLimitMiddleware
from .middleware.request_id import RequestIDMiddleware
from .pipeline.orchestrator import build_pipeline
from .proxy.router import router as proxy_router
from .proxy.upstream import close_client
from .telemetry.audit import get_audit
from .telemetry.logging import configure as configure_logging
from .telemetry.logging import get_logger
from .telemetry.metrics import get_metrics
from .telemetry.tracing import configure as configure_tracing
from .ui import router as ui_router

log = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings

    log.info(
        "starting promptwall",
        extra={
            "version": __version__,
            "mode": settings.mode.value,
            "fail_mode": settings.fail_mode.value,
            "provider": settings.upstream.provider,
        },
    )

    app.state.pipeline = build_pipeline(settings)
    app.state.audit = get_audit(settings)
    app.state.metrics = get_metrics()
    app.state.metrics.set_degraded(app.state.pipeline.registry.degraded)

    if configure_tracing(settings):
        log.info("tracing enabled", extra={"endpoint": settings.telemetry.otlp_endpoint})

    policy = app.state.pipeline.policy_store.bundle
    log.info("policy loaded", extra=policy.summary())

    for name, status in app.state.pipeline.registry.status().items():
        if not status["enabled"]:
            log.warning("layer inactive", extra={"layer": name, "reason": status["reason"]})

    # Monitor mode is the safe default, but running there indefinitely means
    # PromptWall is watching an attack rather than stopping it. Say so once.
    if not settings.enforcing:
        log.warning(
            "running in MONITOR mode: verdicts are advisory and no traffic will be "
            "blocked or redacted. Set PW_MODE=enforce once you have reviewed what "
            "would have been blocked."
        )

    try:
        yield
    finally:
        log.info("shutting down")
        app.state.pipeline.registry.teardown()
        await close_client()


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application. Importable for tests without touching the CLI."""
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_format)

    app = FastAPI(
        title="PromptWall",
        description=(
            "A layered prompt-injection firewall for LLM applications. "
            "Drop-in proxy for OpenAI-compatible and Anthropic APIs."
        ),
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs",
    )
    app.state.settings = settings

    # Middleware runs bottom-up, so this order means: request id assigned
    # first, then auth, then rate limiting keyed on the authenticated
    # principal. Rate limiting before auth would let an unauthenticated
    # flood consume another tenant's budget.
    app.add_middleware(RateLimitMiddleware, settings=settings)
    app.add_middleware(AuthMiddleware, settings=settings)
    app.add_middleware(RequestIDMiddleware)

    install_error_handlers(app)
    app.include_router(proxy_router)
    app.include_router(admin_router)
    if settings.ui.enabled:
        app.include_router(ui_router)
    _install_ops_routes(app)
    return app


def _install_ops_routes(app: FastAPI) -> None:
    @app.get("/", include_in_schema=False)
    async def root() -> dict[str, Any]:
        document: dict[str, Any] = {
            "service": "promptwall",
            "version": __version__,
            "mode": app.state.settings.mode.value,
            "docs": "/docs",
        }
        if app.state.settings.ui.enabled:
            document["dashboard"] = "/dashboard"
            document["playground"] = "/playground"
        return document

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        """Liveness. Deliberately trivial: it must not depend on policy,
        the provider, or anything that could wedge."""
        return {"status": "ok", "version": __version__}

    @app.get("/readyz", include_in_schema=False)
    async def readyz(request: Request) -> Response:
        """Readiness. Fails when a non-advisory layer is unavailable, so an
        orchestrator pulls the instance instead of routing traffic through a
        gateway that is not actually inspecting it."""
        pipeline = getattr(request.app.state, "pipeline", None)
        if pipeline is None:
            return JSONResponse(status_code=503, content={"status": "starting"})

        degraded = pipeline.registry.degraded
        body = {
            "status": "degraded" if degraded else "ready",
            "layers": pipeline.registry.status(),
            "policy": pipeline.policy_store.bundle.summary(),
        }
        return JSONResponse(status_code=503 if degraded else 200, content=body)

    @app.get("/metrics", include_in_schema=False)
    async def metrics(request: Request) -> Response:
        if not request.app.state.settings.telemetry.metrics_enabled:
            return PlainTextResponse("metrics are disabled\n", status_code=404)
        body, content_type = request.app.state.metrics.render()
        return Response(content=body, media_type=content_type)


# The module-level app uvicorn imports: `uvicorn promptwall.main:app`.
# Built lazily so importing this module for the CLI does not force config
# validation before the CLI has had a chance to load a .env file.
_app: FastAPI | None = None


def __getattr__(name: str) -> Any:
    if name == "app":
        global _app
        if _app is None:
            load_dotenv()
            _app = create_app()
        return _app
    raise AttributeError(name)


def cli(argv: list[str] | None = None) -> int:
    """Console entry point: `promptwall serve`, `check`, `scan`."""
    parser = argparse.ArgumentParser(
        prog="promptwall",
        description="A layered prompt-injection firewall for LLM applications.",
    )
    parser.add_argument("--env-file", default=".env", help="path to a .env file")
    sub = parser.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="run the gateway")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    serve.add_argument("--reload", action="store_true")

    sub.add_parser("check", help="validate configuration and policy, then exit")

    scan = sub.add_parser("scan", help="scan text from a file or stdin")
    scan.add_argument("path", nargs="?", help="file to scan; omit to read stdin")
    scan.add_argument(
        "--trust",
        default="untrusted",
        help="provenance to assume: untrusted|third_party|user|developer|system",
    )
    scan.add_argument("--json", action="store_true", help="emit JSON")

    args = parser.parse_args(argv)
    load_dotenv(args.env_file)
    reset_settings_cache()

    if args.command == "check":
        return _cmd_check()
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "serve" or args.command is None:
        return _cmd_serve(args)
    parser.print_help()
    return 2


def _cmd_check() -> int:
    """Validate everything that could fail at deploy time."""
    try:
        settings = get_settings()
    except ConfigError as exc:
        print(f"config error: {exc.message}", file=sys.stderr)
        return 1

    try:
        pipeline = build_pipeline(settings)
    except Exception as exc:
        print(f"startup error: {exc}", file=sys.stderr)
        return 1

    summary = pipeline.policy_store.bundle.summary()
    print(f"config       ok  (mode={settings.mode.value}, fail={settings.fail_mode.value})")
    print(
        f"policy       ok  (v{summary['version']} digest={summary['digest']}, "
        f"{summary['signatures']} signatures, {summary['tool_rules']} tool rules, "
        f"{summary['redaction_rules']} redaction rules)"
    )

    degraded = False
    for name, status in pipeline.registry.status().items():
        mark = "ok " if status["enabled"] else "OFF"
        note = f"  ({status['reason']})" if status["reason"] else ""
        print(f"  {mark} {name}{note}")
        if not status["enabled"] and name != "l3_judge":
            degraded = True

    if not settings.upstream.api_key:
        print("warning: PW_UPSTREAM_API_KEY is empty; upstream calls will fail")
    if degraded:
        print("readiness    DEGRADED: a required layer is unavailable", file=sys.stderr)
        return 1
    print("readiness    ready")
    return 0


def _cmd_scan(args) -> int:
    """Scan a document the way L0-L2 would, without running a server.

    Useful for triaging a suspicious file, and for checking a rule change
    against a known sample before deploying it.
    """
    import json as _json

    from .constants import TrustLevel

    if args.path:
        with open(args.path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    else:
        text = sys.stdin.read()
    trust = {level.name.lower(): level for level in TrustLevel}.get(
        args.trust.lower(), TrustLevel.UNTRUSTED
    )

    settings = get_settings()
    pipeline = build_pipeline(settings)
    ctx = pipeline.inspect_request(
        [{"role": "user", "content": text, "pw_trust": trust.name.lower()}]
    )
    verdict = ctx.verdict

    if args.json:
        print(_json.dumps(verdict.to_audit_dict(), indent=2))
    else:
        print(f"decision : {verdict.decision.value}")
        print(f"risk     : {verdict.risk:.4f}")
        print(f"families : {', '.join(verdict.families) or 'none'}")
        if ctx.decoded:
            print(f"decoded  : {len(ctx.decoded)} nested payload(s)")
        if verdict.findings:
            print("findings :")
            for finding in sorted(verdict.findings, key=lambda f: -f.weight):
                print(
                    f"  {finding.severity.value:8} {finding.rule_id:26} "
                    f"w={finding.weight:.2f}  {finding.message[:60]}"
                )
        else:
            print("findings : none")
    return 1 if verdict.decision.value == "block" else 0


def _cmd_serve(args) -> int:
    try:
        import uvicorn
    except ImportError:
        print("uvicorn is not installed; pip install 'promptwall[all]'", file=sys.stderr)
        return 1

    settings = get_settings()
    uvicorn.run(
        "promptwall.main:app",
        host=args.host or settings.host,
        port=args.port or settings.port,
        reload=bool(args.reload),
        log_config=None,  # our own logging is already installed
        access_log=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
