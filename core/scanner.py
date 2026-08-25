from __future__ import annotations

from typing import Any, Callable

from config.scanner_config import EXECUTION_ORDER, INTEGRATION_VERSION, TOOL_NAME
from core.results import (
    aggregate_findings,
    build_summary,
    enrich_recon_for_web_scanners,
    ensure_module_result,
    now_iso,
    scanner_error,
)
from modules.recon import run_recon_scan
from modules.security_config import run_security_config_scan
from modules.sqli_scanner import run_sqli_scanner
from modules.xss_scanner import run_xss_scan
from modules.ollama_analyzer import analyze_results, check_ollama


ScannerCallable = Callable[..., dict[str, Any]]


def _run_safely(
    module_name: str,
    target: str,
    scanner: ScannerCallable,
    *args: Any,
    **kwargs: Any,
) -> dict[str, Any]:
    try:
        return ensure_module_result(
            module_name,
            target,
            scanner(*args, **kwargs),
        )
    except Exception as error:
        return scanner_error(module_name, target, error)


def run_integrated_scan(
    target: str,
    ai_enabled: bool = False,
    ai_model: str = "qwen3.5:4b",
    ai_url: str = "http://127.0.0.1:11434",
) -> dict[str, Any]:
    started = now_iso()
    modules: dict[str, dict[str, Any]] = {}

    recon_result = _run_safely("recon", target, run_recon_scan, target)
    modules["recon"] = recon_result

    web_recon = enrich_recon_for_web_scanners(recon_result)

    modules["xss"] = _run_safely(
        "xss",
        target,
        run_xss_scan,
        target,
        recon_data=web_recon,
    )

    modules["sqli"] = _run_safely(
        "sqli",
        target,
        run_sqli_scanner,
        target,
        recon_data=web_recon,
    )

    modules["security_config"] = _run_safely(
        "security_config",
        target,
        run_security_config_scan,
        target,
        recon_data=recon_result,
    )

    findings = aggregate_findings(modules)
    summary = build_summary(findings)

    status = "success"
    if any(result.get("status") == "error" for result in modules.values()):
        status = "partial/error"

    report = {
        "tool": TOOL_NAME,
        "integration_version": INTEGRATION_VERSION,
        "target": target,
        "scan_started": started,
        "scan_finished": now_iso(),
        "status": status,
        "execution_order": EXECUTION_ORDER,
        "modules": modules,
        "summary": summary,
        "findings": findings,
        "ai": {
            "enabled": ai_enabled,
            "status": "not_requested",
            "model": ai_model,
            "base_url": ai_url,
            "analysis": "",
            "error": None,
        },
    }

    if ai_enabled:
        if not check_ollama(ai_url):
            report["ai"].update({
                "status": "error",
                "error": (
                    "Ollama is not reachable at "
                    f"{ai_url}. Start Ollama and try again."
                ),
            })
        else:
            ai_result = analyze_results(
                report,
                model=ai_model,
                base_url=ai_url,
            )
            report["ai"] = {
                "enabled": True,
                **ai_result,
            }

    return report
