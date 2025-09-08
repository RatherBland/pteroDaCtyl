from __future__ import annotations

from typing import Any, Dict, List, Tuple
from pydantic import ValidationError

from pterodactyl.logger import error, warning, logger
from pterodactyl.platforms.schema import RuleSchema, TestNameEnum, TestTypeEnum, PlatformsEnum


def _get_primary_doc(raw_docs: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    """Return the first mapping-like YAML doc from a rule file (or None)."""
    for doc in raw_docs:
        if isinstance(doc, dict):
            return doc
    return None


def _extract_tests(raw_docs: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    """Find a `tests` object in the first two YAML docs, if present."""
    for i in range(min(2, len(raw_docs))):
        d = raw_docs[i]
        if isinstance(d, dict) and d.get("tests"):
            return d["tests"]
    return None


def lint_rule(rule: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """Lint a single rule structure.

    Returns (errors, warnings) lists of messages for this rule.
    """
    errs: List[str] = []
    warns: List[str] = []

    raw_docs = rule.get("raw", [])
    primary = _get_primary_doc(raw_docs) or {}

    # 1) Required: basic rule schema (id, name, tags)…
    try:
        RuleSchema(**primary)
    except ValidationError as ve:
        for e in ve.errors():
            loc = ".".join(str(p) for p in e.get("loc", [])) or "<root>"
            msg = e.get("msg", "invalid value")
            if "name" in e.get("loc", []):
                errs.append(
                    "Invalid 'name': must be lowercase_snake_case (a-z, 0-9, _)"
                )
            elif "id" in e.get("loc", []):
                errs.append("Invalid 'id': must be a UUID4 string")
            elif "tags" in e.get("loc", []):
                errs.append("Invalid 'tags': include at least one 'attack-*' tag")
            else:
                errs.append(f"Invalid field '{loc}': {msg}")

    # 2) Required: tests object (friendly validation)
    tests_obj = _extract_tests(raw_docs)
    if not tests_obj:
        errs.append("Missing required 'tests' object")
    else:
        t_errs, t_warns = _validate_tests_friendly(tests_obj)
        errs.extend(t_errs)
        warns.extend(t_warns)

    # 3) Recommended: suppression block at rule root
    if "suppression" not in primary:
        warns.append("Missing recommended 'suppression' block")

    return errs, warns


def lint_ruleset(rules: List[Dict[str, Any]]) -> Tuple[int, int]:
    """Lint a set of rules. Returns (error_count, warning_count)."""
    total_errs = 0
    total_warns = 0

    logger.info("Starting lint over %d rule file(s)", len(rules))

    for r in rules:
        file_path = r.get("path", "<unknown>")
        errs, warns = lint_rule(r)

        for msg in errs:
            error(msg, file=file_path)
        for msg in warns:
            warning(msg, file=file_path)

        total_errs += len(errs)
        total_warns += len(warns)

    logger.info("Lint complete: %d error(s), %d warning(s)", total_errs, total_warns)
    return total_errs, total_warns


# -----------------------
# Friendly tests validation
# -----------------------

ALLOWED_TEST_KEYS = {e.value for e in TestNameEnum}
RECOMMENDED_PLATFORM_KEYS = {"timeframe", "false_positive_threshold"}
OPTIONAL_PLATFORM_KEYS: set[str] = set()


def _validate_tests_friendly(tests_obj: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    errs: List[str] = []
    warns: List[str] = []

    if not isinstance(tests_obj, dict):
        return ["'tests' must be a mapping with a 'platforms' section"], warns

    platforms = tests_obj.get("platforms")
    if not isinstance(platforms, dict) or not platforms:
        return ["'tests.platforms' must be a non-empty mapping"], warns

    valid_platforms = {p.value for p in PlatformsEnum}

    for platform, body in platforms.items():
        if platform not in valid_platforms:
            errs.append(
                f"Unknown platform '{platform}' under tests.platforms. Expected one of: {', '.join(sorted(valid_platforms))}"
            )
            # Skip deeper checks for unknown platform
            continue

        if not isinstance(body, dict):
            errs.append(
                f"tests.platforms.{platform} must be a mapping of test cases (e.g., true_positive_test_raw)"
            )
            continue

        # Unknown key detection
        allowed_here = ALLOWED_TEST_KEYS | OPTIONAL_PLATFORM_KEYS | RECOMMENDED_PLATFORM_KEYS
        unknown_keys = [k for k in body.keys() if k not in allowed_here]
        for k in unknown_keys:
            if k == "false_positive_threshod":  # common misspelling
                errs.append(
                    f"Unknown key '{k}' in tests.platforms.{platform}. Did you mean 'false_positive_threshold'?"
                )
            else:
                errs.append(
                    f"Unknown key '{k}' in tests.platforms.{platform}. Allowed keys: {', '.join(sorted(allowed_here))}"
                )

        # Recommended keys
        if "timeframe" not in body:
            warns.append(f"Platform '{platform}' missing recommended 'timeframe'")
        if "false_positive_threshold" not in body:
            warns.append(
                f"Platform '{platform}' missing recommended 'false_positive_threshold'"
            )
        else:
            fpt = body.get("false_positive_threshold")
            if not isinstance(fpt, int) or fpt <= 0:
                errs.append(
                    f"tests.platforms.{platform}.false_positive_threshold must be a positive integer"
                )

        # At least one test case
        present_tests = [k for k in ALLOWED_TEST_KEYS if k in body]
        if not present_tests:
            errs.append(
                f"tests.platforms.{platform} must include at least one test case: {', '.join(sorted(ALLOWED_TEST_KEYS))}"
            )
        else:
            # Validate structure of provided test cases
            for test_key in present_tests:
                case = body.get(test_key, {})
                if not isinstance(case, dict):
                    errs.append(
                        f"tests.platforms.{platform}.{test_key} must be a mapping with 'hits' and 'attack_data'"
                    )
                    continue
                # hits
                hits = case.get("hits")
                if not isinstance(hits, int) or hits <= 0:
                    errs.append(
                        f"tests.platforms.{platform}.{test_key}.hits must be a positive integer"
                    )
                # attack_data
                ad = case.get("attack_data")
                if not isinstance(ad, dict):
                    errs.append(
                        f"tests.platforms.{platform}.{test_key}.attack_data must be a mapping with 'data', 'type', 'source'"
                    )
                else:
                    missing = [k for k in ("data", "type", "source") if k not in ad]
                    if missing:
                        errs.append(
                            f"tests.platforms.{platform}.{test_key}.attack_data missing keys: {', '.join(missing)}"
                        )
                    t = ad.get("type")
                    valid_types = {v.value for v in TestTypeEnum}
                    if t is not None and t not in valid_types:
                        errs.append(
                            f"tests.platforms.{platform}.{test_key}.attack_data.type must be one of: {', '.join(sorted(valid_types))}"
                        )

    return errs, warns
