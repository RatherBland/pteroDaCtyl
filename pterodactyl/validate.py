from typing import Dict, Any, Optional, List, Tuple
from pterodactyl.platforms.schema import Tests
from pterodactyl.logger import logger, error, warning
from pydantic import ValidationError
from pterodactyl.platforms import elastic, splunk
from pterodactyl.convert import Conversion
import copy
from pterodactyl.convert import convert_rules
from pterodactyl.utils import deep_merge
from pterodactyl.utils import load_rules


def validate_test_schema(rule: dict, platforms: list) -> Optional[Dict[str, Any]]:
    """
    Validate the test schema for each rule defined in the provided configuration.

    Returns:
        The rule dictionary if the test schema validates successfully; otherwise, None.
    """
    logger.info(f"Validating test schema for rule: {rule['path']}")

    rule_test = None
    raw = rule.get("raw", [])
    if len(raw) > 0 and isinstance(raw[0], dict) and raw[0].get("tests"):
        rule_test = raw[0].get("tests")
    elif len(raw) > 1 and isinstance(raw[1], dict) and raw[1].get("tests"):
        rule_test = raw[1].get("tests")

    if not rule_test:
        warning(
            f"No test schema found for rule: {rule['path']}. This rule will not be tested.",
            file=rule["path"],
        )
        return None

    rule_test_platforms = list(rule_test.get("platforms", {}).keys())

    # Identify any platforms missing a test definition
    platforms_diff = set(platforms) - set(rule_test_platforms)
    if platforms_diff:
        warning(
            f"{rule['path']} missing tests for the following platforms: {', '.join(platforms_diff)}",
            file=rule["path"],
        )

    try:
        # Validate the test schema against the Tests model
        Tests(**rule_test)
        logger.info(f"Test schema validated for rule: {rule['path']}")
        return rule
    except ValidationError as e:
        error(
            f"Test schema validation failed for rule: {rule['path']}, with errors: {e}"
        )
        return None

    return None


def determine_test_platforms(
    platform_config: Dict[str, Any], specific_platform: Optional[str] = None
) -> List[str]:
    """
    Determine which platforms to test based on config and optional specific platform.

    Args:
        platform_config: Configuration dictionary containing platform settings
        specific_platform: Optional specific platform to test

    Returns:
        List of platform names to test
    """
    if specific_platform:
        if specific_platform in platform_config["platforms"]:
            return [specific_platform]
        else:
            error(
                f"Platform {specific_platform} is not available in the platform configuration."
            )
            return []
    else:
        return list(platform_config["platforms"].keys())


def execute_rule_test(
    rule: Dict[str, Any],
    platform: str,
    platform_config: Dict[str, Any],
    platform_functions: Dict[str, Any],
) -> Tuple[Dict[str, Any], str]:
    """
    Execute a test for a specific rule on a specific platform.

    Args:
        rule: The rule dictionary
        platform: Platform name to test on
        platform_config: Platform configuration
        platform_functions: Dictionary mapping platforms to test functions

    Returns:
        Tuple of (test_rule, result_category) where result_category is one of:
        "success", "failed", or "other"
    """
    conversion = Conversion(config=platform_config["platforms"][platform], testing=True)
    
    # Check if rule has raw_query
    platform_config_in_rule = rule["raw"][0].get('platforms', {}).get(platform, {})
    has_raw_query = 'raw_query' in platform_config_in_rule
    
    if has_raw_query:
        # For raw queries, skip Sigma collection initialization
        sigma_rule = None
    else:
        sigma_rule = conversion.init_sigma_rule(rule["raw"])
    
    converted_rule = conversion.convert_rule(rule["raw"][0], sigma_rule)
    pipeline_group = conversion.get_pipeline_config_group(rule["raw"][0])

    test_rule = copy.deepcopy(rule)
    test_rule["platform"] = platform

    if not converted_rule:
        test_rule["reason"] = "Rule could not be converted"
        return test_rule, "other"

    rule_tests = (
        rule["raw"][0].get("tests")
        if rule["raw"][0].get("tests")
        else rule["raw"][1].get("tests")
    )

    # Skip test if the platform is not defined in the rule's test section
    if platform not in rule_tests["platforms"]:
        test_rule["reason"] = f"No test defined for platform {platform}"
        return test_rule, "other"

    data = rule_tests["platforms"][platform]["true_positive_test_raw"]["attack_data"][
        "data"
    ]
    index = platform_config["platforms"][platform]["logs"][pipeline_group]["indexes"][0]

    # Extract query language from rule configuration
    query_language = (
        rule["raw"][0]
        .get("platforms", {})
        .get(platform, {})
        .get("query_language", "esql")
    )

    # Execute the platform-specific test function
    result_count = platform_functions[platform](
        data=data,
        index=index,
        query=converted_rule[0],
        config=platform_config["platforms"][platform],
        query_language=query_language,
    )

    expected_hits = rule_tests["platforms"][platform]["true_positive_test_raw"]["hits"]
    test_rule["reason"] = f"Expected: {expected_hits}, Actual: {result_count}"

    # Compare the results
    if result_count == expected_hits:
        logger.info(
            f"Rule: {rule['path']} tested successfully on platform: {platform} with result count: {result_count}"
        )
        return test_rule, "success"
    else:
        error(
            f"Rule: {rule['path']} test failed on platform: {platform} with result count: {result_count}"
        )
        return test_rule, "failed"


def format_test_results(
    successful_tests: List[Dict[str, Any]],
    failed_tests: List[Dict[str, Any]],
    other_tests: List[Dict[str, Any]],
) -> None:
    """
    Format and print the results of rule tests as tables.

    Args:
        successful_tests: List of tests that passed
        failed_tests: List of tests that failed
        other_tests: List of tests that couldn't be executed
    """
    # Determine dynamic width for the path column
    all_paths = [
        test.get("path", "") for test in successful_tests + failed_tests + other_tests
    ]
    max_path_len = max((len(path) for path in all_paths), default=0) + 5

    # Successful Tests Table
    print("\nSuccessful Tests:")
    header = f"{'Path':<{max_path_len}} {'Platform':<15} {'Result':<15} {'Success Reason':<15}"
    separator = "-" * len(header)
    print(header)
    if successful_tests:
        print(separator)
        for test in successful_tests:
            print(
                f"{test.get('path', ''):<{max_path_len}} {test.get('platform', ''):<15} {'Passed':<15} {test.get('reason', ''):<15}"
            )
    else:
        print("No successful tests.")

    # Failed Tests Table
    print("\nFailed Tests:")
    header = f"{'Path':<{max_path_len}} {'Platform':<15} {'Result':<15} {'Failure Reason':<15}"
    separator = "-" * len(header)
    print(header)
    print(separator)
    if failed_tests:
        for test in failed_tests:
            print(
                f"{test.get('path', ''):<{max_path_len}} {test.get('platform', ''):<15} {'Failed':<15} {test.get('reason', ''):<15}"
            )
    else:
        print("No failed tests.")

    # Other Tests Table
    print("\nOther Tests:")
    if other_tests:
        header = f"{'Path':<{max_path_len}} {'Platform':<15} {'Result':<15} {'Other Reason':<15}"
        separator = "-" * len(header)
        print(header)
        print(separator)
        for test in other_tests:
            print(
                f"{test.get('path', ''):<{max_path_len}} {test.get('platform', ''):<15} {'Failed':<15} {test.get('reason', ''):<15}"
            )

    print("\nTesting complete.\n")


def validate_rules(
    rules: List[Dict[str, Any]],
    platform_config: Dict[str, Any],
    specific_platform: Optional[str] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Validate rules against test criteria for specified platforms.

    Args:
        rules: List of rule dictionaries to validate
        platform_config: Configuration containing platform settings
        specific_platform: Optional specific platform to test

    Returns:
        Dictionary with test results categorized as "successful", "failed", and "other"
    """
    logger.info("Starting rule validation and testing")

    # Determine platforms to test
    platforms = determine_test_platforms(platform_config, specific_platform)
    if not platforms:
        return {"successful": [], "failed": [], "other": []}

    # Define platform-specific test functions
    platform_functions = {
        "elastic": elastic.replay.index_query_delete,
        "splunk": splunk.replay.index_query_delete,
    }

    # Result collections
    successful_tests = []
    failed_tests = []
    other_tests = []

    # Process each rule
    for rule in rules:
        # Validate test schema
        validated_rule = validate_test_schema(rule, platforms)

        if validated_rule:
            # Test rule on each platform
            for platform in platforms:
                test_rule, result_category = execute_rule_test(
                    validated_rule, platform, platform_config, platform_functions
                )

                # Store result in appropriate collection
                if result_category == "success":
                    successful_tests.append(test_rule)
                elif result_category == "failed":
                    failed_tests.append(test_rule)
                else:
                    other_tests.append(test_rule)
        else:
            # Rule schema validation failed
            rule_copy = copy.deepcopy(rule)
            rule_copy["reason"] = "Test schema validation failed"
            other_tests.append(rule_copy)

    # Format and output results
    format_test_results(successful_tests, failed_tests, other_tests)

    # Return results for possible further processing
    return {
        "successful": successful_tests,
        "failed": failed_tests,
        "other": other_tests,
    }


def format_live_test_results(rules: List[Dict[str, Any]]) -> None:
    """
    Format and print the results of live rule tests as tables.

    Args:
        rules: List of converted rules with test results
    """
    # Group rules by environment
    rules_by_env = {}
    for rule in rules:
        env = rule.get("environment", "unknown")
        if env not in rules_by_env:
            rules_by_env[env] = []
        rules_by_env[env].append(rule)

    # Determine dynamic width for columns
    all_names = [rule.get("name", "") for rule in rules]
    all_paths = [rule.get("directory", "") for rule in rules]
    max_name_len = max((len(name) for name in all_names), default=0) + 5
    max_path_len = (
        max((len(f"rules/{path}") for path in all_paths), default=0)
        + 5
        + max_name_len
        + 4
    )

    # Calculate a reasonable width for the query column
    query_width = 50  # default width for query display

    print("\nLive Test Results:")

    # Print results by environment
    for env, env_rules in rules_by_env.items():
        print(f"\nEnvironment: {env}")
        header = f"{'Rule':<{max_name_len}} {'Path':<{max_path_len}} {'Platform':<15} {'Result Count':<15} {'Query':<{query_width}}"
        separator = "-" * len(header)

        print(header)
        print(separator)

        for rule in env_rules:
            rule_name = rule.get("name", "")
            rule_path = f"rules/{rule.get('directory', '')}/{rule.get('name', '')}.yml"
            platform = rule.get("platform", "")
            result_count = rule.get("result_count", 0)

            # Truncate the query if it's too long to display nicely
            query = rule.get("rule", "")

            print(
                f"{rule_name:<{max_name_len}} {rule_path:<{max_path_len}} {platform:<15} {result_count:<15} {query:<{query_width}}"
            )

    print("\nLive testing complete.\n")


def live_test_rules(
    rules: list[dict],
    environments_config: Dict[str, Any],
    platform_config: Dict[str, Any],
    include_exceptions: bool = True,
    verbose: bool = False,
    path_to_rules: str = "rules",
):
    platform_functions = {
        "elastic": elastic.replay.execute_query,
        "splunk": splunk.replay.execute_query,
    }

    converted_rules = convert_rules(
        rules,
        environments_config,
        platform_config,
        testing=True,
        include_exceptions=include_exceptions,
    )

    for rule in converted_rules:
        platform = rule["platform"]
        environment = rule["environment"]

        env_platform_rule_config = deep_merge(
            environments_config["environments"][environment]["platform"][platform],
            platform_config["platforms"][platform],
        )

        # Extract query language and other metadata from the original rule configuration
        raw_rule = load_rules(path_to_rules, rule_name=rule["name"])

        query_language = (
            raw_rule[0]["raw"][0]
            .get("platforms", {})
            .get(platform, {})
            .get("query_language", "esql")
        )

        merged_unconverted_rule = deep_merge(
            raw_rule[0]["raw"][0]
            .get("environments", {})
            .get(environment, {}),
            raw_rule[0]["raw"][0],
        )

        timeframe = (
            merged_unconverted_rule.get("tests", {})
            .get("platforms", {})
            .get(platform, {})
            .get("timeframe", "90d")
        )

        elastic_indexes = None
        if platform == "elastic":
            logs_config = env_platform_rule_config.get("logs", {})
            logsource = merged_unconverted_rule.get("logsource", {})
            candidate_keys = [
                value.lower()
                for value in (
                    logsource.get("service"),
                    logsource.get("product"),
                    logsource.get("category"),
                )
                if isinstance(value, str)
            ]

            if isinstance(logs_config, dict):
                for candidate in candidate_keys:
                    log_config = logs_config.get(candidate)
                    if isinstance(log_config, dict) and log_config.get("indexes"):
                        elastic_indexes = log_config.get("indexes")
                        break

                if not elastic_indexes and len(logs_config) == 1:
                    only_log_config = next(iter(logs_config.values()))
                    if isinstance(only_log_config, dict):
                        elastic_indexes = only_log_config.get("indexes")

            if query_language.lower() == "eql" and not elastic_indexes:
                warning(
                    "EQL rule executed without a matching index configuration; execution will skip."
                )

        execute_kwargs = {
            "query": rule["rule"],
            "config": env_platform_rule_config,
            "query_language": query_language,
            "timeframe": timeframe,
        }

        if platform == "elastic" and elastic_indexes:
            execute_kwargs["index"] = elastic_indexes

        result_count = platform_functions[platform](**execute_kwargs)
        rule["result_count"] = result_count

        platform_tests = (
            merged_unconverted_rule.get("tests", {})
            .get("platforms", {})
            .get(platform)
        )

        threshold = None
        if isinstance(platform_tests, dict):
            threshold = platform_tests.get("false_positive_threshold")

        if threshold is None:
            warning(
                f"False positive threshold not configured for rule {rule['name']} in environment {environment} on platform {platform}; skipping threshold evaluation."
            )
        elif result_count > threshold:
            error(
                f"Rule {rule['name']} in environment {environment} on platform {platform} exceeded false positive threshold with {result_count} results."
            )

    if verbose:
        format_live_test_results(converted_rules)

    return converted_rules
