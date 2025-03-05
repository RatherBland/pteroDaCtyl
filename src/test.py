from typing import Dict, Any, Optional, List, Tuple
from platforms.schema import Tests
from logger import logger
from pydantic import ValidationError
from platforms import elastic, splunk
from convert import Conversion
import copy


def validate_test_schema(rule: dict, platforms: list) -> Optional[Dict[str, Any]]:
    """
    Validate the test schema for each rule defined in the provided configuration.

    Returns:
        The rule dictionary if the test schema validates successfully; otherwise, None.
    """

    logger.info(f"Validating test schema for rule: {rule['path']}")

    # Retrieve the tests section from the rule definition, if present
    rule_test = (
        rule["raw"][0].get("tests")
        if rule["raw"][0].get("tests")
        else rule["raw"][1].get("tests")
    )

    if rule_test:
        rule_test_platforms = list(rule_test.get("platforms").keys())

        # Identify any platforms missing a test definition
        platforms_diff = set(platforms) - set(rule_test_platforms)

        if platforms_diff:
            logger.warning(
                f"{rule['path']} missing tests for the following platforms: {', '.join(platforms_diff)}"
            )

        try:
            # Validate the test schema against the Tests model
            Tests(**rule_test)
            logger.info(f"Test schema validated for rule: {rule['path']}")
            return rule
        except ValidationError as e:
            logger.error(
                f"Test schema validation failed for rule: {rule['path']}, with errors: {e}"
            )
    else:
        logger.warning(
            f"No test schema found for rule: {rule['path']}. This rule will not be tested."
        )

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
            logger.error(
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
    sigma_rule = conversion.init_sigma_rule(rule["path"])
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

    # Execute the platform-specific test function
    result_count = platform_functions[platform](
        data=data,
        index=index,
        query=converted_rule[0],
        config=platform_config["platforms"][platform],
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
        logger.error(
            f"Rule: {rule['path']} failed to test on platform: {platform} with result count: {result_count}. Expected: {expected_hits}"
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
