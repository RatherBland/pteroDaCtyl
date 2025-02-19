from typing import Dict, Any, Optional
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
    rule_test = rule["raw"][0].get("tests") if rule["raw"][0].get("tests") else rule["raw"][1].get("tests")
    
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
        logger.warning(f"No test schema found for rule: {rule['path']}. This rule will not be tested.")
    
    return None


def test_rules(rules: list[dict], platform_config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    
    platforms = list(platform_config['platforms'].keys())
    
    platform_functions = {"elastic": elastic.replay.index_query_delete, "splunk": splunk.replay.index_query_delete}
    
    successful_tests = []
    failed_tests = []
    other_tests = []
    
    for rule in rules:
        validated_rule = validate_test_schema(rule, platforms)
        
        
        for platform in platforms:
            if validated_rule:
                # try:
                conversion = Conversion(config=platform_config['platforms'][platform], testing=True)
                sigma_rule = conversion.init_sigma_rule(rule['path'])
                converted_rule = conversion.convert_rule(rule['raw'][0], sigma_rule)
                pipeline_group = conversion.get_pipeline_config_group(rule['raw'][0])
                test_rule = copy.deepcopy(rule)
                test_rule['platform'] = platform
                if converted_rule:
                    
                    rule_tests = rule['raw'][0].get('tests') if rule['raw'][0].get('tests') else rule['raw'][1].get('tests')
                    
                    data = rule_tests['platforms'][platform]['true_positive_test_raw']['attack_data']['data']
                    index = platform_config['platforms'][platform]['logs'][pipeline_group]['indexes'][0]

                    result_count = platform_functions[platform](
                        data=data,
                        index=index,
                        query=converted_rule[0],
                        config=platform_config['platforms'][platform]

                    )
                    
                    if result_count == rule_tests['platforms'][platform]['true_positive_test_raw']['hits']:
                        logger.info(
                            f"Rule: {validated_rule['path']} tested successfully on platform: {platform} with result count: {result_count}"
                        )
                        test_rule['reason'] = f"Expected: {rule_tests['platforms'][platform]['true_positive_test_raw']['hits']}, Actual: {result_count}"
                        successful_tests.append(test_rule)
                    else:
                        logger.error(
                            f"Rule: {validated_rule['path']} failed to test on platform: {platform} with result count: {result_count}. Expected: {rule_tests['platforms'][platform]['true_positive_test_raw']['hits']}"
                        )
                        test_rule['reason'] = f"Expected: {rule_tests['platforms'][platform]['true_positive_test_raw']['hits']}, Actual: {result_count}"
                        failed_tests.append(test_rule)
                else:
                    test_rule['reason'] = "Rule could not be converted"
                    other_tests.append(test_rule)
            else:
                rule['reason'] = "Test schema validation failed"
                other_tests.append(rule)
                    
                        
    # Print tables for successful and failed tests

    
    # Determine dynamic width for the path column based on the largest path plus 5 spaces
    all_paths = [test['path'] for test in successful_tests + failed_tests + other_tests]
    max_path_len = max((len(path) for path in all_paths), default=0) + 5

    # Successful Tests Table
    print("\nSuccessful Tests:")
    header = f"{'Path':<{max_path_len}} {'Platform':<15} {'Result':<15} {'Success Reason':<15}"
    separator = "-" * len(header)
    print(header)
    if successful_tests:
        print(separator)
        for test in successful_tests:
            print(f"{test['path']:<{max_path_len}} {test['platform']:<15} {'Passed':<15} {test['reason']:<15}")
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
            print(f"{test['path']:<{max_path_len}} {test['platform']:<15} {'Failed':<15} {test['reason']:<15}")
    else:
        print("No failed tests.")
    
    print("\nOther Tests:")
    if other_tests:
        header = f"{'Path':<{max_path_len}} {'Platform':<15} {'Result':<15} {'Other Reason':<15}"
        separator = "-" * len(header)
        print(header)
        print(separator)
        for test in other_tests:
            print(f"{test['path']:<{max_path_len}} {test['platform']:<15} {'Failed':<15} {test['reason']:<15}")
    
                # except Exception as e:
                #     logger.error(
                #         f"Rule: {validated_rule['path']} failed to test on platform: {platform} with error: {e}"
                #     )
    print("\nTesting complete.\n")