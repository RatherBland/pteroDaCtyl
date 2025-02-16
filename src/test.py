from typing import Dict, Any, Optional
from platforms.schema import Tests
from logger import logger
from pydantic import ValidationError
from platforms import elastic, splunk
from convert import Conversion


def validate_test_schema(rule: dict, platforms: list) -> Optional[Dict[str, Any]]:
    """
    Validate the test schema for each rule defined in the provided configuration.

    Returns:
        The rule dictionary if the test schema validates successfully; otherwise, None.
    """
    
    logger.info(f"Validating test schema for rule: {rule['path']}")
    
    # Retrieve the tests section from the rule definition, if present
    rule_test = rule["raw"].get("tests")
    
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
    
    
    for rule in rules:
        validated_rule = validate_test_schema(rule, platforms)
        
        for platform in platforms:
            if validated_rule:
                # try:
                conversion = Conversion(config=platform_config['platforms'][platform], testing=True)
                sigma_rule = conversion.init_sigma_rule(rule['path'])
                converted_rule = conversion.convert_rule(rule['raw'], sigma_rule)
                pipeline_group = conversion.get_pipeline_config_group(rule['raw'])
                if converted_rule:
                    data = rule['raw']['tests']['platforms'][platform]['true_positive_test_raw']['attack_data']['data']
                    index = platform_config['platforms'][platform]['logs'][pipeline_group]['indexes'][0]

                    result_count = platform_functions[platform](
                        data=data,
                        index=index,
                        query=converted_rule[0]

                    )
                    if result_count == rule['raw']['tests']['platforms'][platform]['true_positive_test_raw']['hits']:
                        logger.info(
                            f"Rule: {validated_rule['path']} tested successfully on platform: {platform} with result count: {result_count}"
                        )
                    else:
                        logger.error(
                            f"Rule: {validated_rule['path']} failed to test on platform: {platform} with result count: {result_count}. Expected: {rule['raw']['tests']['platforms'][platform]['true_positive_test_raw']['hits']}"
                        )
                # except Exception as e:
                #     logger.error(
                #         f"Rule: {validated_rule['path']} failed to test on platform: {platform} with error: {e}"
                #     )