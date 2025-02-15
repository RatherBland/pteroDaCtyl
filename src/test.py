from utils import load_rules
from platforms.schema import Tests
from logger import logger
from pydantic import ValidationError

def validate_test_schema(pterodactyl_config, platform_config):
    
    rules = load_rules(pterodactyl_config['base']["sigma_rules_directory"])
    
    for rule in rules:
        
        rule_test = rule["rule"].get("tests")
        
        if rule_test:
            
            try:
                test = Tests(**rule_test)
                logger.info(f"Test schema validated for rule: {rule['path']}")
                return rule
            except ValidationError as e:
                logger.error(f"Test schema validation failed for rule: {rule['path']}, with the following errors: {e}")
        
        else:
            logger.warning(f"No test schema found for rule: {rule['path']}. This rule will not be tested.")