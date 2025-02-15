from typing import Any, Dict, List
from pathlib import Path
import yaml



def load_rules(sigma_rules_directory: str) -> List[Dict[str, Any]]:
    """
    Load sigma rules from a given directory.

    Parameters:
    sigma_rules_directory (str): The directory path where sigma rule YAML files are stored.

    Returns:
    List[Dict[str, Any]]: A list of dictionaries, each containing:
      - "path": the file path of the rule as a string.
      - "rule": the parsed YAML content of the rule.
    """
    path = Path(sigma_rules_directory)
    return [
        {"path": str(rule_file), "raw": yaml.safe_load(open(rule_file, "rb"))}
        for rule_file in path.rglob("*.y*ml")
    ]
    
def deep_merge(primary: dict, secondary: dict) -> dict:
    """
    Merge two dictionaries recursively.
    Keys from primary overwrite keys in secondary only when there is a conflict.
    If both values are dictionaries, merge them recursively rather than overwriting.
    """
    result = secondary.copy()
    for key, value in primary.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = deep_merge(value, result[key])
        else:
            result[key] = value
    return result