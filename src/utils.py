from typing import Any, Dict, List
from pathlib import Path
import yaml
import json
from .logger import logger


def load_rules(path_to_rules: str) -> List[Dict[str, Any]]:
    """
    Load sigma rules from a given directory.

    Parameters:
    path_to_rules (str): The directory path where sigma rule YAML files are stored.

    Returns:
    List[Dict[str, Any]]: A list of dictionaries, each containing:
      - "path": the file path of the rule as a string.
      - "rule": the parsed YAML content of the rule.
    """
    path = Path(path_to_rules)
    if path_to_rules.endswith(".yml") or path_to_rules.endswith(".yaml"):
        files = [
            {
                "path": path_to_rules,
                "raw": list(yaml.safe_load_all(open(path_to_rules, "rb"))),
            }
        ]
    else:
        files = [
            {
                "path": str(rule_file),
                "raw": list(yaml.safe_load_all(open(rule_file, "rb"))),
            }
            for rule_file in path.rglob("*.y*ml")
        ]
    return files


def deep_merge(primary: dict, secondary: dict) -> dict:
    """
    Merge two dictionaries recursively.
    Keys from primary overwrite keys in secondary only when there is a conflict.
    If both values are dictionaries, merge them recursively rather than overwriting.
    """
    result = secondary.copy()
    for key, value in primary.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key.lower()] = deep_merge(value, result[key])
        else:
            result[key.lower()] = value
    return result


def write_converted_rule(
    rule_data: dict,
    environment: str,
    platform: str,
    directory: str,
    filename: str,
    output_dir: str = "output",
) -> None:
    """
    Write the converted rule to a file following the format:
    output/<environment>/<platform>/<directory>/<rule>

    Parameters:
    rule_data (dict): The rule content to write.
    environment (str): The environment name.
    platform (str): The platform name.
    directory (str): A subdirectory name.
    filename (str): The name of the rule file (e.g., "example.yaml").
    """

    output_path = Path(f"{output_dir}/{environment}/{platform}/{directory}")
    output_path.mkdir(parents=True, exist_ok=True)
    file_path = Path(f"{output_path}/{filename}.yaml")
    try:
        with file_path.open("w") as f:
            yaml.dump(json.loads(rule_data), f)
    except json.decoder.JSONDecodeError:
        logger.error(
            f"Rule data is not in JSON format. {environment}/{platform}/{directory}/{filename}.yaml could not be written."
        )
