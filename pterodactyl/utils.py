from typing import Any, Dict, List
from pathlib import Path
import yaml
import json
from pterodactyl.logger import error


def load_rules(path_to_rules: str, rule_name: str = "") -> List[Dict[str, Any]]:
    """
    Load sigma rules from a given directory or a single file and optionally filter by rule name.

    Parameters:
    path_to_rules (str): The directory path or file path where sigma rule YAML files are stored.
    rule_name (str): Optional sigma rule "name" field to filter the results.

    Returns:
    List[Dict[str, Any]]: A list of dictionaries, each containing:
      - "path": the file path of the rule as a string.
      - "raw": the parsed YAML content of the rule.
    """
    path = Path(path_to_rules)

    if path.is_file():
        candidates = [path]
    else:
        candidates = list(path.rglob("*.y*ml"))

    files: List[Dict[str, Any]] = []
    for rule_file in candidates:
        with rule_file.open("rb") as handle:
            raw_documents = list(yaml.safe_load_all(handle))

        if rule_name:
            primary_doc = raw_documents[0] if raw_documents else {}
            if primary_doc.get("name") != rule_name:
                continue

        files.append({"path": str(rule_file), "raw": raw_documents})

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
        error(
            f"Rule data is not in JSON format. {environment}/{platform}/{directory}/{filename}.yaml could not be written."
        )
