from typing import Any, Dict, List
from sigma.conversion.base import SigmaCollection
from sigma.backends import elasticsearch
from pathlib import Path
import yaml

def convert_sigma_rule(rule: Path, exceptions_dir: Path) -> Any:
    """
    Convert a single sigma rule to an Elasticsearch SQL query using the ESQL backend.
    
    Parameters:
    rule (Path): The path to the sigma rule file.
    exceptions_dir (Path): The path to the directory containing exception filters.

    Returns:
    Any: The result of the conversion process (likely an ESQL query).
    """
    sigma_rule = SigmaCollection.load_ruleset([rule, exceptions_dir])
    backend = elasticsearch.ESQLBackend()
    return backend.convert(sigma_rule)


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
    return [{
        "path": str(rule_file),
        "rule": yaml.safe_load(open(rule_file, "rb"))
    } for rule_file in path.rglob("*.y*ml")]


def convert_rules(organisations_config: Dict[str, Any], pterodactyl_config: Dict[str, Any]) -> None:
    """
    For each organisation and its products, convert sigma rules that match the log types defined.
    
    Parameters:
    organisations_config (Dict[str, Any]): Configuration dict for organisations, including their products.
    pterodactyl_config (Dict[str, Any]): Configuration dict that contains the base sigma rules directory.
    """
    rules = load_rules(pterodactyl_config['base']['sigma_rules_directory'])
    organisations = organisations_config['organisations']
    
    for organisation, org_data in organisations.items():
        try:
            products = org_data['product']
            for product, prod_data in products.items():
                logs = prod_data['logs'].keys()
                for log in logs:
                    matching_rules = [
                        rule for rule in rules
                        if log in {
                            rule['rule']['logsource'].get('product'),
                            rule['rule']['logsource'].get('service'),
                            rule['rule']['logsource'].get('category')
                        }
                    ]
                    
                    for rule in matching_rules:
                        return convert_sigma_rule(Path(rule['path']), Path(f"organisations/{organisation}/filters"))
        except KeyError:
            print(f"No products assigned to {organisation} in organisations.toml")
