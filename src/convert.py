from typing import Any, Dict, List
from sigma.conversion.base import Backend, SigmaCollection
from pathlib import Path
from sigma.plugins import InstalledSigmaPlugins
import yaml
from platforms.elastic import add_indexes
from sigma.processing.pipeline import ProcessingPipeline


class Conversion:
    
    def __init__(self, org_product_rule_config, organisation: str) -> None:
        self._config = org_product_rule_config
        self._platform_name = self._config.get('query_language')
        self._filters_directory = f"organisations/{organisation}/filters"
        self._organisation = organisation
        
        
    def get_pipeline_config_group(self, rule_content):
        """Retrieve the logsource config group name
        Search a match in the configuration in platforms.x.pipelines and fetch the pipeline group name

        Return: a str with the pipeline config group
        """

        sigma_logsource_fields = ["category", "product", "service"]
        rule_logsource = {}

        for key, value in rule_content["logsource"].items():
            if key in sigma_logsource_fields:
                rule_logsource[key] = value

        for key, value in self._config.get('pipelines').items():
            value = {k: v for k, v in value.items()  if k in sigma_logsource_fields}
            if value == rule_logsource:
                # self.logger.info(f"Pipeline config found: {key}")
                group_match = key
                break
            else:
                group_match = None
        
        return group_match
        
    def init_sigma_rule(self, rule_path: Path, exceptions_dir: Path = None) -> SigmaCollection:
        
        if exceptions_dir:
            sigma_rule = SigmaCollection.load_ruleset([rule_path, exceptions_dir])
        else:
            sigma_rule = SigmaCollection.load_ruleset([rule_path])
            
        return sigma_rule
    
    def convert_rule(self, rule_content: dict, rule_path: Path, sigma_rule: SigmaCollection) -> None:
        plugins = InstalledSigmaPlugins.autodiscover()
        backends = plugins.backends
        pipeline_resolver = plugins.get_pipeline_resolver()
        pipeline_config_group = self.get_pipeline_config_group(rule_content)
        
        backend_name = self._platform_name
        
        if pipeline_config_group:
            rule_supported = True
            pipeline_config = self._config['pipelines'][pipeline_config_group]["pipelines"]
            # Format
            # if "format" in self._parameters[pipeline_config_group]:
            #     self._format = self._parameters[pipeline_config_group]["format"]
            # else:
            #     self._format = "default"
        else:
            rule_supported = False
            
        if rule_supported:
            backend_class = backends[backend_name]
            if pipeline_config:
                pipeline = pipeline_resolver.resolve(pipeline_config)
            else:
                pipeline = None
            include_indexes = ProcessingPipeline().from_dict(add_indexes(self._config['logs'][pipeline_config_group]['indexes'])) #TODO: Find a way to merge pipelines or alt method to add indexes
            
            backend: Backend = backend_class(processing_pipeline=pipeline)
            if backend_name in ("esql", "eql"):
                pass
            
            return backend.convert(sigma_rule)
                


def convert_sigma_rule(rule: Path, exceptions_dir: Path, backend) -> Any:
    """
    Convert a single sigma rule to an Elasticsearch ESQL query using the ESQL backend.
    
    Parameters:
    rule (Path): The path to the sigma rule file.
    exceptions_dir (Path): The path to the directory containing exception filters.

    Returns:
    Any: The result of the conversion process (likely an ESQL query).
    """
    sigma_rule = SigmaCollection.load_ruleset([rule, exceptions_dir])
    # backend = elasticsearch.ESQLBackend()
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


def convert_rules(organisations_config: Dict[str, Any], pterodactyl_config: Dict[str, Any], platform_config: Dict[str, Any]) -> None:
    """
    For each organisation and its products, convert sigma rules that match the log types defined.
    
    Parameters:
    organisations_config (Dict[str, Any]): Configuration dict for organisations, including their products.
    pterodactyl_config (Dict[str, Any]): Configuration dict that contains the base sigma rules directory.
    """
    rules = load_rules(pterodactyl_config['base']['sigma_rules_directory'])
    organisations = organisations_config['organisations']
    
    
    for organisation, org_data in organisations.items():
        products = org_data.get('product')
        for product, prod_data in products.items():
            
            # Takes the platform config and overwrites the platform config with the organisation's product config
            org_product_rule_config = {**platform_config['platforms'][product], **organisations[organisation]['product'][product]}
            
            # print(json.dumps(org_product_rule_config, indent=4))
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
                    
                    conversion = Conversion(org_product_rule_config, organisation)
                    sigma_rule = conversion.init_sigma_rule(Path(rule['path']), Path(f"organisations/{organisation}/filters"))
                    
                    return conversion.convert_rule(rule['rule'], Path(rule['path']), sigma_rule)
                    
