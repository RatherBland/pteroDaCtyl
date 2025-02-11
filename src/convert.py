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
        self._platform_name = self._config.get("query_language")
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

        for key, value in self._config.get("pipelines").items():
            value = {k: v for k, v in value.items() if k in sigma_logsource_fields}
            if value == rule_logsource:
                group_match = key
                break
            else:
                group_match = None

        return group_match

    def init_sigma_rule(
        self, rule_path: Path, exceptions_dir: Path = None
    ) -> SigmaCollection:
        if exceptions_dir:
            sigma_rule = SigmaCollection.load_ruleset([rule_path, exceptions_dir])
        else:
            sigma_rule = SigmaCollection.load_ruleset([rule_path])

        return sigma_rule

    def convert_rule(self, rule_content: dict, sigma_rule: SigmaCollection) -> None:
        plugins = InstalledSigmaPlugins.autodiscover()
        backends = plugins.backends
        pipeline_resolver = plugins.get_pipeline_resolver()
        pipeline_config_group = self.get_pipeline_config_group(rule_content)

        backend_name = self._platform_name

        if pipeline_config_group:
            rule_supported = True
            pipeline_config = self._config["pipelines"][pipeline_config_group][
                "pipelines"
            ]

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
                if backend_name in ("esql", "eql"):
                    include_indexes = ProcessingPipeline().from_dict(
                        add_indexes(
                            self._config["logs"][pipeline_config_group]["indexes"]
                        )
                    )
                    pipeline_resolver.add_pipeline_class(include_indexes)
                    pipeline_config.append("add_elastic_indexes")

                pipeline = pipeline_resolver.resolve(pipeline_config)
            else:
                pipeline = None

            backend: Backend = backend_class(processing_pipeline=pipeline)
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
    return [
        {"path": str(rule_file), "rule": yaml.safe_load(open(rule_file, "rb"))}
        for rule_file in path.rglob("*.y*ml")
    ]


def convert_rules(
    organisations_config: Dict[str, Any],
    pterodactyl_config: Dict[str, Any],
    platform_config: Dict[str, Any],
) -> None:
    """
    For each organisation and its products, convert sigma rules that match the log types defined.

    Parameters:
    organisations_config (Dict[str, Any]): Configuration dict for organisations, including their products.
    pterodactyl_config (Dict[str, Any]): Configuration dict that contains the base sigma rules directory.
    """
    rules = load_rules(pterodactyl_config["base"]["sigma_rules_directory"])
    organisations = organisations_config["organisations"]

    for organisation, org_data in organisations.items():
        products = org_data.get("product")
        for product, prod_data in products.items():
            # Takes the platform config and overwrites the platform config with the organisation's product config
            org_product_rule_config = {
                **platform_config["platforms"][product],
                **organisations[organisation]["product"][product],
            }

            logs = prod_data["logs"].keys()
            for log in logs:
                matching_rules = [
                    rule
                    for rule in rules
                    if log
                    in {
                        rule["rule"]["logsource"].get("product"),
                        rule["rule"]["logsource"].get("service"),
                        rule["rule"]["logsource"].get("category"),
                    }
                ]

                for rule in matching_rules:
                    conversion = Conversion(org_product_rule_config, organisation)
                    sigma_rule = conversion.init_sigma_rule(
                        Path(rule["path"]),
                        Path(f"organisations/{organisation}/filters"),
                    )

                    return conversion.convert_rule(rule["rule"], sigma_rule)
