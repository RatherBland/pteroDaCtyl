from typing import Any, Dict
from pathlib import Path
from logger import logger
from sigma.conversion.base import Backend, SigmaCollection
from sigma.plugins import InstalledSigmaPlugins
from platforms.elastic.handle_indexes import add_indexes
from sigma.processing.pipeline import ProcessingPipeline
from utils import load_rules


class Conversion:
    def __init__(self, org_product_rule_config: dict, organisation: str) -> None:
        self._config = org_product_rule_config
        self._platform_name = self._config.get("query_language")
        self._filters_directory = f"organisations/{organisation}/filters"
        self._organisation = organisation
        logger.info(f"Initialized Conversion for organisation '{organisation}'")

    def get_pipeline_config_group(self, rule_content):
        """Retrieve the logsource config group name"""
        sigma_logsource_fields = ["category", "product", "service"]
        rule_logsource = {}

        for key, value in rule_content["logsource"].items():
            if key in sigma_logsource_fields:
                rule_logsource[key] = value

        group_match = None
        for key, value in self._config.get("pipelines").items():
            filtered_value = {k: v for k, v in value.items() if k in sigma_logsource_fields}
            if filtered_value == rule_logsource:
                group_match = key
                break
        if not group_match:
            logger.warning(f"No matching pipeline config group found for rule with logsource {rule_logsource}")
        return group_match

    def init_sigma_rule(
        self, rule_path: Path, exceptions_dir: Path = None
    ) -> SigmaCollection:
        if exceptions_dir:
            sigma_rule = SigmaCollection.load_ruleset([rule_path, exceptions_dir])
            logger.info(f"Loaded sigma rule from '{rule_path}' with exceptions directory '{exceptions_dir}'")
        else:
            sigma_rule = SigmaCollection.load_ruleset([rule_path])
            logger.info(f"Loaded sigma rule from '{rule_path}' without exceptions directory")
        
        return sigma_rule

    def convert_rule(self, rule_content: dict, sigma_rule: SigmaCollection) -> None:
        logger.info(f"Starting conversion for rule: {rule_content.get('title', 'Unknown title')}")
        plugins = InstalledSigmaPlugins.autodiscover()
        backends = plugins.backends
        pipeline_resolver = plugins.get_pipeline_resolver()
        pipeline_config_group = self.get_pipeline_config_group(rule_content)
        backend_name = self._platform_name

        if pipeline_config_group:
            rule_supported = True
            pipeline_config = [*self._config["pipelines"][pipeline_config_group]["pipelines"],
                               *self._config["pipelines"][pipeline_config_group]["query_pipelines"]]
            logger.info(f"Rule is supported; using pipeline config group '{pipeline_config_group}'")
        else:
            rule_supported = False
            logger.warning("Rule is not supported due to missing pipeline config group.")

        if rule_supported:
            backend_class = backends[backend_name]
            if pipeline_config:
                if backend_name in ("esql", "eql"):
                    include_indexes = ProcessingPipeline().from_dict(
                        add_indexes(self._config["logs"][pipeline_config_group]["indexes"])
                    )
                    pipeline_resolver.add_pipeline_class(include_indexes)
                    pipeline_config.append("add_elastic_indexes")
                pipeline = pipeline_resolver.resolve(pipeline_config)
                logger.info(f"Pipeline resolved successfully with config {pipeline_config}")
            else:
                pipeline = None
                logger.info("No pipeline configuration provided.")
            backend: Backend = backend_class(processing_pipeline=pipeline)
            converted_rule = backend.convert(sigma_rule)
            logger.info(f"Conversion completed successfully for rule: {rule_content.get('title', 'Unknown title')}")
            return converted_rule
        else:
            logger.error("Conversion aborted: rule unsupported")
            return None


def convert_rules(
    organisations_config: Dict[str, Any],
    pterodactyl_config: Dict[str, Any],
    platform_config: Dict[str, Any],
) -> list[str]:
    logger.info("Starting conversion of sigma rules for organisations.")
    rules = load_rules(pterodactyl_config["base"]["sigma_rules_directory"])
    organisations = organisations_config["organisations"]

    for organisation, org_data in organisations.items():
        products = org_data.get("product")
        if products:
            for product, prod_data in products.items():
                logger.info(f"Processing organisation '{organisation}' for product '{product}'")
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
                    logger.info(f"Found {len(matching_rules)} matching rule(s) for log '{log}' in organisation '{organisation}'")
                    for rule in matching_rules:
                        rule_organisations = rule['rule'].get("organisations")
                        if rule_organisations and organisation not in rule_organisations:
                            logger.info(f"Skipping rule '{rule['rule'].get('title', 'Unknown title')}' as organisation '{organisation}' is not in the permitted list")
                            continue

                        conversion = Conversion(org_product_rule_config, organisation)
                        sigma_rule = conversion.init_sigma_rule(
                            Path(rule["path"]),
                            Path(f"organisations/{organisation}/filters")
                        )
                        result = conversion.convert_rule(rule["rule"], sigma_rule)
                        if result is not None:
                            logger.info(f"Rule converted successfully for organisation '{organisation}'")
                        else:
                            logger.error(f"Failed to convert rule for organisation '{organisation}'")
                        return result
