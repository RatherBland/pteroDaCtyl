from typing import Any, Dict
from pathlib import Path
from logger import logger
from sigma.conversion.base import Backend, SigmaCollection
from sigma.plugins import InstalledSigmaPlugins
from platforms import elastic, splunk
from sigma.processing.pipeline import ProcessingPipeline
from utils import deep_merge


class Conversion:
    def __init__(self, config: dict, testing: bool = False) -> None:
        self._config = config
        self._platform_name = self._config.get("query_language")
        self._testing = testing        

    def get_pipeline_config_group(self, rule_content):
        """Retrieve the logsource config group name"""
        sigma_logsource_fields = ["category", "product", "service"]
        rule_logsource = {}

        for key, value in rule_content["logsource"].items():
            if key in sigma_logsource_fields:
                rule_logsource[key] = value

        group_match = None
        for key, value in self._config.get("logs").items():
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
            if self._testing:
                pipeline_config = [*self._config["logs"][pipeline_config_group].get("query_pipelines", [])]
            else:
                pipeline_config = [*self._config["logs"][pipeline_config_group].get("pipelines", []),
                               *self._config["logs"][pipeline_config_group].get("query_pipelines", [])]
            logger.info(f"Rule is supported; using pipeline config group '{pipeline_config_group}'")
        else:
            rule_supported = False
            logger.warning("Rule is not supported due to missing pipeline config group.")

        if rule_supported:
            try:
                backend_class = backends[backend_name]
            except KeyError:
                if backend_name is None:
                    logger.error(f"Conversion aborted: backend {backend_name} not found. No backend specified in platforms.toml.")
                else:
                    logger.error(f"Conversion aborted: backend {backend_name} not found. It has not been installed.")
                return None
            # if pipeline_config:
            if backend_name in ("esql", "eql"):
                index_config = self._config["logs"][pipeline_config_group]["indexes"]
                include_indexes = ProcessingPipeline().from_dict(
                    elastic.handle_indexes.add_indexes(index_config)
                )
                pipeline_resolver.add_pipeline_class(include_indexes)
                pipeline_config.append("add_elastic_indexes")
            elif backend_name in ("splunk"):
                index_config = self._config["logs"][pipeline_config_group]["indexes"]
                include_indexes = ProcessingPipeline().from_dict(
                    splunk.handle_indexes.add_indexes(index_config)
                )
                pipeline_resolver.add_pipeline_class(include_indexes)
                pipeline_config.append("add_splunk_indexes")
            pipeline = pipeline_resolver.resolve(pipeline_config)
            logger.info(f"Pipeline resolved successfully with config {pipeline_config}")
            # else:
            #     pipeline = None
            #     logger.info("No pipeline configuration provided.")
            backend: Backend = backend_class(processing_pipeline=pipeline)
            converted_rule = backend.convert(sigma_rule)
            logger.info(f"Conversion completed successfully for rule: {rule_content.get('title', 'Unknown title')}")
            return converted_rule
        else:
            logger.error("Conversion aborted: rule unsupported")
            return None


def convert_rules(
    rules: list[dict],
    organisations_config: Dict[str, Any],
    platform_config: Dict[str, Any],
) -> list[str]:
    logger.info("Starting conversion of sigma rules")
    organisations = organisations_config["organisations"]
    
    converted_rules = []

    for organisation, org_data in organisations.items():
        platforms = org_data.get("platform")
        if platforms:
            for platform, platform_data in platforms.items():
                logger.info(f"Processing organisation '{organisation}' for platform '{platform}'")
                org_platform_rule_config = deep_merge(
                    organisations[organisation]["platform"][platform],
                    platform_config["platforms"][platform]
                )
                logs = platform_data["logs"].keys()
                for log in logs:
                    matching_rules = [
                        rule
                        for rule in rules
                        if log
                        in {
                            rule["raw"]["logsource"].get("product"),
                            rule["raw"]["logsource"].get("service"),
                            rule["raw"]["logsource"].get("category"),
                        }
                    ]
                    logger.info(f"Found {len(matching_rules)} matching rule(s) for log '{log}' in organisation '{organisation}'")
                    for rule in matching_rules:
                        rule_organisations = rule['raw'].get("organisations")
                        if rule_organisations and organisation not in rule_organisations:
                            logger.info(f"Skipping rule '{rule['raw'].get('title', 'Unknown title')}' as organisation '{organisation}' is not in the permitted list")
                            continue

                        conversion = Conversion(org_platform_rule_config, organisation)
                        logger.info(f"Initialized Conversion for organisation '{organisation}'")
                        sigma_rule = conversion.init_sigma_rule(
                            Path(rule["path"]),
                            Path(f"organisations/{organisation}/filters")
                        )
                        result = conversion.convert_rule(rule["raw"], sigma_rule)
                        if result is not None:
                            logger.info(f"Rule converted successfully for organisation '{organisation}'")
                        else:
                            logger.error(f"Failed to convert rule for organisation '{organisation}'")
                        converted_rules.extend(result)
    return converted_rules
