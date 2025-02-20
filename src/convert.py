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
        
        rule_content = rule_content[0] if type(rule_content) is list else rule_content

        for key, value in rule_content["logsource"].items():
            if key in sigma_logsource_fields:
                rule_logsource[key] = value

        group_match = None
        try:
            for key, value in self._config.get("logs").items():
                filtered_value = {k: v for k, v in value.items() if k in sigma_logsource_fields}
                if filtered_value.items() <= rule_logsource.items():
                    group_match = key
                    break
            if not group_match:
                logger.warning(f"No matching pipeline config group found for rule with logsource {rule_logsource}")
            return group_match
        except AttributeError:
            logger.error(f"No logsources were found the platform {self._platform_name}. Please check the platforms.toml")
            return None

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
        
        rule_content = rule_content[0] if type(rule_content) is list else rule_content
        
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

            backend: Backend = backend_class(processing_pipeline=pipeline)
            converted_rule = backend.convert(sigma_rule)
            logger.info(f"Conversion completed successfully for rule: {rule_content.get('title', 'Unknown title')}")
            return converted_rule
        else:
            logger.error("Conversion aborted: rule unsupported")
            return None


def convert_rules(
    rules: list[dict],
    environments_config: Dict[str, Any],
    platform_config: Dict[str, Any],
) -> list[str]:
    logger.info("Starting conversion of sigma rules")
    environments = environments_config["environments"]
    converted_rules = []

    for environment, env_data in environments.items():
        platforms = env_data.get("platform")
        if not platforms:
            continue

        for platform, platform_data in platforms.items():
            logger.info(
                f"Processing environment '{environment}' for platform '{platform}'"
            )

            # Merge platform configuration for the current environment
            env_platform_rule_config = deep_merge(
                environments[environment]["platform"][platform],
                platform_config["platforms"][platform],
            )
            logs = platform_data["logs"].keys()

            for log in logs:
                # Filter rules matching the current log by comparing logsource fields
                matching_rules = [
                    rule
                    for rule in rules
                    if log
                    in {
                        rule["raw"][0]["logsource"].get("product"),
                        rule["raw"][0]["logsource"].get("service"),
                        rule["raw"][0]["logsource"].get("category"),
                    }
                ]
                logger.info(
                    f"Found {len(matching_rules)} matching rule(s) for log '{log}' in environment '{environment}'"
                )

                for rule in matching_rules:
                    rule_raw = rule["raw"][0]
                    rule_environments = rule_raw.get("environments")
                    rule_directory = rule_raw.get("directory", rule_raw["logsource"].get("product", log))

                    if rule_environments and environment not in rule_environments:
                        logger.info(
                            f"Skipping rule '{rule_raw.get('title', 'Unknown title')}' as environment '{environment}' is not in the permitted list"
                        )
                        continue

                    conversion = Conversion(env_platform_rule_config)
                    logger.info(f"Initialized Conversion for environment '{environment}'")

                    sigma_rule = conversion.init_sigma_rule(
                        Path(rule["path"]),
                        Path(f"environments/{environment}/filters")
                    )
                    result = conversion.convert_rule(rule["raw"], sigma_rule)

                    if result is not None:
                        logger.info(f"Rule converted successfully for environment '{environment}'")

                        result_dict = {
                            "environment": environment,
                            "platform": platform,
                            "directory": rule_directory,
                            "name": rule_raw.get("name", rule_raw.get("id")),
                            "rule": result[0],
                            
                        }
                        converted_rules.append(result_dict)
                    else:
                        logger.error(f"Failed to convert rule for environment '{environment}'")

    # if converted_rules:
    #     headers = ["name", "environment", "platform", "directory", "rule"]
    #     # Calculate maximum width for each column
    #     widths = {h: len(h) for h in headers}
    #     for rule in converted_rules:
    #         for h in headers:
    #             widths[h] = max(widths[h], len(str(rule[h])))

    #     # Create header and separator rows
    #     header_row = " | ".join(h.ljust(widths[h]) for h in headers)
    #     separator = "-+-".join("-" * widths[h] for h in headers)

    #     print("\n")
    #     print(header_row)
    #     print(separator)

    #     # Print each row with proper alignment
    #     for rule in converted_rules:
    #         row = " | ".join(str(rule[h]).ljust(widths[h]) for h in headers)
    #         print(row)
    # else:
    #     print("No converted rules to display.")

    return converted_rules
