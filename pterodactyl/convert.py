from typing import Any, Dict, List
from pathlib import Path
from pterodactyl.logger import logger, error, warning
from sigma.conversion.base import Backend, SigmaCollection
from sigma.plugins import InstalledSigmaPlugins
from pterodactyl.platforms import elastic, splunk
from sigma.processing.pipeline import ProcessingPipeline
from pterodactyl.utils import deep_merge
import yaml
import re


def substitute_indexes(raw_query: str, indexes: list) -> str:
    """
    Substitute index placeholders in raw queries with actual index values.
    
    Supports:
    - {{index}} - replaced with first index or comma-separated list if multiple
    - {{index[0]}}, {{index[1]}}, etc. - replaced with specific index by position
    
    Args:
        raw_query: Query string containing index placeholders
        indexes: List of index patterns from environment configuration
        
    Returns:
        Query string with placeholders replaced by actual index values
    """
    if not indexes:
        logger.warning("No indexes provided for substitution")
        return raw_query
    
    # Replace {{index}} with first index or comma-separated list
    if len(indexes) == 1:
        raw_query = re.sub(r'\{\{index\}\}', indexes[0], raw_query)
    else:
        # For multiple indexes, join with comma (platform-specific formatting may be needed)
        raw_query = re.sub(r'\{\{index\}\}', ','.join(indexes), raw_query)
    
    # Replace indexed placeholders {{index[n]}}
    for i, index in enumerate(indexes):
        raw_query = re.sub(rf'\{{\{{index\[{i}\]\}}\}}', index, raw_query)
    
    # Log if any placeholders remain (might indicate missing indexes)
    remaining_placeholders = re.findall(r'\{\{index(?:\[\d+\])?\}\}', raw_query)
    if remaining_placeholders:
        logger.warning(f"Unresolved index placeholders remain: {remaining_placeholders}")
    
    return raw_query


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
                filtered_value = {
                    k: v for k, v in value.items() if k in sigma_logsource_fields
                }
                if filtered_value.items() <= rule_logsource.items():
                    group_match = key
                    break
            if not group_match:
                return error(
                    f"No matching pipeline config group found for rule with logsource {rule_logsource}"
                )
            return group_match
        except AttributeError:
            return error(
                f"No logsources were found the platform {self._platform_name}. Please check the platforms.toml"
            )
            return None

    def init_sigma_rule(
        self, rules: list[dict], filters: list[dict] = None
    ) -> SigmaCollection:
        if filters:
            sigma_rule = SigmaCollection.from_dicts(rules + filters)

        else:
            sigma_rule = SigmaCollection.from_dicts(rules)

        return sigma_rule

    def convert_rule(self, rule_content: dict, sigma_rule: SigmaCollection | None) -> None:
        rule_content = rule_content[0] if type(rule_content) is list else rule_content

        logger.info(
            f"Starting conversion for rule: {rule_content.get('title', 'Unknown title')}"
        )
        
        # Determine current platform
        current_platform = None
        if self._config.get("elasticsearch_hosts"):
            current_platform = "elastic"
        elif self._config.get("host"):  # Splunk config
            current_platform = "splunk"
        
        # Check for raw query in platform configuration
        platform_config = rule_content.get('platforms', {}).get(current_platform, {})
        raw_query = platform_config.get('raw_query')
        
        # Setup common pipeline infrastructure
        plugins = InstalledSigmaPlugins.autodiscover()
        backends = plugins.backends
        pipeline_resolver = plugins.get_pipeline_resolver()
        pipeline_config_group = self.get_pipeline_config_group(rule_content)
        
        try:
            backend_name = rule_content['platforms'][current_platform]['query_language']
        except KeyError:
            backend_name = self._platform_name
            
        if raw_query and pipeline_config_group:
            # Handle raw query with pipeline formatting
            logger.info(f"Processing raw query for platform '{current_platform}'")
            
            # Get indexes for substitution
            indexes = self._config["logs"][pipeline_config_group].get("indexes", [])
            
            # Substitute index placeholders in raw query
            converted_query = substitute_indexes(raw_query, indexes)
            
            # For raw queries, we need to create a minimal Sigma structure
            # and apply only the formatting pipelines
            if not self._testing:
                # Apply formatting pipelines (e.g., esql_ndjson.yml)
                pipeline_config = self._config["logs"][pipeline_config_group].get("pipelines", [])
                
                # Create a minimal Sigma rule for metadata preservation
                minimal_rule_dict = {
                    "title": rule_content.get("title", "Unknown"),
                    "id": rule_content.get("id", "00000000-0000-0000-0000-000000000000"),
                    "description": rule_content.get("description", ""),
                    "author": rule_content.get("author", ""),
                    "references": rule_content.get("references", []),
                    "tags": rule_content.get("tags", []),
                    "falsepositives": rule_content.get("falsepositives", []),
                    "level": rule_content.get("level", "medium"),
                    "logsource": rule_content.get("logsource", {}),
                    "detection": {"selection": {"field": "value"}, "condition": "selection"},  # Dummy detection for Sigma
                    "custom_attributes": rule_content  # Preserve full rule for template access
                }
                
                # Create SigmaCollection with minimal rule
                sigma_rule = SigmaCollection.from_dicts([minimal_rule_dict])
                
                # Setup pipeline with formatting only
                if backend_name in ("esql", "eql"):
                    include_indexes = ProcessingPipeline().from_dict(
                        elastic.handle_indexes.add_indexes(indexes)
                    )
                    pipeline_resolver.add_pipeline_class(include_indexes)
                    pipeline_config.append("add_elastic_indexes")
                
                pipeline = pipeline_resolver.resolve(pipeline_config)
                backend_class = backends[backend_name]
                backend: Backend = backend_class(processing_pipeline=pipeline)
                
                # Convert through backend to apply formatting
                # The backend will apply the template, but we need to inject our raw query
                converted_rules = backend.convert(sigma_rule)
                
                # Replace the dummy query with our actual raw query in the output
                if converted_rules and len(converted_rules) > 0:
                    # Parse the JSON output and replace the query field
                    import json
                    result_dict = json.loads(converted_rules[0])
                    result_dict["query"] = converted_query
                    return [json.dumps(result_dict)]
                
                return [converted_query]
            else:
                # For testing, return raw query directly
                return [converted_query]

        if pipeline_config_group:
            rule_supported = True
            if self._testing:
                pipeline_config = [
                    *self._config["logs"][pipeline_config_group].get(
                        "query_pipelines", []
                    )
                ]
            else:
                pipeline_config = [
                    *self._config["logs"][pipeline_config_group].get("pipelines", []),
                    *self._config["logs"][pipeline_config_group].get(
                        "query_pipelines", []
                    ),
                ]
            logger.info(
                f"Rule is supported; using pipeline config group '{pipeline_config_group}'"
            )
        else:
            rule_supported = False
            warning(
                "Rule is not supported due to missing pipeline config group.",
                file=getattr(rule_content, "source", "unknown"),
            )

        if rule_supported:
            try:
                backend_class = backends[backend_name]
            except KeyError:
                if backend_name is None:
                    return error(
                        f"Conversion aborted: backend {backend_name} not found. No backend specified in platforms.toml."
                    )
                else:
                    return error(
                        f"Conversion aborted: backend {backend_name} not found. It has not been installed."
                    )
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
            logger.info(
                f"Conversion completed successfully for rule: {rule_content.get('title', 'Unknown title')}"
            )
            return converted_rule
        else:
            return error("Conversion aborted: rule unsupported")


def find_matching_rules(rules: list[dict], log: str) -> list[dict]:
    """
    Find rules that match a specific log type by comparing logsource fields.

    Args:
        rules: List of rule dictionaries
        log: Log type to match against

    Returns:
        List of matching rules
    """
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
    logger.info(f"Found {len(matching_rules)} matching rule(s) for log '{log}'")
    return matching_rules


def convert_rule_for_environment(
    rule: dict,
    environment: str,
    platform: str,
    env_platform_rule_config: Dict[str, Any],
    testing: bool = False,
    include_exceptions: bool = True,
) -> Dict[str, Any]:
    """
    Convert a single rule for a specific environment and platform.

    Args:
        rule: Rule dictionary
        environment: Environment name
        platform: Platform name
        env_platform_rule_config: Merged platform configuration
        testing: Flag to indicate if conversion is for testing
        include_exceptions: Whether to include organization level exceptions

    Returns:
        Dictionary with converted rule information or None if conversion fails
    """
    import copy

    # Create a deep copy of the rule to avoid modifying the original
    rule = copy.deepcopy(rule)
    rule_raw = rule["raw"]
    rule_environments = rule_raw[0].get("environments")
    rule_directory = rule_raw[0].get(
        "directory", rule_raw[0]["logsource"].get("product", "unknown")
    )

    # Check if environments is a dictionary and apply overrides
    if isinstance(rule_environments, dict):
        # Skip if environment not in rule's environments dictionary
        if environment not in rule_environments:
            logger.info(
                f"Skipping rule '{rule_raw[0].get('title', 'Unknown title')}' as environment '{environment}' is not in the environments dictionary"
            )
            return None

        # Apply environment-specific overrides
        env_overrides = rule_environments[environment]
        logger.info(f"Applying environment-specific overrides for '{environment}'")

        # Apply each override to the rule
        for key, value in env_overrides.items():
            if key != "environments":  # Avoid recursive overrides
                rule_raw[0][key] = value
                logger.info(
                    f"Applied override for key '{key}' in environment '{environment}'"
                )

    # Initialize converter and convert rule
    conversion = Conversion(env_platform_rule_config, testing=testing)
    logger.info(f"Initialized Conversion for environment '{environment}'")

    # Check if rule has raw_query - if so, skip Sigma processing
    platform_config = rule_raw[0].get('platforms', {}).get(platform, {})
    has_raw_query = 'raw_query' in platform_config
    
    if has_raw_query:
        # For raw queries, skip Sigma collection initialization
        logger.info(f"Rule uses raw query for platform '{platform}', skipping Sigma processing")
        sigma_rule = None
    else:
        # Standard Sigma processing
        # Check if environment filters directory exists and should be used
        filters_path = Path(f"environments/{environment}/filters")

        # Load all yaml files from filters_path into a flattened list
        filters = []
        if filters_path.exists():
            for filter_file in filters_path.rglob("*.y*ml"):
                with open(filter_file, "rb") as f:
                    # Add all documents from each YAML file to the filters list
                    filters.extend(list(yaml.safe_load_all(f)))
        logger.info(f"Loaded {len(filters)} filter documents from {filters_path}")
        if not include_exceptions or not filters_path.exists():
            if not include_exceptions:
                logger.info("Skipping exceptions for rule as requested")
            elif not filters_path.exists():
                warning(
                    f"Filters directory {filters_path} does not exist for environment '{environment}'",
                    file=str(filters_path),
                )

            # sigma_rule = conversion.init_sigma_rule(Path(rule["path"]))
            sigma_rule = conversion.init_sigma_rule(rule_raw)
            logger.info(
                f"Loaded sigma rule from '{Path(rule['path'])}' without exceptions directory"
            )
        else:
            # sigma_rule = conversion.init_sigma_rule(Path(rule["path"]), filters_path)
            sigma_rule = conversion.init_sigma_rule(rule_raw, filters)
            logger.info(
                f"Loaded sigma rule from '{rule['path']}' with exceptions directory '{filters_path}'"
            )

    result = conversion.convert_rule(rule_raw, sigma_rule)

    if result is not None:
        logger.info(f"Rule converted successfully for environment '{environment}'")
        return {
            "environment": environment,
            "platform": platform,
            "directory": rule_directory,
            "name": rule_raw[0].get("name", rule_raw[0].get("id")),
            "rule": result[0],
        }
    else:
        logger.error(f"Failed to convert rule for environment '{environment}'")
        return None


def print_conversion_results(converted_rules: List[Dict[str, Any]]) -> None:
    """
    Format and print conversion results as a table.

    Args:
        converted_rules: List of converted rule dictionaries
    """
    if not converted_rules:
        print("No converted rules to display.")
        return

    headers = ["name", "environment", "platform", "directory", "rule"]

    # Calculate maximum width for each column
    widths = {h: len(h) for h in headers}
    for rule in converted_rules:
        for h in headers:
            if h == "rule" and len(str(rule[h])) > 50:
                # Truncate rule display for better table formatting
                widths[h] = max(widths[h], 50)
            else:
                widths[h] = max(widths[h], len(str(rule[h])))

    # Create header and separator rows
    header_row = " | ".join(h.ljust(widths[h]) for h in headers)
    separator = "-+-".join("-" * widths[h] for h in headers)

    print("\n")
    print(header_row)
    print(separator)

    # Print each row with proper alignment
    for rule in converted_rules:
        row_items = []
        for h in headers:
            if h == "rule" and len(str(rule[h])) > 50:
                # Truncate long rules and add ellipsis
                row_items.append(f"{str(rule[h])[:47]}...".ljust(widths[h]))
            else:
                row_items.append(str(rule[h]).ljust(widths[h]))
        row = " | ".join(row_items)
        print(row)


def convert_rules(
    rules: list[dict],
    environments_config: Dict[str, Any],
    platform_config: Dict[str, Any],
    testing: bool = False,
    verbose: bool = False,
    include_exceptions: bool = True,
) -> list[dict]:
    """
    Convert sigma rules based on environments and platforms configuration.

    Args:
        rules: List of rule dictionaries
        environments_config: Configuration for environments
        platform_config: Configuration for platforms
        testing: Flag to indicate if conversion is for testing
        verbose: Whether to output detailed information
        include_exceptions: Whether to include organization level exceptions

    Returns:
        List of converted rule dictionaries
    """
    logger.info("Starting conversion of sigma rules")
    environments = environments_config["environments"]
    converted_rules = []

    # Iterate through environments and platforms
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

            # Process each log type
            for log in logs:
                # Find rules matching the current log
                matching_rules = find_matching_rules(rules, log)

                # Convert each matching rule for this environment/platform
                for rule in matching_rules:
                    result = convert_rule_for_environment(
                        rule,
                        environment,
                        platform,
                        env_platform_rule_config,
                        testing=testing,
                        include_exceptions=include_exceptions,
                    )
                    if result:
                        converted_rules.append(result)

    # Print formatted results
    if verbose:
        print_conversion_results(converted_rules)

    return converted_rules
