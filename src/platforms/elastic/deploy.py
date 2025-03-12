import os
import requests
from ...logger import logger
from typing import Union
from ...utils import deep_merge


def deploy_rule(
    rule: dict, kibana_url: str, auth: Union[tuple, str] = (), verify: bool = False
):
    # Construct the API endpoint for detection rules
    rule_id = rule.get("id")
    rule_name = rule.get("name")
    endpoint = os.path.join(kibana_url, "api/detection_engine/rules")

    headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
    if isinstance(auth, str):
        headers["Authorization"] = f"ApiKey {auth}"
        auth_param = None
    else:
        auth_param = auth

    # Try creating the rule first
    response = requests.post(
        endpoint, headers=headers, auth=auth_param, json=rule, verify=verify
    )

    if response.status_code == 409:
        response = requests.put(
            endpoint, headers=headers, auth=auth_param, json=rule, verify=verify
        )
        if response.status_code in [200, 201]:
            logger.info(
                f"Updated rule {rule_name}:{rule_id} with status code {response.status_code}"
            )
        else:
            logger.error(f"Error updating rule {rule_name}:{rule_id}: {response.text}")
    elif response.status_code in [200, 201]:
        logger.info(
            f"Deployed rule '{rule_name}:{rule_id}' successfully with status code {response.status_code}"
        )
    else:
        logger.error(f"Error deploying rule {rule_name}:{rule_id}: {response.text}")

    return response


def deploy_rules(rules: list[dict], environment_config: dict, platform_config: dict):
    config = deep_merge(environment_config, platform_config)
    for rule in rules:
        kibana_url = config["kibana_base_url"]
        if "kibana_workspace_name" in config:
            kibana_url = os.path.join(
                kibana_url, "s", config["kibana_workspace_name"].lower()
            )
        if "api_key" in config:
            auth = config["api_key"]
        else:
            auth = (config["username"], config["password"])
        deploy_rule(
            rule=rule["raw"][0],
            kibana_url=kibana_url,
            auth=auth,
            verify=config.get("ssl_verify", True),
        )
