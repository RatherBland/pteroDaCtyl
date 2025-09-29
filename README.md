# pteroDaCtyl

PteroDaCtyl is a command-line tool that processes Sigma detection rules and converts or validates them against various security platforms (e.g., Elastic, Splunk, Sentinel). It offers a flexible, configurable architecture for both rule conversion and testing.

pteroDaCtyl addresses the problem of automating and standardizing the conversion and validation of generic Sigma detection rules for various security platforms. Specifically, it:

* **Automates Rule Conversion**: transforms Sigma rules into platform-specific formats (e.g., Elastic, Splunk) using configurable processing pipelines.

* **Validates Detection Rules**: tests rules against defined schemas to ensure that they include necessary test cases and are compliant with platform requirements.

* **False Positive Identification**: can execute rules against live environments to identify if rules are likely to generate large numbers of false positives or benign true positives to prevent low quality rules being deployed to production.

* **Supports Multi-Environment Configurations**: leverages environment-specific and global configurations, making it adaptable to different environments and requirements.

## Installation

You can install pteroDaCtyl using pip:

```bash
# Install from the repository
git clone https://github.com/yourusername/pteroDaCtyl.git
cd pteroDaCtyl
pip install -e .

# Or install directly from PyPI (if available)
# pip install pterodactyl
```

This will install the `pterodactyl` command-line tool and all its dependencies.

### Requirements

PteroDaCtyl requires:
- Python 3.8 or higher
- Dependencies listed in requirements.txt

## Acknowledgements
* **medioxor: dactical** https://github.com/medioxor/dactical/
Provided the idea and code for storing platform specific tests within Sigma rules and a whole suite of other feedback and direction. This project wouldn't be possible without them.

* **certeu: droid** https://github.com/certeu/droid/
The whole idea for this project came about after seeing the work produced to make droid. Many architecture decisions and code were directly influenced by the droid project.


## CLI Functions

The tool provides three primary CLI commands:

- **validate:**
  Validates detection rules by running tests defined in the YAML rule files against a test schema or in a live environment. This helps ensure that each rule includes the necessary test cases and that the schema is correct.

  Options:
  - `-f, --file`: Path to the detection rule to validate (optional)
  - `-p, --platform`: Platform to validate against (optional)
  - `-v, --verbose`: Enables verbose output
  - Required (mutually exclusive):
    - `--pre-compilation`: Validates tests schema and query against test data
    - `--post-compilation`: Executes rules against a live environment
  - `-e, --include-exceptions`: Includes environment level exceptions (default: True)

- **compile:**
  Converts Sigma rules into platform-specific detection formats. The conversion process uses configurable processing pipelines and backend modules (e.g., Elastic backend using ESQL) to output the rules in the appropriate format for your SIEM platform.

  Options:
  - `-f, --file`: Path to the detection rule to compile (optional)
  - `-o, --output`: Path to the output directory (optional)
  - `-v, --verbose`: Enables verbose output

- **deploy:**
  Deploys detection rules to security platforms. Currently only supports deploying to Elastic. If no options are provided PteroDaCtyl will use the information in the configuration files `environments.toml` and information from the rule to deploy to the correct place(s).

  Options:
  - `-f, --file`: Path to the detection rule to deploy (optional)
  - `-p, --platform`: Platform to deploy to (optional)
  - `-e, --environment`: Environment or organization to deploy to (optional)


## Architecture Overview

pteroDaCtyl is organized around a modular architecture:

- **Configuration:**
  Configuration files (in TOML format) provide settings for platforms, environments, and global defaults. These are loaded via helper functions (`load_organisations_config`, `load_pterodactyl_config`, `load_platform_config`).

- **CLI:**
  The CLI (e.g., in `pterodactyl/cli.py`) parses user commands and arguments. It supports subcommands for validation, compilation, and deployment. The CLI accepts an optional file parameter to target a specific rule file; if omitted, it uses a configured directory of Sigma rules.

- **Conversion:**
  The conversion logic (in `pterodactyl/convert.py`) leverages a pipeline architecture. A `Conversion` class resolves and applies processing pipelines based on the platform configuration. For instance, for Elastic, it might use pipelines configured with functions like `add_indexes` to ensure proper index handling.

- **Testing:**
  Testing logic (in `pterodactyl/test.py`) uses a Pydantic schema to validate rule test definitions. This ensures that each rule has at least one test and meets the required structure.

- **Platform-Specific Modules:**
  Platform-specific functionalities reside within `pterodactyl/platforms/`. For example:
  - `pterodactyl/platforms/elastic/` contains code to manage Elastic-specific pipelines and replay functionality.
  - `pterodactyl/platforms/splunk/` holds similar functionality for Splunk, including index management and document deletion.
  - The `schema.py` file under `pterodactyl/platforms/` defines Pydantic schemas used for validating test cases.

- **Utilities:**
  Utility functions (in `pterodactyl/utils.py`) handle common tasks such as loading rule files, deep merging configurations, etc.

## Directory Structure

Below is the current structure of the project, outlining the purpose of each directory and file:
```
pteroDaCtyl/                                  # Root folder of the project
├── README.md                                 # Project overview and instructions
├── platforms.toml                            # Global configuration for SIEM platforms
├── environments.toml                         # Global environments configuration
├── pterodactyl.toml                          # Global tool configuration (e.g., default rule paths)
├── requirements.txt                          # Python dependencies
├── setup.py                                  # Python package setup file
│
├── rules/                                    # Contains Sigma rule YAML files organized by cloud provider
│   ├── aws/                                  # AWS-related Sigma rule definitions
│   │   ├── auth_failed_cloudtrail.yml        # Example AWS CloudTrail rule
│   │   └── iam_administrator_policy_attachment.yml  # Additional AWS rule
│   └── azure/                                # Azure-related Sigma rule definitions
│       └── microsoft_365_multiple_failed_login_attempts_from_different_sources.yml
│
├── test_data/                                # Sample payloads for testing rule conversion and validation
│   ├── elastic/                              # Test data for Elastic
│   │   └── aws/                              # AWS-specific test data for Elastic rules
│   │       └── auth_failed_cloudtrail.json   # Example event data for Elastic testing
│   ├── sentinel/                             # Test data for Microsoft Sentinel
│   │   └── auth_failed_cloudtrail.csv        # Example event data for Sentinel testing
│   └── splunk/                               # Test data for Splunk (empty directory)
│
├── pipelines/                                # Pipeline configuration files used during rule conversion
│   └── elastic/                              # Elastic-specific pipelines
│       └── aws/                              # Pipelines for AWS CloudTrail rules in Elastic
│           ├── ecs_cloudtrail.yml            # Query pipeline configuration for pre-compilation or testing
│           └── esql_ndjson.yml               # Conversion pipeline configuration for Elastic
│
├── environments/                             # Environment-specific configuration files
│   ├── acme/                                 # Configuration for the ACME environment
│   │   └── filters/                          # Environment-level exceptions/filters
│   │       └── filter-out-sample-users.yml   # Example filter for ACME environment
│   └── ecorp/                                # Configuration for the ECORP environment
│       └── filters/                          # Environment-level exceptions/filters (empty directory)
│
├── output/                                   # Output directory for compiled rules
│   ├── acme/                                 # Output for ACME environment
│   │   └── elastic/                          # Output for Elastic platform
│   │       ├── aws/                          # AWS rules output
│   │       │   └── authorization_failed_for_cloudtrail_event.yaml
│   │       └── azure/                        # Azure rules output
│   │           └── microsoft_365_multiple_failed_login_attempts.yaml
│   └── ecorp/                                # Output for ECORP environment
│       └── splunk/                           # Output for Splunk platform
│           └── aws/                          # AWS rules output
│               └── authorization_failed_for_cloudtrail_event.yaml
│
├── containers/                               # Container configurations for testing
│   ├── elastic/                              # Elastic container configuration
│   │   ├── compose.yml                       # Docker Compose file for Elastic
│   │   └── elastic-security/                 # Elastic Security specific configuration
│   └── splunk/                               # Splunk container configuration
│       └── compose.yml                       # Docker Compose file for Splunk
│
└── pterodactyl/                              # Source code for pteroDaCtyl
    ├── __init__.py                           # Package initialization
    ├── cli.py                                # CLI entry point; routes 'validate', 'compile', and 'deploy' commands
    ├── config.py                             # Loads TOML configuration files
    ├── convert.py                            # Contains conversion logic and the Conversion class
    ├── logger.py                             # Logging functionality
    ├── utils.py                              # Utility functions (e.g., file loading, deep merge)
    ├── validate.py                           # Contains routines to validate Sigma rule tests
    └── platforms/                            # Platform-specific integration and adapters
        ├── __init__.py                       # Package initialization
        ├── schema.py                         # Pydantic schemas for validating test configurations
        ├── elastic/                          # Elastic-specific modules
        │   ├── __init__.py                   # Package initialization
        │   ├── deploy.py                     # Functions for deploying rules to Elastic
        │   ├── handle_indexes.py             # Functions for managing Elastic indexes
        │   └── replay.py                     # Functions for event indexing, querying, and deletion
        ├── sentinel/                         # Microsoft Sentinel-specific modules
        │   └── replay.py                     # Functions for event replay in Sentinel
        └── splunk/                           # Splunk-specific modules
            ├── __init__.py                   # Package initialization
            ├── handle_indexes.py             # Functions for managing Splunk indexes
            └── replay.py                     # Functions for event submission and deletion
```


## Usage Examples

### Validating Rules

To validate detection rules against the test schema (pre-compilation):

```bash
pterodactyl validate -f ./rules/aws/auth_failed_cloudtrail.yml --pre-compilation
```

To validate detection rules against a live environment (post-compilation):

```bash
pterodactyl validate -f ./rules/aws/auth_failed_cloudtrail.yml --post-compilation
```

If the `-f` parameter is omitted, the tool loads all rules from the directory specified in `pterodactyl.toml -> "base" -> "sigma_rules_directory"`.

### Compiling Rules

To compile a Sigma rule into a format suitable for your target SIEM platform:
```bash
pterodactyl compile -f ./rules/aws/auth_failed_cloudtrail.yml -o output
```

This command:

1. Loads the environment, pterodactyl, and platform-specific configurations.
2. Resolves and applies the correct processing pipelines.
3. Uses the appropriate backend (e.g., Elastic or Splunk) to output the converted rule.
4. Saves compiled rules to the `output` directory

### Using Raw Queries

PteroDaCtyl can bypass Sigma detection translation and inject a hand-crafted query by reading a `raw_query` field under the platform configuration inside a rule. When present, the converter skips Sigma expression building, copies your query into the compiled artifact, and still applies the configured pipelines so scheduling metadata, templates, and deployment formats remain consistent.

- Keep `platforms.<platform>.query_language` set to the desired backend (for example `esql` or `eql`) so the correct formatter runs.
- The converter still resolves a pipeline config group from the rule `logsource`; ensure a matching `[platforms.<platform>.logs.<group>]` entry exists in `platforms.toml` with the pipelines you expect.
- Index placeholders such as `{{index}}` (all indexes joined) and `{{index[0]}}`, `{{index[1]}}`, etc. are substituted from the active configuration before the query is emitted.
- `pterodactyl validate` respects the same shortcut, so validation and compilation both exercise the raw query instead of the Sigma `detection` block.

#### ESQL example

```yaml
title: Suspicious Login Burst
logsource:
  product: o365
platforms:
  elastic:
    query_language: esql
    raw_query: |
      FROM {{index}}
      | WHERE event.action == "login"
      | STATS count = COUNT(*) BY user.name
      | WHERE count > 5
```

If the matching logsource in `platforms.toml` defines `indexes = ["logs-o365", "logs-o365-archive"]`, the converter writes `FROM logs-o365,logs-o365-archive` into the compiled query while preserving the rule metadata.

#### EQL example

```yaml
title: Suspicious Dual-Stage Activity
logsource:
  product: endpoint
platforms:
  elastic:
    query_language: eql
    raw_query: |
      sequence by host.id with maxspan=5m
        [process where process.name == "cmd.exe" and process.args : "*rundll32*"]
        [network where network.direction == "outgoing" and network.port == 4444]
```

With `indexes = ["logs-endpoint-*", "logs-endpoint-archive"]` the placeholder resolves to the first index, and the generated detection artifact contains your EQL sequence alongside the usual schedule and tag metadata.

### Deploying Rules

To deploy a rule to Elastic in a specific environment:
```bash
pterodactyl deploy -f ./output/acme/elastic/aws/auth_failed_cloudtrail.json -p elastic -e acme
```

This command deploys the specified rule to the Elastic platform in the "acme" environment.

## Current Feature Set
* **Rule Validation**:
Uses Pydantic schemas to enforce the structure of test definitions in Sigma rule YAML files.

* **Rule Conversion**:
Converts Sigma rules into SIEM-specific configurations based on customizable processing pipelines.

* **Platform Integration**:
Supports integrations with Elastic and Splunk, including functions for replaying events, index management, and deletion of test documents.

* **Configurable Workflow**:
Merges organisation-specific and global configurations to dynamically adjust processing based on defined rules and platforms.

* **Environment-Specific Rule Overrides**:
Allows rules to have different configurations for different environments. This is particularly useful for adjusting severity levels or detection logic based on the specific needs of each environment.

## Example Rule with PteroDaCtyl Extensions

Below is an example rule file that demonstrates both standard Sigma fields and PteroDaCtyl-specific extensions:

```yaml
# Standard Sigma fields
title: Authorization failed for a CloudTrail event
name: authorization_failed_for_cloudtrail_event
id: e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a
description: Detects when a CloudTrail event fails to be authorized.
references:
  - https://www.trendmicro.com/cloudoneconformity/knowledge-base/aws/CloudWatchLogs/authorization-failures-alarm.html
author: user
date: 2024-02-01
modified: 2024-02-01
tags:
  - attack.T1078
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    - errorMessage: '*not authorized*'
  condition: selection
falsepositives:
  - As this is a general purpose rule, legitimate usage of the encode functionality will trigger some false positives. Apply additional filters accordingly
level: medium
fields:
  - eventTime
  - eventSource
  - eventName
  - errorMessage

# ===== PteroDaCtyl-specific extensions below =====

# PteroDaCtyl Extension: Environment-specific overrides
# This dictionary controls which environments the rule applies to and any environment-specific overrides
environments:
  acme:  # This rule will be applied to 'acme' environment with these overrides
    level: high  # Override severity level for acme environment
  ecorp:  # This rule will be applied to 'ecorp' environment with these overrides
    level: critical  # Override severity level for ecorp environment
    detection:  # Override detection logic for ecorp environment
      selection:
        - errorMessage: '*not authorized*'
        - errorMessage: '*access denied*'  # Additional pattern for ecorp
      condition: selection
  # Any environment not listed here will not have this rule applied

# PteroDaCtyl Extension: Platform-specific configurations
# platforms:  # Uncomment to specify which platforms this rule applies to
#   - elastic
#   - splunk

# PteroDaCtyl Extension: Output directory configuration
directory: aws  # Directory where the rule output will be stored

# PteroDaCtyl Extension: Test cases for validation
tests:
  platforms:
    elastic:  # Test cases for Elastic platform
      true_positive_test_file:  # Test case using a file
        hits: 1  # Expected number of hits
        attack_data:
          data: ./test_data/elastic/aws/auth_failed_cloudtrail.json
          type: file
          source: aws:cloudtrail
      true_positive_test_raw:  # Test case using raw data
        hits: 1
        attack_data:
          data: '[{"eventTime":"2022-08-10T22:04:13Z","errorMessage":"You are not authorized to perform this operation."}]'
          type: raw
          source: aws:cloudtrail
    splunk:  # Test cases for Splunk platform
      true_positive_test_raw:
        hits: 1
        attack_data:
          data: '{"eventTime": "2022-08-10T22:04:13Z", "errorMessage": "You are not authorized to perform this operation."}'
          type: raw
          source: aws:cloudtrail
```

### Environment-Specific Overrides

The `environments` dictionary serves two purposes:

1. **Restricting rule application**: The rule will only be applied to environments listed in this dictionary
2. **Customizing rule properties**: For each environment, you can override any rule property

For example:

```yaml
environments:
  acme:  # This rule will be applied to 'acme' with these overrides
    level: high
  ecorp:  # This rule will be applied to 'ecorp' with these overrides
    level: critical
  production: {}  # This rule will be applied to 'production' with no overrides
  # The rule will NOT be applied to any other environment
```

You can override any key in the rule, including complex structures like detection logic:

```yaml
environments:
  production:
    detection:  # Override detection logic for production
      selection:
        - errorMessage: '*not authorized*'
        - errorMessage: '*access denied*'  # Additional pattern
      condition: selection
```

When PteroDaCtyl processes a rule for a specific environment, it will:
1. Check if the environment is in the `environments` dictionary
2. If not, skip the rule for that environment
3. If yes, apply any overrides defined for that environment before converting the rule

## Future Feature Set

* **Extended Platform Support**:
Integrate additional backends such as Microsoft Sentinel and others.

* **Automated Testing**:
Integrate automated unit testing and continuous integration to ensure rule conversion and validation stability.

* **Automated Deployment**:
Integrate automated rule deployment
