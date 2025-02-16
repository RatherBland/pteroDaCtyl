# pteroDaCtyl

pteroDaCtyl is a command-line tool that processes Sigma detection rules and converts or validates them against various security platforms (e.g., Elastic, Splunk, Sentinel). It offers a flexible, configurable architecture for both rule conversion and testing. pterDaCtyl supports multi-org and multi-tenanted environments.

## CLI Functions

The tool provides two primary CLI commands:

- **validate (or test):**  
  Validates detection rules by running tests defined in the YAML rule files against a test schema. This helps ensure that each rule includes the necessary test cases and that the schema is correct.

- **convert:**  
  Converts Sigma rules into platform-specific detection formats. The conversion process uses configurable processing pipelines and backend modules (e.g., Elastic backend using ESQL) to output the rules in the appropriate format for your SIEM platform.


## Architecture Overview

pteroDaCtyl is organized around a modular architecture:

- **Configuration:**  
  Configuration files (in TOML format) provide settings for platforms, organisations, and global defaults. These are loaded via helper functions (`load_organisations_config`, `load_pterodactyl_config`, `load_platform_config`).

- **CLI:**  
  The CLI (e.g., in `src/cli.py`) parses user commands and arguments. It supports subcommands for both validation/testing and conversion. The CLI accepts an optional file parameter to target a specific rule file; if omitted, it uses a configured directory of Sigma rules.

- **Conversion:**  
  The conversion logic (in `src/convert.py`) leverages a pipeline architecture. A `Conversion` class resolves and applies processing pipelines based on the platform configuration. For instance, for Elastic, it might use pipelines configured with functions like `add_indexes` to ensure proper index handling.

- **Testing:**  
  Testing logic (in `src/test.py`) uses a Pydantic schema to validate rule test definitions. This ensures that each rule has at least one test and meets the required structure.

- **Platform-Specific Modules:**  
  Platform-specific functionalities reside within `src/platforms/`. For example:
  - `src/platforms/elastic/` contains code to manage Elastic-specific pipelines and replay functionality.
  - `src/platforms/splunk/` holds similar functionality for Splunk, including index management and document deletion.
  - The `schema.py` file under `src/platforms/` defines Pydantic schemas used for validating test cases.

- **Utilities:**  
  Utility functions (in `src/utils.py`) handle common tasks such as loading rule files, deep merging configurations, etc.

## Directory Structure

Below is an example structure outlining the purpose of each directory and file:
```
pteroDaCtyl/                                  # Root folder of the project
├── README.md                                 # Project overview and instructions
├── platforms.toml                            # Global configuration for SIEM platforms
├── organisations.toml                        # Global organisation configuration (overrides may also reside in organisations/)
├── pterodactyl.toml                          # Global tool configuration (e.g., default rule paths)
├── requirements.txt                          # Python dependencies
├── rules/                                    # Contains Sigma rule YAML files organized by category or platform
│   ├── aws/                                  # AWS-related Sigma rule definitions
│   │   ├── auth_failed_cloudtrail.yml        # Example AWS CloudTrail rule
│   │   └── other_aws_rule.yml                  # Additional AWS rule files
│   ├── windows/                              # Windows-related Sigma rule definitions
│   │   └── sample_windows_rule.yml           # Example rule for Windows events
│   └── linux/                                # Linux-related Sigma rule definitions
│       └── sample_linux_rule.yml             # Example rule for Linux events
├── test_data/                                # Sample payloads and files for testing rule conversion and validation
│   ├── elastic/                              # Test data for Elastic
│   │   └── aws/                              # AWS-specific test data for Elastic rules
│   │       └── auth_failed_cloudtrail.json   # Example event data for Elastic testing
│   └── splunk/                               # Test data for Splunk
│       └── aws/                              # AWS-specific test data for Splunk rules
│           └── auth_failed_cloudtrail.json   # Example event data for Splunk testing
├── pipelines/                                # Pipeline configuration files used during rule conversion
│   ├── elastic/                              # Elastic-specific pipelines
│   │   └── aws/                              # Pipelines for AWS CloudTrail rules in Elastic
│   │       ├── ecs_cloudtrail.yml            # Query pipeline configuration for pre-compilation or testing
│   │       └── esql_ndjson_cloudtrail.yml      # Conversion pipeline configuration for Elastic
│   └── splunk/                               # Splunk-specific pipelines
│       └── aws/                              # Pipelines for AWS CloudTrail rules in Splunk
│           └── some_splunk_pipeline.yml        # Example pipeline configuration for Splunk
├── organisations/                            # Organisation-specific configuration files to override global settings
│   ├── org1/                               
│   │   └── filters/                          # Organisational level execeptions/filters to apply during rule conversion
|   |       └── filter-out-sample.yml/         
│   └── org2/                                  
└── src/                                      # Source code for pteroDaCtyl
    ├── cli.py                                # CLI entry point; routes 'validate/test' and 'convert' commands
    ├── config.py                             # Loads TOML configuration files
    ├── convert.py                            # Contains conversion logic and the Conversion class
    ├── test.py                               # Contains routines to validate Sigma rule tests using Pydantic schemas
    ├── utils.py                              # Utility functions (e.g., file loading, deep merge)
    └── platforms/                            # Platform-specific integration and adapters
        ├── schema.py                         # Pydantic schemas for validating test configurations
        ├── elastic/                          # Elastic-specific modules
        │   └── replay.py                     # Functions for event indexing, querying, and deletion in Elastic
        └── splunk/                           # Splunk-specific modules
            └── replay.py                     # Functions for index management, event submission, and deletion in Splunk
```


## Usage Examples

### Validating Rules

To validate detection rules against the test schema:

```bash
python src/cli.py validate -f ./rules/aws/auth_failed_cloudtrail.yml
```

If the `-f` parameter is omitted, the tool loads all rules from the directory specified in `pterodactyl.toml -> "base" -> "sigma_rules_directory"`.

## Converting Rules

To convert a Sigma rule into a format suitable for your target SIEM platform:
```bash
python src/cli.py convert -f ./rules/aws/auth_failed_cloudtrail.yml
```

This command:

1. Loads the organisation, pterodactyl, and platform-specific configurations.
2. Resolves and applies the correct processing pipelines.
3. Uses the appropriate backend (e.g., Elastic or Splunk) to output the converted rule.

## Current Feature Set
* **Rule Validation**:
Uses Pydantic schemas to enforce the structure of test definitions in Sigma rule YAML files.

* **Rule Conversion**:
Converts Sigma rules into SIEM-specific configurations based on customizable processing pipelines.

* **Platform Integration**:
Supports integrations with Elastic and Splunk, including functions for replaying events, index management, and deletion of test documents.

* **Configurable Workflow**:
Merges organisation-specific and global configurations to dynamically adjust processing based on defined rules and platforms.

## Future Feature Set

* **Extended Platform Support**:
Integrate additional backends such as Microsoft Sentinel and others.

* **Automated Testing**:
Integrate automated unit testing and continuous integration to ensure rule conversion and validation stability.

* **Automated Deployment**:
Integrate automated rule deployment