from pterodactyl.config import (
    load_environments_config,
    load_pterodactyl_config,
    load_platform_config,
)
from pterodactyl.convert import convert_rules
from pterodactyl.validate import (
    validate_rules,
    live_test_rules,
)
import argparse
from pterodactyl.utils import load_rules, write_converted_rule
from pterodactyl.platforms.elastic.deploy import deploy_rules
from pterodactyl.lint import lint_ruleset
from pterodactyl.logger import error, set_exit_on_error


def main():
    try:
        environments_config = load_environments_config()
        pterodactyl_config = load_pterodactyl_config()
        platform_config = load_platform_config()
    except FileNotFoundError as exc:
        error(f"Failed to load configuration: {exc}")
        raise SystemExit(1)

    parser = argparse.ArgumentParser(description="pteroDaCtyl CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    validate_parser = subparsers.add_parser(
        "validate", help="Validate detection rules against available security platforms"
    )
    validate_parser.add_argument(
        "-f", "--file", help="The path to the detection to validate", required=False
    )
    validate_parser.add_argument(
        "-p", "--platform", help="The platform to validate against", required=False
    )
    validate_parser.add_argument(
        "-v", "--verbose", help="Verbose output", action="store_true", default=False
    )

    validate_parser.add_argument(
        "--continue-on-failure",
        help=(
            "Log validation failures without exiting. Useful for production pipelines "
            "where new false positives should not break builds."
        ),
        action="store_true",
        default=False,
    )

    validate_group = validate_parser.add_mutually_exclusive_group(required=True)
    validate_group.add_argument(
        "--pre-compilation",
        help="Validate tests schema and query against test data. Does not factor in environment level exceptions. Primary purpose is to validate that detection logic is sound against a predefined data set. ",
        action="store_true",
    )
    validate_group.add_argument(
        "--post-compilation",
        help="Execute rules against a live environment. Will include environment level exceptions. Primary purpose is to identify how many false positives will be seen in an uncontrolled environment",
        action="store_true",
    )

    validate_parser.add_argument(
        "-e",
        "--include-exceptions",
        help="Include evironment level exceptions when processing rules (default: True)",
        action="store_true",
        default=True,
    )

    convert_parser = subparsers.add_parser(
        "compile", help="Compile detection rules to security platforms format"
    )
    convert_parser.add_argument(
        "-f", "--file", help="The path to the detection to convert", required=False
    )
    convert_parser.add_argument(
        "-o", "--output", help="The path to the output directory", required=False
    )
    convert_parser.add_argument(
        "-v", "--verbose", help="Verbose output", action="store_true"
    )

    deploy_parser = subparsers.add_parser(
        "deploy", help="Deploy detection rules to security platforms"
    )
    deploy_parser.add_argument(
        "-f", "--file", help="The path to the detection to deploy", required=False
    )
    deploy_parser.add_argument(
        "-p", "--platform", help="The platform to deploy to", required=False
    )
    deploy_parser.add_argument(
        "-e",
        "--environment",
        help="Environment or organisation to deploy to",
        required=False,
    )

    # Lint subcommand
    lint_parser = subparsers.add_parser(
        "lint", help="Lint Sigma rules for required and recommended extensions"
    )
    lint_parser.add_argument(
        "-f", "--file", help="The path to the detection(s) to lint", required=False
    )

    args = parser.parse_args()

    if hasattr(args, "file") and args.file:
        path_to_rules = args.file
    else:
        path_to_rules = pterodactyl_config["base"]["sigma_rules_directory"]

    if args.command == "validate":
        if args.continue_on_failure:
            set_exit_on_error(False)
        if args.pre_compilation:
            validate_rules(
                rules=load_rules(path_to_rules),
                platform_config=platform_config,
                specific_platform=args.platform,
            )
        elif args.post_compilation:
            live_test_rules(
                rules=load_rules(path_to_rules),
                environments_config=environments_config,
                platform_config=platform_config,
                include_exceptions=args.include_exceptions,
                verbose=args.verbose,
                path_to_rules=path_to_rules,
            )

    elif args.command == "compile":
        output_rules = convert_rules(
            load_rules(path_to_rules),
            environments_config,
            platform_config,
            verbose=args.verbose,
        )
        if args.output:
            for rule in output_rules:
                write_converted_rule(
                    rule["rule"],
                    rule["environment"],
                    rule["platform"],
                    rule["directory"],
                    rule["name"],
                    output_dir=args.output,
                )

    elif args.command == "deploy":
        if (
            args.platform
            and args.platform == "elastic"
            and args.environment
            and args.file
        ):
            deploy_rules(
                rules=load_rules(args.file),
                environment_config=environments_config["environments"][
                    args.environment
                ]["platform"][args.platform],
                platform_config=platform_config["platforms"][args.platform],
            )

        elif args.platform and args.platform == "elastic":
            for env_name, env_data in environments_config["environments"].items():
                # Check if this environment has Elastic platform configuration
                if "platform" in env_data and "elastic" in env_data["platform"]:
                    print(f"Deploying to environment: {env_name}")
                    deploy_rules(
                        rules=load_rules(args.file),
                        environment_config=environments_config["environments"][
                            env_name
                        ]["platform"][args.platform],
                        platform_config=platform_config["platforms"][args.platform],
                    )

    elif args.command == "lint":
        errors, warnings = lint_ruleset(load_rules(path_to_rules))
        if errors:
            # Non-zero exit for CI when errors are present
            import sys

            sys.exit(1)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
