from config import load_organisations_config, load_pterodactyl_config, load_platform_config
from convert import convert_rules
from test import test_rules
import argparse
from utils import load_rules


def main():
    organisations_config = load_organisations_config()
    pterodactyl_config = load_pterodactyl_config()
    platform_config = load_platform_config()
    
    parser = argparse.ArgumentParser(description='pteroDaCtyl CLI')    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    validate_parser = subparsers.add_parser('validate', help='Validate detection rules against available security platforms')
    validate_parser.add_argument('-f', '--file', help='The path to the detection to validate', required=False)
    validate_group = validate_parser.add_mutually_exclusive_group(required=True)
    validate_group.add_argument('-p', '--pre-compilation', help='Validate tests schema and query against test data. Does not factor in organisation level exceptions. Primary purpose is to validate that detection logic is sound against a predefined data set. ', action='store_true')
    validate_group.add_argument('-l', '--post-compilation', help='Execute rules against a live environment. Will include organisation level exceptions. Primary purpose is to identify how many false positives will be seen in an uncontrolled environment', action='store_true')
    
    convert_parser = subparsers.add_parser('compile', help='Compile detection rules to security platforms format')
    convert_parser.add_argument('-f', '--file', help='The path to the detection to convert', required=False)
    
    args = parser.parse_args()
    
    if hasattr(args, 'file') and args.file:
        path_to_rules = args.file
    else:
        path_to_rules = pterodactyl_config["base"]["sigma_rules_directory"]
        
    if args.command == 'validate':
        test_rules(load_rules(path_to_rules), platform_config)
    elif args.command == 'compile':
        print(convert_rules(load_rules(path_to_rules), organisations_config, platform_config))

    else:
        parser.print_help()
    
if __name__ == "__main__":
    main()
