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
    
    convert_parser = subparsers.add_parser('convert', help='Convert detection rules to security platforms format')
    convert_parser.add_argument('-f', '--file', help='The path to the detection to convert', required=False)
    
    args = parser.parse_args()
    
    if args.file:
        path_to_rules = args.file
    else:
        path_to_rules = pterodactyl_config["base"]["sigma_rules_directory"]
        
    if args.command == 'validate':
        test_rules(load_rules(path_to_rules), platform_config)
    elif args.command == 'convert':
        print(convert_rules(load_rules(path_to_rules), organisations_config, platform_config))
    elif args.command == 'livetest':
        pass
    else:
        parser.print_help()
    
if __name__ == "__main__":
    main()
