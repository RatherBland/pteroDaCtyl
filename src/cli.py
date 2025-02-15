from config import load_organisations_config, load_pterodactyl_config, load_platform_config
from convert import convert_rules
from test import validate_test_schema
import argparse


def main():
    organisations_config = load_organisations_config()
    pterodactyl_config = load_pterodactyl_config()
    platform_config = load_platform_config()
    
    parser = argparse.ArgumentParser(description='pteroDaCtyl CLI')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    test_parser = subparsers.add_parser('test', help='Test detection rules against available security platforms')
    
    convert_parser = subparsers.add_parser('convert', help='Convert detection rules to security platforms format')
    
    args = parser.parse_args()
    
    if args.command == 'test':
        validate_test_schema(pterodactyl_config, platform_config)
        pass
    elif args.command == 'convert':
        print(convert_rules(organisations_config, pterodactyl_config, platform_config))
        pass
    else:
        parser.print_help()
    
if __name__ == "__main__":
    main()
