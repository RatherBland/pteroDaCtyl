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

    test_parser = subparsers.add_parser('test', help='Test detection rules against available security platforms')
    
    convert_parser = subparsers.add_parser('convert', help='Convert detection rules to security platforms format')
    
    args = parser.parse_args()
    
    if args.command == 'test':
        test_rules(load_rules(pterodactyl_config["base"]["sigma_rules_directory"]), platform_config)
        pass
    elif args.command == 'convert':
        print(convert_rules(organisations_config, pterodactyl_config, platform_config))
        pass
    else:
        parser.print_help()
    
if __name__ == "__main__":
    main()
