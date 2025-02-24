from config import load_environments_config, load_pterodactyl_config, load_platform_config
from convert import convert_rules
from test import test_rules
import argparse
from utils import load_rules, write_converted_rule
from platforms.elastic.deploy import deploy_rules


def main():
    environments_config = load_environments_config()
    pterodactyl_config = load_pterodactyl_config()
    platform_config = load_platform_config()
    
    parser = argparse.ArgumentParser(description='pteroDaCtyl CLI')    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    validate_parser = subparsers.add_parser('validate', help='Validate detection rules against available security platforms')
    validate_parser.add_argument('-f', '--file', help='The path to the detection to validate', required=False)
    validate_parser.add_argument('-p', '--platform', help='The platform to validate against', required=False)
    
    validate_group = validate_parser.add_mutually_exclusive_group(required=True)
    validate_group.add_argument('--pre-compilation', help='Validate tests schema and query against test data. Does not factor in organisation level exceptions. Primary purpose is to validate that detection logic is sound against a predefined data set. ', action='store_true')
    validate_group.add_argument('--post-compilation', help='Execute rules against a live environment. Will include organisation level exceptions. Primary purpose is to identify how many false positives will be seen in an uncontrolled environment', action='store_true')
    
    convert_parser = subparsers.add_parser('compile', help='Compile detection rules to security platforms format')
    convert_parser.add_argument('-f', '--file', help='The path to the detection to convert', required=False)
    convert_parser.add_argument('-o', '--output', help='The path to the output directory', required=False)
    
    deploy_parser = subparsers.add_parser('deploy', help='Deploy detection rules to security platforms')
    deploy_parser.add_argument('-f', '--file', help='The path to the detection to deploy', required=False)
    deploy_parser.add_argument('-p', '--platform', help='The platform to deploy to', required=False)
    deploy_parser.add_argument('-e', '--environment', help='Environment or organisation to deploy to', required=False)
    
    
    
    args = parser.parse_args()
    
    if hasattr(args, 'file') and args.file:
        path_to_rules = args.file
    else:
        path_to_rules = pterodactyl_config["base"]["sigma_rules_directory"]
        
    if args.command == 'validate':
        if args.pre_compilation:
            test_rules(rules=load_rules(path_to_rules), platform_config=platform_config, specific_platform=args.platform)
            
    elif args.command == 'compile':
        output_rules = convert_rules(load_rules(path_to_rules), environments_config, platform_config)
        if args.output:
            for rule in output_rules:
                write_converted_rule(rule['rule'], rule['environment'], rule['platform'], rule['directory'], rule['name'], output_dir=args.output)
                
    elif args.command == 'deploy':
        if args.platform and args.platform == 'elastic' and args.environment and args.file:
            deploy_rules(rules=load_rules(args.file),
                         environment_config=environments_config['environments'][args.environment]['platform'][args.platform],
                         platform_config=platform_config['platforms'][args.platform])
    
    else:
        parser.print_help()
    
if __name__ == "__main__":
    main()
