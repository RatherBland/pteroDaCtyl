from config import load_organisations_config, load_pterodactyl_config
from convert import convert_rules

def main():
    organisations_config = load_organisations_config()
    pterodactyl_config = load_pterodactyl_config()
    convert_rules(organisations_config, pterodactyl_config)

if __name__ == "__main__":
    main()