# import tomllib
from dynaconf import Dynaconf

def load_environments_config(filename="environments.toml"):

    return Dynaconf(settings_files=[filename], envvar_prefix="ENVIRONMENTS", load_dotenv=True)

def load_pterodactyl_config(filename="pterodactyl.toml"):
    
    return Dynaconf(settings_files=[filename], envvar_prefix="PTERODACTYL", load_dotenv=True)
    
def load_platform_config(filename="platforms.toml"):
    
    return Dynaconf(settings_files=[filename], envvar_prefix="PLATFORMS", load_dotenv=True)