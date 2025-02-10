import tomllib

def load_organisations_config(filename="organisations.toml"):
    with open(filename, "rb") as f:
        return tomllib.load(f)

def load_pterodactyl_config(filename="pterodactyl.toml"):
    with open(filename, "rb") as f:
        return tomllib.load(f)
    
def load_platform_config(filename="platforms.toml"):
    with open(filename, "rb") as f:
        return tomllib.load(f)