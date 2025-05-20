from setuptools import setup, find_packages

# Read long description from README if available
try:
    with open("README.md", "r", encoding="utf-8") as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = (
        "Security detection rule conversion, validation, and deployment tool"
    )

# Read version from a version file, or set a default
try:
    with open("VERSION", "r", encoding="utf-8") as f:
        version = f.read().strip()
except FileNotFoundError:
    version = "0.1.0"  # Default version if file doesn't exist

setup(
    name="pteroDaCtyl",
    version=version,
    description="Security detection rule converter and validator",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Security Team",
    author_email="security@example.com",
    url="https://github.com/ratherbland/pteroDaCtyl",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "elasticsearch",
        "PyYAML",
        "toml",
        "requests",
        "pymongo",
        "pydantic",
        "dynaconf"
        # Add any other dependencies you need
    ],
    entry_points={
        "console_scripts": [
            "pterodactyl=pterodactyl.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.12",
    keywords="security, detection, rules, sigma, elastic, splunk",
)
