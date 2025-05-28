import logging
import os
import sys


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    "%(asctime)s - %(levelname)s - %(pathname)s:%(lineno)d - %(message)s"
)
handler.setFormatter(formatter)
logger.addHandler(handler)


def error(msg, *args, **kwargs):
    """Log an error message and return 1 to break execution flow."""

    if os.environ.get("GITHUB_ACTIONS") == "true":
        # Format: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-a-warning-message
        file = kwargs.get("file", "")
        line = kwargs.get("line", "1")
        col = kwargs.get("col", "1")

        if file:
            print(f"::error file={file},line={line},col={col}::{msg}")
        else:
            print(f"::error::{msg}")

    # Create a new dict without GitHub Actions specific keys
    logging_kwargs = {
        k: v for k, v in kwargs.items() if k not in ("file", "line", "col")
    }
    # Set stacklevel=2 to capture the caller's frame instead of this function
    logging_kwargs["stacklevel"] = logging_kwargs.get("stacklevel", 2)
    logger.error(msg, *args, **logging_kwargs)

    if os.environ.get("CI"):
        sys.exit(1)

    return msg


def warning(msg, *args, **kwargs):
    """
    Log a warning message and output GitHub Actions workflow command for warnings.

    This will make GitHub Actions recognize warnings in the logs.
    """

    # Check if running in GitHub Actions
    if os.environ.get("GITHUB_ACTIONS") == "true":
        # Format: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-a-warning-message
        file = kwargs.get("file", "")
        line = kwargs.get("line", "1")
        col = kwargs.get("col", "1")

        if file:
            print(f"::warning file={file},line={line},col={col}::{msg}")
        else:
            print(f"::warning::{msg}")

    # Create a new dict without GitHub Actions specific keys
    logging_kwargs = {
        k: v for k, v in kwargs.items() if k not in ("file", "line", "col")
    }
    # Set stacklevel=2 to capture the caller's frame instead of this function
    logging_kwargs["stacklevel"] = logging_kwargs.get("stacklevel", 2)
    logger.warning(msg, *args, **logging_kwargs)
    return msg
