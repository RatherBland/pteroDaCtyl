import uuid
import time
import splunklib.client as client
import splunklib.results as results
from pterodactyl.logger import logger, error
import json


# Custom exceptions for better error handling
class SplunkAuthenticationError(Exception):
    """Raised when authentication credentials are missing or invalid."""

    pass


class SplunkConnectionFailure(Exception):
    """Raised when connection to Splunk fails."""

    pass


class SplunkPlatform:
    def __init__(self, config: dict):
        self._host = config.get("host")
        self._port = config.get("port")
        self._username = config.get("username")
        self._password = config.get("password")
        self._ssl_verify = config.get("ssl_verify", True)
        self._client = None  # Cache for the client

        # Validate authentication parameters
        if not self._username or not self._password:
            raise SplunkAuthenticationError(
                "No authentication credentials provided for Splunk. "
                "Please provide a username and password."
            )

    @property
    def client(self):
        if self._client is None:
            try:
                self._client = client.connect(
                    host=self._host,
                    port=self._port,
                    username=self._username,
                    password=self._password,
                    verify=self._ssl_verify,
                )
                # Test connection (check if we can list indexes)
                _ = list(self._client.indexes)
            except Exception as e:
                error(f"Connection error: {e}")
                raise SplunkConnectionFailure(f"Failed to connect to Splunk: {e}")
        return self._client


def delete_all(client):
    """
    Delete all documents from all Splunk indexes.

    Args:
        client: Splunk client connection

    Raises:
        Exception: If deletion fails
    """
    try:
        for index in client.indexes:
            delete_query = f"search index={index.name} | delete"
            job = client.jobs.create(delete_query)
            while not job.is_done():
                time.sleep(2)
    except Exception as e:
        error(f"Error deleting documents: {e}")
        raise


def index_query_delete(
    data: str, index: str, query: str, config: dict, wait: int = 2
) -> int:
    """
    Submits events to a Splunk index, executes a search query, then deletes the events.

    Args:
        data: The event data as a JSON string
        index: The target Splunk index
        query: The Splunk search query to execute
        config: Dictionary containing Splunk connection configuration
        wait: Time (in seconds) to wait between operations

    Returns:
        The number of search result events returned
    """
    try:
        # Setup client
        splunk = SplunkPlatform(config)
        client_instance = splunk.client

        # Ensure index exists
        if index not in client_instance.indexes:
            logger.info(f"Creating index '{index}' as it does not exist")
            client_instance.indexes.create(index)
        index_obj = client_instance.indexes[index]

        # Parse data and prepare for indexing
        parsed_data = json.loads(data)
        data_list = parsed_data if isinstance(parsed_data, list) else [parsed_data]

        # Add cleanup IDs to each event
        cleanup_ids = []
        logger.info(f"Adding document(s) to index: {index}")

        for event in data_list:
            cleanup_id = str(uuid.uuid4())
            cleanup_ids.append(cleanup_id)
            event["cleanup_id"] = cleanup_id

            # Index the event
            try:
                index_obj.submit(json.dumps(event))
            except Exception as e:
                error(f"Failed to index event: {e}")
                # Continue with other events

        # Wait for indexing to complete
        time.sleep(wait)

        # Execute search query
        logger.info(f"Executing query: {query}")
        job = client_instance.jobs.create(f"search {query}")

        while not job.is_done():
            time.sleep(wait)

        rr = results.ResultsReader(job.results())
        result_count = sum(1 for _ in rr)
        logger.info(f"Query returned {result_count} results")

        # Clean up the indexed events
        cleanup_ids_str = ", ".join(f'"{cid}"' for cid in cleanup_ids)
        delete_query = (
            f"search index={index} | where cleanup_id IN ({cleanup_ids_str}) | delete"
        )

        try:
            delete_job = client_instance.jobs.create(delete_query)
            while not delete_job.is_done():
                time.sleep(wait)
            logger.info(f"Cleaned up {len(cleanup_ids)} events from index '{index}'")
        except Exception as e:
            error(f"Failed to clean up events: {e}")

        return result_count

    except SplunkAuthenticationError as e:
        error(f"Authentication error: {e}")
        return 0
    except SplunkConnectionFailure as e:
        error(f"Connection failure: {e}")
        return 0
    except Exception as e:
        error(f"Unexpected error in index_query_delete: {e}")
        return 0


def count_docs(index: str, config: dict) -> int:
    """
    Counts the number of documents in a Splunk index.

    Args:
        index: The target Splunk index
        config: Dictionary containing Splunk connection configuration

    Returns:
        The number of documents in the index
    """
    try:
        splunk = SplunkPlatform(config)
        client_instance = splunk.client

        if index not in client_instance.indexes:
            return 0

        index_obj = client_instance.indexes[index]
        return index_obj.totalEventCount
    except Exception as e:
        error(f"Error counting documents in index {index}: {e}")
        return 0


def execute_query(query: str, config: dict) -> int:
    """
    Executes a search query and returns the number of results.

    Args:
        query: The Splunk search query to execute
        config: Dictionary containing Splunk connection configuration

    Returns:
        The number of search results
    """
    try:
        splunk = SplunkPlatform(config)
        client_instance = splunk.client

        logger.info(f"Executing query: {query}")
        job = client_instance.jobs.create(f"search {query}")

        while not job.is_done():
            time.sleep(2)

        rr = results.ResultsReader(job.results())
        result_count = sum(1 for _ in rr)
        logger.info(f"Query returned {result_count} results")

        return result_count
    except Exception as e:
        error(f"Error executing query: {e}")
        return 0
