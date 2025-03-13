from elasticsearch import Elasticsearch
from elastic_transport import ConnectionError as ElasticConnectionError
import time
import uuid
from pterodactyl.logger import logger
import json
from elasticsearch import helpers


# Custom exceptions for better error handling
class ElasticAuthenticationError(Exception):
    """Raised when authentication credentials are missing or invalid."""

    pass


class ElasticConnectionFailure(Exception):
    """Raised when connection to Elasticsearch fails."""

    pass


class ElasticPlatform:
    def __init__(self, config):
        self._hosts = config["elasticsearch_hosts"]
        self._username = config.get("username")
        self._password = config.get("password")
        self._basic_auth = (self._username, self._password) if self._username else None
        self._api_key = config.get("api_key")
        self._tls_verify = config.get("ssl_verify", True)
        self._client = None  # Cache for the client

        # Validate authentication parameters
        if not self._username and not self._api_key:
            raise ElasticAuthenticationError(
                "No authentication credentials provided for Elasticsearch. "
                "Please provide a username/password or API key."
            )

    @property
    def client(self):
        if self._client is None:
            try:
                auth_kwargs = {
                    "hosts": self._hosts,
                    "verify_certs": self._tls_verify,
                }
                if self._api_key:
                    auth_kwargs["api_key"] = self._api_key
                else:
                    auth_kwargs["basic_auth"] = self._basic_auth
                self._client = Elasticsearch(**auth_kwargs)
                # Test connection
                if not self._client.ping():
                    raise ElasticConnectionFailure(
                        "Failed to ping Elasticsearch server"
                    )
            except ElasticConnectionError as e:
                logger.error(f"Connection error: {e}")
                raise ElasticConnectionFailure(
                    f"Failed to connect to Elasticsearch: {e}"
                )
            except Exception as e:
                logger.error(f"Unexpected error initializing Elasticsearch client: {e}")
                raise
        return self._client


def delete_all(client):
    try:
        client.delete_by_query(index="*", body={"query": {"match_all": {}}})
    except Exception as e:
        logger.error(f"Error deleting documents: {e}")
        raise


def index_query_delete(
    data: str,
    index: str,
    query: str,
    config: dict,
    wait: int = 2,
) -> int:
    try:
        elastic = ElasticPlatform(config)
        client = elastic.client

        data = json.loads(data)

        document_ids = []
        logger.info(f"Adding document(s) to index: {index}")
        actions = []
        data_list = data if isinstance(data, list) else [data]

        for doc in data_list:
            doc_id = str(uuid.uuid4())
            actions.append({"_index": index, "_id": doc_id, "_source": doc})
            document_ids.append(doc_id)

        try:
            helpers.bulk(client, actions)
        except ElasticConnectionError:
            logger.error(
                "Failed to connect to the Elasticsearch service during bulk indexing."
            )
            raise ElasticConnectionFailure("Failed during bulk indexing operation")

        time.sleep(wait)

        logger.info(f"Executing query: {query}")
        resp = client.esql.query(query=query)
        result_count = len(resp["values"])

        for doc_id in document_ids:
            client.delete(index=index, id=doc_id)

        return result_count

    except ElasticAuthenticationError as e:
        logger.error(f"Authentication error: {e}")
        return 0
    except ElasticConnectionFailure as e:
        logger.error(f"Connection failure: {e}")
        return 0
    except Exception as e:
        logger.error(f"Unexpected error in index_query_delete: {e}")
        return 0


def count_docs(index: str, config: dict) -> int:
    try:
        elastic = ElasticPlatform(config)
        client = elastic.client
        response = client.count(index=index)
        return response.get("count", 0)
    except Exception as e:
        logger.error(f"Error counting documents in index {index}: {e}")
        return 0


def execute_query(query: str, config: dict) -> int:
    try:
        elastic = ElasticPlatform(config)
        client = elastic.client

        logger.info(f"Executing query: {query}")
        resp = client.esql.query(query=query)
        return len(resp.get("values", []))
    except Exception as e:
        logger.error(f"Error executing query: {e}")
        return 0
