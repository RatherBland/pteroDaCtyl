from collections.abc import Sequence
from elasticsearch import Elasticsearch
from elastic_transport import ConnectionError as ElasticConnectionError
import time
import uuid
from pterodactyl.logger import logger, error
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
                        f"Failed to ping Elasticsearch server: {self._client.info()}"
                    )
            except ElasticConnectionError as e:
                error(f"Connection error: {e}")
                raise ElasticConnectionFailure(
                    f"Failed to connect to Elasticsearch: {e}"
                )
            except Exception as e:
                error(f"Unexpected error initializing Elasticsearch client: {e}")
                raise
        return self._client


def delete_all(client):
    try:
        client.delete_by_query(index="*", body={"query": {"match_all": {}}})
    except Exception as e:
        error(f"Error deleting documents: {e}")
        raise


def index_query_delete(
    data: str,
    index: str,
    query: str,
    config: dict,
    wait: int = 2,
    query_language: str = "esql",
    # timeframe: str = None,
) -> int:
    try:
        elastic = ElasticPlatform(config)
        client = elastic.client

        data = json.loads(data)

        document_ids = []
        logger.info(f"Adding document(s) to index: {index}")
        actions = []
        data_list = data if isinstance(data, list) else [data]

        # if timeframe:
        #     timespan_dsl = {
        #         "bool": {
        #             "must": [
        #                 {
        #                     "range": {
        #                         "@timestamp": {
        #                             "gte": f"now-{timeframe}",
        #                             "lte": "now",
        #                         }
        #                     }
        #                 }
        #             ]
        #         }
        #     }

        for doc in data_list:
            doc_id = str(uuid.uuid4())
            actions.append({"_index": index, "_id": doc_id, "_source": doc})
            document_ids.append(doc_id)

        try:
            helpers.bulk(client, actions)
        except ElasticConnectionError:
            error(
                "Failed to connect to the Elasticsearch service during bulk indexing."
            )
            raise ElasticConnectionFailure("Failed during bulk indexing operation")

        time.sleep(wait)

        logger.info(f"Executing {query_language.upper()} query: {query}")

        if query_language.lower() == "eql":
            resp = client.eql.search(
                index=index,
                body={"query": query},
                # filter=timespan_dsl if timeframe else None,
            )
            result_count = len(resp.get("hits", {}).get("events", []))
        else:  # Default to ESQL
            resp = client.esql.query(
                query=query,
                #  filter=timespan_dsl if timeframe else None
            )
            result_count = len(resp.get("values", []))

        for doc_id in document_ids:
            client.delete(index=index, id=doc_id)

        return result_count

    except ElasticAuthenticationError as e:
        error(f"Authentication error: {e}")
        return 0
    except ElasticConnectionFailure as e:
        error(f"Connection failure: {e}")
        return 0
    except Exception as e:
        error(f"Unexpected error in index_query_delete: {e}")
        return 0


def count_docs(index: str, config: dict) -> int:
    try:
        elastic = ElasticPlatform(config)
        client = elastic.client
        response = client.count(index=index)
        return response.get("count", 0)
    except Exception as e:
        error(f"Error counting documents in index {index}: {e}")
        return 0


def _coerce_index_value(index_value: str | Sequence[str] | None) -> str | None:
    """Normalize an index or collection of indexes into a comma-delimited string."""

    if not index_value:
        return None

    if isinstance(index_value, str):
        return index_value

    if isinstance(index_value, Sequence):
        filtered = [value for value in index_value if value]
        return ",".join(filtered) if filtered else None

    return None


def _resolve_default_index(config: dict) -> str | None:
    """Attempt to resolve a default index from the merged platform configuration."""

    logs_config = config.get("logs") if isinstance(config, dict) else None
    if not isinstance(logs_config, dict):
        return None

    if len(logs_config) != 1:
        return None

    first_log_config = next(iter(logs_config.values()), {})
    if not isinstance(first_log_config, dict):
        return None

    return _coerce_index_value(first_log_config.get("indexes"))


def execute_query(
    query: str,
    config: dict,
    query_language: str = "esql",
    timeframe: str = None,
    index: str | Sequence[str] | None = None,
) -> int:
    try:
        elastic = ElasticPlatform(config)
        client = elastic.client

        logger.info(f"Executing {query_language.upper()} query: {query}")

        timespan_dsl = None
        if timeframe:
            timespan_dsl = {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": f"now-{timeframe}",
                                    "lte": "now",
                                }
                            }
                        }
                    ]
                }
            }

        # Normalise provided index or fall back to the single configured log index.
        target_index = _coerce_index_value(index) or _resolve_default_index(config)

        if query_language.lower() == "eql":
            # For EQL, we need to specify an index pattern
            if not target_index:
                raise ValueError(
                    "EQL queries require an explicit index. Provide the index argument "
                    "or ensure a single log configuration supplies indexes."
                )
            resp = client.eql.search(
                index=target_index,
                body={"query": query},
                filter=timespan_dsl if timeframe else None,
            )
            return len(resp.get("hits", {}).get("events", []))
        else:  # Default to ESQL
            resp = client.esql.query(
                query=query, filter=timespan_dsl if timeframe else None
            )
            return len(resp.get("values", []))
    except Exception as e:
        error(f"Error executing query: {e}")
        return 0
