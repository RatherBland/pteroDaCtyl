from elasticsearch import Elasticsearch
from elastic_transport import ConnectionError as ElasticConnectionError
import time
import uuid
from logger import logger
import json
from elasticsearch import helpers

class ElasticPlatform:
    def __init__(self, config):
        self._hosts = config.get('elasticsearch_hosts', [])
        self._username = config.get('username')
        self._password = config.get('password')
        self._basic_auth = (self._username, self._password)
        self._api_key = config.get('api_key')
        self._tls_verify = config.get('ssl_verify', True)
        self._client = None  # Cache for the client

    @property
    def client(self):
        if self._client is None:
            self._client = Elasticsearch(
                hosts=self._hosts,
                basic_auth=self._basic_auth,
                api_key=self._api_key,
                verify_certs=self._tls_verify
            )
        return self._client


def delete_all(client):
    
    client.delete_by_query(index="*", body={"query": {"match_all": {}}})


def index_query_delete(data: str, index: str, query: str, config: dict, wait: int = 2,) -> int:
    
    elastic = ElasticPlatform(config)
        
    client = elastic.client
    
    data = json.loads(data)
    
    document_ids = []
    logger.info(f"Adding document(s) to index: {index}")
    actions = []
    data_list = data if isinstance(data, list) else [data]

    for doc in data_list:
        doc_id = str(uuid.uuid4())
        actions.append({
            "_index": index,
            "_id": doc_id,
            "_source": doc
        })
        document_ids.append(doc_id)

    try:
        helpers.bulk(client, actions)
    except ElasticConnectionError:
        logger.error("Failed to connect to the Elasticsearch service during bulk indexing. Check host and credentials are correct.")
        return

    time.sleep(wait)

    logger.info(f"Executing query: {query}")
    resp = client.esql.query(query=query)
    result_count = len(resp['values'])

    for doc_id in document_ids:
        client.delete(index=index, id=doc_id)
    
    # delete_all(client)

    return result_count


def count_docs(index: str, config: dict) -> int:
    elastic = ElasticPlatform(config)
    client = elastic.client
    try:
        response = client.count(index=index)
        return response.get("count", 0)
    except Exception as e:
        logger.error(f"Error counting documents in index {index}: {e}")
        return 0