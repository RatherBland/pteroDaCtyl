from elasticsearch import Elasticsearch
from elastic_transport import ConnectionError as ElasticConnectionError
import time
from logger import logger


def delete_all():
    client = Elasticsearch("https://192.168.86.108:9200", basic_auth=("elastic", "changeme"), verify_certs=False)
    client.delete_by_query(index="*", body={"query": {"match_all": {}}})

def index_query_delete(data: dict, index: str, query: str, wait: int = 2) -> int:
    
    client = Elasticsearch("https://192.168.86.108:9200", basic_auth=("elastic", "changeme"), verify_certs=False)
    

    logger.info(f"Adding document to index: {index}")
    try:
        client.index(index=index, id=1, document=data)
    except (ElasticConnectionError):
        logger.error("Failed to connect to the Elasticsearch service. Check host and credentials are correct.")
        return
    time.sleep(wait)

    logger.info(f"Executing query: {query}")
    resp = client.esql.query(query=query)
    result_count = len(resp['values'])

    client.delete(index=index, id=1)

    return result_count
