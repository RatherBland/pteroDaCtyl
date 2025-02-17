from elasticsearch import Elasticsearch
from elastic_transport import ConnectionError as ElasticConnectionError
import time
import uuid
from logger import logger
import json
from elasticsearch import helpers


def delete_all():
    client = Elasticsearch("https://192.168.86.108:9200", basic_auth=("elastic", "changeme"), verify_certs=False)
    client.delete_by_query(index="*", body={"query": {"match_all": {}}})


def index_query_delete(data: str, index: str, query: str, wait: int = 2) -> int:
    # delete_all()
    client = Elasticsearch("https://192.168.86.108:9200", basic_auth=("elastic", "changeme"), verify_certs=False)
    
    data = json.loads(data)
    
    document_ids = []
    logger.info(f"Adding document(s) to index: {index}")
    actions = []
    for doc in data:
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

    return result_count
