import uuid
import time
import splunklib.client as client
import splunklib.results as results
from logger import logger
import json


class SplunkPlatform:
    def __init__(self, config: dict):
        # You can pass a config dictionary with keys like host, port, username, password, and verify
        self._host = config.get('host')
        self._port = config.get('port')
        self._username = config.get('username')
        self._password = config.get('password')
        self._ssl_verify = config.get('ssl_verify', True)

    def client(self):
        try:
            service = client.connect(
                host=self._host,
                port=self._port,
                username=self._username,
                password=self._password,
                verify=self._ssl_verify
            )
        except Exception as e:
            logger.error(f"Failed to connect to the Splunk service: {e}")
            raise
        return service

def delete_all_documents(index: str, config: dict, wait: int = 2) -> None:
    """
    Deletes all documents from the given Splunk index.
    
    Args:
        index: The target Splunk index.
        config: A dictionary containing the Splunk connection configuration.
        wait: Time (in seconds) to wait between polling job status.
    """
    splunk = SplunkPlatform(config)
    service = splunk.client()

    # Create a deletion job that targets all events from the index.
    delete_query = f"search index={index} | delete"
    try:
        delete_job = service.jobs.create(delete_query)
    except Exception as e:
        logger.error(f"Failed to create delete job: {e}")
        return

    # Poll until the deletion job has finished.
    while not delete_job.is_done():
        time.sleep(wait)

    logger.info(f"All documents in index '{index}' have been deleted.")

def index_query_delete(index: str, data, query: str, config: dict, wait: int = 2) -> int:
    """
    Submits one or more events to a Splunk index, executes a search query, then deletes the event(s).
    
    Args:
        index: The target Splunk index.
        data: The event data as a string or a list of strings.
        query: The Splunk search query to execute.
        config: A dictionary containing the Splunk connection configuration.
        wait: Time (in seconds) to wait for indexing and job completion.
        
    Returns:
        The number of search result events returned.
    """
    splunk = SplunkPlatform(config)
    service = splunk.client()

    # Create a unique cleanup identifier for the batch.
    
    logger.info(f"Adding document(s) to index: {index}")
    
    data = json.loads(data)

    # Ensure the index exists or create it
    if index not in service.indexes:
        service.indexes.create(index)
    index_obj = service.indexes[index]
    
    data_list = data if isinstance(data, list) else [data]

    # Index multiple events if provided; otherwise, index a single document.
    
    cleanup_ids = []

    for event in data_list:
        cleanup_id = str(uuid.uuid4())
        cleanup_ids.append(cleanup_id)
        event['cleanup_id'] = cleanup_id
        index_obj.submit(json.dumps(event))

    # Allow some time for the event(s) to get indexed.
    time.sleep(wait)

    logger.info(f"Executing query: {query}")
    job = service.jobs.create(f"search {query}")
    while not job.is_done():
        time.sleep(wait)

    rr = results.ResultsReader(job.results())
    result_count = sum(1 for _ in rr)
    # Cleanup: delete only the event(s) with our unique cleanup_id.
    cleanup_ids_str = ", ".join(f"\"{cid}\"" for cid in cleanup_ids)
    delete_query = f"search index={index} | where cleanup_id IN ({cleanup_ids_str}) | delete"
    print(delete_query)
    delete_job = service.jobs.create(delete_query)
    while not delete_job.is_done():
        time.sleep(wait)
        
    # delete_all_documents(index, config)

    return result_count