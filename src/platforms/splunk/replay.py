import uuid
import time
import splunklib.client as client
import splunklib.results as results
from logger import logger


def delete_all_documents(index: str, wait: int = 2) -> None:
    """
    Deletes all documents from a given Splunk index.
    
    Args:
        index: The target Splunk index.
        wait: Time to wait (in seconds) between polling the job status.
    """
    # Connect to Splunk service
    try:
        service = client.connect(
            host="192.168.86.106",
            port=8089,
            username="admin",
            password="dontchangeme"
        )
    except ConnectionRefusedError:
        logger.error("Failed to connect to the Splunk service. Check host and credentials are correct.")
        return
        
    # Create a deletion job with a search that matches all events in the index.
    delete_query = f"search index={index} | delete"
    delete_job = service.jobs.create(delete_query)
    
    # Wait until the deletion job is finished
    while not delete_job.is_done():
        time.sleep(wait)
    
    print(f"All documents in index '{index}' have been deleted.")

def index_query_delete(index: str, data: str, query: str, wait: int = 2) -> int:
    """
    Submits an event to a Splunk index, executes a search query, and then deletes the event.
    
    Args:
        index: The target Splunk index.
        data: The event data, as a string.
        query: The Splunk search query to execute.
        wait: The time to wait for the event to be indexed and the search to complete.
        
    Returns:
        The number of search results returned by the query.
    """
    # Connect to Splunk service
    try:
        service = client.connect(
            host="192.168.86.106",
            port=8089,
            username="admin",
            password="dontchangeme",
            verify=False
            )
    except ConnectionRefusedError:
        logger.error("Failed to connect to the Splunk service. Check host and credentials are correct.")
        return
    
    # Create a unique cleanup identifier
    cleanup_id = str(uuid.uuid4())
        
    # Append the cleanup_id to the event data so we can later identify it.
    event_data = f"{data} cleanup_id={cleanup_id}"
    logger.info(f"Adding document to index: {index}")
    # Submit the event to the specified index
    if index not in service.indexes:
        service.indexes.create(index)
    index_obj = service.indexes[index]
    index_obj.submit(event_data)
    
    # Allow some time for the event to be indexed
    time.sleep(wait)
    
    # Execute the provided query
    # Often, you might want to append a filter to target our unique event
    logger.info(f"Executing query: {query}")
    job = service.jobs.create(f"search {query}")
    while not job.is_done():
        time.sleep(wait)
    
    # Count the number of results from the query
    rr = results.ResultsReader(job.results())
    result_count = sum(1 for _ in rr)
    
    # Cleanup: Delete the event using a Splunk delete command and our unique identifier.
    # The delete command requires appropriate permissions.
    delete_query = f"search index={index} | delete"
    delete_job = service.jobs.create(delete_query)
    while not delete_job.is_done():
        time.sleep(wait)
    
    return result_count