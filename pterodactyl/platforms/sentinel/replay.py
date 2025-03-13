import uuid
import time
import json
import io
from azure.kusto.data import KustoClient, KustoConnectionStringBuilder, DataFormat
from azure.kusto.ingest import QueuedIngestClient, IngestionProperties
import datetime


def generate_schema(record: dict) -> str:
    """
    Generates a Kusto table schema string from a sample Python dictionary.
    
    Args:
        record (dict): A dictionary representing a sample record.
            Example: {"timestamp": "2025-02-16T12:00:00Z", "value": 42, "active": True}
    
    Returns:
        str: A comma-separated string representing the Kusto schema.
            Example: "timestamp: datetime, value: long, active: bool"
    """
    schema_fields = []
    
    for key, value in record.items():
        # Default to string unless we can infer a different type.
        field_type = "string"
        
        if isinstance(value, int):
            field_type = "long"
        elif isinstance(value, float):
            field_type = "real"
        elif isinstance(value, bool):
            field_type = "bool"
        elif isinstance(value, str):
            # Attempt to parse as a datetime in ISO format.
            try:
                # Replace Z with +00:00 for proper ISO handling
                datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
                field_type = "datetime"
            except ValueError:
                field_type = "string"
        
        schema_fields.append(f"{key}: {field_type}")
    
    return ", ".join(schema_fields)


def index_query_delete(database: str, table: str, data: dict, query: str, wait: int = 2) -> int:
    """
    Ingests an event (provided as a Python dict) into a Kusto Emulator table, executes a query to 
    retrieve it, and then cleans up (deletes) the ingested data based on a unique cleanup identifier.
    
    Args:
        database (str): The target Kusto database.
        table (str): The target table name where the event will be ingested.
        data (dict): The event data as a Python dictionary.
        query (str): The Kusto query to execute. This query should be written to return the ingested event.
        wait (int): Time (in seconds) to wait for ingestion and query propagation.
        
    Returns:
        int: The number of results returned by the query.
    """
    # Build the connection string for the Kusto Emulator (adjust the endpoint as needed)
    kusto_cluster = "https://kvc-atz5xzdfte0dhq16x5.australiaeast.kusto.windows.net"  # Emulator endpoint
    kcsb = KustoConnectionStringBuilder.with_aad_device_authentication(connection_string=kusto_cluster)
    kusto_client = KustoClient(kcsb)
    
    ingest_endpoint = "https://ingest-kvc-atz5xzdfte0dhq16x5.australiaeast.kusto.windows.net"
    ingest_kcsb = KustoConnectionStringBuilder.with_aad_device_authentication(ingest_endpoint)

    # Create an ingestion client for submitting data
    ingest_client = QueuedIngestClient(ingest_kcsb)
    
    # Generate a unique cleanup identifier and inject it into the data
    cleanup_id = str(uuid.uuid4())
    updated_data = data.copy()
    updated_data['cleanup_id'] = cleanup_id
    print(updated_data)
    
    schema = generate_schema(updated_data)
    create_command = f".create table {table} ({schema})"
    kusto_client.execute_mgmt(database, create_command)

    # Convert the updated data to a JSON string
    event_json = json.dumps(updated_data)
    
    # Ingest the event data using an in-memory stream
    ingestion_props = IngestionProperties(
        database=database,
        table=table,
        data_format=DataFormat.JSON  # Ingest data in JSON format
    )
    stream = io.StringIO(event_json)
    
    ingest_client.ingest_from_stream(stream, ingestion_properties=ingestion_props)
    
    # Wait for the data to be ingested and become queryable
    time.sleep(wait)
    
    # Execute the provided query, appending a filter for our unique cleanup_id
    full_query = f"{query}"
    response = kusto_client.execute(database, full_query)
    
    # Count the results returned by the query
    result_count = 0
    primary_results = response.primary_results if response.primary_results else []
    for result_table in primary_results:
        for _ in result_table:
            result_count += 1

    # Cleanup: Delete the ingested data using a management command.
    delete_command = f".drop table {table} ifexists"
    kusto_client.execute_mgmt(database, delete_command)
    
    return result_count

print(index_query_delete("MyDatabase", "TestTable", {"event": "test"}, "TestTable | project event", wait=2))