from elasticsearch import Elasticsearch


client  = Elasticsearch("https://192.168.86.108:9200", basic_auth=("elastic", "changeme"), verify_certs=False)

def delete_all():
    client.delete_by_query(index="*", body={"query": {"match_all": {}}})

def add_query_delete(data: dict, index: str, query: str) -> int:
    
    client.index(index=index, id=1, document=data)
    resp = client.esql.query(query=query)
    result_count = len(resp['values'])
    # Deleting the document after testing was causing search results to be empty about 9 in 10 times. Unsure why.
    # client.delete(index=index, id=1)
    
    return result_count
    

    
