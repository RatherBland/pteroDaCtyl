from elasticsearch import Elasticsearch


client  = Elasticsearch("https://192.168.86.108:9200", basic_auth=("elastic", "changeme"), verify_certs=False)

def add_query_delete(data: dict, index: str, query: str) -> int:
    
    print(index, query)
    client.index(index=index, id=1, document=data)
    resp = client.esql.query(query=query)
    result_count = len(resp['values'])
    client.delete(index=index, id=1)
    
    return result_count
    

# data = '{"@timestamp":"2022-08-10T22:04:13Z","cloud":{"account":{"id":"111111111111"},"provider":"aws","region":"us-west-2"},"event":{"action":"GetPasswordData","category":["iam"],"kind":"event","outcome":"failure","type":["api"],"id":"0cdd3757-296a-4454-9619-d0f8be335081","created":"2022-08-10T22:04:13Z"},"user":{"id":"AROAYTOGP2RLP5AASA6I5:aws-go-sdk-1660169051746043000","name":"sample-role-used-by-stratus-for-ec2-password-data","roles":["sample-role-used-by-stratus-for-ec2-password-data"]},"source":{"address":"142.254.89.27","ip":"142.254.89.27"},"user_agent":{"original":"stratus-red-team_e3e4b259-63a4-4d89-acd5-a7286a279bb8"},"error":{"code":"Client.UnauthorizedOperation","message":"You are not authorized to perform this operation.","type":"authorization"},"aws":{"cloudtrail":{"event_version":"1.08","read_only":true,"recipient_account_id":"111111111111","request_id":"87368810-7b30-4ff9-b097-702778a53f22","user_identity":{"type":"AssumedRole","session_context":{"mfa_authenticated":"false","creation_date":"2022-08-10T22:04:12Z"}},"tls_details":{"tls_version":"TLSv1.2","cipher_suite":"ECDHE-RSA-AES128-GCM-SHA256","client_provided_host_header":"ec2.us-west-2.amazonaws.com"}}},"related":{"user":["sample-role-used-by-stratus-for-ec2-password-data"]}}'

# req = client.index(index="logs-aws.cloudtrail", id=1, document=data)

# print(req)

# print(client.get(index="logs-aws.cloudtrail", id=1))

# req = client.esql.query(query="from logs-aws.cloudtrail metadata _id, _index, _version | where error.message like \"*not authorized*\"")

# req = client.delete(index="logs-aws.cloudtrail", id=1)

# print(req)

