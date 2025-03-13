
def add_indexes(indexes: list, product: str = None, category: str = None, service: str = None) -> dict:

  transform = {
    "name": "add_splunk_indexes",
    "priority": 100,
    "transformations": [
      {
        "id": "prefix_index",
        "type": "add_condition",
        "conditions": {
            
        }
      }
    ]
  }

  if len(indexes) >= 2:
    val = indexes

  else:
    val = indexes[0]
    
  transform['transformations'][0]['conditions']['index'] = val
  
  # rule_conditions = {
  #   "rule_conditions": [
  #         {
  #           "type": "logsource",
  #     }
  #   ]
  # }
  
  return transform