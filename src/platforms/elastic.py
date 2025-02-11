
def add_indexes(indexes: list, product: str = None, category: str = None, service: str = None) -> dict:

  transform = {
    "name": "add_elastic_indexes",
    "priority": 100,
    "transformations": [
      {
        "id": "index_set_state",
        "type": "set_state",
        "key": "index",
      }
    ]
  }

  if len(indexes) >= 2:
    val = indexes

  else:
    val = indexes[0]
    
  transform['transformations'][0]['val'] = val
  
  # rule_conditions = {
  #   "rule_conditions": [
  #         {
  #           "type": "logsource",
  #     }
  #   ]
  # }
  
  return transform
  
  