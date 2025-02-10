
def add_indexes(indexes: list, product: str, category: str, service: str) -> dict:

  transform = {
    "name": "Add Elastic Index(es)",
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
  
  