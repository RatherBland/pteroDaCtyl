from pydantic import BaseModel, PositiveInt, Field
from typing import Dict
from enum import Enum


class PlatformsEnum(str, Enum):
    elastic = "elastic"
    splunk = "splunk"
    sentinel = "sentinel"


class TestNameEnum(str, Enum):
    true_positive_test_url = "true_positive_test_url"
    true_positive_test_file = "true_positive_test_file"
    true_positive_test_raw = "true_positive_test_raw"


class TestTypeEnum(str, Enum):
    url = "url"
    file = "file"
    raw = "raw"


class AttackData(BaseModel):
    data: str
    type: TestTypeEnum
    source: str


class TestCase(BaseModel):
    hits: PositiveInt
    attack_data: AttackData


class Tests(BaseModel):
    platforms: Dict[PlatformsEnum, Dict[TestNameEnum, TestCase]] = Field(
        ..., min_items=1
    )
