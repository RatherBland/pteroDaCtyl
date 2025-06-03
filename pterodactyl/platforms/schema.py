from pydantic import (
    BaseModel,
    PositiveInt,
    Field,
    field_validator,
    model_validator,
    UUID4,
)
from typing import Dict, List, Annotated
from pydantic.functional_validators import AfterValidator
from enum import Enum
import re
import uuid


class PlatformsEnum(str, Enum):
    elastic = "elastic"
    splunk = "splunk"
    sentinel = "sentinel"


class QueryLanguageEnum(str, Enum):
    esql = "esql"
    eql = "eql"


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


class DynamicTestingThreshold(BaseModel):
    false_positive_threshold: PositiveInt = Field(
        ..., description="Threshold for dynamic testing"
    )


class Tests(BaseModel):
    platforms: Dict[
        PlatformsEnum,
        Dict[TestNameEnum, TestCase] | DynamicTestingThreshold,
    ]

    @model_validator(mode="after")
    def validate_platforms_not_empty(self):
        """Validate that platforms dictionary has at least one item"""
        if len(self.platforms) < 1:
            raise ValueError("Platforms dictionary must have at least one item")
        return self


class RuleSchema(BaseModel):
    """Schema for validating rule structure and format"""

    id: UUID4 | Annotated[str, AfterValidator(lambda x: uuid.UUID(x, version=4))] = (
        Field(..., description="Rule ID must be a valid UUID4")
    )
    name: str = Field(..., description="Rule name must be lowercase with underscores")
    tags: List[str] = Field(
        ..., description="List of tags, must include at least one MITRE tag"
    )

    @field_validator("name")
    @classmethod
    def name_must_be_lowercase_with_underscores(cls, v):
        """Validate that name is lowercase with underscores instead of spaces"""
        if v != v.lower():
            raise ValueError("Name must be all lowercase")
        if " " in v:
            raise ValueError("Name must use underscores instead of spaces")
        if not re.match(r"^[a-z0-9_]+$", v):
            raise ValueError(
                "Name must only contain lowercase letters, numbers, and underscores"
            )
        return v

    @model_validator(mode="after")
    def validate_mitre_tags(self):
        """Validate that at least one MITRE tag exists"""
        if not any(tag.startswith("attack-") for tag in self.tags):
            raise ValueError(
                "At least one MITRE tag starting with 'attack-' must be included"
            )
        return self

    class Config:
        extra = "allow"  # Allow additional fields that aren't specifically defined
