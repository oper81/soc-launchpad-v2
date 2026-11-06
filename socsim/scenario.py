"""Загрузка и валидация сценария (JSON). Сценарий — данные, не код."""
import json
from typing import Any, Dict

SCHEMA_VERSION = 1

REQUIRED_TOP = ("schema_version", "name", "duration_days", "seed", "hosts", "campaigns")


class ScenarioError(ValueError):
    pass


def load_scenario(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise ScenarioError("не JSON: %s" % e)
    validate_scenario(data)
    return data


def validate_scenario(data: Dict[str, Any]) -> None:
    if not isinstance(data, dict):
        raise ScenarioError("корень сценария должен быть объектом")
    for key in REQUIRED_TOP:
        if key not in data:
            raise ScenarioError("нет обязательного поля: %s" % key)
    if data["schema_version"] != SCHEMA_VERSION:
        raise ScenarioError(
            "schema_version=%r, поддерживается %d" % (data["schema_version"], SCHEMA_VERSION)
        )
    if not isinstance(data["hosts"], list) or not data["hosts"]:
        raise ScenarioError("hosts должен быть непустым списком")
    if not isinstance(data["campaigns"], list):
        raise ScenarioError("campaigns должен быть списком")
    for i, c in enumerate(data["campaigns"]):
        if not isinstance(c, dict) or "type" not in c:
            raise ScenarioError("campaigns[%d]: нужен объект с полем type" % i)