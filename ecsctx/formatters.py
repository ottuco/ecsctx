from ecs_logging import StructlogFormatter


class ECSFormatter(StructlogFormatter):
    """
    Custom ECS formatter that uses ECS 1.12.0 instead of library default.

    The ecs-logging library:
    1. Runs normalize_dict() which converts dotted keys to nested objects
    2. Runs format_to_ecs() which calls setdefault("ecs.version", "1.6.0")

    Setting ecs.version in a processor doesn't work because normalize_dict
    converts it to nested {"ecs": {"version": ...}} and removes the flat key,
    so setdefault adds a new flat key with the library's version.

    This formatter overrides the version AFTER the library sets it.
    """

    ECS_VERSION = "1.12.0"

    def format_to_ecs(self, event_dict):
        event_dict = super().format_to_ecs(event_dict)
        # Remove nested ecs object created by normalize_dict()
        event_dict.pop("ecs", None)
        # Set only flat key (ECS standard)
        event_dict["ecs.version"] = self.ECS_VERSION
        # structlog's logger.exception() reports its method name ("exception")
        # as the level, which is not a valid ECS/syslog level and breaks
        # log.level:error filters in Kibana. The level may sit nested or flat
        # depending on where in the pipeline it was set.
        log_obj = event_dict.get("log")
        if isinstance(log_obj, dict) and log_obj.get("level") == "exception":
            log_obj["level"] = "error"
        if event_dict.get("log.level") == "exception":
            event_dict["log.level"] = "error"
        return event_dict