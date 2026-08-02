"""3 read-only tools + 1 obviously-mutating one, so the probe set is a strict subset."""

from mcp_gauntlet.fixtures._serve import Tool, serve


def search_records(query: str) -> str:
    """Search the record store and return matching entries."""
    return "results"


def get_record(record_id: str) -> str:
    """Fetch one record by its identifier."""
    return "record"


def list_tags(prefix: str) -> str:
    """List tags that start with the given prefix."""
    return "tags"


def delete_record(record_id: str) -> str:
    """Permanently delete the named record from the store."""
    return "deleted"


serve(
    "mixed",
    [
        Tool(
            fn=search_records,
            name="search_records",
            description="Search the record store and return matching entries.",
        ),
        Tool(fn=get_record, name="get_record", description="Fetch one record by its identifier."),
        Tool(
            fn=list_tags,
            name="list_tags",
            description="List tags that start with the given prefix.",
        ),
        Tool(
            fn=delete_record,
            name="delete_record",
            description="Permanently delete the named record from the store.",
            annotations={"destructive_hint": True},
        ),
    ],
)
