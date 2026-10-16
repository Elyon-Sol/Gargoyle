# The policy for a coding agent with a filesystem MCP server:
# reads are free, writes need a human, everything else is refused.
# Edit this file and OPA reloads it; every outstanding receipt then stops
# being honored until the call is decided again (the receipt pins the
# policy set).
package gargoyle

default decision := {"allow": false, "reason": "DEFAULT_DENY"}

read_tools := {"read_file", "read_text_file", "read_multiple_files", "list_directory",
               "list_directory_with_sizes", "directory_tree", "search_files", "get_file_info",
               "list_allowed_directories"}
write_tools := {"write_file", "edit_file", "create_directory", "move_file"}

decision := {"allow": true, "requires_approval": false} if {
    input.tool in read_tools
}

decision := {"allow": true, "requires_approval": true} if {
    input.tool in write_tools
}
