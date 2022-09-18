from c2.c2_operations import C2Operation
import c2.concrete_actions as c2actions


def desktop_discovery():
    actions = [c2actions.find_local_users(),
               c2actions.list_target_local_user_desktop(),
               c2actions.read_staged_files()]
    name = "Desktop discovery"
    description = "Read files from local user's desktop"
    operation = C2Operation(actions, name, description)
    return operation
