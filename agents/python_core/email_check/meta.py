directive ={
    "parent": True,
    "universal_id": "email-harvest",
    "name": "email_check",
    "tags": {
        "connection": {
            "proto": "email",
            "direction": {"incoming": True}
        },
        "packet_signing": {"in": True, "out": True},
        "symmetric_encryption": {"type": "aes"}
    },
    "config": {
        "ui": {
            "agent_tree": {"emoji": "📨"},
            "panel": [
                "email_check.email_check"
            ]
        },
        "service-manager": [
            {
                "role": [
                    "hive.email_check.check_email@cmd_check_email",
                    "hive.email_check.retrieve_email@cmd_retrieve_email",
                    "hive.email_check.delete_email@cmd_delete_email",
                    "hive.email_check.update_accounts@cmd_update_accounts",
                    "hive.email_check.remove_account@cmd_remove_account",
                    "hive.email_check.list_accounts@cmd_list_accounts",
                    "hive.email_check.nuke_accounts@cmd_nuke_accounts",
                    "hive.email_check.list_mailbox@cmd_list_mailbox",
                    "hive.email_check.list_folders@cmd_list_folders",
                ],
                "scope": ["parent", "any"]
            }
        ]
    }
}