matrix_directive = {
        "universal_id": "matrix",
        "name": "matrix",
        "tags": {
          "packet_signing": {
            "in": True,
            "out": True
          }
        },

        "children": [{
                    "universal_id": "swarm-notifier-go",
                    "name": "swarm_notifier_go",
                    "app": "go_core",
                    "lang": "go",
                    "config": {
                        "service-manager": [{
                                            "role": [
                                                "hive.wave@cmd_say_hi",
                                            ],
                                            "scope": ["parent", "any"],
                                            "auth": {"sig": True},
                                            "priority": 10,
                                            "exclusive": False
                                        }],
                        "poke_interval_sec": 10,
                        "watch_directive_interval": 30,
                        "echo_packets": True
                    }
                },
{
            "universal_id": "telegram-bot-father-2",
            "name": "telegram_relay",
            "tags": {
                "connection": {
                    "proto": "telegram"
                },
            },
            "config": {
                "service-manager": [{
                    "role": [
                        "comm",
                        "comm.security",
                        "comm.*",
                        "hive.alert@cmd_send_alert_msg"
                    ],
                    "scope": ["parent", "any"],
                    "auth": {"sig": True},
                    "priority": 10,
                    "exclusive": False
                }]
            }
        },
        ]
      }