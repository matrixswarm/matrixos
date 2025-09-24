matrix_directive = {
        "universal_id": "matrix",
        "name": "matrix",
        "tags": {
          "packet_signing": {
            "in": True,
            "out": True
          }
        },

        "children": [# MATRIX PROTECTION LAYER 4 SENTINELS
        # 4th SENTINEL WATCHES MATRIX, REST WATCH SENTINEL IN FRONT
        # ONLY WAY TO KILL MATRIX WOULD BE TO KILL THEM ALL, TAKING ANY COMBO OF 4 OUT DOES NOTHING
        {
            "universal_id": "guardian-1",
            "name": "sentinel",
            "app": "matrix-core",
            "filesystem": {},
            "config": {"matrix_secure_verified": 1},
            "children": [
                {
                    "universal_id": "guardian-2",
                    "name": "sentinel",
                    "app": "matrix-core",
                    "filesystem": {},
                    "config": {"matrix_secure_verified": 1},
                    "children": [
                        {
                            "universal_id": "guardian-3",
                            "name": "sentinel",
                            "app": "matrix-core",
                            "filesystem": {},
                            "config": {"matrix_secure_verified": 1},
                            "children": [
                                {
                                    "universal_id": "guardian-4",
                                    "name": "sentinel",
                                    "app": "matrix-core",
                                    "filesystem": {},
                                    "config": {
                                        "matrix_secure_verified": 1,
                                        "watching": "the Queen",
                                        "universal_id_under_watch": "matrix"
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        },
          {
            "universal_id": "matrix-https",
            "name": "matrix_https",
            "tags": {
              "packet_signing": {
                "in": True,
                "out": True
              },
              "connection": {
                "proto": "https"
              },
              "connection_cert": {
                "proto": "https"
              },
            },
            "config": {
              "service-manager": []
            }
          },
          {
            "universal_id": "websocket-relay",
            "name": "matrix_websocket",
            "tags": {
                "packet_signing": {
                    "in": True,
                    "out": True
                },
                "connection": {
                    "proto": "wss"
                },
                "connection_cert": {
                    "proto": "wss"
                }
            },
            "config": {
                "service-manager": [
                    {
                        "role": [
                            "hive.alert@cmd_send_alert_msg",
                            "hive.rpc@cmd_rpc_route"
                        ],
                        "scope": [
                            "parent",
                            "any"
                        ],
                        "priority": {
                            "hive.log.delivery": -1,
                            "hive.proxy.route": 5,
                            "default": 10
                        }
                    }
                ]
                },
            },
            {
              "universal_id": "npc-simulator-1",
              "name": "npc_simulator",
              "app": "swarm-core",
              "config": {
                "grid_size": 20,
                "npc_count": 100,
                "tick_interval_sec": 1,
                "service-manager": [{
                  "role": [
                    "npc.swarm.control@cmd_control_npcs",
                    "npc.swarm.status@cmd_report_status"
                  ],
                  "scope": ["parent", "any"],
                  "priority": {
                    "npc.swarm.control": 1,
                    "npc.swarm.status": 1,
                    "default": 10
                  },
                  "exclusive": False
                }]
              }
            },
            {
            "universal_id": "apache_watchdog-1",
            "name": "apache_watchdog",
                "config": {
                    "check_interval_sec": 10,
                    "service_name": "httpd",  # change to "httpd" for RHEL/CentOS
                    "ports": [80, 443],
                    "restart_limit": 3,
                    "always_alert": 1,
                    "alert_cooldown": 300,
                    "alert_to_role": "hive.alert",
                    "report_to_role": "hive.forensics.data_feed",
                },
            },
            {
                "universal_id": "mysql-red-phone",
                "name": "mysql_watchdog",
                "config": {
                    "mysql_port": 3306,
                    "socket_path": "/var/run/mysqld/mysqld.sock",
                    "service_name": "mariadb",
                    "check_interval_sec": 20,
                    "restart_limit": 3,
                    "alert_thresholds": {
                        "uptime_pct_min": 90,
                        "slow_restart_sec": 10
                    },
                    "alert_to_role": "hive.alert",
                    "report_to_role": "hive.forensics.data_feed",
                }

            },
            {
            "universal_id": "log_sentinel",
            "name": "log_sentinel",
            "tags": {
                "packet_signing": {
                    "in": True,
                    "out": True
                },
            },
            "config": {

                "service-manager": [{
                    "role": ["hive.log@cmd_stream_log"],
                    "scope": ["parent", "any"],  # who it serves
                    "priority": {  # lower = more preferred
                        "hive.log.delivery": -1,
                        "hive.proxy.route": 5,
                        "default": 10
                    },
                }],

            },
          },
          {
            "universal_id": "invisible-man",
            "name": "ghost_wire",
            "config": {
                "tick_rate": 5,
                "watch_paths": [
                    "/etc/passwd",
                    "/etc/shadow",
                    "/root/.ssh",
                    "/var/www",
                    "/home"
                ],
                "command_patterns": [
                    "rm -rf",
                    "scp",
                    "curl",
                    "wget",
                    "nano /etc",
                    "vi /etc",
                    "vim /etc",
                    "sudo",
                    "su",
                    "chmod 777"
                ]
            }
        },
        {
            "universal_id": "gatekeeper",
            "name": "gatekeeper",
            "config": {
                "log_path": "/var/log/auth.log",
                "maxmind_db": "GeoLite2-City.mmdb",
                "geoip_enabled": 1,
                "always_alert": 1,

            }
            ,
            "children": []
        },
        {
            "universal_id": "discord-delta-5",
            "name": "discord_relay",
            "tags": {
                "connection": {
                    "proto": "discord"
                },
            },
            "config": {
                "service-manager": [{
                    "role": ["hive.alert@cmd_send_alert_msg"],
                    "scope": ["parent", "any"],

                }]
            }
        },
        {
            "universal_id": "forensic-detective-1",
            "name": "forensic_detective",
            "config": {
                "service-manager": [{
                    "role": ["hive.forensics.data_feed@cmd_ingest_status_report"],
                }],
                "oracle_analysis": {
                    "enable_oracle": 1,
                    "role": "hive.oracle"
                }
            }
            # It will automatically receive reports from agents using its role
        },
        {
            # Our new, config-driven system health monitor
            "universal_id": "system-health-1",
            "name": "system_health",
            "config": {
                "check_interval_sec": 60,
                "mem_threshold_percent": 90.0,  # Custom threshold
                "cpu_threshold_percent": 85.0,  # Custom threshold
                "disk_threshold_percent": 95.0,
                # It reports to the same data feed as the other watchdogs
                "report_to_role": "hive.forensics.data_feed",
            }
        },
        {
            "universal_id": "network-health-1",
            "name": "network_health",
            "config": {
                "check_interval_sec": 30,  # Check network status every 30 seconds
                "exclude_interfaces": [],  # List of interfaces to skip (e.g. ["lo"])
                "tx_threshold_mbps": 100,  # Warn if outbound rate exceeds 100 Mbps
                "rx_threshold_mbps": 100,  # Warn if inbound rate exceeds 100 Mbps
                "conn_threshold": 1000,  # Warn if active TCP/UDP conns > 1000
                "top_n_procs": 5,  # Include top 5 process hogs in report
                "report_to_role": "hive.forensics.data_feed",
            }
        },
        {
            "universal_id": "nginx-sentinel",
            "name": "nginx_watchdog",
            "enabled": False,
            "config": {
                "check_interval_sec": 10,
                "always_alert": 1,
                "restart_limit": 3,
                "service_name": "nginx",
                "ports": [85],
                "alert_cooldown": 300,
                "alert_to_role": "hive.alert", #They both send alerts, but report_to_role - a little more
                "report_to_role": "hive.forensics.data_feed"
            }
        },
        {
            "universal_id": "redis-hammer",
            "name": "redis_watchdog",
            "app": "redis-core",
            "config": {
                "check_interval_sec": 10,
                "restart_limit": 3,
                "redis_port": 6379,
                "always_alert": 1,
                "socket_path": "/var/run/redis/redis-server.sock",
                "alert_to_role": "hive.alert",
                "report_to_role": "hive.forensics.data_feed",
                "service_name": "redis"
            }
            ,
            "children": []
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
        {
            "universal_id": "golden-child-4",
            "name": "oracle",
            "tags": {
              "connection": { "proto": "openai" }
            },
            "config": {
                "service-manager": [{
                    "role": ["hive.oracle@cmd_msg_prompt"],
                }]
            }

        },
        ]
      }