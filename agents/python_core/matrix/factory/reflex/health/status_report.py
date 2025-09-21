from core.python_core.tree_parser import TreeParser
def attach(agent, config):
    def msg_health_report(content, packet):
        target_uid = content.get("target_universal_id")
        status = content.get("status")
        heartbeat = content.get("last_heartbeat")


        tp = TreeParser.load_tree(agent.tree_path)

        if not tp:
            agent.log("[AUTO-CONFIRM][FAIL] Could not load tree.")
            return

        node = tp.get_node(target_uid)
        if not node:
            agent.log(f"[AUTO-CONFIRM][FAIL] Node not found in tree: {target_uid}")
            return

        agent.log(f"[AUTO-CONFIRM][CHECK] {target_uid} status={status}, heartbeat={heartbeat}, confirmed={node.get('confirmed')}")

        if not node.get("confirmed") and status == "alive" and heartbeat is not None:
            node["confirmed"] = True
            tp.save_tree(agent.tree_path)
            agent.delegate_tree_to_agent(target_uid)
            agent.log(f"[AUTO-CONFIRM] ✅ {target_uid} confirmed via heartbeat.")

    agent.msg_health_report = msg_health_report