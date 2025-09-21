import json
from pprint import pformat
def inject_spawn_landing_zone(source_code: str, path_resolution: dict, command_line_args: dict, tree_node: dict) -> str:
    """
    Dynamically inject sys.path, MatrixSwarm runtime info, and environment-aware Python package paths.
    This version supports system Python, conda, and virtualenv without requiring user tweaks.
    """

    import json

    landing_start = "# ======== 🛬 LANDING ZONE BEGIN 🛬 ========"
    landing_end = "# ======== 🛬 LANDING ZONE END 🛬 ========"

    bootstrap = "\n".join([
        "import sys",
        "import os",
        f"# ✅ Injected Python site-packages path",
        f"sys.path.insert(0, \"{path_resolution.get('python_site', '/root/miniconda3/lib/python3.12/site-packages')}\")",
        "",
        "# ⛓️ Inject MatrixSwarm paths",
        f"site_root = \"{path_resolution['site_root_path']}\"",
        "if site_root not in sys.path:",
        "    sys.path.insert(0, site_root)",
        f"agent_path = \"{path_resolution['agent_path']}\"",
        "if agent_path not in sys.path:",
        "    sys.path.insert(0, agent_path)",
        "import agent"
    ])


    injected = (
        f"{landing_start}\n"
        f"{bootstrap}\n"
        f"path_resolution = {json.dumps(path_resolution, indent=4)}\n"
        f"command_line_args = {json.dumps(command_line_args, indent=4)}\n"
        f"tree_node = {json.dumps(tree_node or {}, indent=4)}\n"
        f"path_resolution['pod_path_resolved'] = os.path.dirname(os.path.abspath(__file__))\n"
        f"{landing_end}"
    )

    if landing_start in source_code and landing_end in source_code:
        pre = source_code.split(landing_start)[0]
        post = source_code.split(landing_end)[1]
        return pre + injected + post
    else:
        return injected + "\n" + source_code
