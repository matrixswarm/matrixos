import time
import tempfile
import base64
import os
import copy
import json
import hashlib
from core.python_core.utils.crypto_utils import generate_aes_key
from core.python_core.mixin.log_method import LogMixin

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

class TreeParser(LogMixin):
    """Manages the agent directive, acting as the swarm's architect.

    This class is responsible for loading, parsing, validating, and manipulating
    the agent tree structure. It ensures structural integrity by rejecting
    duplicate agents, and it establishes the chain of trust by assigning
    cryptographically signed identities to each agent node.
    """
    CHILDREN_KEY = "children"
    UNIVERSAL_ID_KEY = "universal_id"

    def __init__(self, root, tree_path=None):
        """Initializes the TreeParser with a root node of an agent tree.

        Args:
            root (dict): The root dictionary of the agent tree structure.
            tree_path (str, optional): The original file path of the tree,
                used for saving. Defaults to None.
        """
        self.root = root  # Root of the JSON tree
        self.nodes = {}  # Dictionary to store all parsed nodes
        self._duplicate_nodes = []  # To track any duplicate permanent IDs
        self.delegated = {}  # Any delegated data (not relevant here)
        self.tree_path = tree_path
        self._rejected_nodes = []  # Track rejected universal_ids
        self._added_nodes = []


    def _initialize_data(self, data):

        if isinstance(data, str):
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                return {}
        return data if isinstance(data, dict) else {}

    def _parse_nodes(self, node):
        """"
        Recursively traverses the tree from the given node, validating each
        node and adding it to the internal `self.nodes` dictionary.

        This is a core internal method that builds the parser's understanding
        of the tree. It rejects any subtree that contains a duplicate universal_id
        to maintain a clean state.
        """
        if not node or not isinstance(node, dict):
            return

        universal_id = node.get(self.UNIVERSAL_ID_KEY)
        if not universal_id:
            return

        # 🚫 Prevent duplicate agents from being loaded into the swarm.
        if universal_id in self.nodes:
            print(f"[TREE-REJECT] ❌ Duplicate universal_id '{universal_id}' — rejecting this subtree and all children.")
            self._duplicate_nodes.append(universal_id)
            self._rejected_nodes.append(universal_id)
            return  # Skip processing this node and all its children.

        self._validate_and_store_node(node)

        for child in node.get(self.CHILDREN_KEY, []):
            self._parse_nodes(child)


    def _validate_and_store_node(self, node):
        """
        Validates and stores a node, ensuring unique `universal_id`.
        """
        universal_id = node.get(self.UNIVERSAL_ID_KEY)
        if not universal_id:
           return

        # Clean up malformed children
        valid_children = []
        for child in node.get(self.CHILDREN_KEY, []):
           if isinstance(child, dict) and child.get("universal_id"):
               valid_children.append(child)
           else:
               print(f"[TREE] ⚠️ Malformed child skipped: {child}")
               self._rejected_nodes.append(child)

        node[self.CHILDREN_KEY] = valid_children
        node.setdefault(self.CHILDREN_KEY, [])

        # Add the node if it's not a duplicate
        if universal_id not in self.nodes:
            self.nodes[universal_id] = node
            self._added_nodes.append(universal_id)
        else:
            self._duplicate_nodes.append(universal_id)
            return

        # Ensure children is properly initialized
        node.setdefault(self.CHILDREN_KEY, [])

    def reparse(self):
        """
        Clears the internal node cache and re-parses the entire tree from the root.
        This is useful after making structural changes like injections to ensure
        the internal state is up-to-date.
        """
        self.nodes.clear()
        self._duplicate_nodes.clear()
        self._rejected_nodes.clear()
        self._added_nodes.clear()
        self._parse_nodes(self.root)
        self.log("[TREE] Reparsed tree and refreshed internal node cache.")

    def get_first_level_child_ids(self, universal_id):
        """
        Get a list of universal_ids for all direct children of a node.
        """
        node = self._find_node(self.root, universal_id)
        if not node:
            return []
        return [child["universal_id"] for child in node.get(self.CHILDREN_KEY, []) if "universal_id" in child]

    def get_first_level_children(self, universal_id):
        """
        Retrieve all first-level children of the node with the given `universal_id`.
        Only direct (one-level) children are included.
        """
        # Find the node in the tree using `_find_node`
        node = self._find_node(self.root, universal_id)

        # If the node is not found, return an empty list
        if not node:
            return []

        # Get the immediate children
        first_level_children = node.get(self.CHILDREN_KEY, [])

        # Return the full children list (only one level down)
        return first_level_children

    def _find_node(self, node, universal_id):
        """
        Recursively searches for a node by `universal_id`.

        Args:
            node (dict): The current node being searched.
            universal_id (str): The permanent ID of the target node.

        Returns:
            dict: The node with the matching `universal_id`, or None if not found.
        """
        if not node:
            return None  # Base case: no node to search

        if node.get(self.UNIVERSAL_ID_KEY) == universal_id:
            return node  # Found the target node

        # Recursively search children
        for child in node.get(self.CHILDREN_KEY, []):
            found = self._find_node(child, universal_id)
            if found:  # Return as soon as the node is found
                return found

        return None  # Return None if the node is not found in the current branch

    def insert_node(self, new_node, parent_universal_id=None, matrix_priv_obj=None):
        """
        Inserts a new node into the tree under a specified parent.

        This method is the primary way to dynamically add agents to the live
        tree structure. It performs validation to ensure the new node has a
        unique ID before attaching it to the parent.

        Args:
            new_node (dict): The agent node to insert.
            parent_universal_id (str, optional): The ID of the parent. If None,
                the node is added to the root.

        Returns:
            list: A list of universal_ids that were successfully added.
        """
        self._added_nodes.clear()
        self._rejected_nodes.clear()
        self._duplicate_nodes.clear()

        new_universal_id = new_node.get(self.UNIVERSAL_ID_KEY)
        if not new_universal_id:
            raise ValueError("New node must have a `universal_id`.")

        # 🧼 Clean the node to ensure it meets basic structural requirements.
        new_node = TreeParser.strip_invalid_nodes(new_node)
        if not new_node:
            raise ValueError("New node rejected due to missing name or universal_id.")

        # 🚫 Check for existing node with same UID.
        if self.has_node(new_universal_id):
            print(f"[TREE-INSERT] ❌ Node with universal_id '{new_universal_id}' already exists. Rejecting insertion.")
            self._duplicate_nodes.append(new_universal_id)
            self._rejected_nodes.append(new_universal_id)
            return []

        self._validate_and_store_node(new_node)

        # Find the parent and append the new node to its children list.
        parent_node = self.root if parent_universal_id is None else self._find_node(self.root, parent_universal_id)
        if not parent_node:
            raise ValueError(f"Parent with `universal_id` {parent_universal_id} not found.")

        parent_node.setdefault(self.CHILDREN_KEY, []).append(new_node)

        if matrix_priv_obj:
            for node in self.walk_tree(new_node):
                uid = node.get(self.UNIVERSAL_ID_KEY)
                if uid:
                    self.assign_identity_token_to_node(uid, matrix_priv_obj, encryption_enabled=True, force=True)

        return list(self._added_nodes)

    @staticmethod
    def strip_invalid_nodes(tree):
        """
        Recursively removes nodes from a tree that are missing a 'name' or 'universal_id'.
        This is a utility method to ensure data integrity before parsing or insertion.
        """
        if not isinstance(tree, dict):
            return None

        if not tree.get("name", "").strip() or not tree.get("universal_id", "").strip():
            return None

        # Recursively clean children and keep only the valid ones.
        cleaned_children = [
            cleaned for child in tree.get("children", [])
            if (cleaned := TreeParser.strip_invalid_nodes(child)) is not None
        ]

        tree["children"] = cleaned_children
        return tree

    def save_tree(self, output_path=None):
        """
        Atomically saves the current state of the entire tree to a JSON file.

        It writes to a temporary file first and then replaces the original,
        preventing data corruption if the save operation is interrupted.
        """
        path = output_path or self.tree_path
        if not path:
            self.log("No output path specified for save().")
            return False
        try:
            with tempfile.NamedTemporaryFile("w", delete=False, dir=os.path.dirname(path)) as temp_f:
                json.dump(self.root, temp_f, indent=2)
                temp_path = temp_f.name
            os.replace(temp_path, path)
            return True
        except Exception as e:
            self.log(f"Failed to save tree: {e}")
            return False

    def mark_confirmed(self, universal_id):
        """
        Marks a node as confirmed by setting a timestamp.
        """
        node = self.nodes.get(universal_id)
        if node:
            node["confirmed"] = time.time()
            return True
        return False

    def get_unconfirmed(self):
        """
        Returns a list of universal_ids for nodes that are not confirmed.
        """
        return [p for p, node in self.nodes.items() if "confirmed" not in node]

    def dump_tree(self, output_path):
        """
        Saves the current tree structure to a file.
        """
        try:
            with tempfile.NamedTemporaryFile("w", delete=False, dir=os.path.dirname(output_path)) as temp_file:
                json.dump(self.root, temp_file, indent=2)
                temp_file.flush()
                os.fsync(temp_file.fileno())
                temp_path = temp_file.name
            os.replace(temp_path, output_path)
            return True
        except Exception as e:
            # print(f"[TREE-DUMP-ERROR] Failed to save tree: {e}")
            return False

    def is_valid_tree(self):
        """
        Validates the tree by checking for duplicate universal_ids.
        """
        return len(self._duplicate_nodes) == 0

    def get_duplicates(self):
        """
        Retrieves a list of duplicate nodes.
        """
        return self._duplicate_nodes


    def dump_all_nodes(self):
        """
        Prints all stored nodes in the tree.
        """
        print("Dumping all nodes in the tree:")

        if not self.nodes:
            print("(self.nodes is empty!)")
            return None  # No nodes to dump

        for universal_id, node in self.nodes.items():
            print(f"Permanent ID: {universal_id}, Node: {node}")

        return self.nodes  # Optionally return the `self.nodes` dictionary

    def extract_subtree_by_id(self, universal_id):
        """
        Extract a full subtree rooted at the given `universal_id`, including all children.
        Returns a deep copy of the node structure.
        """
        root_node = self._find_node(self.root, universal_id)
        if not root_node:
            return None

        return copy.deepcopy(root_node)

    def save(self, output_path=None):
        """
        Save the current tree to disk. Uses the original path if output_path is not provided.
        """
        if not output_path and hasattr(self, 'tree_path'):
            output_path = self.tree_path

        if not output_path:
            self.log("No output path specified for save().")
            return False

        try:
            with tempfile.NamedTemporaryFile("w", delete=False, dir=os.path.dirname(output_path)) as temp_file:
                json.dump(self.root, temp_file, indent=2)
                temp_file.flush()
                os.fsync(temp_file.fileno())
                temp_path = temp_file.name
            os.replace(temp_path, output_path)
            return True
        except Exception as e:
            self.log(f"Failed to save tree: {e}")
            return False

    def remove_exact_node(self, target_node):
        """
        Recursively remove the exact instance of a node from the tree by identity.
        """
        def recurse(node):
            if not isinstance(node, dict):
                return False

            children = node.get(self.CHILDREN_KEY, [])
            for i, child in enumerate(children):
                if child is target_node:
                    del children[i]
                    print(f"[TREE-PRECISION] 🎯 Removed node '{target_node.get(self.UNIVERSAL_ID_KEY)}'")
                    return True
                if recurse(child):  # Dive deeper
                    return True
            return False

        # Start at root
        return recurse(self.root)

    def get_rejected_nodes(self):
        return self._rejected_nodes

    def get_added_nodes(self):
        return self._added_nodes

    def pre_scan_for_duplicates(self, node):
        """
        Pre-scan the tree to detect duplicates and remove all but the first instance.
        """
        from collections import defaultdict

        seen = defaultdict(list)

        def recurse(n, path="root"):
            if not isinstance(n, dict):
                return
            uid = n.get(self.UNIVERSAL_ID_KEY)
            if uid:
                seen[uid].append(n)
            for child in n.get(self.CHILDREN_KEY, []):
                recurse(child, path + f" > {uid}")

        recurse(node)

        # Keep the first instance, remove all subsequent ones
        for uid, instances in seen.items():
            if len(instances) > 1:
                print(f"[TREE-SCAN] ⚠️ Found {len(instances)} clones of '{uid}' — purging {len(instances) - 1}")
                self._rejected_nodes.append(uid)
                # Remove by ID, not direct node, so cleanup will strike even deep ghosts
                for dup_node in instances[1:]:
                    self.remove_exact_node(dup_node)
                    self._rejected_nodes.append(uid)

    @classmethod
    def load_tree(cls, input_path):
        try:
            # Load JSON data
            with open(input_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            #    print("Successfully loaded JSON data:", data)

            # Create TreeParser instance and parse root node
            instance = cls(data)  # Root node initialized
            #   print("Calling _parse_nodes once...")
            instance._parse_nodes(instance.root)  # Parse the tree
            return instance  # Correctly return the instance

        except Exception as e:  # Catch exceptions like FileNotFoundError or JSONDecodeError
            #  print(f"Error occurred while loading tree: {e}")
            return None  # Handle failure to load data gracefully

    @classmethod
    def load_tree_direct(cls, data):
        """Loads and parses a tree from a raw directive dictionary.

        This is the primary factory method for creating a TreeParser instance.
        It takes a raw dictionary (the directive), cleanses it of malformed
        nodes, scans for and removes duplicate universal_ids, and then
        parses the final, validated tree structure.

        Args:
            data (dict): The raw dictionary from a directive file.

        Returns:
            TreeParser: A new instance of the TreeParser with the loaded tree.
        """
        if isinstance(data, dict) and "agent_tree" in data:
            root_tree = data["agent_tree"]
            services = data.get("services", [])
        else:
            root_tree = data
            services = []

        instance = cls(root_tree)
        instance._service_manager_services = services  # inject globally scoped services
        # Strip disabled nodes before any other processing
        instance.strip_disabled_nodes(instance.root)

        instance.cleanse()
        instance.pre_scan_for_duplicates(instance.root)
        instance._parse_nodes(instance.root)
        return instance


    def _remove_node_and_children(self, target_uid):
        """
        Removes the node and its entire subtree from the tree.
        """
        parent = self.find_parent_of(target_uid)

        if parent:
            children = parent.get(self.CHILDREN_KEY, [])
            parent[self.CHILDREN_KEY] = [
                c for c in children if c.get(self.UNIVERSAL_ID_KEY) != target_uid
            ]
            print(f"[TREE-REMOVE] 🌪 Removed duplicate subtree '{target_uid}' from parent '{parent.get(self.UNIVERSAL_ID_KEY)}'")
        elif self.root.get(self.UNIVERSAL_ID_KEY) == target_uid:
            print(f"[TREE-REMOVE] 🌪 Root node is duplicate '{target_uid}', clearing root.")
            self.root = {self.UNIVERSAL_ID_KEY: "root", self.CHILDREN_KEY: []}


    @staticmethod
    def flatten_tree(subtree):
        nodes = []

        def recurse(node):
            if not isinstance(node, dict):
                return
            if "agent_name" in node and "name" not in node:
                node["name"] = node["agent_name"]
            nodes.append(node)
            for child in node.get("children", []):
                recurse(child)

        recurse(subtree)
        return nodes

    def merge_subtree(self, subtree):
        """
        Attempt to merge a subtree into the tree. Rejects if any duplicate universal_ids exist.
        """
        if not isinstance(subtree, dict):
            return False

        # 🧹 Clean out nameless nodes
        subtree = TreeParser.strip_invalid_nodes(subtree)
        if not subtree:
            print("[MERGE-REJECT] Entire subtree rejected due to invalid root node.")
            return False

        # Pre-scan for duplicate universal_ids
        new_ids = {node["universal_id"] for node in self.flatten_tree(subtree) if "universal_id" in node}
        collision = new_ids.intersection(set(self.nodes.keys()))
        if collision:
            print(f"[MERGE-REJECT] ❌ Subtree rejected due to duplicate IDs: {list(collision)}")
            self._duplicate_nodes.extend(collision)
            self._rejected_nodes.extend(collision)
            return False

        new_root_id = subtree.get("universal_id")
        if not new_root_id:
            return False

        self._parse_nodes(subtree)
        self.root[self.CHILDREN_KEY].append(subtree)
        return True

    def get_all_nodes_flat(self):
        flat = {}

        def recurse(node):
            if isinstance(node, dict) and 'universal_id' in node:
                flat[node['universal_id']] = node
            for child in node.get('children', []):
                recurse(child)

        recurse(self.root)
        return flat

    def load_dict(self, data):
        """
        Load a tree from a raw Python dictionary and return the cleansed version.
        """
        self.root = self._initialize_data(data)
        self.cleanse()
        return self.root

    def cleanse(self):
        """
        Fully cleanse the entire root tree including children.
        """

        def recursive_purge(node):
            if not isinstance(node, dict) or not node.get(self.UNIVERSAL_ID_KEY):
                return None

            clean_children = []
            for child in node.get(self.CHILDREN_KEY, []):
                clean = recursive_purge(child)
                if clean:
                    clean_children.append(clean)
                else:
                    print(f"[TREE] ⚠️ Removed malformed node during cleanse: {child}")

            node[self.CHILDREN_KEY] = clean_children
            return node

        self.root = recursive_purge(self.root)
        return self.root

    def find_parent_of(self, child_universal_id):
        """
        Recursively find the parent node that has a child with the given universal_id.
        """

        def recurse(node):
            if not node or not isinstance(node, dict):
                print(f"[RECURSE] Skipping bad node: {node}")
                return None

            children = node.get(self.CHILDREN_KEY, [])
            if not isinstance(children, list):
                print(f"[RECURSE] Children field is not a list for node: {node}")
                return None

            for child in children:
                if not isinstance(child, dict):
                    print(f"[RECURSE] Skipping bad child: {child}")
                    continue  # skip non-dict children

                child_perm = child.get(self.UNIVERSAL_ID_KEY, None)
                if child_perm == child_universal_id:
                    print(f"[RECURSE] FOUND parent of {child_universal_id} under node {node.get(self.UNIVERSAL_ID_KEY)}")
                    return node

                result = recurse(child)
                if result:
                    return result

            return None

        return recurse(self.root)

    def get_subtree_nodes(self, universal_id):
        """
        Get all nodes under and including the given universal_id.
        """
        if universal_id not in self.nodes:
            return []

        result = []

        def collect(node):
            result.append(node[self.UNIVERSAL_ID_KEY])
            for child in node.get(self.CHILDREN_KEY, []):
                collect(child)

        collect(self.nodes[universal_id])
        return result

    def walk_tree(self, node):
        if not node or not isinstance(node, dict):
            return []

        results = [node]

        for child in node.get("children", []):
            results.extend(self.walk_tree(child))

        return results

    def all_universal_ids(self):
        return [n["universal_id"] for n in self.walk_tree(self.root)]

    def get_node(self, universal_id):
        for node in self.walk_tree(self.root):
            if node.get("universal_id") == universal_id:
                return node
        return None

    def has_node(self, universal_id):
        return self.get_node(universal_id) is not None

    def get_service_managers(self, caller_universal_id=None):
        """
        Returns a flat list of all nodes that have a non-empty 'service-manager' field
        under their config.
        If caller_universal_id is provided, it annotates each service with:
            - _is_child: True if the caller is an ancestor of the service node
            - _level: depth from caller to service node (0 if same, 1 if direct child, etc)
        """
        service_nodes = []

        def recurse(node, path_stack):
            if not isinstance(node, dict):
                return
            config = node.get("config", {})
            universal_id = node.get("universal_id")
            full_path = path_stack + [universal_id] if universal_id else path_stack

            if config.get("service-manager") and (universal_id != caller_universal_id):
                annotated_node = dict(node)  # shallow copy

                if caller_universal_id and caller_universal_id in full_path:
                    idx = full_path.index(caller_universal_id)
                    annotated_node["_is_child"] = True
                    annotated_node["_level"] = len(full_path) - idx - 1
                else:
                    annotated_node["_is_child"] = False
                    annotated_node["_level"] = None

                service_nodes.append(annotated_node)

            for child in node.get("children", []):
                recurse(child, full_path)

        recurse(self.root, [])
        return service_nodes

    def get_node_shallow(self, universal_id: str):
        """
        Returns a deep copy of the specified node with children stripped.
        Useful when sharing metadata without replicating the full subtree.
        """
        node = self.get_node(universal_id)
        if not node:
            return None
        clone = copy.deepcopy(node)
        if "children" in clone:
            clone["children"] = []
        return clone

    def assign_identity_to_all_nodes(self, matrix_priv_obj, matrix_pub=None, matrix_priv=None, matrix_key_b64=None,
                                     encryption_enabled=True, force=False):
        """
        Consolidated identity assignment routine.

        - If node is "matrix", assign it the Matrix keys directly.
        - If node is a sentinel with `matrix_secure_verified`, assign Matrix credentials.
        - Otherwise, generate fresh keys for that node.

        Args:
            matrix_priv_obj: RSA private key object for signing.
            matrix_pub: PEM-encoded Matrix public key string.
            matrix_priv: PEM-encoded Matrix private key string.
            matrix_key_b64: Base64-encoded AES key string.
        """
        for node in self.walk_tree(self.root):
            uid = node.get("universal_id")
            if not uid:
                continue

            # === CASE 1: Matrix Node ===
            if uid == "matrix":
                self.assign_identity_token_to_node(
                    uid,
                    matrix_priv_obj=matrix_priv_obj,
                    replace_keys={
                        "priv_key": matrix_priv,
                        "pub_key": matrix_pub,
                        "private_key": matrix_key_b64
                    },
                    encryption_enabled=encryption_enabled,
                    force=True
                )
                print(f"[ASSIGN-ALL] Matrix node assigned root keypair.")

            # === CASE 2: Verified Sentinel ===
            elif node.get("config", {}).get("matrix_secure_verified"):
                self.assign_identity_token_to_node(
                    uid,
                    matrix_priv_obj=matrix_priv_obj,
                    encryption_enabled=encryption_enabled,
                    force=True
                )
                node.setdefault("config", {}).setdefault("matrix_secure_store", {})
                node["config"]["matrix_secure_store"]["matrix_priv"] = matrix_priv
                node["config"]["matrix_secure_store"]["matrix_pub"] = matrix_pub
                node["config"]["matrix_secure_store"]["matrix_key"] = matrix_key_b64
                node["config"]["matrix_secure_store"]["matrix_node"] = self.get_node_shallow('matrix')
                node["config"]["matrix_secure_store"]["verified_timestamp"] = int(time.time())
                print(f"[ASSIGN-ALL] 🔐 Sentinel '{uid}' given Matrix credentials.")

            # === CASE 3: Standard Agent ===
            else:
                self.assign_identity_token_to_node(uid, matrix_priv_obj, encryption_enabled, force=force)

    def assign_identity_token_to_node(self, uid, matrix_priv_obj, encryption_enabled=True, force=False, replace_keys:dict={}):
        """
        Generates and assigns a cryptographically secure identity to a single node.

        This is the core of the identity creation process. For a given node, it:
        1. Generates a new RSA public/private key pair and an AES key.
        2. Creates an identity "token" containing the agent's universal_id and public key.
        3. Signs this token with the master Matrix private key, creating a verifiable chain of trust.
        4. Stores the new keys and the signed token in the node's `vault`.
        """
        node = self.get_node(uid)
        if not node:
            print(f"[ASSIGN-ID] ❌ No node found for UID: {uid}")
            raise RuntimeError(f"[ASSIGN-ID] ❌ No node found for UID: {uid}")

        if "vault" in node and not force and not replace_keys:
            print(f"[ASSIGN-ID] ⏭️ Vault already exists for '{uid}', skipping (use force=True to overwrite)")
            return False

        try:
            # Ensure matrix_priv_obj is in proper RSA format
            if isinstance(matrix_priv_obj, str):
                matrix_priv_obj = RSA.import_key(matrix_priv_obj.encode())
            elif isinstance(matrix_priv_obj, bytes):
                matrix_priv_obj = RSA.import_key(matrix_priv_obj)
            elif not isinstance(matrix_priv_obj, RSA.RsaKey):
                raise TypeError("❌ matrix_priv_obj must be an RSA key or PEM string/bytes.")

            if bool(replace_keys.get('priv_key', False)) and (replace_keys.get('pub_key', False)):
                priv_pem = replace_keys.get('priv_key')
                pub_pem = replace_keys.get('pub_key')
                private_key = replace_keys.get('private_key')
            else:
                # Generate new identity keypair
                key = RSA.generate(2048)
                priv_pem = key.export_key().decode()
                pub_pem = key.publickey().export_key().decode()
                private_key = generate_aes_key()

            # Create signed identity token
            token = {
                "universal_id": uid,
                "pub": pub_pem,
                "timestamp": int(time.time())
            }

            digest = SHA256.new(json.dumps(token, sort_keys=True).encode())
            sig = pkcs1_15.new(matrix_priv_obj).sign(digest)
            sigg = base64.b64encode(sig).decode()

            # Assign vault
            node["vault"] = {
                "priv": priv_pem,
                "private_key": private_key,  # aes encryption key
                "sig": sigg,  # Matrix Sig
                "identity": token
            }

            if not replace_keys:
                print(f"[ASSIGN-ID] ✅ Identity token assigned for '{uid}'")
            return True

        except Exception as e:
            raise RuntimeError(f"[GOSPEL-KEY] Failed to assign identity token for '{uid}': {e}")

    # in TreeParser class
    def mark_target_list(self, target_uid: str, mark: dict, recurse_children: bool = True):
        """Mark target_uid and optionally its descendants with `mark` dict."""
        affected = []

        def recurse(node):
            if not isinstance(node, dict):
                return
            uid = node.get("universal_id") or node.get(self.UNIVERSAL_ID_KEY)
            if uid:
                node.update(mark)
                affected.append(uid)
            if recurse_children:
                for child in node.get(self.CHILDREN_KEY, []):
                    recurse(child)

        target_node = self.get_node(target_uid)
        if target_node:
            recurse(target_node)
        else:
            print(f"[MARK] ❌ Node '{target_uid}' not found.")
        return affected

    def strip_disabled_nodes(self, node):
        """
        Recursively removes nodes (and their entire subtrees) that are
        explicitly marked with "enabled": false in their config.
        """
        if not isinstance(node, dict):
            return None

        # Check if the node is explicitly disabled in its config.
        if node.get("enabled") is False:
            self.log(f"[TREE-CLEAN] ✂️ Stripping disabled agent and its subtree: '{node.get('universal_id')}'")
            self._rejected_nodes.append(node.get("universal_id"))
            return None  # This removes the node and its children from the tree.

        # If the node is enabled, recursively process its children.
        if self.CHILDREN_KEY in node:
            node[self.CHILDREN_KEY] = [
                processed_child for child in node.get(self.CHILDREN_KEY, [])
                if (processed_child := self.strip_disabled_nodes(child)) is not None
            ]
        return node

    def get_minimal_services_tree(self, root_universal_id=None):
        """
        Returns a stripped-down list of all service-manager-enabled nodes
        in the tree, excluding the node with universal_id == root_universal_id.
        Preserves only: name, universal_id, and config.service-manager.
        """
        minimal_tree = []

        for node in self.walk_tree(self.root):
            if root_universal_id and node.get("universal_id") == root_universal_id:
                continue  # ❌ Skip the excluded node

            config = node.get("config", {})
            if config.get("service-manager"):
                minimal_tree.append({
                    "name": node.get("name"),
                    "universal_id": node.get("universal_id"),
                    "config": {
                        "service-manager": config["service-manager"]
                    }
                })

        return minimal_tree