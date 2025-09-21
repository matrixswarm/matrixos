class JsonChildPurge():

    @staticmethod
    def the_purge(node):
        clean = []
        for child in node.get("children", []):
            if isinstance(child, dict) and child.get("universal_id"):
                JsonChildPurge.the_purge(child)
                clean.append(child)
            else:
                print(f"[MATRIX][PURGE] Ghost node removed: {child}")
        node["children"] = clean