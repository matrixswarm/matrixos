
class PermanentIdExtract(object):
    @staticmethod
    def get_dict_by_universal_id(data, universal_id):
        for item in data:
            if item.get("universal_id") == universal_id:  # Match on universal_id
                return item  # Return the whole dictionary

        return {}  # If no match is found


