from pathlib import Path

def get_swarm_root():
    """
    Resolves the swarm root directory based on .swarm pointer or default fallback.
    """
    pointer_paths = [
        Path.home() / ".matrixswarm_pointer",
        Path.home() / ".matrixswarm" / ".swarm",
    ]

    for pointer in pointer_paths:
        if pointer.exists():
            with open(pointer, "r", encoding="utf-8") as f:
                return Path(f.read().strip()).expanduser().resolve()

    # Fallback to local .matrixswarm if no pointer found
    fallback = Path.home() / ".matrixswarm"
    return fallback
