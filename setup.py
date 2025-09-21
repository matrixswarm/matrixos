[project]
name = "matrixswarm"
version = "0.1.0"
description = "MatrixOS - multi-language swarm runtime"
dependencies = [
    "pycryptodome",
    "psutil",
]
[project.scripts]
matrixd = "matrixos.cli:main"
