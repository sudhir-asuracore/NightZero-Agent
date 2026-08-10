import os
from pathlib import Path

from nightzero.api import serve


if __name__ == "__main__":
    serve(Path(__file__).parents[1], int(os.environ.get("PORT", "8080")))