"""Build and test MAML locally using the same entry points as CI.

Run with a Python environment containing maml, pytest, and the PE extra when
using --python-tests; install build as well when using --artifacts.
"""

import argparse
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", choices=("Debug", "Release"), default="Release")
    parser.add_argument("--build-dir", default="build")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--python-tests", action="store_true")
    parser.add_argument("--artifacts", action="store_true")
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    root = Path(__file__).resolve().parents[1]

    def run(*command):
        print("+", " ".join(map(str, command)), flush=True)
        subprocess.run(command, cwd=root, check=True)

    run("cmake", "-S", ".", "-B", args.build_dir,
        f"-DCMAKE_BUILD_TYPE={args.config}")
    run("cmake", "--build", args.build_dir, "--config", args.config,
        "--parallel", str(args.jobs))
    run("ctest", "--test-dir", args.build_dir, "-C", args.config,
        "--output-on-failure")
    if args.python_tests:
        run(sys.executable, "-m", "pytest", "tests/python", "-q", "-o", "pythonpath=")
    if args.artifacts:
        run(sys.executable, "-m", "build")


if __name__ == "__main__":
    main()
