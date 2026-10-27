import subprocess
import shlex
import sys


def run(cmd: str):
    subprocess.run(shlex.split(cmd), check=True)


def main():
    level = sys.argv[1]
    run("cargo clippy --release")
    # Pushing the tag runs .github/workflows/release.yml, which publishes to crates.io.
    run(f"cargo release {level} --no-publish")


if __name__ == "__main__":
    main()
