import os
import sys
import shutil
from pathlib import Path
import logging

# Check Python version at runtime
if sys.version_info >= (3, 11):
    import tomllib as toml  # Use the built-in tomllib for Python 3.11+
else:
    import tomli as toml    # Use the external tomli for Python 3.7 to 3.10

# Uncomment if library can still function if extensions fail to compile (e.g. slower, python fallback).
# Don't allow failure if cibuildwheel is running.
# allowed_to_fail = os.environ.get("CIBUILDWHEEL", "0") != "1"
allowed_to_fail = False

def read_cython_path():
    try:
        with open("pyproject.toml", "rb") as f:
            pyproject_data = toml.load(f)
    except toml.TOMLDecodeError as e:
        print(f"Exception while decoding pyproject.toml: {e}")
        return {}
    except Exception as e:
        print(f"general exception while reading pyproject.toml: {e}")
        return {}

    return pyproject_data.get("tool", {}).get("build", {}).get("config", {})

def build_cython_extensions():
    # when using setuptools, you should import setuptools before Cython,
    # otherwise, both might disagree about the class to use.
    from setuptools import Extension  # noqa: I001
    from setuptools.dist import Distribution  # noqa: I001
    import Cython.Compiler.Options  # pyright: ignore [reportMissingImports]
    from Cython.Build import build_ext, cythonize  # pyright: ignore [reportMissingImports]

    Cython.Compiler.Options.annotate = True

    config = read_cython_path()
    extensions_path = config.get("extensions_path","extensions")
    include_dirs = config.get("include_dirs", [])
    build_log = config.get("build_log", False)

    if build_log:
        logging.basicConfig(level=logging.DEBUG)
        logger = logging.getLogger(__name__)

        file_handler = logging.FileHandler("build.log", mode="w")
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        logger.info(f"Logging build.py")

    if build_log:
        logger.info(f"Using extensions path: {extensions_path}")

    if os.name == "nt":  # Windows
        extra_compile_args = [
            "/O2",
        ]
    else:  # UNIX-based systems
        extra_compile_args = [
            "-O3",
            "-Werror",
            "-Wno-unreachable-code-fallthrough",
            "-Wno-deprecated-declarations",
            "-Wno-parentheses-equality",
            "-Wno-unreachable-code",  # TODO: This should no longer be necessary with Cython>=3.0.3
        ]
    extra_compile_args.append("-UNDEBUG")  # Cython disables asserts by default.
    # Relative to project root director
    if isinstance(include_dirs, str):
        include_dirs = [directory.strip() for directory in include_dirs.split(",")]
    else:
        include_dirs = [str(Path(directory)) for directory in include_dirs]

    ext_dirs = []

    # Dynamically find all .c files in the cyth directory
    root_path = Path(extensions_path)
    extensions = []
    patterns = ["*.c", "*.pyx"]
    for subdir in root_path.iterdir():
        c_files = []
        if subdir.is_dir():
            # Recursively get all .c and .pyx files for the current module
            c_files = [file for pattern in patterns for file in subdir.rglob(pattern)]
        if c_files:
            ext_dirs.append(subdir)
            extensions.append(
                Extension(
                    str(subdir.name),
                    [str(c_file) for c_file in c_files],
                    include_dirs=include_dirs,
                    extra_compile_args=extra_compile_args,
                    language="c"
                )
            )

    # Log discovered extensions
    if build_log:
        logger.info(f"Creating Extensions: {[ext.name for ext in extensions]}")
        logger.info(f"collected extension directories: {ext_dirs}")

    include_dirs = set()
    for extension in extensions:
        include_dirs.update(extension.include_dirs)
    include_dirs = list(include_dirs)

    if build_log:
        logger.info("Cythonizing.....")
    ext_modules = cythonize(extensions, include_path=include_dirs, language_level=3, annotate=True)
    if build_log:
        logger.info("End of Cythonizing")
    dist = Distribution({"ext_modules": ext_modules})
    cmd = build_ext(dist)
    cmd.ensure_finalized()
    cmd.run()

    for output, src_path in zip(cmd.get_outputs(),ext_dirs):
        output = Path(output)
        src_relative_path = src_path / output.name
        shutil.copyfile(output, src_relative_path)
        if build_log:
            logger.info(f"Copied {output} to {src_relative_path}")

def build(setup_kwargs):
    try:
        build_cython_extensions()
    except Exception:
        if not allowed_to_fail:
            raise
