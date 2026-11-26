from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("ccvet")
except PackageNotFoundError:
    # Running from source without being installed (or installed under a
    # different distribution name) - this is the only situation where
    # there's no installed metadata to read.
    __version__ = "0.0.0+unknown"
