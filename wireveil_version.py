"""Version embedded into WireVeil Checker builds.

Tagged CI builds replace this value with the version from ``checker-v*`` before
PyInstaller starts.  Keeping the value in a tiny module also makes the version
available to the UI and the updater without importing Tkinter.
"""

APP_VERSION = "1.9.14"
