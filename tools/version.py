# PlatformIO pre-build script: bake `git describe` into the firmware as FW_VERSION,
# so the dashboard shows exactly which build is running.
import subprocess
Import("env")  # noqa: F821 (provided by PlatformIO)

try:
    ver = subprocess.check_output(["git", "describe", "--tags", "--match", "v*", "--always", "--dirty"],
                                  cwd=env.subst("$PROJECT_DIR"), stderr=subprocess.DEVNULL).decode().strip()
except Exception:
    ver = "unknown"
env.Append(CPPDEFINES=[("FW_VERSION", '\\"%s\\"' % ver)])
