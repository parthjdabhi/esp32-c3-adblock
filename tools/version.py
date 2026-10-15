# PlatformIO pre-build script: bake the firmware version into the build as FW_VERSION,
# so the dashboard shows exactly which build is running.
# The version comes from the VERSION file (bump it in every PR: 0.1 -> 0.2 -> ...).
# "-dirty" is added when the build has uncommitted changes.
import os
import subprocess
Import("env")  # noqa: F821 (provided by PlatformIO)

root = env.subst("$PROJECT_DIR")
try:
    with open(os.path.join(root, "VERSION")) as f:
        ver = f.read().strip() or "unknown"
except OSError:
    ver = "unknown"
try:
    dirty = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"],
                                    cwd=root, stderr=subprocess.DEVNULL).decode().strip()
    if dirty:
        ver += "-dirty"
except Exception:
    pass
env.Append(CPPDEFINES=[("FW_VERSION", '\\"%s\\"' % ver)])
