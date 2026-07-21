# PyInstaller spec - one-file `orthrus` CLI binary.
#   pyinstaller packaging/orthrus.spec
# Produces dist/orthrus (or dist/orthrus.exe on Windows). The dynamic scanner /
# exploit / recon registries are populated by static imports in each package's
# __init__, so collect_submodules('orthrus') is enough to pull them in; the
# Jinja report templates are bundled as data.
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

hiddenimports = (
    collect_submodules("orthrus")
    + collect_submodules("httpx")
    + ["aiosqlite", "sqlalchemy.dialects.sqlite.aiosqlite"]
)
datas = collect_data_files("orthrus", includes=["reporting/templates/*", "**/*.html", "**/*.json"])

a = Analysis(
    ["../orthrus/__main__.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    # Heavy optional extras aren't needed in the portable binary; they stay pip-only.
    excludes=["playwright", "celery", "redis", "asyncpg", "boto3", "grpc", "sslyze", "matplotlib"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="orthrus",
    console=True,
    strip=False,
    upx=True,
)
