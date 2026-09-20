# PyInstaller spec for the AIDefender CLI binary.
from PyInstaller.utils.hooks import collect_submodules

hidden = collect_submodules("aidefender")
a = Analysis(
    ["../aidefender/__main__.py"],
    pathex=[".."],
    binaries=[],
    datas=[("../signatures.json", ".")],
    hiddenimports=hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="aidefender",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)
