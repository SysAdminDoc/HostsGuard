# -*- mode: python ; coding: utf-8 -*-
block_cipher = None

a = Analysis(
    ['HostsGuard.py'],
    pathex=[],
    binaries=[],
    datas=[('icon.png', '.'), ('icon.ico', '.')],
    hiddenimports=['psutil', 'maxminddb'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # HostsGuard needs only PySide6, psutil, maxminddb. Exclude the heavy scientific/
    # ML/dev packages that may be present in a shared build environment — without
    # these excludes PyInstaller drags in torch/tensorflow/scipy and the onedir
    # output balloons to 800MB+.
    excludes=[
        'PyQt5', 'PyQt6', 'PySide2', 'tkinter', 'matplotlib', 'numpy', 'scipy',
        'torch', 'torchvision', 'torchaudio', 'tensorflow', 'onnxruntime', 'pandas',
        'sklearn', 'sympy', 'IPython', 'jupyter', 'notebook', 'PIL', 'cv2',
        'transformers', 'numba', 'llvmlite', 'pyarrow', 'cryptography', 'pytest',
        'hypothesis', 'setuptools', 'pip', 'wheel', 'lib2to3', 'pydoc_data',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='HostsGuard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico',
    version='version_info.txt',
    uac_admin=True,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='HostsGuard',
)
