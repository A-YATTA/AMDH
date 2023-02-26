# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all
import os

hiddenimports = []
venv_path = os.environ['VIRTUAL_ENV']

binaries=[(venv_path+'/lib/python3.10/site-packages/androguard/core/api_specific_resources/aosp_permissions/',
                'androguard/core/api_specific_resources/aosp_permissions/'),
          (venv_path+'/lib/python3.10/site-packages/pwnlib/shellcraft/templates/__doc__',
                'pwnlib/shellcraft/templates/')]

datas=[(venv_path+'/lib/python3.10/site-packages/androguard/core/resources/public.xml', 'androguard/core/resources')]
pathex=[venv_path+'/lib/python3.10/site-packages/']

block_cipher = None


a = Analysis(
    ['amdh.py'],
    pathex=pathex,
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='amdh',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
