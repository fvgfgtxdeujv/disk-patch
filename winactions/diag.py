# -*- coding: utf-8 -*-
"""diag.py —— runner 环境诊断（虚拟化迹象 / 权限 / 会话），失败不阻断"""
import os
import sys


def main():
    print('=' * 50)
    print('环境诊断')
    print('=' * 50)
    try:
        import ctypes
        adv = ctypes.windll.shell32.IsUserAnAdmin()
        print('  管理员        : %s' % bool(adv))
    except Exception as e:
        print('  管理员        : 未知 (%s)' % e)
    print('  用户          : %s' % os.environ.get('USERNAME'))
    print('  会话          : %s' % os.environ.get('SESSIONNAME'))
    print('  Python        : %s' % sys.version.split()[0])
    try:
        print('  CPU 数        : %d' % (os.cpu_count() or 0))
    except Exception:
        pass

    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           r'HARDWARE\DESCRIPTION\System\BIOS')
        print('  --- BIOS（反虚拟化通常查这里）---')
        for name in ('SystemManufacturer', 'SystemProductName',
                     'BIOSVendor', 'BIOSVersion'):
            try:
                print('  %-14s: %s' % (name, winreg.QueryValueEx(k, name)[0]))
            except OSError:
                pass
    except OSError as e:
        print('  BIOS 读取失败 : %s' % e)

    # CPUID hypervisor bit（leaf 1, ECX bit31）：Python 没法直接 cpuid，
    # 用 IsProcessorFeaturePresent 不可靠，这里退化为读注册表 HypervisorEnforcedCodeIntegrity
    try:
        import winreg
        k = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r'SYSTEM\CurrentControlSet\Control\DeviceGuard')
        try:
            v, _ = winreg.QueryValueEx(k, 'EnableVirtualizationBasedSecurity')
            print('  VBS 启用      : %s（启用的话更可能命中反虚拟化）' % v)
        except OSError:
            print('  VBS 启用      : 未配置')
    except OSError:
        pass
    print('=' * 50)
    return 0


if __name__ == '__main__':
    sys.exit(main())
