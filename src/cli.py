"""命令行入口：保持旧 patch_tool 的动词（status/patch/restore/enable/disable），
退出码 0=成功、1=失败且已打印原因、2=用法错误。"""
import sys

import antigravity_patch

if __name__ == '__main__':
    sys.exit(antigravity_patch.main(sys.argv[1:]))
