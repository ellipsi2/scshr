#include "app/app.h"

namespace scshr::app {

// X11 keysyms (keymap.py / keyboard_grab.py).
uint32_t vk_to_keysym(unsigned vk, bool extended) {
    (void)extended;
    switch (vk) {
    case VK_ESCAPE: return 0xff1b; case VK_TAB: return 0xff09; case VK_BACK: return 0xff08; case VK_RETURN: return 0xff0d;
    case VK_DELETE: return 0xffff; case VK_INSERT: return 0xff63; case VK_HOME: return 0xff50; case VK_END: return 0xff57;
    case VK_PRIOR: return 0xff55; case VK_NEXT: return 0xff56; case VK_LEFT: return 0xff51; case VK_UP: return 0xff52; case VK_RIGHT: return 0xff53; case VK_DOWN: return 0xff54;
    case VK_LSHIFT: return 0xffe1; case VK_RSHIFT: return 0xffe2; case VK_SHIFT: return 0xffe1;
    case VK_LCONTROL: return 0xffe3; case VK_RCONTROL: return 0xffe4; case VK_CONTROL: return 0xffe3;
    case VK_LMENU: return 0xffe9; case VK_RMENU: return 0xffea; case VK_MENU: return 0xffe9;
    case VK_LWIN: return 0xffeb; case VK_RWIN: return 0xffec; case VK_CAPITAL: return 0xffe5;
    default: break;
    }
    if (vk >= VK_F1 && vk <= VK_F24) return 0xffbe + (vk - VK_F1);
    return 0;   // printable: WM_CHAR delivers the layout-correct codepoint
}

uint32_t vk_to_keysym_letter(unsigned vk) {
    if (vk >= '0' && vk <= '9') return vk;
    if (vk >= 'A' && vk <= 'Z') return vk + 0x20;
    if (vk == VK_SPACE) return ' ';
    switch (vk) {
    case 0xBA: return ';'; case 0xBB: return '='; case 0xBC: return ','; case 0xBD: return '-'; case 0xBE: return '.'; case 0xBF: return '/'; case 0xC0: return '`';
    case 0xDB: return '['; case 0xDC: return '\\'; case 0xDD: return ']'; case 0xDE: return '\'';
    case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66: case 0x67: case 0x68: case 0x69: return '0' + (vk - 0x60);
    case 0x6A: return '*'; case 0x6B: return '+'; case 0x6D: return '-'; case 0x6E: return '.'; case 0x6F: return '/';
    default: return 0;
    }
}

}  // namespace scshr::app
