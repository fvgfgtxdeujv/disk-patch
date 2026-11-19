// winctl: 用 Win32 消息直接操作对话框（绕开 X 层焦点问题）
// 用法:
//   winctl list
//   winctl fill "Name" "mail@x.com" "CODE-...."
//   winctl click "Register Now"
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static HWND g_target = NULL;
static wchar_t g_title_needle[128] = L"Offline Register";

static void u2a(const wchar_t *w, char *out, int n) {
    if (!w) { out[0] = 0; return; }
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, n, NULL, NULL);
}
static void a2u(const char *a, wchar_t *out, int n) {
    MultiByteToWideChar(CP_UTF8, 0, a, -1, out, n);
}
static int wcontains(const wchar_t *hay, const wchar_t *needle) {
    return hay && needle && wcsstr(hay, needle) != NULL;
}

BOOL CALLBACK enum_top(HWND h, LPARAM lp) {
    wchar_t t[512];
    GetWindowTextW(h, t, 512);
    if (wcontains(t, g_title_needle)) { g_target = h; return FALSE; }
    return TRUE;
}

typedef struct { HWND h; int id; wchar_t cls[128]; wchar_t txt[1024]; RECT rc; } Ctrl;
static Ctrl g_ctrls[256];
static int g_nctrl = 0;

BOOL CALLBACK enum_child(HWND h, LPARAM lp) {
    if (g_nctrl >= 256) return TRUE;
    Ctrl *c = &g_ctrls[g_nctrl];
    c->h = h;
    c->id = GetDlgCtrlID(h);
    GetClassNameW(h, c->cls, 128);
    GetWindowTextW(h, c->txt, 1024);
    GetWindowRect(h, &c->rc);
    g_nctrl++;
    return TRUE;
}

static void collect(void) {
    g_nctrl = 0;
    EnumChildWindows(g_target, enum_child, 0);
}

static void do_list(void) {
    printf("TARGET hwnd=%p\n", (void*)g_target);
    for (int i = 0; i < g_nctrl; i++) {
        char cls[512], txt[4096];
        u2a(g_ctrls[i].cls, cls, sizeof cls);
        u2a(g_ctrls[i].txt, txt, sizeof txt);
        printf("[%02d] hwnd=%p id=%d class=%s text=<%s> rect=(%ld,%ld)-(%ld,%ld) vis=%d\n",
               i, (void*)g_ctrls[i].h, g_ctrls[i].id, cls, txt,
               g_ctrls[i].rc.left, g_ctrls[i].rc.top, g_ctrls[i].rc.right, g_ctrls[i].rc.bottom,
               IsWindowVisible(g_ctrls[i].h));
    }
    fflush(stdout);
}

static int is_edit(Ctrl *c) {
    return _wcsicmp(c->cls, L"Edit") == 0;
}

static void do_fill(const char *name, const char *email, const char *code) {
    // 按 y 排序（从上到下）填 Edit
    int idx[64], n = 0;
    for (int i = 0; i < g_nctrl && n < 64; i++) if (is_edit(&g_ctrls[i])) idx[n++] = i;
    for (int a = 0; a < n; a++) for (int b = a + 1; b < n; b++)
        if (g_ctrls[idx[b]].rc.top < g_ctrls[idx[a]].rc.top) { int t = idx[a]; idx[a] = idx[b]; idx[b] = t; }
    const char *vals[3] = { name, email, code };
    printf("found %d edit controls\n", n);
    for (int i = 0; i < n && i < 3; i++) {
        wchar_t w[1024];
        a2u(vals[i], w, 1024);
        SendMessageW(g_ctrls[idx[i]].h, WM_SETTEXT, 0, (LPARAM)w);
        printf("  edit#%d id=%d <- <%s>\n", i, g_ctrls[idx[i]].id, vals[i]);
    }
    fflush(stdout);
}

static void do_click(const char *label) {
    wchar_t want[256];
    a2u(label, want, 256);
    for (int i = 0; i < g_nctrl; i++) {
        if (_wcsicmp(g_ctrls[i].cls, L"Button") == 0 && wcontains(g_ctrls[i].txt, want)) {
            printf("clicking id=%d text=<%s>\n", g_ctrls[i].id, label);
            fflush(stdout);
            SendMessageW(g_ctrls[i].h, BM_CLICK, 0, 0);
            return;
        }
    }
    printf("button <%s> not found\n", label);
    fflush(stdout);
}

static void menu_dump(HMENU m, int depth) {
    int n = GetMenuItemCount(m);
    for (int i = 0; i < n; i++) {
        wchar_t buf[512] = L""; char a[1024];
        GetMenuStringW(m, i, buf, 512, MF_BYPOSITION);
        u2a(buf, a, sizeof a);
        UINT id = GetMenuItemID(m, i);
        printf("%*s[%d] id=%u <%s>\n", depth * 2, "", i, id, a);
        HMENU sub = GetSubMenu(m, i);
        if (sub) menu_dump(sub, depth + 1);
    }
}

static int menu_find_cmd(HMENU m, const wchar_t *needle, UINT *out) {
    int n = GetMenuItemCount(m);
    for (int i = 0; i < n; i++) {
        wchar_t buf[512] = L"";
        GetMenuStringW(m, i, buf, 512, MF_BYPOSITION);
        if (wcontains(buf, needle)) {
            UINT id = GetMenuItemID(m, i);
            if (id != 0 && id != (UINT)-1) { *out = id; return 1; }
        }
        HMENU sub = GetSubMenu(m, i);
        if (sub && menu_find_cmd(sub, needle, out)) return 1;
    }
    return 0;
}

BOOL CALLBACK enum_all(HWND h, LPARAM lp) {
    wchar_t t[512]; char a[1024];
    GetWindowTextW(h, t, 512);
    u2a(t, a, sizeof a);
    printf("TOP %p <%s> vis=%d\n", (void*)h, a, IsWindowVisible(h));
    return TRUE;
}

int main(int argc, char **argv) {
    char *env_title = getenv("WINCTL_TITLE");
    if (env_title && env_title[0]) a2u(env_title, g_title_needle, 128);
    EnumWindows(enum_top, 0);
    if (!g_target) {
        printf("target window not found; dumping all top-level:\n");
        EnumWindows(enum_all, 0);
        fflush(stdout); return 2;
    }
    collect();
    if (argc < 2) { do_list(); return 0; }
    if (!strcmp(argv[1], "tops")) { EnumWindows(enum_all, 0); fflush(stdout); }
    else if (!strcmp(argv[1], "list")) do_list();
    else if (!strcmp(argv[1], "fill") && argc >= 5) do_fill(argv[2], argv[3], argv[4]);
    else if (!strcmp(argv[1], "click") && argc >= 3) do_click(argv[2]);
    else if (!strcmp(argv[1], "setid") && argc >= 4) {
        int want = atoi(argv[2]); wchar_t w[1024];
        a2u(argv[3], w, 1024);
        for (int i = 0; i < g_nctrl; i++)
            if (g_ctrls[i].id == want) {
                SendMessageW(g_ctrls[i].h, WM_SETTEXT, 0, (LPARAM)w);
                printf("set id=%d <- <%s>\n", want, argv[3]); fflush(stdout); return 0;
            }
        printf("id %d not found\n", want); fflush(stdout); return 6;
    }
    else if (!strcmp(argv[1], "show")) {
        ShowWindow(g_target, SW_SHOW);
        SetWindowPos(g_target, HWND_TOP, 0,0,0,0, SWP_NOMOVE|SWP_NOSIZE|SWP_SHOWWINDOW);
        printf("shown %p vis=%d\n", (void*)g_target, IsWindowVisible(g_target)); fflush(stdout);
    }
    else if (!strcmp(argv[1], "close")) {
        printf("WM_CLOSE -> %p\n", (void*)g_target); fflush(stdout);
        PostMessageW(g_target, WM_CLOSE, 0, 0); Sleep(800);
    }
    else if (!strcmp(argv[1], "menu")) {
        HMENU m = GetMenu(g_target);
        if (!m) { printf("no menu\n"); fflush(stdout); return 4; }
        menu_dump(m, 0); fflush(stdout);
    }
    else if (!strcmp(argv[1], "cmd") && argc >= 3) {
        wchar_t want[256]; UINT id = 0;
        a2u(argv[2], want, 256);
        HMENU m = GetMenu(g_target);
        if (m && menu_find_cmd(m, want, &id)) {
            printf("PostMessage WM_COMMAND id=%u\n", id); fflush(stdout);
            PostMessageW(g_target, WM_COMMAND, id, 0);
            Sleep(1500);
        } else { printf("menu item not found\n"); fflush(stdout); return 5; }
    }
    else if (!strcmp(argv[1], "gettext") && argc >= 3) {
        int idx = atoi(argv[2]);
        if (idx >= 0 && idx < g_nctrl) {
            wchar_t buf[4096] = L""; char a[8192];
            SendMessageW(g_ctrls[idx].h, WM_GETTEXT, 4096, (LPARAM)buf);
            u2a(buf, a, sizeof a);
            printf("ctrl[%d] id=%d text=<%s>\n", idx, g_ctrls[idx].id, a);
        } else printf("bad index\n");
        fflush(stdout);
    }
    else { printf("bad args\n"); fflush(stdout); return 3; }
    return 0;
}
