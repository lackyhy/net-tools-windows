/* ss - socket statistics (iproute2 style) for Windows */
#include "common.h"
#include <tlhelp32.h>
#include <ctype.h>

enum { SS_UNKNOWN, SS_ESTABLISHED, SS_SYN_SENT, SS_SYN_RECV, SS_FIN_WAIT1, SS_FIN_WAIT2, SS_TIME_WAIT,
       SS_CLOSE, SS_CLOSE_WAIT, SS_LAST_ACK, SS_LISTEN, SS_CLOSING, SS_MAX };
#define SB(x) (1u << (x))
#define SS_ALL (((1u << SS_MAX) - 1) & ~1u)
#define SS_CONN (SS_ALL & ~(SB(SS_LISTEN) | SB(SS_CLOSE) | SB(SS_TIME_WAIT) | SB(SS_SYN_RECV)))

static const char *st_short[] = {"UNKNOWN", "ESTAB", "SYN-SENT", "SYN-RECV", "FIN-WAIT-1", "FIN-WAIT-2",
                                 "TIME-WAIT", "UNCONN", "CLOSE-WAIT", "LAST-ACK", "LISTEN", "CLOSING"};

typedef struct {
    uint8_t udp, fam, state;
    uint16_t lport, rport;
    uint32_t lscope, rscope, pid;
    uint8_t la[16], ra[16];
} sock_t;

/* options */
static int o_tcp, o_udp, o_unix, o_raw, o_fam4, o_fam6, o_numeric, o_resolve, o_proc, o_summary,
    o_noheader, o_kill, o_ext;
static unsigned o_states;
static int states_set;

/* ======================= processes ======================= */

typedef struct { uint32_t pid; char *name; } proc_t;
static proc_t *procs;
static int nprocs;

static int proc_cmp(const void *a, const void *b) {
    uint32_t x = ((const proc_t *)a)->pid, y = ((const proc_t *)b)->pid;
    return x < y ? -1 : x > y;
}

static void load_procs(void) {
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof pe;
    int cap = 512;
    procs = (proc_t *)malloc(cap * sizeof(proc_t));
    if (Process32FirstW(h, &pe)) {
        do {
            if (nprocs == cap) { cap *= 2; procs = (proc_t *)realloc(procs, cap * sizeof(proc_t)); }
            procs[nprocs].pid = pe.th32ProcessID;
            procs[nprocs].name = w2u(pe.szExeFile);
            nprocs++;
        } while (Process32NextW(h, &pe));
    }
    CloseHandle(h);
    qsort(procs, nprocs, sizeof(proc_t), proc_cmp);
}

static const char *proc_name(uint32_t pid) {
    proc_t key = {pid, NULL};
    proc_t *p = (proc_t *)bsearch(&key, procs, nprocs, sizeof(proc_t), proc_cmp);
    return p ? p->name : NULL;
}

/* ======================= socket tables ======================= */

static sock_t *socks;
static int nsocks, capsocks;

static sock_t *new_sock(void) {
    if (nsocks == capsocks) {
        capsocks = capsocks ? capsocks * 2 : 1024;
        socks = (sock_t *)realloc(socks, capsocks * sizeof(sock_t));
    }
    sock_t *s = &socks[nsocks++];
    memset(s, 0, sizeof *s);
    return s;
}

static int map_tcp_state(DWORD s) {
    switch (s) {
    case MIB_TCP_STATE_CLOSED: return SS_CLOSE;
    case MIB_TCP_STATE_LISTEN: return SS_LISTEN;
    case MIB_TCP_STATE_SYN_SENT: return SS_SYN_SENT;
    case MIB_TCP_STATE_SYN_RCVD: return SS_SYN_RECV;
    case MIB_TCP_STATE_ESTAB: return SS_ESTABLISHED;
    case MIB_TCP_STATE_FIN_WAIT1: return SS_FIN_WAIT1;
    case MIB_TCP_STATE_FIN_WAIT2: return SS_FIN_WAIT2;
    case MIB_TCP_STATE_CLOSE_WAIT: return SS_CLOSE_WAIT;
    case MIB_TCP_STATE_CLOSING: return SS_CLOSING;
    case MIB_TCP_STATE_LAST_ACK: return SS_LAST_ACK;
    case MIB_TCP_STATE_TIME_WAIT: return SS_TIME_WAIT;
    default: return SS_CLOSE;
    }
}

static void *get_table(int tcp, int fam) {
    static char *buf;
    static DWORD bufsz;
    DWORD sz = bufsz, r;
    for (int tries = 0; tries < 8; tries++) {
        r = tcp ? GetExtendedTcpTable(buf, &sz, FALSE, fam, TCP_TABLE_OWNER_PID_ALL, 0)
                : GetExtendedUdpTable(buf, &sz, FALSE, fam, UDP_TABLE_OWNER_PID, 0);
        if (r == ERROR_INSUFFICIENT_BUFFER) {
            sz += sz / 4 + 4096;
            free(buf);
            buf = (char *)malloc(sz);
            bufsz = sz;
            continue;
        }
        break;
    }
    if (r != NO_ERROR) return NULL;
    return buf;
}

static void collect(int tcp, int fam) {
    void *t = get_table(tcp, fam);
    if (!t) return;
    if (tcp && fam == AF_INET) {
        MIB_TCPTABLE_OWNER_PID *tb = (MIB_TCPTABLE_OWNER_PID *)t;
        for (DWORD i = 0; i < tb->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID *r = &tb->table[i];
            sock_t *s = new_sock();
            s->fam = AF_INET;
            s->state = (uint8_t)map_tcp_state(r->dwState);
            memcpy(s->la, &r->dwLocalAddr, 4);
            memcpy(s->ra, &r->dwRemoteAddr, 4);
            s->lport = ntohs((u_short)r->dwLocalPort);
            s->rport = ntohs((u_short)r->dwRemotePort);
            s->pid = r->dwOwningPid;
        }
    } else if (tcp) {
        MIB_TCP6TABLE_OWNER_PID *tb = (MIB_TCP6TABLE_OWNER_PID *)t;
        for (DWORD i = 0; i < tb->dwNumEntries; i++) {
            MIB_TCP6ROW_OWNER_PID *r = &tb->table[i];
            sock_t *s = new_sock();
            s->fam = AF_INET6;
            s->state = (uint8_t)map_tcp_state(r->dwState);
            memcpy(s->la, r->ucLocalAddr, 16);
            memcpy(s->ra, r->ucRemoteAddr, 16);
            s->lscope = r->dwLocalScopeId;
            s->rscope = r->dwRemoteScopeId;
            s->lport = ntohs((u_short)r->dwLocalPort);
            s->rport = ntohs((u_short)r->dwRemotePort);
            s->pid = r->dwOwningPid;
        }
    } else if (fam == AF_INET) {
        MIB_UDPTABLE_OWNER_PID *tb = (MIB_UDPTABLE_OWNER_PID *)t;
        for (DWORD i = 0; i < tb->dwNumEntries; i++) {
            MIB_UDPROW_OWNER_PID *r = &tb->table[i];
            sock_t *s = new_sock();
            s->udp = 1;
            s->fam = AF_INET;
            s->state = SS_CLOSE;
            memcpy(s->la, &r->dwLocalAddr, 4);
            s->lport = ntohs((u_short)r->dwLocalPort);
            s->pid = r->dwOwningPid;
        }
    } else {
        MIB_UDP6TABLE_OWNER_PID *tb = (MIB_UDP6TABLE_OWNER_PID *)t;
        for (DWORD i = 0; i < tb->dwNumEntries; i++) {
            MIB_UDP6ROW_OWNER_PID *r = &tb->table[i];
            sock_t *s = new_sock();
            s->udp = 1;
            s->fam = AF_INET6;
            s->state = SS_CLOSE;
            memcpy(s->la, r->ucLocalAddr, 16);
            s->lscope = r->dwLocalScopeId;
            s->lport = ntohs((u_short)r->dwLocalPort);
            s->pid = r->dwOwningPid;
        }
    }
}

/* ======================= filter expression ======================= */

enum { F_AND, F_OR, F_NOT, F_SPORT, F_DPORT, F_SRC, F_DST };
enum { OP_EQ, OP_NE, OP_GT, OP_LT, OP_GE, OP_LE };

typedef struct fnode {
    int t, op;
    struct fnode *l, *r;
    int port;      /* -1 = any */
    int has_addr;
    inaddr addr;
} fnode;

static char **tk;
static int ntk, tpos;

static void tk_push(const char *s, size_t n) {
    tk = (char **)realloc(tk, (ntk + 1) * sizeof(char *));
    tk[ntk] = (char *)malloc(n + 1);
    memcpy(tk[ntk], s, n);
    tk[ntk][n] = 0;
    ntk++;
}

static void tokenize(const char *s) {
    while (*s) {
        if (isspace((unsigned char)*s)) { s++; continue; }
        if (*s == '(' || *s == ')') { tk_push(s, 1); s++; continue; }
        if (strchr("=<>!&|,", *s)) {
            size_t n = 1;
            if (strchr("!<>=", s[0]) && s[1] == '=') n = 2;
            else if ((s[0] == '&' && s[1] == '&') || (s[0] == '|' && s[1] == '|')) n = 2;
            tk_push(s, n);
            s += n;
            continue;
        }
        const char *b = s;
        while (*s && !isspace((unsigned char)*s) && !strchr("()=<>!&|,", *s)) s++;
        tk_push(b, s - b);
    }
}

static const char *peek(void) { return tpos < ntk ? tk[tpos] : NULL; }

static void fdie(const char *msg, const char *t) {
    errf("ss: bad filter: %s%s%s%s\n", msg, t ? " near \"" : "", t ? t : "", t ? "\"" : "");
    exit(1);
}

static fnode *mk(int t, fnode *l, fnode *r) {
    fnode *n = (fnode *)calloc(1, sizeof(fnode));
    n->t = t;
    n->l = l;
    n->r = r;
    n->port = -1;
    return n;
}

static int parse_op(int *op) {
    const char *t = peek();
    if (!t) return 0;
    static const struct { const char *s; int op; } ops[] = {
        {"=", OP_EQ}, {"==", OP_EQ}, {"eq", OP_EQ}, {"!=", OP_NE}, {"ne", OP_NE}, {"neq", OP_NE},
        {">", OP_GT}, {"gt", OP_GT}, {"<", OP_LT}, {"lt", OP_LT}, {">=", OP_GE}, {"ge", OP_GE},
        {"geq", OP_GE}, {"<=", OP_LE}, {"le", OP_LE}, {"leq", OP_LE}};
    for (size_t i = 0; i < sizeof ops / sizeof ops[0]; i++)
        if (!_stricmp(t, ops[i].s)) { *op = ops[i].op; tpos++; return 1; }
    return 0;
}

static int parse_port(const char *p) {
    if (*p == ':') p++;
    if (!*p || !strcmp(p, "*")) return -1;
    char *e;
    long v = strtol(p, &e, 10);
    if (!*e && v >= 0 && v <= 65535) return (int)v;
    int sp = svc_port(p);
    if (sp < 0) fdie("unknown port", p);
    return sp;
}

static void parse_hostport(const char *v, fnode *n) {
    char buf[160];
    if (strlen(v) >= sizeof buf) fdie("address too long", v);
    strcpy(buf, v);
    char *addr = buf, *port = NULL;
    if (buf[0] == '[') {
        char *rb = strchr(buf, ']');
        if (!rb) fdie("bad address", v);
        *rb = 0;
        addr = buf + 1;
        if (rb[1] == ':') port = rb + 2;
        else if (rb[1] == '/') { memmove(rb, rb + 1, strlen(rb + 1) + 1); }
    } else {
        char *c1 = strchr(buf, ':');
        if (c1 && !strchr(c1 + 1, ':')) { *c1 = 0; port = c1 + 1; } /* v4[:port] */
    }
    if (port) n->port = parse_port(port);
    if (*addr && strcmp(addr, "*")) {
        if (!ip_parse(addr, 0, &n->addr)) fdie("bad address", v);
        n->has_addr = 1;
    }
}

static fnode *p_expr(void);

static fnode *p_primary(void) {
    const char *t = peek();
    if (!t) fdie("unexpected end of expression", NULL);
    if (!strcmp(t, "(")) {
        tpos++;
        fnode *n = p_expr();
        if (!peek() || strcmp(peek(), ")")) fdie("missing ')'", peek());
        tpos++;
        return n;
    }
    if (!strcmp(t, "!") || !_stricmp(t, "not")) { tpos++; return mk(F_NOT, p_primary(), NULL); }
    if (!_stricmp(t, "sport") || !_stricmp(t, "dport")) {
        fnode *n = mk(_stricmp(t, "sport") ? F_DPORT : F_SPORT, NULL, NULL);
        tpos++;
        if (!parse_op(&n->op)) n->op = OP_EQ;
        if (!peek()) fdie("port expected", t);
        n->port = parse_port(tk[tpos++]);
        return n;
    }
    if (!_stricmp(t, "src") || !_stricmp(t, "dst")) {
        fnode *n = mk(_stricmp(t, "src") ? F_DST : F_SRC, NULL, NULL);
        tpos++;
        if (!parse_op(&n->op)) n->op = OP_EQ;
        if (n->op != OP_EQ && n->op != OP_NE) fdie("only = and != are valid for addresses", t);
        if (!peek()) fdie("address expected", t);
        parse_hostport(tk[tpos++], n);
        return n;
    }
    fdie("unexpected token", t);
    return NULL;
}

static int is_or(const char *t) { return t && (!_stricmp(t, "or") || !strcmp(t, "||") || !strcmp(t, ",")); }

static fnode *p_term(void) {
    fnode *n = p_primary();
    const char *t;
    while ((t = peek()) && strcmp(t, ")") && !is_or(t)) {
        if (!_stricmp(t, "and") || !strcmp(t, "&&")) tpos++;
        n = mk(F_AND, n, p_primary());
    }
    return n;
}

static fnode *p_expr(void) {
    fnode *n = p_term();
    while (is_or(peek())) { tpos++; n = mk(F_OR, n, p_term()); }
    return n;
}

static int port_cmp(int op, int v, int ref) {
    switch (op) {
    case OP_EQ: return v == ref;
    case OP_NE: return v != ref;
    case OP_GT: return v > ref;
    case OP_LT: return v < ref;
    case OP_GE: return v >= ref;
    case OP_LE: return v <= ref;
    }
    return 0;
}

static int addr_ok(const fnode *n, int fam, const uint8_t *a, uint16_t port) {
    int ok = 1;
    if (n->port >= 0 && port != n->port) ok = 0;
    if (ok && n->has_addr) {
        if (n->addr.family == fam) ok = prefix_match(fam, a, n->addr.a, n->addr.plen);
        else if (n->addr.family == AF_INET && fam == AF_INET6) {
            static const uint8_t mp[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
            ok = !memcmp(a, mp, 12) && prefix_match(AF_INET, a + 12, n->addr.a, n->addr.plen);
        } else ok = 0;
    }
    return n->op == OP_NE ? !ok : ok;
}

static int f_eval(const fnode *n, const sock_t *s) {
    switch (n->t) {
    case F_AND: return f_eval(n->l, s) && f_eval(n->r, s);
    case F_OR: return f_eval(n->l, s) || f_eval(n->r, s);
    case F_NOT: return !f_eval(n->l, s);
    case F_SPORT: return n->port < 0 || port_cmp(n->op, s->lport, n->port);
    case F_DPORT: return n->port < 0 || port_cmp(n->op, s->rport, n->port);
    case F_SRC: return addr_ok(n, s->fam, s->la, s->lport);
    case F_DST: return addr_ok(n, s->fam, s->ra, s->rport);
    }
    return 1;
}

/* ======================= state names ======================= */

static unsigned state_mask(const char *s) {
    static const struct { const char *n; unsigned m; } tab[] = {
        {"all", SS_ALL},
        {"connected", SS_ALL & ~(SB(SS_LISTEN) | SB(SS_CLOSE))},
        {"synchronized", SS_ALL & ~(SB(SS_LISTEN) | SB(SS_CLOSE) | SB(SS_SYN_SENT))},
        {"bucket", SB(SS_SYN_RECV) | SB(SS_TIME_WAIT)},
        {"big", SS_ALL & ~(SB(SS_SYN_RECV) | SB(SS_TIME_WAIT))},
        {"established", SB(SS_ESTABLISHED)}, {"estab", SB(SS_ESTABLISHED)},
        {"syn-sent", SB(SS_SYN_SENT)}, {"syn-recv", SB(SS_SYN_RECV)},
        {"fin-wait-1", SB(SS_FIN_WAIT1)}, {"fin-wait-2", SB(SS_FIN_WAIT2)},
        {"time-wait", SB(SS_TIME_WAIT)}, {"closed", SB(SS_CLOSE)}, {"unconn", SB(SS_CLOSE)},
        {"close-wait", SB(SS_CLOSE_WAIT)}, {"last-ack", SB(SS_LAST_ACK)},
        {"listening", SB(SS_LISTEN)}, {"listen", SB(SS_LISTEN)}, {"closing", SB(SS_CLOSING)},
    };
    for (size_t i = 0; i < sizeof tab / sizeof tab[0]; i++)
        if (!_stricmp(s, tab[i].n)) return tab[i].m;
    errf("ss: wrong state name: %s\n", s);
    exit(1);
}

/* ======================= formatting ======================= */

typedef struct {
    sock_t *s;
    char la[300], lp[40], ra[300], rp[40];
    const char *pname;
} row_t;

typedef struct { int fam; uint8_t a[16]; char *name; } rcache_t;
static rcache_t *rc;
static int nrc;
static int wsa_ok;

static const char *resolve_host(int fam, const uint8_t *a) {
    for (int i = 0; i < nrc; i++)
        if (rc[i].fam == fam && !memcmp(rc[i].a, a, fam == AF_INET ? 4 : 16)) return rc[i].name;
    if (!wsa_ok) { WSADATA w; WSAStartup(MAKEWORD(2, 2), &w); wsa_ok = 1; }
    SOCKADDR_INET sa;
    sa_set(&sa, fam, a, 0);
    wchar_t host[NI_MAXHOST];
    char *name = NULL;
    if (GetNameInfoW((SOCKADDR *)&sa, fam == AF_INET ? sizeof(SOCKADDR_IN) : sizeof(SOCKADDR_IN6), host,
                     NI_MAXHOST, NULL, 0, NI_NAMEREQD) == 0)
        name = w2u(host);
    rc = (rcache_t *)realloc(rc, (nrc + 1) * sizeof(rcache_t));
    rc[nrc].fam = fam;
    memcpy(rc[nrc].a, a, 16);
    rc[nrc].name = name;
    nrc++;
    return name;
}

static void fmt_addr(char *dst, int fam, const uint8_t *a, uint32_t scope) {
    char ip[64];
    const char *h = NULL;
    if (o_resolve && !ip_is_unspec(fam, a)) h = resolve_host(fam, a);
    if (h) { snprintf(dst, 300, "%s", h); return; }
    ip_fmt(ip, fam, a);
    if (fam == AF_INET) { strcpy(dst, ip); return; }
    if (scope && a[0] == 0xFE && (a[1] & 0xC0) == 0x80)
        snprintf(dst, 300, "[%s]%%%s", ip, ifname_idx(scope));
    else
        snprintf(dst, 300, "[%s]", ip);
}

static void fmt_port(char *dst, int udp, uint16_t port) {
    if (!port) { strcpy(dst, "*"); return; }
    if (!o_numeric) {
        const char *n = svc_name(udp, port);
        if (n) { snprintf(dst, 40, "%s", n); return; }
    }
    char *p = dst, t[8];
    int i = 0;
    do { t[i++] = (char)('0' + port % 10); port /= 10; } while (port);
    while (i) *p++ = t[--i];
    *p = 0;
}

static void kill_sock(const sock_t *s) {
    if (s->udp || s->fam != AF_INET) {
        errf("ss: cannot kill %s socket (Windows supports killing only IPv4 TCP)\n", s->udp ? "UDP" : "IPv6 TCP");
        return;
    }
    MIB_TCPROW r;
    r.dwState = MIB_TCP_STATE_DELETE_TCB;
    memcpy(&r.dwLocalAddr, s->la, 4);
    memcpy(&r.dwRemoteAddr, s->ra, 4);
    r.dwLocalPort = htons(s->lport);
    r.dwRemotePort = htons(s->rport);
    DWORD e = SetTcpEntry(&r);
    if (e != NO_ERROR) {
        if (e == ERROR_ACCESS_DENIED || e == ERROR_MR_MID_NOT_FOUND || e == 317)
            errf("ss: SOCK_DESTROY failed: Operation not permitted (run as Administrator)\n");
        else win_errf(e, "ss: SOCK_DESTROY failed: ");
    }
}

static void summary(void) {
    int t4 = 0, t6 = 0, u4 = 0, u6 = 0, est = 0, closed = 0, tw = 0;
    for (int i = 0; i < nsocks; i++) {
        sock_t *s = &socks[i];
        if (s->udp) { if (s->fam == AF_INET) u4++; else u6++; continue; }
        if (s->fam == AF_INET) t4++; else t6++;
        if (s->state == SS_ESTABLISHED) est++;
        else if (s->state == SS_TIME_WAIT) tw++;
        else if (s->state == SS_CLOSE) closed++;
    }
    int t = t4 + t6, u = u4 + u6;
    sb_printf(&g_out, "Total: %d\n", t + u);
    sb_printf(&g_out, "TCP:   %d (estab %d, closed %d, orphaned 0, timewait %d)\n\n", t, est, closed, tw);
    sb_printf(&g_out, "Transport Total     IP        IPv6\n");
    sb_printf(&g_out, "RAW\t  %-9d %-9d %-9d\n", 0, 0, 0);
    sb_printf(&g_out, "UDP\t  %-9d %-9d %-9d\n", u, u4, u6);
    sb_printf(&g_out, "TCP\t  %-9d %-9d %-9d\n", t, t4, t6);
    sb_printf(&g_out, "INET\t  %-9d %-9d %-9d\n", t + u, t4 + u4, t6 + u6);
    sb_printf(&g_out, "FRAG\t  %-9d %-9d %-9d\n\n", 0, 0, 0);
}

static void usage(int code) {
    sb_puts(&g_out,
        "Usage: ss [ OPTIONS ]\n"
        "       ss [ OPTIONS ] [ FILTER ]\n"
        "   -h, --help          this message\n"
        "   -V, --version       output version information\n"
        "   -n, --numeric       don't resolve service names\n"
        "   -r, --resolve       resolve host names\n"
        "   -a, --all           display all sockets\n"
        "   -l, --listening     display listening sockets\n"
        "   -p, --processes     show process using socket\n"
        "   -s, --summary       show socket usage summary\n"
        "   -K, --kill          forcibly close sockets (IPv4 TCP, needs Administrator)\n"
        "   -H, --no-header     suppress header line\n"
        "   -4, --ipv4          display only IP version 4 sockets\n"
        "   -6, --ipv6          display only IP version 6 sockets\n"
        "   -t, --tcp           display only TCP sockets\n"
        "   -u, --udp           display only UDP sockets\n"
        "   -x, --unix          display only Unix domain sockets (none on Windows)\n"
        "   -f, --family=FAMILY display sockets of type FAMILY (inet|inet6|unix)\n"
        "   -A, --query=QUERY   QUERY := {all|inet|tcp|udp|unix}[,QUERY]\n"
        "\n"
        "   FILTER := [ state STATE-FILTER ] [ EXPRESSION ]\n"
        "   STATE-FILTER := {all|connected|synchronized|bucket|big|TCP-STATES}\n"
        "     TCP-STATES := {established|syn-sent|syn-recv|fin-wait-{1,2}|time-wait|closed|\n"
        "                    close-wait|last-ack|listening|closing}\n"
        "   EXPRESSION := { sport|dport OP [:]PORT | src|dst [=|!=] ADDR[/LEN][:PORT] }\n"
        "                 joined with and/or/not and ( )\n"
        "   OP := { = | != | < | > | <= | >= | eq | ne | lt | gt | le | ge }\n"
        "\n"
        "Examples:  ss -tulpn     ss -tan state established '( dport = :443 or sport = :443 )'\n");
    out_flush();
    exit(code);
}

static void set_query(const char *q) {
    char buf[256];
    snprintf(buf, sizeof buf, "%s", q);
    for (char *t = strtok(buf, ","); t; t = strtok(NULL, ",")) {
        if (!_stricmp(t, "all")) { o_tcp = o_udp = o_unix = 1; }
        else if (!_stricmp(t, "inet")) { o_tcp = o_udp = 1; }
        else if (!_stricmp(t, "tcp")) o_tcp = 1;
        else if (!_stricmp(t, "udp")) o_udp = 1;
        else if (!_stricmp(t, "unix") || !_stricmp(t, "unix_stream") || !_stricmp(t, "unix_dgram")) o_unix = 1;
        else if (!_stricmp(t, "raw")) o_raw = 1;
        else { errf("ss: wrong query: %s\n", t); exit(1); }
    }
}

static void set_family(const char *f) {
    if (!_stricmp(f, "inet")) o_fam4 = 1;
    else if (!_stricmp(f, "inet6")) o_fam6 = 1;
    else if (!_stricmp(f, "unix")) o_unix = 1;
    else if (!_stricmp(f, "link") || !_stricmp(f, "netlink")) o_raw = 1;
    else { errf("ss: invalid family: %s\n", f); exit(1); }
}

int wmain(int argc, wchar_t **wargv) {
    char **argv = argv_utf8(argc, wargv);
    out_init();
    int listen = 0, all = 0;
    int i = 1;
    for (; i < argc; i++) {
        char *a = argv[i];
        if (a[0] != '-' || !a[1]) break;
        if (!strcmp(a, "--")) { i++; break; }
        if (a[1] == '-') {
            const char *l = a + 2;
            char *eq = strchr(a, '=');
            const char *val = eq ? eq + 1 : NULL;
            if (eq) *eq = 0;
            if (!strcmp(l, "tcp")) o_tcp = 1;
            else if (!strcmp(l, "udp")) o_udp = 1;
            else if (!strcmp(l, "unix")) o_unix = 1;
            else if (!strcmp(l, "raw")) o_raw = 1;
            else if (!strcmp(l, "listening")) listen = 1;
            else if (!strcmp(l, "all")) all = 1;
            else if (!strcmp(l, "numeric")) o_numeric = 1;
            else if (!strcmp(l, "resolve")) o_resolve = 1;
            else if (!strcmp(l, "processes")) o_proc = 1;
            else if (!strcmp(l, "summary")) o_summary = 1;
            else if (!strcmp(l, "no-header")) o_noheader = 1;
            else if (!strcmp(l, "kill")) o_kill = 1;
            else if (!strcmp(l, "ipv4")) o_fam4 = 1;
            else if (!strcmp(l, "ipv6")) o_fam6 = 1;
            else if (!strcmp(l, "extended")) o_ext = 1;
            else if (!strcmp(l, "options") || !strcmp(l, "info") || !strcmp(l, "memory") ||
                     !strcmp(l, "oneline") || !strcmp(l, "threads")) ;
            else if (!strcmp(l, "help")) usage(0);
            else if (!strcmp(l, "version")) { sb_puts(&g_out, "ss utility, lnx-net " LNX_VERSION " (Windows)\n"); out_flush(); return 0; }
            else if (!strcmp(l, "family") || !strcmp(l, "query")) {
                if (!val) { if (++i >= argc) usage(1); val = argv[i]; }
                if (l[0] == 'f') set_family(val); else set_query(val);
            } else { errf("ss: unrecognized option '--%s'\n", l); usage(1); }
            continue;
        }
        for (char *c = a + 1; *c; c++) {
            switch (*c) {
            case 't': o_tcp = 1; break;
            case 'u': o_udp = 1; break;
            case 'x': o_unix = 1; break;
            case 'w': o_raw = 1; break;
            case 'l': listen = 1; break;
            case 'a': all = 1; break;
            case 'n': o_numeric = 1; break;
            case 'r': o_resolve = 1; break;
            case 'p': o_proc = 1; break;
            case 's': o_summary = 1; break;
            case 'H': o_noheader = 1; break;
            case 'K': o_kill = 1; break;
            case '4': o_fam4 = 1; break;
            case '6': o_fam6 = 1; break;
            case 'e': o_ext = 1; break;
            case 'o': case 'i': case 'm': case 'O': case 'T': case 'b': case 'E': break;
            case 'h': usage(0); break;
            case 'V': sb_puts(&g_out, "ss utility, lnx-net " LNX_VERSION " (Windows)\n"); out_flush(); return 0;
            case 'f': case 'A': {
                const char *v = c[1] ? c + 1 : (++i < argc ? argv[i] : NULL);
                if (!v) usage(1);
                if (*c == 'f') set_family(v); else set_query(v);
                goto next_arg;
            }
            default: errf("ss: invalid option -- '%c'\n", *c); usage(1);
            }
        }
    next_arg:;
    }

    /* filter: [state X]... [exclude X]... EXPR */
    sbuf fexpr = {0};
    for (; i < argc; i++) {
        if (!_stricmp(argv[i], "state") || !_stricmp(argv[i], "exclude") || !_stricmp(argv[i], "excl")) {
            if (i + 1 >= argc) { errf("ss: state name expected\n"); return 1; }
            unsigned m = state_mask(argv[i + 1]);
            if (argv[i][0] == 's' || argv[i][0] == 'S') {
                if (!states_set) { o_states = 0; states_set = 1; }
                o_states |= m;
            } else {
                if (!states_set) { o_states = all ? SS_ALL : listen ? (SB(SS_LISTEN) | SB(SS_CLOSE)) : SS_CONN; states_set = 1; }
                o_states &= ~m;
            }
            i++;
            continue;
        }
        if (fexpr.n) sb_putc(&fexpr, ' ');
        sb_puts(&fexpr, argv[i]);
    }
    fnode *filter = NULL;
    if (fexpr.n) {
        tokenize(fexpr.p);
        if (ntk) {
            filter = p_expr();
            if (tpos < ntk) fdie("unexpected token", tk[tpos]);
        }
    }

    if (!states_set) o_states = all ? SS_ALL : listen ? (SB(SS_LISTEN) | SB(SS_CLOSE)) : SS_CONN;

    int want_tcp = o_tcp, want_udp = o_udp;
    if (!o_tcp && !o_udp && !o_unix && !o_raw) want_tcp = want_udp = 1;
    if (o_summary && !o_tcp && !o_udp) want_tcp = want_udp = 1;
    int want4 = o_fam4 || !o_fam6, want6 = o_fam6 || !o_fam4;

    if (o_summary) {
        collect(1, AF_INET); collect(1, AF_INET6); collect(0, AF_INET); collect(0, AF_INET6);
        summary();
        out_flush();
        return 0;
    }

    if (want_tcp && want4) collect(1, AF_INET);
    if (want_tcp && want6) collect(1, AF_INET6);
    if (want_udp && want4) collect(0, AF_INET);
    if (want_udp && want6) collect(0, AF_INET6);

    if (o_proc) load_procs();

    int show_netid = (o_tcp + o_udp + o_unix + o_raw) != 1;
    row_t *rows = (row_t *)malloc(sizeof(row_t) * (nsocks ? nsocks : 1));
    int nr = 0;
    int w_state = 5, w_la = 13, w_lp = 4, w_ra = 12, w_rp = 4;
    for (int k = 0; k < nsocks; k++) {
        sock_t *s = &socks[k];
        if (!(o_states & SB(s->state))) continue;
        if (filter && !f_eval(filter, s)) continue;
        row_t *r = &rows[nr++];
        r->s = s;
        fmt_addr(r->la, s->fam, s->la, s->lscope);
        fmt_port(r->lp, s->udp, s->lport);
        if (s->udp) {
            strcpy(r->ra, s->fam == AF_INET ? "0.0.0.0" : "[::]");
            strcpy(r->rp, "*");
        } else {
            fmt_addr(r->ra, s->fam, s->ra, s->rscope);
            fmt_port(r->rp, 0, s->rport);
        }
        r->pname = o_proc && s->pid ? proc_name(s->pid) : NULL;
        int w;
        if ((w = (int)strlen(st_short[s->state])) > w_state) w_state = w;
        if ((w = utf8_width(r->la)) > w_la) w_la = w;
        if ((w = utf8_width(r->lp)) > w_lp) w_lp = w;
        if ((w = utf8_width(r->ra)) > w_ra) w_ra = w;
        if ((w = utf8_width(r->rp)) > w_rp) w_rp = w;
    }

    if (!o_noheader) {
        if (show_netid) sb_puts(&g_out, "Netid ");
        sb_padstr(&g_out, "State", w_state, 0);
        sb_puts(&g_out, " Recv-Q Send-Q ");
        sb_padstr(&g_out, "Local Address", w_la, 1);
        sb_putc(&g_out, ':');
        sb_padstr(&g_out, "Port", w_lp, 0);
        sb_putc(&g_out, ' ');
        sb_padstr(&g_out, "Peer Address", w_ra, 1);
        sb_putc(&g_out, ':');
        if (o_proc) { sb_padstr(&g_out, "Port", w_rp, 0); sb_puts(&g_out, " Process"); }
        else sb_puts(&g_out, "Port");
        sb_putc(&g_out, '\n');
    }
    for (int k = 0; k < nr; k++) {
        row_t *r = &rows[k];
        sock_t *s = r->s;
        if (show_netid) sb_puts(&g_out, s->udp ? "udp   " : "tcp   ");
        sb_padstr(&g_out, st_short[s->state], w_state, 0);
        sb_puts(&g_out, " 0      0      ");
        sb_padstr(&g_out, r->la, w_la, 1);
        sb_putc(&g_out, ':');
        sb_padstr(&g_out, r->lp, w_lp, 0);
        sb_putc(&g_out, ' ');
        sb_padstr(&g_out, r->ra, w_ra, 1);
        sb_putc(&g_out, ':');
        if (o_proc || o_ext) {
            sb_padstr(&g_out, r->rp, w_rp, 0);
            if (o_proc && s->pid) {
                sb_printf(&g_out, " users:((\"%s\",pid=%u))", r->pname ? r->pname : "?", s->pid);
            }
            if (o_ext) sb_printf(&g_out, " pid:%u", s->pid);
        } else {
            sb_puts(&g_out, r->rp);
        }
        sb_putc(&g_out, '\n');
        if (o_kill) kill_sock(s);
    }
    out_flush();
    return 0;
}
