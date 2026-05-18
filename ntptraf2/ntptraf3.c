/*
 ********************************************************
 * ntptraf3.c
 * NTP Traffic Statistics 3
 ********************************************************
 * Program description:
 * Read captured ethernet packets using the pcap library,
 * and then print out some NTP statistics.
 ********************************************************
 * To compile: $ gcc -Wall -Wextra -o ntptraf3 ntptraf3.c -lpcap -lncurses -lm
 *
 * To run: sudo tcpdump -i eth0 -n "udp and port 123 and host ntp.example.nl" \
 *             -p --immediate-mode -U -s110 -w - 2>/dev/null | ./ntptraf3 -
 *     Or: ./ntptraf3 <some file captured from tcpdump or wireshark>
 ********************************************************
 *
 * Original made by Marco Davids, based on a lot of stuff from people
 * who are much smarter than him.
 *
 * This version improved by Claude Sonnet 4.6 (Anthropic, 2026), building
 * on the original. Changes include:
 *  - Two-column ncurses layout with semantic colour scheme
 *  - History graph: rolling 1-minute QPS sparkline (bar chart)
 *  - Keyboard input: 'r' resets counters, 'q' quits cleanly
 *  - Signal handlers made async-signal-safe (flag pattern throughout)
 *  - KoD detection uses memcmp() instead of a magic integer literal
 *  - Replaced gettimeofday() with clock_gettime(CLOCK_MONOTONIC)
 *  - NTP version percentage bars in display
 *  - Typos in comments corrected
 *  - Dead code removed (ip_bytes / ipv6_bytes globals were never read)
 *  - Semantic Versioning (semver.org) maintained
 ********************************************************
 *
 * Remaining TODO items:
 *  - NTS (RFC 8915) counters — requires extending the BPF filter to
 *    also capture TCP port 4460 (NTS-KE), and careful payload inspection.
 *  - Daemonize option / Prometheus exporter for Grafana — best treated
 *    as a separate build target or a compile-time #ifdef to avoid
 *    mixing ncurses and HTTP server code.
 */

/* Feature-test macro: needed for POSIX extensions used by pcap/ncurses */
#define _GNU_SOURCE

/* Libraries */
#include <time.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <locale.h>
#include <ncurses.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

/* Version — https://semver.org/ */
#define VERSION "0.1.1-20260517"

/*
 * History graph: how many seconds of QPS history to keep.
 * The graph is drawn up to terminal width, capped at HISTORY_LEN.
 */
#define HISTORY_LEN 120

/* ------------------------------------------------------------------ */
/* Prototypes                                                           */
/* ------------------------------------------------------------------ */
void handle_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
int  center(int row, char *title);
static void panel_center(int row, int col_start, int col_end, const char *title);
void print_numbers(void);
void draw_history(int row_start, int col_start, int width, int bar_h);
void reset_counters(void);
void cleanup_and_exit(int status);

/* ------------------------------------------------------------------ */
/* Global counters                                                      */
/* ------------------------------------------------------------------ */
static unsigned long long int tot_packet_counter     = 0;
static unsigned long long int tot_bytes_counter      = 0;
static unsigned long long int ip_packet_counter      = 0;
static unsigned long long int ip_bytes_counter       = 0;
static unsigned long long int ipv6_packet_counter    = 0;
static unsigned long long int ipv6_bytes_counter     = 0;
static unsigned long long int ntpv1_counter          = 0;
static unsigned long long int ntpv1_mode_counter     = 0;
static unsigned long long int ntpv2_counter          = 0;
static unsigned long long int ntpv3_counter          = 0;
static unsigned long long int ntpv4_counter          = 0;
static unsigned long long int ntpv5_counter          = 0;
static unsigned long long int kiss_rate_counter      = 0;

/* Counts how many display ticks ago the last KoD packet was seen.
 * While kiss_rate_blink_ticks > 0 the indicator blinks red;
 * each tick the counter is decremented until it reaches 0. */
#define KOD_BLINK_TICKS 3
static int kiss_rate_blink_ticks = 0;
static unsigned long long int ntp_client_counter     = 0;
static unsigned long long int ntp_server_counter     = 0;
static unsigned long long int ntp_control_counter    = 0;
static unsigned long long int ntp_private_counter    = 0;

/* Previous-tick snapshots for rate calculations */
static unsigned long long int ntp_client_prev        = 0;
static unsigned long long int tot_bytes_prev         = 0;

/* Derived display values (computed in print_numbers, read in draw) */
static float  ip_percentage      = 0.0;
static float  ipv6_percentage    = 0.0;
static float  server_percentage  = 0.0;
static unsigned int ip_avg_bytes   = 0;
static unsigned int ipv6_avg_bytes = 0;
static float  ntp_qps            = 0.0;
static float  bytes_sec          = 0.0;

/* QPS history ring buffer */
static float  qps_history[HISTORY_LEN];
static int    qps_history_idx    = 0;
static float  qps_history_max   = 1.0; /* avoid division by zero */

/* Timing */
static struct timespec ts_prev;

/* Start-time string for closing stats */
static time_t  starttime;
static char    time_start[26];

/* pcap handle — needed by signal handlers */
static pcap_t *handle = NULL;

/*
 * Set to 1 when reading from a live tcpdump pipe (argv[1] == "-").
 * pcap_file() cannot distinguish a pipe from a savefile because both
 * use pcap_open_offline internally; we track this ourselves instead.
 */
static int is_live_capture = 0;

/* BPF filter string */
static char pcap_filter[17] = "udp and port 123";
static struct bpf_program comp_filter;

/*
 * Async-signal-safe flags.
 * Signal handlers only set these; the main loop / alarm handler
 * reads them and does the actual work.
 */
static volatile sig_atomic_t flag_resize  = 0;
static volatile sig_atomic_t flag_alarm   = 0;
static volatile sig_atomic_t flag_quit    = 0;

/* tty FILE handles opened for ncurses — kept global for cleanup */
static FILE *tty_in  = NULL;
static FILE *tty_out = NULL;

/* ------------------------------------------------------------------ */
/* Signal handlers — async-signal-safe: only set flags                 */
/* ------------------------------------------------------------------ */
static void sigwinch_handler(int sig) { (void)sig; flag_resize = 1; }
static void sigalrm_handler(int sig)  { (void)sig; flag_alarm  = 1; }
static void sigint_handler(int sig)   { (void)sig; flag_quit   = 1; }

/* ------------------------------------------------------------------ */
/* Cleanup and exit (called from main loop, not from signal handlers)  */
/* ------------------------------------------------------------------ */
void
cleanup_and_exit(int status)
{
    time_t endtime;
    char   time_end[26];

    alarm(0);
    if (handle) { pcap_close(handle); handle = NULL; }
    endwin();
    if (tty_in)  { fclose(tty_in);  tty_in  = NULL; }
    if (tty_out) { fclose(tty_out); tty_out = NULL; }

    /* ANSI clear screen */
    printf("\e[1;1H\e[2J");

    endtime = time(NULL);
    ctime_r(&endtime, time_end);

    printf("\n-----------------------------\n");
    printf("Some closing stats:\n");
    printf("Applied filter: '%s'\n", pcap_filter);
    printf("IPv4 bytes: %'llu (%.3f %%), IPv6 bytes: %'llu (%.3f %%).\n",
           ip_bytes_counter, ip_percentage,
           ipv6_bytes_counter, ipv6_percentage);
    /* ctime_r appends '\n' */
    printf("Start time: %s", time_start);
    printf("  End time: %s", time_end);
    printf("Total packets: %'llu.\n", tot_packet_counter);
    printf("IPv4: %'llu packets, IPv6: %'llu packets.\n",
           ip_packet_counter, ipv6_packet_counter);
    printf("Goodbye!\n");
    printf("-----------------------------\n");

    exit(status);
}

/* ------------------------------------------------------------------ */
/* Reset all counters to zero ('r' key)                                */
/* ------------------------------------------------------------------ */
void
reset_counters(void)
{
    tot_packet_counter  = tot_bytes_counter  = 0;
    ip_packet_counter   = ip_bytes_counter   = 0;
    ipv6_packet_counter = ipv6_bytes_counter = 0;
    ntpv1_counter = ntpv1_mode_counter = ntpv2_counter = 0;
    ntpv3_counter = ntpv4_counter      = ntpv5_counter = 0;
    kiss_rate_counter   = 0;
    kiss_rate_blink_ticks = 0;
    ntp_client_counter  = ntp_server_counter  = 0;
    ntp_control_counter = ntp_private_counter = 0;
    ntp_client_prev     = tot_bytes_prev      = 0;
    ntp_qps   = bytes_sec   = 0.0;
    ip_percentage = ipv6_percentage = server_percentage = 0.0;
    ip_avg_bytes  = ipv6_avg_bytes  = 0;

    /* Reset history */
    memset(qps_history, 0, sizeof(qps_history));
    qps_history_idx = 0;
    qps_history_max = 1.0;

    /* Restart timing baseline */
    clock_gettime(CLOCK_MONOTONIC, &ts_prev);
}

/* ------------------------------------------------------------------ */
/* Draw the rolling QPS sparkline (bar chart)                          */
/* ------------------------------------------------------------------ */
void
draw_history(int row_start, int col_start, int width, int bar_h)
{
    int bar_cols = (width < HISTORY_LEN) ? width : HISTORY_LEN;

    /* Recompute max for scaling */
    float maxval = 1.0;
    for (int i = 0; i < HISTORY_LEN; i++)
        if (qps_history[i] > maxval) maxval = qps_history[i];
    qps_history_max = maxval;

    /* Draw bars, oldest to newest */
    for (int x = 0; x < bar_cols; x++) {
        int idx = (qps_history_idx - bar_cols + x + HISTORY_LEN) % HISTORY_LEN;
        float val = qps_history[idx];
        int filled = (int)round((val / maxval) * bar_h);

        for (int y = 0; y < bar_h; y++) {
            int draw_row = row_start + (bar_h - 1 - y);
            if (y < filled) {
                /* Colour by intensity */
                if (val >= maxval * 0.8)
                    attron(COLOR_PAIR(4) | A_BOLD);
                else if (val >= maxval * 0.4)
                    attron(COLOR_PAIR(2));
                else
                    attron(COLOR_PAIR(6));
                mvaddch(draw_row, col_start + x, ACS_BLOCK);
            } else {
                attron(COLOR_PAIR(5));
                mvaddch(draw_row, col_start + x, ' ');
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Draw a mini percentage bar                                          */
/* ------------------------------------------------------------------ */
static void
draw_pct_bar(int row, int col, int width, float pct, int color_pair)
{
    int filled = (int)round((pct / 100.0) * width);
    if (filled > width) filled = width;
    attron(color_pair);
    for (int i = 0; i < width; i++)
        mvaddch(row, col + i, (i < filled) ? ACS_BLOCK : '.');
}

/* ------------------------------------------------------------------ */
/* Print all numbers — called once per second from the alarm flag      */
/* ------------------------------------------------------------------ */
void
print_numbers(void)
{
    int rows, cols;

    /* Handle terminal resize */
    if (flag_resize) {
        flag_resize = 0;
        endwin();
        refresh();
        clear();
    }

    getmaxyx(stdscr, rows, cols);

    /* ---- Timing ---- */
    struct timespec ts_now;
    clock_gettime(CLOCK_MONOTONIC, &ts_now);
    double elapsed = (ts_now.tv_sec  - ts_prev.tv_sec) +
                     (ts_now.tv_nsec - ts_prev.tv_nsec) * 1e-9;
    ts_prev = ts_now;
    if (elapsed < 0.001) elapsed = 1.0; /* guard against anomalies */

    /* ---- Rate calculations ---- */
    unsigned long long ntp_diff   = ntp_client_counter - ntp_client_prev;
    unsigned long long bytes_diff = tot_bytes_counter   - tot_bytes_prev;
    ntp_client_prev = ntp_client_counter;
    tot_bytes_prev  = tot_bytes_counter;

    ntp_qps   = (float)(ntp_diff   / elapsed);
    bytes_sec = (float)(bytes_diff / elapsed);

    /* Store in ring buffer */
    qps_history[qps_history_idx] = ntp_qps;
    qps_history_idx = (qps_history_idx + 1) % HISTORY_LEN;

    /* ---- Percentages ---- */
    if (tot_packet_counter > 0) {
        ip_percentage   = 100.0f * ip_packet_counter   / tot_packet_counter;
        ipv6_percentage = 100.0f * ipv6_packet_counter / tot_packet_counter;
    } else {
        ip_percentage = ipv6_percentage = 0.0f;
    }

    ip_avg_bytes   = (ip_packet_counter   > 0)
                   ? (unsigned int)round((double)ip_bytes_counter   / ip_packet_counter)
                   : 0;
    ipv6_avg_bytes = (ipv6_packet_counter > 0)
                   ? (unsigned int)round((double)ipv6_bytes_counter / ipv6_packet_counter)
                   : 0;

    server_percentage = (ntp_client_counter > 0)
                      ? 100.0f * ntp_server_counter / ntp_client_counter
                      : 0.0f;

    unsigned long long ntp_total_queries =
        ntpv1_counter + ntpv1_mode_counter +
        ntpv2_counter + ntpv3_counter +
        ntpv4_counter + ntpv5_counter;

    /* ---- Current time ---- */
    time_t now = time(NULL);
    char   timebuf[32];
    struct tm *tm_info = localtime(&now);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S %Z", tm_info);

    /* ================================================================
     * Layout (minimum 100x24):
     *
     * Row  0:  timestamp (right)           version (left)
     * Row  1:  ---- section header: TRAFFIC OVERVIEW ----
     * Row  2:  total packets    total bytes
     * Row  3:  IPv4  bar
     * Row  4:  IPv6  bar
     * Row  5:  bps
     * Row  6:  ---- section header: QPS HISTORY ----
     * Row  7-11: sparkline
     * Row 12:  current QPS (big)
     *
     * Col mid: vertical separator
     *
     * Row  1:  ---- NTP VERSION DISTRIBUTION ----  (right panel)
     * Row  2-7:  NTPv1..v5 with bar
     * Row  8:  ---- NTP MODE BREAKDOWN ----
     * Row  9-14: mode counters
     * Row 15: RATE KoD
     *
     * Row rows-1: hint bar
     * ================================================================
     */

    erase(); /* erase() avoids flicker — clear() would blank the screen immediately */

    int mid   = cols / 2;
    int lpane = mid - 1;          /* last col of left panel  (exclusive) */
    int rpane_start = mid + 1;    /* first col of right panel */

    /*
     * IPv4 / IPv6 rows: text formatted to a fixed width so the bar always
     * starts at the same column, regardless of how large the packet count is.
     *
     * Left panel column layout:
     *   col  2: "IPv4  xx.xx%  avg xxx B  "  — 26 chars
     *   col 28: packet count, right-aligned in 12 chars
     *   col 40: space
     *   col 41: percentage bar up to lpane-1
     */
    int ltext_end = 41;
    int lbar_w    = lpane - ltext_end - 1;
    if (lbar_w < 4) lbar_w = 4;

    /*
     * Right panel version rows column layout:
     *   rpane_start+1: "NTPvX  " (7) + count (10) + "  xx.xx%%" (9) = 26 chars
     *   rpane_start+27: percentage bar
     */
    int rtext_end = rpane_start + 27;
    int rbar_w    = cols - rtext_end - 1;
    if (rbar_w < 4) rbar_w = 4;

    /* sparkline dimensions */
    int spark_top    = 8;
    int spark_bottom = rows - 4;
    if (spark_bottom < spark_top + 2) spark_bottom = spark_top + 2;
    int spark_h      = spark_bottom - spark_top;
    int spark_w      = lpane - 2;
    if (spark_w > HISTORY_LEN) spark_w = HISTORY_LEN;
    int qps_row      = spark_bottom + 1;

    /* ---- Row 0: top bar ---- */
    attron(COLOR_PAIR(5));
    mvprintw(0, 1, "v%s", VERSION);
    attron(COLOR_PAIR(3) | A_BOLD);
    mvprintw(0, cols - (int)strlen(timebuf) - 1, "%s", timebuf);

    /* ---- Vertical separator ---- */
    attron(COLOR_PAIR(5));
    mvaddch(0,      mid, ACS_TTEE);
    for (int r = 1; r < rows - 1; r++)
        mvaddch(r, mid, ACS_VLINE);
    mvaddch(rows-1, mid, ACS_BTEE);

    /* ================================================================
     * LEFT PANEL
     * ================================================================ */

    attron(COLOR_PAIR(2) | A_BOLD);
    panel_center(1, 0, lpane, " TRAFFIC OVERVIEW ");

    attron(COLOR_PAIR(3) | A_BOLD);
    mvprintw(2, 2, "Total packets : %'llu", tot_packet_counter);
    mvprintw(3, 2, "Total bytes   : %'llu  (%'.0f bps)",
             tot_bytes_counter, bytes_sec * 8.0);

    /* IPv4 rij */
    {
        char pkts[16];
        snprintf(pkts, sizeof(pkts), "%'llu", ip_packet_counter);
        attron(COLOR_PAIR(1) | A_BOLD);
        mvprintw(4, 2, "IPv4 %6.2f%%  avg %3u B  %12s",
                 ip_percentage, ip_avg_bytes, pkts);
        draw_pct_bar(4, ltext_end, lbar_w, ip_percentage, COLOR_PAIR(1));
    }

    /* IPv6 rij */
    {
        char pkts[16];
        snprintf(pkts, sizeof(pkts), "%'llu", ipv6_packet_counter);
        attron(COLOR_PAIR(2) | A_BOLD);
        mvprintw(5, 2, "IPv6 %6.2f%%  avg %3u B  %12s",
                 ipv6_percentage, ipv6_avg_bytes, pkts);
        draw_pct_bar(5, ltext_end, lbar_w, ipv6_percentage, COLOR_PAIR(2));
    }

    /* Section: QPS history sparkline */
    attron(COLOR_PAIR(2) | A_BOLD);
    panel_center(7, 0, lpane, " QPS HISTORY ");

    draw_history(spark_top, 2, spark_w, spark_h);

    attron(COLOR_PAIR(4) | A_BOLD);
    mvprintw(qps_row, 2, ">>> %'.1f queries/sec <<<", ntp_qps);

    /* ================================================================
     * RIGHT PANEL
     * ================================================================ */

    /* Section: NTP version distribution */
    attron(COLOR_PAIR(2) | A_BOLD);
    panel_center(1, rpane_start, cols, " NTP VERSION DISTRIBUTION ");

    struct { const char *label; unsigned long long cnt; int pair; } vers[] = {
        { "NTPv1", ntpv1_counter + ntpv1_mode_counter, 5 },
        { "NTPv2", ntpv2_counter,  5 },
        { "NTPv3", ntpv3_counter,  7 },
        { "NTPv4", ntpv4_counter,  4 },
        { "NTPv5", ntpv5_counter,  6 },
    };
    int n_vers = 5;

    for (int v = 0; v < n_vers; v++) {
        float vpct = (ntp_total_queries > 0)
                   ? 100.0f * vers[v].cnt / ntp_total_queries
                   : 0.0f;
        char cnt[16];
        snprintf(cnt, sizeof(cnt), "%'llu", vers[v].cnt);
        attron(COLOR_PAIR(vers[v].pair) | A_BOLD);
        mvprintw(2 + v, rpane_start + 1, "%-6s %10s  %6.2f%%",
                 vers[v].label, cnt, vpct);
        draw_pct_bar(2 + v, rtext_end, rbar_w, vpct,
                     COLOR_PAIR(vers[v].pair));
    }

    /* Section: NTP mode breakdown */
    attron(COLOR_PAIR(2) | A_BOLD);
    panel_center(8, rpane_start, cols, " NTP MODE BREAKDOWN ");

    attron(COLOR_PAIR(2) | A_BOLD);
    mvprintw( 9, rpane_start + 1, "Client reqs  (mode 3): %'llu  (%.1f qps)",
              ntp_client_counter, ntp_qps);
    mvprintw(10, rpane_start + 1, "Server resps (mode 4): %'llu  (%6.2f%%)",
              ntp_server_counter, server_percentage);
    attron(COLOR_PAIR(5));
    mvprintw(11, rpane_start + 1, "Control pkts (mode 6): %'llu",
              ntp_control_counter);
    mvprintw(12, rpane_start + 1, "Private/ntpdc(mode 7): %'llu",
              ntp_private_counter);

    /* KoD — blinks red for KOD_BLINK_TICKS seconds after the last KoD packet,
     * then shows white (less distracting). */
    if (kiss_rate_blink_ticks > 0)
        kiss_rate_blink_ticks--;

    if (kiss_rate_counter > 0) {
        if (kiss_rate_blink_ticks > 0) {
            attron(COLOR_PAIR(1) | A_BOLD | A_BLINK);
            mvprintw(14, rpane_start + 1, "RATE KoD  [!]: %'llu", kiss_rate_counter);
            attroff(A_BLINK);
        } else {
            attron(COLOR_PAIR(5) | A_BOLD);
            mvprintw(14, rpane_start + 1, "RATE KoD  [!]: %'llu", kiss_rate_counter);
        }
    } else {
        attron(COLOR_PAIR(5));
        mvprintw(14, rpane_start + 1, "RATE KoD     : 0");
    }

    /* ---- Bottom hint bar ---- */
    attron(COLOR_PAIR(5));
    mvhline(rows - 1, 0, ' ', cols);
    mvprintw(rows - 1, 1, " 'r' reset counters    'q' quit ");

    refresh();
}

/* ------------------------------------------------------------------ */
/* Packet handler (callback for pcap_loop)                             */
/* ------------------------------------------------------------------ */
void
handle_packet(u_char *args,
              const struct pcap_pkthdr *header,
              const u_char *packet)
{
    (void)args;

    uint32_t i, capturelength;
    capturelength = header->caplen;

    const struct ether_header *eth_hdr =
        (const struct ether_header *)packet;

    uint32_t headerLength = header->len;
    uint16_t ethertype;

    ++tot_packet_counter;

    ethertype = ntohs(eth_hdr->ether_type);
    switch (ethertype) {
    case ETHERTYPE_IP:
        ip_bytes_counter  += headerLength;
        tot_bytes_counter += headerLength;
        ++ip_packet_counter;
        break;
    case ETHERTYPE_IPV6:
        ipv6_bytes_counter += headerLength;
        tot_bytes_counter  += headerLength;
        ++ipv6_packet_counter;
        break;
    default:
        /* BPF filter should prevent arriving here */
        break;
    }

    /* Skip Ethernet header (14 bytes) */
    packet       += 14;
    capturelength -= 14;

    /* Skip IP header */
    switch (ethertype) {
    case ETHERTYPE_IP:
        i = (packet[0] & 0xf) * 4; /* variable IPv4 header length */
        packet       += i;
        capturelength -= i;
        break;
    case ETHERTYPE_IPV6:
        packet       += 40;         /* fixed IPv6 header */
        capturelength -= 40;
        break;
    default:
        break;
    }
    ethertype = 0;

    /* Skip UDP header (8 bytes) */
    packet       += 8;
    capturelength -= 8;

    /* Need at least 1 byte for the flags */
    if (capturelength < 1)
        return;

    /* Inspect mode bits (low 3 bits of first byte) */
    switch (packet[0] & 0x7) {
    case 0:
        /* Zero-mode: original RFC 1059 NTPv1 had no mode field */
        if ((packet[0] & 0x3f) != 0x8)
            return; /* not NTPv1 either — ignore */
        ++ntpv1_counter;
        break;

    case 3:
        /* Client request */
        ++ntp_client_counter;
        /* Extract NTP version (bits 3-5) */
        switch ((packet[0] >> 3) & 0x7) {
        case 1: ++ntpv1_mode_counter; break;
        case 2: ++ntpv2_counter;      break;
        case 3: ++ntpv3_counter;      break;
        case 4: ++ntpv4_counter;      break;
        case 5: ++ntpv5_counter;      break;
        default: break;
        }
        break;

    case 4:
        /* Server response */
        ++ntp_server_counter;
        /*
         * Kiss-of-Death detection:
         *   LI=3, stratum=0, reference ID == "RATE"
         *   See RFC 5905 section 11.1, last paragraph.
         *   Using memcmp avoids unaligned-access and byte-order issues.
         */
        if ((packet[0] & 0xc0) == 0xc0 &&   /* LI == 3           */
             packet[1]          == 0    &&   /* stratum == 0       */
             capturelength      >= 16   &&   /* enough bytes       */
             memcmp(packet + 12, "RATE", 4) == 0) /* ref ID "RATE" */
        {
            ++kiss_rate_counter;
            kiss_rate_blink_ticks = KOD_BLINK_TICKS;
        }
        break;

    case 6:
        /* Control packet (mode 6) — RFC 9327 */
        ++ntp_control_counter;
        break;

    case 7:
        /* Private / ntpdc (mode 7) — extremely rare */
        ++ntp_private_counter;
        break;

    default:
        break;
    }
}

/* ------------------------------------------------------------------ */
/* panel_center() — draw a decorated header centred within col_start.. */
/* col_end (exclusive). Replaces center() for split-panel use.         */
/* ------------------------------------------------------------------ */
static void
panel_center(int row, int col_start, int col_end, const char *title)
{
    int width = col_end - col_start;
    int len   = (int)strlen(title);
    if (len >= width) return;

    int indent = col_start + (width - len) / 2;

    /* dashes left */
    for (int c = col_start; c < indent - 1; c++)
        mvaddch(row, c, '-');
    mvaddch(row, indent - 1, '[');

    mvaddstr(row, indent, title);

    mvaddch(row, indent + len, ']');
    /* dashes right */
    for (int c = indent + len + 1; c < col_end; c++)
        mvaddch(row, c, '-');
}

/* ------------------------------------------------------------------ */
/* center() — draw a decorated header centred on a row                 */
/* ------------------------------------------------------------------ */
int
center(int desiredrow, char *title)
{
    int rows, cols, len, indent, pos;
    getmaxyx(stdscr, rows, cols);

    if (desiredrow >= rows) return EXIT_FAILURE;

    len = (int)strlen(title);
    if (len >= cols)        return EXIT_FAILURE;

    indent = (cols - len) / 2;
    if (indent < 0)         return EXIT_FAILURE;

    for (pos = 0; pos < indent - 1; pos++)
        mvaddch(desiredrow, pos, '-');
    addch('[');
    mvaddstr(desiredrow, indent, title);
    mvaddch(desiredrow, pos + len + 1, ']');
    for (pos += len + 2; pos < cols; pos++)
        mvaddch(desiredrow, pos, '-');

    return EXIT_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */
int
main(int argc, char *argv[])
{
    setlocale(LC_NUMERIC, "en_US.UTF-8");

    if (argc == 1) {
        printf("Version: %s\n", VERSION);
        printf("Usage: $ ./ntptraf3 [captured_file_name]\n");
        printf("   or: tcpdump [parameters] | ./ntptraf3 -\n");
        exit(EXIT_FAILURE);
    }
    if (argc > 2) {
        printf("Error: unrecognized command!\n");
        printf("Usage: $ ./ntptraf3 [captured_file_name]\n");
        printf("   or: tcpdump [parameters] | ./ntptraf3 -\n");
        exit(EXIT_FAILURE);
    }

    const char *fname = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    /* "-" means tcpdump is piping into us — never treat r==0 as EOF */
    is_live_capture = (strcmp(fname, "-") == 0);

    handle = pcap_open_offline(fname, errbuf);
    if (handle == NULL) {
        printf("Cannot open pcap source [%s]: %s\n", fname, errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_compile(handle, &comp_filter, pcap_filter, 1,
                     PCAP_NETMASK_UNKNOWN) != 0 ||
        pcap_setfilter(handle, &comp_filter) != 0)
    {
        printf("Cannot compile/set filter '%s' on [%s]\n",
               pcap_filter, fname);
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    /* ---- ncurses init ---- */
    /*
     * Open /dev/tty explicitly for ncurses input/output.
     * When stdin (fd 0) is a tcpdump pipe, initscr() would try to read
     * keyboard input from that same fd — causing pcap-data to be
     * misinterpreted as keypresses (including 'q', triggering immediate exit).
     * newterm() with an explicit /dev/tty avoids the conflict entirely.
     */
    tty_in  = fopen("/dev/tty", "r");
    tty_out = fopen("/dev/tty", "w");
    if (!tty_in || !tty_out) {
        fprintf(stderr, "Cannot open /dev/tty: is this a real terminal?\n");
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }
    SCREEN *scr = newterm(NULL, tty_out, tty_in);
    if (!scr) {
        fprintf(stderr, "newterm() failed\n");
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }
    set_term(scr);

    if (LINES < 24 || COLS < 100) {
        endwin();
        printf("Version: %s\n", VERSION);
        printf("This program requires at least 100 columns by 24 lines.\n");
        printf("Please resize your terminal window.\n");
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    start_color();
    curs_set(0);
    nodelay(stdscr, TRUE);  /* non-blocking getch() for keyboard input */
    keypad(stdscr, TRUE);
    clear();

    /*
     * Colour pairs:
     *  1 = red    (KoD, IPv4)
     *  2 = green  (section headers, IPv6, NTPv4)
     *  3 = cyan   (totals, timestamps)
     *  4 = yellow (QPS highlight, NTPv4 bar peak)
     *  5 = white/default (muted / structural)
     *  6 = blue   (NTPv5, low bars)
     *  7 = magenta (NTPv3 — older but still used)
     */
    init_pair(1, COLOR_RED,     COLOR_BLACK);
    init_pair(2, COLOR_GREEN,   COLOR_BLACK);
    init_pair(3, COLOR_CYAN,    COLOR_BLACK);
    init_pair(4, COLOR_YELLOW,  COLOR_BLACK);
    init_pair(5, COLOR_WHITE,   COLOR_BLACK);
    init_pair(6, COLOR_BLUE,    COLOR_BLACK);
    init_pair(7, COLOR_MAGENTA, COLOR_BLACK);

    /* ---- Signal handlers ---- */
    signal(SIGWINCH, sigwinch_handler);
    signal(SIGINT,   sigint_handler);
    signal(SIGALRM,  sigalrm_handler);

    /* ---- Initialise timing ---- */
    starttime = time(NULL);
    ctime_r(&starttime, time_start);
    clock_gettime(CLOCK_MONOTONIC, &ts_prev);
    memset(qps_history, 0, sizeof(qps_history));

    alarm(1); /* first tick */

    /* ---- Run pcap_loop in a non-blocking manner ----
     * We break out of the loop periodically via the alarm signal so
     * we can process keyboard input and screen updates.
     * pcap_loop returns -2 when pcap_breakloop() is called.
     */

    mvprintw(2, 2, "Waiting for packets...");
    refresh();

    /*
     * Main event loop:
     *  - pcap_dispatch processes queued packets without blocking
     *  - alarm flag triggers screen update once per second
     *  - getch() polls keyboard without blocking (nodelay)
     */
    for (;;) {
        /* Check for clean quit flag (SIGINT or 'q') */
        if (flag_quit)
            cleanup_and_exit(EXIT_SUCCESS);

        /* Handle alarm: update display */
        if (flag_alarm) {
            flag_alarm = 0;
            print_numbers();
            alarm(1); /* reschedule */
        }

        /* Process available packets (non-blocking).
         * pcap_dispatch() return values:
         *   >0  : packets processed
         *    0  : no packets right now (live pipe: normal) OR EOF (savefile)
         *   -1  : pcap error
         *   -2  : pcap_breakloop() called
         *
         * For a live pipe, r==0 just means "nothing in the buffer yet" —
         * we must not exit. For a savefile, r==0 means genuine EOF.
         */
        int r = pcap_dispatch(handle, 256, handle_packet, NULL);
        if (r == -1) {
            break; /* real pcap error */
        }
        if (r == 0 && !is_live_capture) {
            break; /* EOF on savefile */
        }
        if (r == 0) {
            /* Live pipe: nothing buffered yet — yield briefly.
             * Use select() so that an incoming SIGALRM can interrupt
             * us cleanly without EINTR causing an unexpected exit. */
            struct timeval tv = { 0, 5000 }; /* 5 ms */
            select(0, NULL, NULL, NULL, &tv);
        }

        /* Poll keyboard */
        int ch = getch();
        if (ch == 'q' || ch == 'Q')
            flag_quit = 1;
        if (ch == 'r' || ch == 'R') {
            reset_counters();
            /* Force immediate redraw */
            flag_alarm = 1;
        }
    }

    /* EOF or error from pcap — do a final update then wait */
    sleep(1);
    flag_alarm = 1;
    print_numbers();
    alarm(0);

    attron(COLOR_PAIR(1) | A_BOLD);
    int rows_end, cols_end;
    getmaxyx(stdscr, rows_end, cols_end);
    mvprintw(0, cols_end - 10, " STOPPED ");
    (void)rows_end;
    refresh();

    /* Wait for 'q' before exiting so the user can read the final stats */
    nodelay(stdscr, FALSE); /* blocking getch */
    for (;;) {
        int ch = getch();
        if (ch == 'q' || ch == 'Q' || ch == 'r' /* any key */ || ch != ERR)
            break;
    }

    cleanup_and_exit(EXIT_SUCCESS);
    return EXIT_SUCCESS; /* unreachable */
}
