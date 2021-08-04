/*
 ********************************************************
 * ntptraf2.c
 * NTP Traffic Statistics 2
 ********************************************************
 * Program description:
 * Read captured ethernet packets using the pcap library,
 * and then print out some NTP statistics.
 ********************************************************
 * To compile: $ gcc -Wall -o ntptraf2 ntptraf2.c -l pcap -l ncurses
 * 
 * To run: sudo tcpdump -i eth0 -n "udp and port 123 and host ntp.example.nl" -p --immediate-mode -U -s110 -w - 2> /dev/null | ./ntptraf2 -
 *     Or: ./ntptraf2 <some file captured from tcpdump or wireshark>
 ******************************************************** 
 *
 * Made by Marco Davids, based on a lot of stuff from people
 * who are much smarter than me. 
 */

/*
 * Ideas for future enhancements:
 *  - count IP_TTL ? Could be interesting for anycast catchment measurments
 *  - NTS (RFC8915) counters?
 *  - Better layout? Other colours?
 */

/* Libraries */
#include <time.h>
#include <math.h> // for round()
#include <stdlib.h> // malloc
#include <string.h> // strlen
#include <signal.h> // for SIGWINCH handler
#include <unistd.h> // contains alarm()
#include <locale.h> // format the numbers in printf
#include <ncurses.h>
#include <sys/socket.h>
#include <netinet/in.h> // internet protocol family
#include <pcap.h>
#include <netinet/if_ether.h> // ethernet header declarations

/* Prototypes */
void handle_packet(u_char * ,
  const struct pcap_pkthdr * ,
    const u_char * );
int center(int row, char * title);
void print_numbers(void);
void sigwinchHandler(int sig);
void sigintHandler(int sig);
void sigalrmHandler(int sig);

/* Global Variables */
unsigned long long int tot_packet_counter = 0; // total packet number
unsigned long long int tot_bytes_counter = 0; // total bytes total
unsigned long long int ip_packet_counter = 0; // ipv4 packet number
unsigned long long int ip_bytes_counter = 0; // ipv4 bytes total
unsigned long long int ipv6_packet_counter = 0; // ipv6 packet number
unsigned long long int ipv6_bytes_counter = 0; // ipv6 bytes total
// TODO typical IPv4 is 90 and IPv6 is 110, so how useful is this avg counter??
unsigned int ip_avg_bytes = 0; // ipv4 averege bytes/packet
unsigned int ipv6_avg_bytes = 0; // ipv6 average bytes/packet
unsigned long long int ntpv1_counter = 0; // RFC1059 NTPv1 packetcount
unsigned long long int ntpv1_mode_counter = 0; // NTPv1 but with mode (bit unusual, but it might happen)
unsigned long long int ntpv2_counter = 0; // RFC1119 NTPv2 packetcount
unsigned long long int ntpv3_counter = 0; // RFC1305 NTPv3 packetcount
unsigned long long int ntpv4_counter = 0; // RFC5905 NTPv4 packetcount
unsigned long long int kiss_rate_counter = 0; // Kiss-o'-death RATE
unsigned long long int ntp_client_counter = 0; // mode 3 client
unsigned long long int ntp_server_counter = 0; // mode 4 server
unsigned long long int ntp_control_counter = 0; // mode 6 control
unsigned long long int ntp_private_counter = 0; // mode 7 private (ntpdc)
unsigned long long int ntp_client_counter_previous = 0; // for qps
unsigned long long int tot_bytes_counter_previous = 0; // for qps
unsigned long long int ntp_client_diff; // for qps
unsigned long long int bytes_diff; // for bps
static volatile sig_atomic_t resizedwin = 0; // SIGWINCH handler flag 
float ip_percentage = 0.0; // percentage ipv4
float ipv6_percentage = 0.0; // percentage ipv6
float server_percentage = 0.0; // response percentage
int headerLength = 0; // packet header length
int ip_bytes = 0; // headerLength in IPv4 case
int ipv6_bytes = 0; // headerLength in IPv6 case
pcap_t * handle;
char pcap_filter[17] = "udp and port 123"; // filter string
struct bpf_program comp_filter; // compiled filter
uint16_t ethertype = 0;
time_t starttime;
time_t endtime;
char time_start[26];
char time_end[26];
struct timeval tvOld, tvNew;
float tvDiff; // time difference between tvNew and tvOld
float ntp_qps = 0;
float bytes_sec = 0;
int row, col;

/* Defines */
#define VERSION "0.0.1-20210803"
// https://semver.org/

/* Main */
int
main(int argc, char * argv[]) {
  setlocale(LC_NUMERIC, "en_US.UTF-8");
  const char * fname = argv[1]; // pcap filename
  char errbuf[PCAP_ERRBUF_SIZE]; // error buffer

  // handle if pcap file is missing
  if (argc == 1) {
    printf("Version: %s\n", VERSION);
    printf("Usage: $./ntptraf2 [captured_file_name] \n");
    printf("   or: tcpdump [parameters] | ./ntptraf2 - \n");
    exit(EXIT_FAILURE);
  }

  // handle error if command is wrong
  if (argc > 2) {
    printf("Error: unrecognized command! \n");
    printf("Usage: $./ntptraf2 [captured_file_name] \n");
    printf("   or: tcpdump [parameters] | ./ntptraf2 -\n");
    exit(EXIT_FAILURE);
  }

  // open pcap file
  handle = pcap_open_offline(fname, errbuf);

  // if pcap file has errors
  if (handle == NULL) {
    printf("pcap file [%s] with error %s \n", fname, errbuf);
    exit(EXIT_FAILURE);
  }

  /* compile and set filter and continue only if this was successful
   * this will cause any packet that doesn't include the UDP header to be skipped!
   * so we will allways need at least 42 bytes for IPv4 and 62 bytes for IPv6 to get complete statistics
   */
  if (pcap_compile(handle, & comp_filter, pcap_filter, 1, PCAP_NETMASK_UNKNOWN) || pcap_setfilter(handle, & comp_filter)) {
    printf("pcap file [%s] cannot compile or set filter '%s' \n", fname, pcap_filter);
    exit(EXIT_FAILURE);
  }

  /* Start ncurses */

  // TODO doesn't help with restoring proper output at end of program
  //savetty();
  initscr();

  if ((LINES < 20) || (COLS < 100)) {
    endwin();
    printf("Version: %s\n", VERSION);
    printf
      ("This program requires a screen size of at least 100 columns by 20 lines\n"
        "Please resize your window.\n");
    exit(EXIT_FAILURE);
  }

  // own SIGWINCH signal handler 
  signal(SIGWINCH, sigwinchHandler);
  // own SIGNINT signal handler
  signal(SIGINT, sigintHandler);
  // own SIGALEM signal handler (interval timer)
  signal(SIGALRM, sigalrmHandler);
  // TODO could be combined in one handler: http://www.csl.mtu.edu/cs4411.ck/www/NOTES/signal/two-signals.html
  alarm(1); // schedule the first alarm

  start_color();
  curs_set(0);
  clear();
  // red on black
  init_pair(1, COLOR_RED, COLOR_BLACK);
  // green on black
  init_pair(2, COLOR_GREEN, COLOR_BLACK);
  // magenta on black
  init_pair(3, COLOR_MAGENTA, COLOR_BLACK);

  mvprintw(2, 1, "Here we go!");

  attrset(COLOR_PAIR(2) | A_BOLD);
  center(1, " IP Statistics ");
  center(8, " NTP Statistics ");
  // also change resizedwin() when you change stuff here

  // get starttime
  starttime = time(NULL);
  ctime_r( & starttime, time_start);

  // determine precise start time for qps calculations 
  gettimeofday( & tvOld, NULL);

  // pcap loop to set our callback function
  // the work is done in handle_packet
  pcap_loop(handle, 0, handle_packet, NULL);

  // stop the interval (but allow for one loop, to at least get something)
  sleep(2);
  alarm(0);
  attron(COLOR_PAIR(3));
  mvprintw(0, col - 24, "                 Stopped");
  refresh();

  /* prevent leaving with bye (and thereby erasing the screen)
   * primarily handy when pcap is a command-line parameter
   * won't work for the unrecommended 'cat ./ntp.pcap | ./ntptraf2 -' scenario
   */
  getchar();
  pcap_close(handle);
  endwin();
  printf("\nBye.\n");
  return (EXIT_SUCCESS);
}

void
sigwinchHandler(int sig)
// do as little as possible within the handler
{
  resizedwin = 1;
}

void
sigintHandler(int sig) {
  pcap_close(handle);
  endwin();
  // ANSI clear screen
  printf("\e[1;1H\e[2J");
  // get endtime
  endtime = time(NULL);
  ctime_r( & endtime, time_end);
  printf("\n-----------------------------\nSome closing stats:\n");
  printf("Applied filter: '%s'\n", pcap_filter);
  printf
    ("IPv4 bytes: %'llu (%.3f %%), IPv6 bytes: %'llu (%.3f %%).\n",
      ip_bytes_counter, ip_percentage, ipv6_bytes_counter, ipv6_percentage);
  // an '\n' is added by ctime
  // TODO remove? extend? 
  printf("Starttime: %s", time_start);
  printf("  Endtime: %s", time_end);
  printf("Total number of packets: %'llu.\n", tot_packet_counter);
  printf("IPv4: %'llu packets, IPv6: %'llu packets.\n",
    ip_packet_counter, ipv6_packet_counter);
  printf("Goodbye!\n");
  printf("-----------------------------\n");
  exit(EXIT_SUCCESS);
}

void sigalrmHandler(int sig) {
  print_numbers();
  alarm(1); // schedule the next alarm
}

/* Handle packet */
void
handle_packet(u_char * args,
  const struct pcap_pkthdr * header,
    const u_char * packet) {

  uint32_t i, capturelength;

  /* get the capture length (not to be confused with len)
   * due to our filter this will at least contain ethernet+ip+udp headers.
   * so, with too small snaplengths we wont end up here.
   */
  capturelength = header -> caplen;

  //pointer to ethernet packet header
  const struct ether_header * ethernet_header;

  //get actual header length (not to be confused with caplen)
  headerLength = header -> len;

  //increase packet counter -> packet number
  ++tot_packet_counter;

  //define ethernet header
  ethernet_header = (struct ether_header * )(packet);

  // now, it's time to determine the IP statistics
  // (we use the ethernet header for it for no particular reason)
  ethertype = ntohs(ethernet_header -> ether_type);
  switch (ethertype) {
    // https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
    // https://github.com/wireshark/wireshark/blob/master/epan/etypes.h
    // IPv4 traffic
  case ETHERTYPE_IP:
    ip_bytes_counter += headerLength;
    tot_bytes_counter += headerLength;
    ++ip_packet_counter;
    ip_bytes = headerLength;
    ipv6_bytes = 0;
    break;
    // IPv6
  case ETHERTYPE_IPV6:
    ipv6_bytes_counter += headerLength;
    tot_bytes_counter += headerLength;
    ++ipv6_packet_counter;
    ip_bytes = 0;
    ipv6_bytes = headerLength;
    break;
    // Other traffic
    // because of our built-in filter, we should not get here
    // no default: needed
  }

  /* now it's time to determine the NTP statistics
   * we have a static built-in filter, so we won't double check for udp/123 here.
   * and we know that we have at least ethernet+ip+udp headers, no checks needed.
   */

  //skip ethernet header
  packet += 14, capturelength -= 14;

  //skip IP header
  switch (ethertype) {
  case ETHERTYPE_IP:
    i = (packet[0] & 0xf) * 4; // IPv4 can have options, let's examine header length field
    packet += i, capturelength -= i;
    ethertype = 0; // TODO needed?
    break;
  case ETHERTYPE_IPV6:
    packet += 40, capturelength -= 40; // IPv6 is fixed
    ethertype = 0; // TODO needed?
    break;
    // no default: needed
  }

  // skip UDP header
  packet += 8, capturelength -= 8;

  // if we have 1 more byte, we have some flags to inspect ;-)
  // 'normal' NTP would leave us (at least) 48 bytes here
  if (capturelength < 1)
    return;

  // let's inspect flags for mode bits
  switch (packet[0] & 0x7) {
  case 0:
    // count zero-mode NTPv1 requests (original RFC1059 had no mode)
    if ((packet[0] & 0x3f) != 0x8)
      // rare case: no mode, but also not NTPv1, let's ignore this for now 
      return;
    ++ntpv1_counter;
    // we assume we count only *clients* (as our modern servers set a mode 4 in replies).
    // so we don't add additionals checks to see if this is a client or server packet
    break;
  case 3:
    /* a client packet */
    ++ntp_client_counter;
    // let's inspect flags for NTP versions 1 to 4 (and mode flags <> 000)
    switch ((packet[0] >> 3) & 0x7) {
    case 1:
      ++ntpv1_mode_counter; // this happens, a NTPv1, but with some mode
      break;
    case 2:
      ++ntpv2_counter;
      break;
    case 3:
      ++ntpv3_counter;
      break;
    case 4:
      ++ntpv4_counter;
      break;
      // no default: needed
    }
    break;
  case 4:
    /* a server packet */
    ++ntp_server_counter;
    /* Is it a KoD? */
    // leap indicator 3, stratum 0, RATE
    // see https://datatracker.ietf.org/doc/html/rfc5905#section-11.1 last paragraph! */
    // fprintf(stderr, "for debuging: %X\n", ((uint32_t *)packet)[3]); // run as ./ntptraf2 ./kod.pcap 2>kanweg; more kanweg
    // TODO: is this ok, or do we have a potential byte order issue?
    if ((packet[0] & 0xc0) == 192 && (packet[1] == 0) && ((uint32_t * ) packet)[3] == 1163149650) //0x45544152 is 'RATE' in reverse order
      ++kiss_rate_counter;
    break;
  case 6:
    /* a control packet (rare) */
    ++ntp_control_counter;
    // TODO: control packets have their own dynamics; do we want to finetune?
    // 6 and 7 are not seen a lot in the wild anymore - let's still count them for fun
    break;
  case 7:
    /* an ntpdc packet  (extremely rare nowadays) */
    ++ntp_private_counter;
    break;
    // no default: needed   
  }
  return;
}

void
print_numbers(void) {
  time_t timer;
  char timebuffer[26];
  struct tm * tm_info;

  // check if window was resized
  if (resizedwin) {
    resizedwin = 0;
    endwin();
    refresh();
    clear();
    attrset(COLOR_PAIR(2) | A_BOLD);
    center(1, " IP Statistics ");
    center(8, " NTP Statistics ");
    // Also change similar lines above, when changing here
  }

  getmaxyx(stdscr, row, col);

  // print time
  timer = time(NULL);
  tm_info = localtime( & timer);
  strftime(timebuffer, 26, "%Y-%m-%d %H:%M:%S %Z", tm_info);
  attron(COLOR_PAIR(3));
  mvprintw(0, col - 24, "%s", timebuffer);
  mvprintw(row - 1, col - 15, "v%s", VERSION);

  // for qps
  gettimeofday( & tvNew, NULL);
  tvDiff = ((tvNew.tv_sec * 1000000 + tvNew.tv_usec) - (tvOld.tv_sec * 1000000 + tvOld.tv_usec));
  tvDiff = tvDiff / 1000000;
  tvOld = tvNew;
  ntp_client_diff = ntp_client_counter - ntp_client_counter_previous;
  ntp_client_counter_previous = ntp_client_counter;
  if (tvDiff != 0) // prevent devide by zero
    ntp_qps = (ntp_client_diff / tvDiff);
  else ntp_qps = 0;
  // for bps
  bytes_diff = tot_bytes_counter - tot_bytes_counter_previous;
  tot_bytes_counter_previous = tot_bytes_counter;
  if (tvDiff != 0) // prevent devision by zero
    bytes_sec = (bytes_diff / tvDiff);
  else bytes_sec = 0;

  // do the math
  if (tot_packet_counter > 0) { // prevent devision by  0
    ip_percentage =
      ((float) ip_packet_counter / (float) tot_packet_counter) * 100;
    ipv6_percentage =
      ((float) ipv6_packet_counter / (float) tot_packet_counter) * 100;
    server_percentage =
      ((float) ntp_server_counter / (float) ntp_client_counter) * 100;

    ip_avg_bytes =
      round((float) ip_bytes_counter / (float) ip_packet_counter);
    ipv6_avg_bytes =
      round((float) ipv6_bytes_counter / (float) ipv6_packet_counter);
  };
  // print the new numbers on screen
  attron(COLOR_PAIR(3) | A_BOLD);
  // some spaces behind it to overwrite previous 'waiting for packets...'-text
  mvprintw(2, 1, "Total packets: %'llu    ", tot_packet_counter);
  // IPv4
  attron(COLOR_PAIR(1));
  mvprintw
    (4, 3,
      "IPv4 pkts:  %'9llu: %6.2f %% (%'llu bytes / avg size: %i bytes)",
      ip_packet_counter, ip_percentage, ip_bytes_counter, ip_avg_bytes);
  // IPv6
  attron(COLOR_PAIR(2));
  mvprintw
    (5, 3,
      "IPv6 pkts:  %'9llu: %6.2f %% (%'llu bytes / avg size: %i bytes)",
      ipv6_packet_counter, ipv6_percentage, ipv6_bytes_counter, ipv6_avg_bytes);
  // total bytes
  attron(COLOR_PAIR(3) | A_BOLD);
  mvprintw(7, 1, "Total bytes: %'llu (%'9.0f bps)                ", tot_bytes_counter, bytes_sec * 8);

  attron(COLOR_PAIR(2));
  mvprintw(9, 3, "NTPv1 queries: %'9llu", ntpv1_counter + ntpv1_mode_counter); // TODO: seperate?
  mvprintw(10, 3, "NTPv2 queries: %'9llu", ntpv2_counter);
  mvprintw(11, 3, "NTPv3 queries: %'9llu", ntpv3_counter);
  mvprintw(12, 3, "NTPv4 queries: %'9llu", ntpv4_counter);
  mvprintw(14, 3, "client reqs:   %'9llu (%6.2f qps)                ", ntp_client_counter, ntp_qps);
  mvprintw(15, 3, "server rspns:  %'9llu (%6.2f %%)         ", ntp_server_counter, server_percentage);
  mvprintw(16, 3, "control pkts:  %'9llu", ntp_control_counter);
  mvprintw(17, 3, "ntpdc pkts:    %'9llu", ntp_private_counter);
  attron(COLOR_PAIR(1));
  mvprintw(19, 3, "RATE KODs:     %'9llu", kiss_rate_counter);

  refresh();
}

int
center(int desiredrow, char * title) {
  int len, indent, row, col, pos;

  getmaxyx(stdscr, row, col);

  if (desiredrow > row)
    return (EXIT_FAILURE);

  len = strlen(title);

  if (len > col)
    //exit (EXIT_FAILURE);
    return (EXIT_FAILURE);

  indent = (col - len) / 2;

  if (indent < 0)
    //exit (EXIT_FAILURE);
    return (EXIT_FAILURE);

  for (pos = 0; pos < indent - 1; pos++)
    mvaddch(desiredrow, pos, '-');

  addch('[');

  mvaddstr(desiredrow, indent, title);
  mvaddch(desiredrow, pos + (len + 1), ']');

  for (pos += (len + 2); pos < col; pos++)
    mvaddch(desiredrow, pos, '-');

  refresh();

  return (EXIT_SUCCESS);
}
