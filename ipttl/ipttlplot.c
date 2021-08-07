/*
 ********************************************************
 * ipttlplot.c
 * NTP Traffic IP TTL Analyzer
 ********************************************************
 * Program description:
 * Read captured ethernet packets using the pcap library,
 * and specifically looks at the ip.ttl and ipv6.hlim
 * Supposed to be a bit faster than:
 * tshark -r ~/v6_ntp.pcap -Tfields -eip.ttl -eipv6.hlim -eip.version
 ********************************************************
 * To compile: $ gcc -Wall -o ipttlplot ipttlplot.c -l pcap
 * 
 * To run: sudo tcpdump -i eth0 -n "udp and port 123 and host ntp.example.nl" -p --immediate-mode -U -s62 -w - 2> /dev/null | ./ipttlplot - > out.dat
 *     Or: ./ipttlplot <some file captured from tcpdump or wireshark> > out.dat
 ******************************************************** 
 *
 * Made by Marco Davids, based on a lot of stuff from people
 * who are much smarter than me. 
 */

/*
 * Ideas for future enhancements:
 * - anomaly detection like dns-flood-detector
 * - Or some dnstop-like features
 */

/* Libraries */
#include <stdlib.h> // exit()
#include <signal.h> // for SIG handler
#include <arpa/inet.h> // for ntohs
#include <pcap.h>
#include <netinet/if_ether.h> // ethernet header declarations

/* Prototypes */
void handle_packet(u_char * ,
  const struct pcap_pkthdr * ,
    const u_char * );
int center(int row, char * title);
void print_output(void);
void sigintHandler(int sig);

/* Global Variables */
pcap_t * handle;
// Please note; the filter is very limited and will include server responses!
// We will not look in the NTP packet for a mode 4 (server respons)
// TTL of responses is always 64, so this may clutter the output.
// This can be avoided to provide good pcap input to this simple tool.
// TODO: ignore them?
char pcap_filter[17] = "udp and port 123"; // filter string
struct bpf_program comp_filter; // compiled filter
uint16_t ethertype = 0;
unsigned char ipttl = 0;
unsigned char ipv6hlim = 0;
/* Defines */
#define VERSION "0.0.1-20210806"
// https://semver.org/

/* Main */
int
main(int argc, char * argv[]) {
  const char * fname = argv[1]; // pcap filename
  char errbuf[PCAP_ERRBUF_SIZE]; // error buffer

  // handle if pcap file is missing
  if (argc == 1) {
    printf("Version: %s\n", VERSION);
    printf("Usage: $./ipttlplot [captured_file_name] \n");
    printf("   or: tcpdump [parameters] | ./ipttlplot - \n");
    exit(EXIT_FAILURE);
  }

  // handle error if command is wrong
  if (argc > 2) {
    printf("Error: unrecognized command! \n");
    printf("Usage: $./ipttlplot [captured_file_name] \n");
    printf("   or: tcpdump [parameters] | ./ipttlplot -\n");
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

  // own SIGNINT signal handler
  signal(SIGINT, sigintHandler);

  // pcap loop to set our callback function
  // the work is done in handle_packet
  pcap_loop(handle, 0, handle_packet, NULL);

  pcap_close(handle);
  return (EXIT_SUCCESS);
}

void
sigintHandler(int sig) {
  pcap_close(handle);
  exit(EXIT_SUCCESS);
}

/* Handle packet */
void
handle_packet(u_char * args,
  const struct pcap_pkthdr * header,
    const u_char * packet) {

  uint32_t capturelength;

  /* get the capture length (not to be confused with len)
   * due to our filter this will at least contain ethernet+ip+udp headers.
   * so, with too small snaplengths we wont end up here.
   */
  capturelength = header -> caplen;

  //pointer to ethernet packet header
  const struct ether_header * ethernet_header;

  //define ethernet header
  ethernet_header = (struct ether_header * )(packet);

  // now, it's time to determine the IP statistics
  // (we use the ethernet header for it, instead of IP-header, for no particular reason)
  ethertype = ntohs(ethernet_header -> ether_type);

  //skip ethernet header
  // TODO: needed? Or can we just pinpoint directly?
  packet += 14, capturelength -= 14;

  //Process IP header
  switch (ethertype) {
  case ETHERTYPE_IP:
    ipttl = packet[8];
    ipv6hlim = 0;
    break;
  case ETHERTYPE_IPV6:
    ipv6hlim = packet[8];
    ipttl = 0;
    break;
    // no default: needed
  }

  printf("%i\n", (ipv6hlim ? ipv6hlim : ipttl));
   
  return;
}

