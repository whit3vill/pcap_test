#include "pcap_test.h"


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void printM(u_char *str) {
  int i;

  for(i=0; i<6; i++) {
    printf("%02x", str[i]);
    if(i<5) printf(":");
  }
  printf("\n");
}

int main(int argc, char *argv[]) {
  int i;
  struct pcap_pkthdr *header;
  struct ether_header *etherH;
  struct ip *ipH;
  struct tcphdr *tcpH;
  unsigned char *data;


  if (argc != 2) {
    usage();
    return -1;
  }

  char *dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (1) {
    const u_char *packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    //printf("%u bytes captured\n", header->caplen);

    etherH = (struct ether_header *)(packet);
    printf("Ethernet Header Source MAC:      ");
    printM(etherH->ether_shost);
    printf("Ethernet Header Destination MAC: ");
    printM(etherH->ether_dhost);

    if (ntohs(etherH->ether_type) == ETHERTYPE_IP) {
      ipH = (struct ip *)(packet + sizeof(struct ether_header));
      printf ("IP Header Source IP:            ");
      printf ("%s\n", inet_ntoa(ipH->ip_src));
      printf ("IP Header Destination IP:       ");
      printf ("%s\n", inet_ntoa(ipH->ip_dst));

      if (ipH->ip_p == IPPROTO_TCP) {
        tcpH = (struct tcphdr *)(packet + sizeof(struct ether_header) + 4*(ipH->ip_hl));
        printf ("TCP Header Source Port:         ");
        printf ("%d\n", ntohs(tcpH->th_sport));
        printf ("TCP Header Destination Port:    ");
        printf ("%d\n", ntohs(tcpH->th_dport));

        data = (unsigned char *)tcpH + 4*(tcpH->th_off);
        printf ("Data: ");
        for (i=0; i<16; i++) {
          printf ("%02x", data + i);
        }
      }
    }
  }

  pcap_close(handle);
  return 0;
}
