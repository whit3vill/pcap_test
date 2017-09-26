#include "pcap_test.h"


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }
  struct pcap_pkthdr* header;
  struct ether_header* ethernet;

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (1) {
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    printf("%u bytes captured\n", header->caplen);
    
    ethernet = (struct ether_header*)(packet);
    printf("packet's src MAC :%s\n",ntohs(ethernet->ether_shost));

  }

  pcap_close(handle);
  return 0;
}
