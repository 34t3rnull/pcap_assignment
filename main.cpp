#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <stdio.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    struct ethhdr* eth_h;
    struct ip* ip_h;
    struct tcphdr* tcp_h;
    const u_char* packet;
    unsigned char *data;
    unsigned short eth_type;
    unsigned char ip_proto;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("*********************************************************\n");
    printf("%u bytes captured\n", header->caplen);
    eth_h = (struct ethhdr*)packet;
    eth_type = htons(eth_h->h_proto);
    if (eth_type == 0x0800)
    {
      ip_h = (struct ip*)(packet + sizeof(struct ethhdr));
      ip_proto = ip_h->ip_p;
      if (ip_proto == 0x6)
      {
        tcp_h = (struct tcphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct ip));
        data = (unsigned char *)(packet + sizeof(struct ethhdr) + sizeof(struct ip) + sizeof(struct tcphdr));
        printf("src_MAC:\t%02x:%02x:%02x:%02x:%02x:%02x\n",
          eth_h->h_source[0], eth_h->h_source[1],
          eth_h->h_source[2], eth_h->h_source[3],
          eth_h->h_source[4], eth_h->h_source[5]);
        printf("dst_MAC:\t%02x:%02x:%02x:%02x:%02x:%02x\n",
          eth_h->h_dest[0], eth_h->h_dest[1],
          eth_h->h_dest[2], eth_h->h_dest[3],
          eth_h->h_dest[4], eth_h->h_dest[5]);
        printf("src ip:\t\t%s\n", inet_ntoa(ip_h->ip_src));
        printf("dst ip:\t\t%s\n", inet_ntoa(ip_h->ip_dst));
        printf("src port:\t%u\n", htons(tcp_h->th_sport));
        printf("dst port:\t%u\n", htons(tcp_h->th_dport));
        printf("data:\t\t%02x %02x %02x %02x %02x %02x %02x %02x\n",
          data[0], data[1], data[2], data[3],
          data[4], data[5], data[6], data[7]);
      }
    }
    printf("*********************************************************\n");
  }

  pcap_close(handle);
  return 0;
}
