#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>

#define ETHERTYPE_IP  0x0800
#define IPPROTO_TCP   0x06

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(const char *head, unsigned char *data)
{
  printf("%s\t%02x:%02x:%02x:%02x:%02x:%02x\n", head,
    data[0], data[1], data[2], data[3], data[4], data[5]);
}

void print_data(unsigned char *data, int size)
{
  if (size > 16)
    size = 16;
  printf("data:\t\t");
  if (!size)
  {
    printf("None\n");
    return;
  }
  for(int i = 0; i < size; i++)
  {
    if (!(i % 8) && i)
      printf("\n\t\t");
    printf("%02x ", data[i]);
  }
  printf("\n");
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
    unsigned int ip_length;
    u_int8_t tcp_length;
    int data_size;

    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("*********************************************************\n");
    printf("%u bytes captured\n", header->caplen);
    eth_h = (struct ethhdr*)packet;
    eth_type = htons(eth_h->h_proto);
    if (eth_type == ETHERTYPE_IP)
    {
      ip_h = (struct ip*)(packet + sizeof(struct ethhdr));
      ip_length = ip_h->ip_hl * 4;
      ip_proto = ip_h->ip_p;
      if (ip_proto == IPPROTO_TCP)
      {
        tcp_h = (struct tcphdr*)((char *)ip_h + ip_length);
        tcp_length = tcp_h->th_off * 4;
        data = (unsigned char *)(tcp_h + tcp_length);
        data_size = header->caplen - (sizeof(struct ethhdr) + ip_length + tcp_length);
        print_mac("src_MAC:", (unsigned char *)eth_h->h_source);
        print_mac("dst_MAC:", (unsigned char *)eth_h->h_dest);
        printf("src ip:\t\t%s\n", inet_ntoa(ip_h->ip_src));
        printf("dst ip:\t\t%s\n", inet_ntoa(ip_h->ip_dst));
        printf("src port:\t%u\n", htons(tcp_h->th_sport));
        printf("dst port:\t%u\n", htons(tcp_h->th_dport));
        print_data((unsigned char *)data, data_size);
      }
    }
    printf("*********************************************************\n");
  }

  pcap_close(handle);
  return 0;
}
