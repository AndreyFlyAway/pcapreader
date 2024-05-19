#include "pcapreader.h"
#include <format>

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include "common.h"

namespace {
  #define SIZE_ETHERNET 14
  
  struct PcapStatistic {
    struct common {
      size_t count;
      size_t totalSize;
      size_t tcp;
      size_t udp;
      size_t icmp;
      size_t other;
    } common;
    // L3
    struct L3Stat {
      size_t nIPv4;
      size_t nIPv6;
      size_t nL3Other;
    } l3;
    struct TCPStat {
      size_t syn;
      size_t syn_ack;
      size_t ack;
      size_t fin_ack;
      size_t rst;
      size_t rst_ack;
      size_t other;
    } TCPStat;
  };

  PcapStatistic STATS;
  size_t LINKHDR_LEN;

  size_t getLinkHeaderLen(pcap_t* handle)
  {
    size_t ret;
    int linktype;
    if ((linktype = pcap_datalink(handle)) == PCAP_ERROR) {
      fprintf(stderr, "pcap_datalink(): %s\n", pcap_geterr(handle));
      return 0;
    }
    switch (linktype)
    {
    case DLT_NULL:
      ret = 4;
      break;
    case DLT_EN10MB:
      ret = 14;
      break;
    case DLT_SLIP:
    case DLT_PPP:
      ret = 24;
      break;
    default:
      std::cout << std::format("Unsupported datalink {}", linktype) << std::endl;
      ret = 0;
    }
    return ret;
  }

  void getTcpStat(const tcphdr* tcphdr) {
    ++STATS.common.tcp;
    unsigned char flags = tcphdr->th_flags;
    bool syn = flags & TH_SYN;
    bool ack = flags & TH_ACK;
    bool rst = flags & TH_RST;
    bool fin = flags & TH_FIN;
    if (syn && ack) {
      ++STATS.TCPStat.syn_ack;
    } else if (fin && ack) {
      ++STATS.TCPStat.fin_ack;
    } else if (rst && ack) {
      ++STATS.TCPStat.rst_ack;
    } else {
      STATS.TCPStat.syn += syn;
      STATS.TCPStat.ack += ack;
      STATS.TCPStat.rst += rst;
    }
  }

  void getUdpStat(const udphdr* tcpudr) {
    ++STATS.common.udp;
  }

  void collectStatsHandle(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr)
  {
      struct ip* iphdr;
      struct icmp* icmphdr;
      struct tcphdr* tcphdr;
      struct udphdr* udphdr;
      char iphdrInfo[256];
      char srcip[256];
      char dstip[256];
      packetptr += LINKHDR_LEN;

      iphdr = (struct ip*)packetptr;
      packetptr += 4*iphdr->ip_hl;
      ++STATS.common.count;
      switch (iphdr->ip_p)
      {
      case IPPROTO_TCP:
        tcphdr = (struct tcphdr*)packetptr;
        getTcpStat(tcphdr);
        break;
      case IPPROTO_UDP:
        udphdr = (struct udphdr*)packetptr;
        getUdpStat(udphdr);
        break;
      case IPPROTO_ICMP:
        icmphdr = (struct icmp*)packetptr;
        break;
      }
  }

  void printStatistic() {
    // Common
    std::cout << format("Total packets: {}", STATS.common.count) << std::endl;
    // TCP
    std::cout << format("TCP packets: {}: ", STATS.common.tcp) << std::endl;
    std::cout << format("  SYN: {}; SYN+ACK: {}; ACK: {}; FIN+ACK: {}; RST: {}; RST+ACK: {};  ",
                        STATS.TCPStat.syn, STATS.TCPStat.syn_ack,
                        STATS.TCPStat.ack, STATS.TCPStat.fin_ack,
                        STATS.TCPStat.rst, STATS.TCPStat.rst_ack) << std::endl;
  }
}

int parsepcap(int argc, char* argv[]) {
  if (argc != 2) {
    std::cout << "Wrong usage. Pass the path to pcap file location:\n"
      "\tpcapreader /path/to/file.pcap";
    return 1;
  }

  std::cout << format("Reading file by path {}!\n", argv[1]);
  char errbuf[PCAP_ERRBUF_SIZE];
  FILE* fp = fopen(argv[1], "r");
  if (fp == NULL) {
    std::cout << format("Could not open pcap '{}' file to read!\n", argv[1]);
    return 1;
  }

  pcap_t *handle = pcap_fopen_offline(fp, errbuf);
  if (handle == NULL) {
    std::cout << format("Could not read pcap file {}!\n", errbuf);
    return 1;
  }
  LINKHDR_LEN = getLinkHeaderLen(handle);
  pcap_loop(handle, -1, collectStatsHandle, NULL);
  printStatistic();
  return 0;
}

