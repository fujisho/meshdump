#ifndef MESHDUMP_H
#define MESHDUMP_H

#include <pcap.h>

struct meshdump {
  const char *ifname;
  pcap_t *pcap;
  pcap_dumper_t *dumper;
};

#endif
