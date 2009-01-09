#include <pcap.h>
#include "meshdump.h"

/* Standard Libraries */
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

int running = 1;

struct meshdump *alloc_dumps(int dump_nr)
{
  struct meshdump *dumps = (struct meshdump*) malloc(dump_nr * sizeof(*dumps));
  memset(dumps, 0, sizeof(*dumps) * dump_nr);

  return dumps;
}

void free_dumps(struct meshdump *dumps)
{
  free(dumps);
}

struct bpf_insn filter_insns[] = {
  { 0x28, 0, 0, 0x00000002 },
  { 0x15, 0, 1, 0x00001700 },
  { 0x6, 0, 0, 0x00000057 },
  { 0x6, 0, 0, 0x0000005a },
};

int open_dumps(struct meshdump *dumps, int dump_nr, char **ifnames)
{
  int i;
  char filename[128];
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program filter;

  /* setup filter program */
  memset(&filter, 0, sizeof(filter));
  filter.bf_len = sizeof(filter_insns)/sizeof(filter_insns[0]);
  filter.bf_insns = (struct bpf_insn*)malloc(sizeof(filter_insns));
  memcpy(filter.bf_insns, &filter_insns, sizeof(filter_insns));

  /* loop to initialize dumps */
  for (i = 0; i < dump_nr; ++i) {

    dumps[i].ifname = ifnames[i];
    dumps[i].pcap = pcap_open_live(dumps[i].ifname,
                                    128,
                                    1,
                                    0,
                                    errbuf);
    if (dumps[i].pcap == 0) {
      fprintf(stderr, "%s\n", errbuf);
      return -1;
    }
    
    /* this is a kind of optimization.. */
    if (pcap_setfilter(dumps[i].pcap, &filter)) {
      perror("pcap_setfilter");
      return -1;
    }
      
    /* pcap_dispatch() is used later */
    if (pcap_setnonblock(dumps[i].pcap, 1, errbuf)) {
      fprintf(stderr, "%s\n", errbuf);
      return -1;
    }
    
    /* open dumper */
    /* filename is automatically derived from ifname */
    snprintf(filename, 128, "%s.dump", dumps[i].ifname);
    dumps[i].dumper = pcap_dump_open(dumps[i].pcap, filename);
    if (dumps[i].dumper == 0) {
      return -1;
    }
  }
  
  return 0;
}

void print_stats(struct meshdump *dump)
{
  struct pcap_stat ps;
  pcap_stats(dump->pcap, &ps);

  printf("%s: received %d, dropped %d\n", dump->ifname, ps.ps_recv, ps.ps_drop);
}

void close_dumps(struct meshdump *dumps, int dump_nr)
{
  int i;
  for (i = 0; i < dump_nr; ++i) {
    /* close dumper first */
    if (dumps[i].dumper) {
      pcap_dump_flush(dumps[i].dumper);
      pcap_dump_close(dumps[i].dumper);
    }
    /* close pcap */
    if (dumps[i].pcap) {
      print_stats(&dumps[i]);
      pcap_close(dumps[i].pcap);
    }
  }
}

void process_dumps(struct meshdump *dumps, int dump_nr)
{
  int i, nfds = -1;
  int *fds = (int*)malloc(dump_nr * sizeof(int));
  char buf[4096];
  
  for (i = 0; i < dump_nr; ++i) {
    fds[i] = pcap_fileno(dumps[i].pcap);
    if (fds[i] + 1 > nfds)
      nfds = fds[i] + 1;
  }
  
  while (running) {
    fd_set readfds;
    int err;

    /* initialization */
    FD_ZERO(&readfds);
    for (i = 0; i < dump_nr; ++i) {
      FD_SET(fds[i], &readfds);
    }
    
    err = select(nfds, &readfds, NULL, NULL, NULL);
    if (err < 0)
      break;

    for (i = 0; i < dump_nr; ++i) {
      if (FD_ISSET(fds[i], &readfds)) {
        /* dump frames as many as possible */
        err = pcap_dispatch(dumps[i].pcap,
                            -1,
                            pcap_dump,
                            (u_char*)dumps[i].dumper);
        if (err < 0) 
          continue;
              
      }
    }
  }
  
  free(fds);
}

void print_usage(char *arg0)
{
  printf("%s [-d] <iface> [<iface> ..]\n", arg0);
}

void stop_dumps(int signal)
{
  assert(signal == SIGINT);
  running = 0;
}

int main(int argc, char **argv)
{
  int i;
  struct meshdump *dumps;
  
  /* variables for getopt */
  int c;
  int digit_optind = 0;
  int debug = 0;
  
  /* loop for getopt */
  while (1) {
    int this_option_optind = optind ? optind : 1;
    int option_index = 0;
    static struct option long_options[] = {
      {"help", 0, 0, 'h'},
      {"debug", 0, 0, 'd'},
      {0, 0, 0, 0}
    };
    c = getopt_long(argc, argv, "dh",
                    long_options, &option_index);
    
    if (c == -1) break;

    switch (c) {
      case 'h':
        print_usage(argv[0]);
        return EXIT_SUCCESS;
        
      case 'd':
        debug = 1;
        break;
        
      default:
        printf("?? getopt returned character code 0%o ??\n", c);
    }
  }
  /* no iface specified */
  if (argc < 2) {
    print_usage(argv[0]);
    
    return EXIT_SUCCESS;
  }

  if (signal(SIGINT, stop_dumps)) {
    perror("signal");
    return EXIT_FAILURE;
  }
    
  
  dumps = alloc_dumps(argc - 1);
  
  if (open_dumps(dumps, argc - 1, &argv[1]) < 0)
    goto error;

  process_dumps(dumps, argc - 1);

  /* clean up */
  close_dumps(dumps, argc - 1);
error:
  free_dumps(dumps);
  
  return EXIT_SUCCESS;
}
