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

int open_dumps(struct meshdump *dumps, int dump_nr, char **ifnames)
{
  int i, err;
  char filename[128];
  char errbuf[PCAP_ERRBUF_SIZE];

  for (i = 0; i < dump_nr; ++i) {

    dumps[i].ifname = ifnames[i];
    dumps[i].pcap = pcap_open_live(dumps[i].ifname,
                                    128,
                                    1,
                                    0,
                                    errbuf);
    /* pcap_dispatch() is used later */
    err = pcap_setnonblock(dumps[i].pcap, 1, errbuf);
    if (err) {
      fprintf(stderr, "%s\n", errbuf);
      return -1;
    }
    if (dumps[i].pcap == 0) {
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
    if (dumps[i].pcap)
      pcap_close(dumps[i].pcap);
  }
}

void process_dumps(struct meshdump *dumps, int dump_nr)
{
  int i, nfds = -1;
  int *fds = (int*)malloc(dump_nr * sizeof(int));
  char buf[4096];
  
  for (i = 0; i < dump_nr; ++i) {
    fds[i] = pcap_fileno(dumps[i].pcap);
    if (fds[i] - 1 > nfds)
      nfds = fds[i] - 1;
  }
  
  while (running) {
    fd_set readfds;
    int err;
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
          break;
              
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
