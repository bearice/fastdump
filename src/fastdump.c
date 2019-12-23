
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/net_tstamp.h>
#include <net/if.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <ev.h>
#include <zlib.h>

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

typedef struct tpacket3_hdr *pkthdr_t;
typedef struct tpacket_block_desc *blkhdr_t;
struct ring {
  struct tpacket_req3 req;
  blkhdr_t *block_ptr;
  uint8_t *mmap_ptr;
  uint32_t block_cur;
  uint32_t block_cnt;
};

static uint64_t packets_total = 0, bytes_total = 0;

#define RING_BLOCK_SZ (1 << 22)
#define RING_FRAME_SZ (1 << 12)
#define RING_BLOCK_CNT 128
static int setup_socket(struct ring *ring, char *netdev) {
  int err, i, fd, v = TPACKET_V3;
  struct sockaddr_ll ll;
  unsigned int blocksiz = RING_BLOCK_SZ, framesiz = RING_FRAME_SZ;
  ring->block_cnt = RING_BLOCK_CNT;
  ring->block_cur = 0;
  fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (fd < 0) {
    perror("socket(AF_PACKET, SOCK_RAW)");
    exit(1);
  }
  int one = 1;
  err = setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, &one, sizeof(one));
  if (err < 0) {
    perror("setsockopt(SOL_PACKET, PACKET_QDISC_BYPASS)");
    exit(1);
  }

  int req = SOF_TIMESTAMPING_RAW_HARDWARE;
  err = setsockopt(fd, SOL_PACKET, PACKET_TIMESTAMP, (void *)&req, sizeof(req));
  if (err < 0) {
    perror("setsockopt(SOL_PACKET, PACKET_VERSION)");
    exit(1);
  }
  err = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
  if (err < 0) {
    perror("setsockopt(SOL_PACKET, PACKET_VERSION)");
    exit(1);
  }

  memset(&ring->req, 0, sizeof(ring->req));
  ring->req.tp_block_size = blocksiz;
  ring->req.tp_block_nr = ring->block_cnt;
  ring->req.tp_frame_size = framesiz;
  ring->req.tp_frame_nr = (blocksiz * ring->block_cnt) / framesiz;
  ring->req.tp_retire_blk_tov = 100;
  ring->req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

  err =
      setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &ring->req, sizeof(ring->req));
  if (err < 0) {
    perror("setsockopt(SOL_PACKET, PACKET_RX_RING)");
    exit(1);
  }

  fprintf(stderr,
          "block size:%d, %d blocks, %d MB total;"
          "frame size: %d, %d frame per block, %d frames total\n",
          ring->req.tp_block_size, ring->req.tp_block_nr,
          ring->req.tp_block_size * ring->req.tp_block_nr / 1024 / 1024,
          ring->req.tp_frame_size,
          ring->req.tp_block_size / ring->req.tp_frame_size,
          ring->req.tp_frame_nr);

  ring->mmap_ptr = mmap(NULL, ring->req.tp_block_size * ring->req.tp_block_nr,
                        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
  if (ring->mmap_ptr == MAP_FAILED) {
    perror("mmap");
    exit(1);
  }

  ring->block_ptr = malloc(ring->req.tp_block_nr * sizeof(*ring->block_ptr));
  assert(ring->block_ptr);
  for (i = 0; i < ring->req.tp_block_nr; ++i) {
    ring->block_ptr[i] = (void *)ring->mmap_ptr + (i * ring->req.tp_block_size);
    // ring->rd[i].iov_len = ring->req.tp_block_size;
    // ring->block_ptr[i]->hdr.bh1.block_status = TP_STATUS_KERNEL;
  }

  memset(&ll, 0, sizeof(ll));
  ll.sll_family = PF_PACKET;
  ll.sll_protocol = htons(ETH_P_ALL);
  ll.sll_ifindex = if_nametoindex(netdev);
  ll.sll_hatype = 0;
  ll.sll_pkttype = 0;
  ll.sll_halen = 0;

  err = bind(fd, (struct sockaddr *)&ll, sizeof(ll));
  if (err < 0) {
    perror("bind");
    exit(1);
  }

  return fd;
}
#define _s(x)                                                                  \
  { x, #x }
static struct {
  int value;
  const char *string;
} tpkt_status[] = {_s(TP_STATUS_USER),
                   _s(TP_STATUS_COPY),
                   _s(TP_STATUS_LOSING),
                   _s(TP_STATUS_CSUMNOTREADY),
                   _s(TP_STATUS_VLAN_VALID),
                   _s(TP_STATUS_BLK_TMO),
                   _s(TP_STATUS_VLAN_TPID_VALID),
                   _s(TP_STATUS_CSUM_VALID),
                   _s(TP_STATUS_TS_SOFTWARE),
                   _s(TP_STATUS_TS_SYS_HARDWARE),
                   _s(TP_STATUS_TS_RAW_HARDWARE),
                   {0}};
#undef _s
void print_stat(int s) {
  int i = 0;
  while (tpkt_status[i].value) {
    if (s & tpkt_status[i].value) {
      printf("%s ", tpkt_status[i].string);
    }
    i++;
  }
}
void display(struct tpacket3_hdr *ppd) {
  struct ethhdr *eth = (struct ethhdr *)((uint8_t *)ppd + ppd->tp_mac);
  struct iphdr *ip = (struct iphdr *)((uint8_t *)eth + ETH_HLEN);

  printf("eth_proto: %04x \n", htons(eth->h_proto));
  if (eth->h_proto == htons(ETH_P_IP)) {
    char sbuff[NI_MAXHOST], dbuff[NI_MAXHOST];
    inet_ntop(AF_INET, &ip->saddr, sbuff, sizeof(sbuff));
    inet_ntop(AF_INET, &ip->daddr, dbuff, sizeof(sbuff));
    printf("%s -> %s\n", sbuff, dbuff);
  }

  printf("tp_status: 0x%08x ", ppd->tp_status);
  print_stat(ppd->tp_status);
  puts("");
  printf("tp_len: %u\n", ppd->tp_len);
  printf("tp_snaplen: %u\n", ppd->tp_snaplen);
  printf("tp_rxhash: 0x%08x\n", ppd->hv1.tp_rxhash);
  printf("tp_vlan_tci: %u\n", ppd->hv1.tp_vlan_tci);
  printf("tp_vlan_tpid: %u\n", ppd->hv1.tp_vlan_tpid);
  printf("==========================\n");
}

#define PCAP_HEADER_MAGIC 0xa1b2c3d4
#define PCAP_HEADER_MAGIC_NS 0xa1b23c4d
#define PCAP_HEADER_SIZE (sizeof(struct pcap_fhdr))
struct pcap_fhdr {
  uint32_t magic;
  uint16_t version_major;
  uint16_t version_minor;
  uint32_t thiszone; /* gmt to local correction */
  uint32_t sigfigs;  /* accuracy of timestamps */
  uint32_t snaplen;  /* max length saved portion of each pkt */
  uint32_t linktype; /* data link type (LINKTYPE_*) */
} __attribute__((__packed__));
typedef struct pcap_fhdr *pcap_fhdr_t;

#define PCAP_PKT_HEADER_SIZE (sizeof(struct pcap_phdr))
struct pcap_phdr {
  uint32_t ts_sec;  /* time stamp */
  uint32_t ts_usec; /* time stamp */
  uint32_t caplen;  /* length of portion present */
  uint32_t len;     /* length this packet (off wire) */
} __attribute__((__packed__));
typedef struct pcap_phdr *pcap_phdr_t;

//#define GZOUT
#ifdef GZOUT
#define pcap_file gzFile
#define pcap_open gzopen
#define pcap_write gzfwrite
#define pcap_flush(f) gzflush(f, Z_BLOCK)
#define pcap_close gzclose
#else
#define pcap_file FILE *
#define pcap_open fopen
#define pcap_write fwrite
#define pcap_flush fflush
#define pcap_close fclose
#endif
#define SNAPLEN 2048
#define IO_BLOCK_SZ 4096
static int of;
static char *iobuf;
static off_t iobuf_sz;
static char *of_name;
void save_init(char *name) {
  of_name = name;
  of = open(name, O_CREAT | O_WRONLY | O_TRUNC | O_DIRECT, 0644);
  struct pcap_fhdr hdr = {.magic = PCAP_HEADER_MAGIC_NS,
                          .version_major = 2,
                          .version_minor = 4,
                          .thiszone = 0,
                          .sigfigs = 0,
                          .snaplen = SNAPLEN,
                          .linktype = 1};
  iobuf = aligned_alloc(IO_BLOCK_SZ, RING_BLOCK_SZ);
  iobuf_sz = 0;
  memcpy(iobuf + iobuf_sz, &hdr, sizeof(hdr));
  iobuf_sz += sizeof(hdr);
}

void save_packet(struct tpacket3_hdr *ppd) {
  struct pcap_phdr phdr = {0};
  phdr.caplen = (ppd->tp_snaplen > SNAPLEN) ? SNAPLEN : ppd->tp_snaplen;
  phdr.len = ppd->tp_snaplen;
  phdr.ts_sec = ppd->tp_sec;
  phdr.ts_usec = ppd->tp_nsec;
  // printf("tp_sec=%u tp_nsec=%u\n", ppd->tp_sec, ppd->tp_nsec);
  memcpy(iobuf + iobuf_sz, &phdr, sizeof(phdr));
  iobuf_sz += sizeof(phdr);
  memcpy(iobuf + iobuf_sz, ((uint8_t *)ppd + ppd->tp_mac), phdr.caplen);
  iobuf_sz += phdr.caplen;
}

void save_flush_block() {
  int align = iobuf_sz / IO_BLOCK_SZ;
  int rest = iobuf_sz % IO_BLOCK_SZ;
  write(of, iobuf, align * IO_BLOCK_SZ);
  memmove(iobuf, iobuf + align, rest);
  iobuf_sz = rest;
}

void save_close() {
  save_flush_block();
  if (iobuf_sz) {
    close(of);
    of = open(of_name, O_WRONLY | O_APPEND, 0644);
    write(of, iobuf, iobuf_sz);
    // fssync(of);
  }
  close(of);
  free(iobuf);
}

#define next_packet(ptr, offset) ((pkthdr_t)((uint8_t *)(ptr) + (offset)))
static void walk_block(struct tpacket_block_desc *pbd) {
  int num_pkts = pbd->hdr.bh1.num_pkts;
  unsigned long bytes = 0;
  pkthdr_t ppd;
  ppd = next_packet(pbd, pbd->hdr.bh1.offset_to_first_pkt);
  for (int i = 0; i < num_pkts; ++i) {
    bytes += ppd->tp_snaplen;
    // display(ppd);
    save_packet(ppd);
    ppd = next_packet(ppd, ppd->tp_next_offset);
  }
  save_flush_block();
  packets_total += num_pkts;
  bytes_total += bytes;
}
#undef next_packet

static void flush_block(struct tpacket_block_desc *pbd) {
  pbd->hdr.bh1.block_status = TP_STATUS_KERNEL;
}

static void teardown_socket(struct ring *ring, int fd) {
  munmap(ring->mmap_ptr, ring->req.tp_block_size * ring->req.tp_block_nr);
  free(ring->block_ptr);
  close(fd);
}

static sig_atomic_t sigint = 0;
static void sighandler(int num) { sigint = 1; }
int blks = 0, blklen = 0;
static void read_cb(EV_P_ ev_io *w, int revents) {
  struct ring *ring = w->data;
  struct tpacket_block_desc *pbd;

  while (1) {
    pbd = ring->block_ptr[ring->block_cur];
    if ((pbd->hdr.bh1.block_status & TP_STATUS_USER) == 0) {
      break;
    }
    walk_block(pbd);
    flush_block(pbd);
    ring->block_cur = (ring->block_cur + 1) % ring->block_cnt;
    blks++;
    blklen += pbd->hdr.bh1.blk_len;
    if (blks > 128)
      break;
  }
  if (sigint)
    ev_break(EV_A_ EVBREAK_ALL);
  // printf("Procressed %d blocks\n", blks);
}
static uint64_t bytes_last = 0;
static void stat_cb(EV_P_ ev_timer *w, int revents) {
  struct tpacket_stats_v3 stats;
  socklen_t len;
  int fd, err;
  fd = *(int *)w->data;
  len = sizeof(stats);
  err = getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len);
  char *eol = "\n";
  if (err < 0) {
    perror("getsockopt");
    exit(1);
  }

  // if (isatty(STDERR_FILENO)) {
  //   fprintf(stderr, "\r\033[K");
  //   eol = "";
  // }
  uint64_t x = bytes_total - bytes_last;
  double spd = x * 8 / 1024 / 1024 / 1024.0;
  double bufutil = (blklen * 100.0) / (blks * RING_BLOCK_SZ);
  fprintf(stderr,
          "Dumping: %u pps (%lu total), "
          " %lu Bps / %.2lf Gbps (%lu total), %u dropped, freeze_q_cnt: %u, "
          "Buffer: %d blocks/s , util: %.2lf%% %s",
          stats.tp_packets, packets_total, x, spd, bytes_total, stats.tp_drops,
          stats.tp_freeze_q_cnt, blks, bufutil, eol);
  bytes_last = bytes_total;
  blklen = blks = 0;
  if (loop && sigint)
    ev_break(EV_A_ EVBREAK_ALL);
}

int main(int argc, char **argp) {
  int fd;
  struct ring ring;

  if (argc != 3) {
    fprintf(stderr, "Usage: %s ifname outfile\n", argp[0]);
    return EXIT_FAILURE;
  }

  memset(&ring, 0, sizeof(ring));
  fd = setup_socket(&ring, argp[1]);
  assert(fd > 0);
  save_init(argp[2]);
  struct ev_loop *loop = EV_DEFAULT;
  ev_io io;
  ev_timer timer_stat;

  ev_io_init(&io, read_cb, fd, EV_READ);
  io.data = &ring;
  ev_io_start(loop, &io);

  ev_timer_init(&timer_stat, stat_cb, 1., 1.);
  timer_stat.data = &fd;
  ev_timer_start(loop, &timer_stat);
  signal(SIGINT, sighandler);
  ev_run(loop, 0);

  stat_cb(NULL, &timer_stat, 0);
  save_close();
  teardown_socket(&ring, fd);
  return 0;
}
