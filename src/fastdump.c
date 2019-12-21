
#include <arpa/inet.h>
#include <assert.h>
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

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

struct ring {
  struct iovec *rd;
  uint8_t *map;
  struct tpacket_req3 req;
  uint32_t cur_block;
  uint32_t blocks;
};

static uint64_t packets_total = 0, bytes_total = 0;

static int setup_socket(struct ring *ring, char *netdev) {
  int err, i, fd, v = TPACKET_V3;
  struct sockaddr_ll ll;
  unsigned int blocksiz = 1 << 24, framesiz = 1 << 13;
  ring->blocks = 64;
  ring->cur_block = 0;
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
  ring->req.tp_block_nr = ring->blocks;
  ring->req.tp_block_nr = ring->blocks;
  ring->req.tp_frame_size = framesiz;
  ring->req.tp_frame_nr = (blocksiz * ring->blocks) / framesiz;
  ring->req.tp_retire_blk_tov = 100;
  ring->req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

  err =
      setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &ring->req, sizeof(ring->req));
  if (err < 0) {
    perror("setsockopt(SOL_PACKET, PACKET_RX_RING)");
    exit(1);
  }

  printf("block size:%d, %d blocks, %d MB total; frame size: %d, %d frames\n",
         ring->req.tp_block_size, ring->req.tp_block_nr,
         ring->req.tp_block_size * ring->req.tp_block_nr / 1024 / 1024,
         ring->req.tp_frame_size, ring->req.tp_frame_nr);

  ring->map = mmap(NULL, ring->req.tp_block_size * ring->req.tp_block_nr,
                   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
  if (ring->map == MAP_FAILED) {
    perror("mmap");
    exit(1);
  }

  ring->rd = malloc(ring->req.tp_block_nr * sizeof(*ring->rd));
  assert(ring->rd);
  for (i = 0; i < ring->req.tp_block_nr; ++i) {
    ring->rd[i].iov_base = ring->map + (i * ring->req.tp_block_size);
    ring->rd[i].iov_len = ring->req.tp_block_size;
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

void display(struct tpacket3_hdr *ppd) {
  struct ethhdr *eth = (struct ethhdr *)((uint8_t *)ppd + ppd->tp_mac);
  struct iphdr *ip = (struct iphdr *)((uint8_t *)eth + ETH_HLEN);

  if (eth->h_proto == htons(ETH_P_IP)) {
    char sbuff[NI_MAXHOST], dbuff[NI_MAXHOST];
    inet_ntop(AF_INET, &ip->saddr, sbuff, sizeof(sbuff));
    inet_ntop(AF_INET, &ip->daddr, dbuff, sizeof(sbuff));
    printf("%s -> %s, ", sbuff, dbuff);
  }

  printf("rxhash: 0x%x\n", ppd->hv1.tp_rxhash);
}

#include <zlib.h>
gzFile of = NULL;
// #define CHUNK 16384
// z_stream strm;
// uint8_t out[CHUNK];
void save_init(char *name) {
  of = gzopen(name, "wb5");
  // strm.zalloc = NULL;
  // strm.zfree = NULL;
  // strm.opaque = NULL;
  // return deflateInit(&strm, 9);
}
void save_packet(struct tpacket3_hdr *ppd) {
  gzwrite(of, ((uint8_t *)ppd + ppd->tp_mac), ppd->tp_snaplen);
  // strm.avail_in = ppd->tp_snaplen;
  // strm.next_in = ((uint8_t *)ppd + ppd->tp_mac);
  // do {
  //   strm.avail_out = CHUNK;
  //   strm.next_out = out;
  //   int ret = deflate(&strm, Z_NO_FLUSH);
  //   assert(ret != Z_STREAM_ERROR);
  //   int out_len = CHUNK - strm.avail_out;
  //   if (out_len) {
  //     fwrite(out, 1, out_len, of);
  //   }
  // } while (strm.avail_out == 0);
  // assert(strm.avail_in == 0);
}
void save_close() {
  // strm.avail_in = 0;
  // strm.avail_out = CHUNK;
  // strm.next_out = out;
  // int ret = deflate(&strm, Z_FINISH);
  // assert(ret != Z_STREAM_ERROR);
  // int out_len = CHUNK - strm.avail_out;
  // if (out_len) {
  //   fwrite(out, 1, out_len, of);
  // }
  // deflateEnd(&strm);
  // return fclose(of);
  gzflush(of, Z_FINISH);
  gzclose(of);
}
static void walk_block(struct tpacket_block_desc *pbd) {
  int num_pkts = pbd->hdr.bh1.num_pkts;
  unsigned long bytes = 0;
  struct tpacket3_hdr *ppd;
#define next_packet(ptr, offset)                                               \
  ((struct tpacket3_hdr *)((uint8_t *)(ptr) + (offset)))
  ppd = next_packet(pbd, pbd->hdr.bh1.offset_to_first_pkt);
  for (int i = 0; i < num_pkts; ++i) {
    bytes += ppd->tp_snaplen;
    // display(ppd);
    save_packet(ppd);
    ppd = next_packet(ppd, ppd->tp_next_offset);
  }
#undef next_packet
  packets_total += num_pkts;
  bytes_total += bytes;
}

static void flush_block(struct tpacket_block_desc *pbd) {
  pbd->hdr.bh1.block_status = TP_STATUS_KERNEL;
}

static void teardown_socket(struct ring *ring, int fd) {
  munmap(ring->map, ring->req.tp_block_size * ring->req.tp_block_nr);
  free(ring->rd);
  close(fd);
}

static sig_atomic_t sigint = 0;
static void sighandler(int num) { sigint = 1; }
int blks = 0;
static void read_cb(EV_P_ ev_io *w, int revents) {
  struct ring *ring = w->data;
  struct tpacket_block_desc *pbd;

  while (1) {
    pbd = ring->rd[ring->cur_block].iov_base;

    if ((pbd->hdr.bh1.block_status & TP_STATUS_USER) == 0) {
      break;
    }

    walk_block(pbd);
    flush_block(pbd);
    ring->cur_block = (ring->cur_block + 1) % ring->blocks;
    blks++;
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
  if (err < 0) {
    perror("getsockopt");
    exit(1);
  }

  printf("Received %u packets (%lu total),"
         " %lu bytes (%lu total), %u dropped, freeze_q_cnt: %u, blks: %d\n",
         stats.tp_packets, packets_total, bytes_total - bytes_last, bytes_total,
         stats.tp_drops, stats.tp_freeze_q_cnt, blks);
  bytes_last = bytes_total;
  blks = 0;
  if (sigint)
    ev_break(EV_A_ EVBREAK_ALL);
}

int main(int argc, char **argp) {
  int fd;
  struct ring ring;

  if (argc != 3) {
    fprintf(stderr, "Usage: %s INTERFACE\n", argp[0]);
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

  save_close();
  teardown_socket(&ring, fd);
  return 0;
}
