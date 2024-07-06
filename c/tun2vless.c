
#include "./mongoose/src/event.h"
#include "./mongoose/src/http.h"
#include "./mongoose/src/ws.h"
#include "./mongoose/src/tls.h"
#include "./mongoose/src/url.h"
#include "./mongoose/src/base64.h"
#include "./mongoose/src/log.h"

#include "./inet.h"
#if TUN2VLESS_CACHE_ON
#include "./icache.h"
#endif

int tun_main(int argc, char* argv[], int port);

#ifdef _WIN32
#define usleep(us) Sleep(us/1000)
#else
#include <pthread.h>
#endif

static void start_thread(void* (*f)(void*), void* p) {
#ifdef _WIN32
  _beginthread((void(__cdecl*)(void*)) f, 0, p);
#else
  pthread_t thread_id = (pthread_t)0;
  pthread_attr_t attr;
  (void)pthread_attr_init(&attr);
  (void)pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_create(&thread_id, &attr, f, p);
  pthread_attr_destroy(&attr);
#endif
}


struct mgr_userdata {
  const char* tcpsvr;
  const char* vlurl;
  uint8_t vlguid[16+4];
  uint16_t tcpport;
  uint16_t is_hexdumping : 1;
  uint16_t flags_rfu : 15;
  struct mg_connection* tcpc;
};

struct conn_userdata {
  uint32_t seq; // tcp
  uint32_t ack_seq;
  uint32_t is_ws_opened : 1; // rfu
  uint32_t is_ws_sent : 1;
  uint32_t is_ws_received : 1;
  uint32_t is_ws_closed : 1;
  uint32_t flags_rfu : 28;
  struct iphdr ip;
  char iprfu[60];
#if TUN2VLESS_CACHE_ON
	struct icachectx icctx;
#endif
};

static int _make_ip_header(struct iphdr* ip, struct iphdr* ret_ip, uint32_t tot_len) {
  static uint32_t ack_id = 0x1122; // TODO
  memset(ret_ip, 0, sizeof(*ret_ip));
  ret_ip->version = 4;
  ret_ip->ihl = 5;
  ret_ip->tot_len = htons(tot_len);
  ret_ip->id = htons(ack_id++);
  ret_ip->frag_off = htons(0x4000);
  ret_ip->ttl = 0x80; // 255;
  ret_ip->protocol = 6;
  ret_ip->saddr = ip->daddr;
  ret_ip->daddr = ip->saddr;
  ret_ip->check = ip_checksum((uint8_t*)ret_ip, 20);
  return 20;
}
#define MAKE_TCP_HEADER_OP_FIN 1
#define MAKE_TCP_HEADER_OP_RESEND 2
#define MAKE_TCP_HEADER_OP_RST 3
static int _make_tcp_header(int op, struct tcphdr* tcp, struct tcphdr* ret_tcp, struct conn_userdata* ud, const void* data_ptr, size_t data_len) {
  memset(ret_tcp, 0, sizeof(*ret_tcp));
  ret_tcp->source = tcp->dest;
  ret_tcp->dest = tcp->source;
  ret_tcp->seq = (op == MAKE_TCP_HEADER_OP_RESEND)? tcp->ack_seq : ud->seq;

  if (tcp->syn || tcp->fin || tcp->rst) {
    ud->ack_seq = htonl(ntohl(tcp->seq) + 1);
  }
  else if (tcp->ack){
    uint32_t tot_len = ntohs(((struct iphdr*)(tcp)-1)->tot_len);
    uint32_t offset = (((struct iphdr*)(tcp)-1)->ihl + tcp->doff) << 2;
    if (tot_len > offset) {
      ud->ack_seq = htonl(ntohl(tcp->seq) + tot_len - offset);
    }
  }

  if (tcp->syn) {
    ret_tcp->doff = 8;
    ret_tcp->syn = 1;
    memcpy(ret_tcp + 1, "\x02\x04\xff\xd7\x01\x03\x03\x08\x01\x01\x04\x02", 12);
  }
  else {
    if (op == MAKE_TCP_HEADER_OP_FIN){
      ret_tcp->fin = 1;
    }
    else if (op == MAKE_TCP_HEADER_OP_RST) {
      ret_tcp->rst = 1;
    }
    else if (data_len > 0) {
      ret_tcp->psh = 1;
    }
    ret_tcp->doff = 5;
  }
  ret_tcp->ack_seq = ud->ack_seq;
  ret_tcp->ack = 1;

  if (ret_tcp->syn || ret_tcp->fin) {
    ud->seq = htonl(ntohl(ud->seq) + 1);
  }
  else if ((data_len > 0) && (op != MAKE_TCP_HEADER_OP_RESEND)) {
    ud->seq = htonl(ntohl(ud->seq) + data_len);
  }

  ret_tcp->window = htons(0x1800); // 0xffff

  ret_tcp->check = tcp_checksum(ret_tcp, data_ptr, data_len);
  return (ret_tcp->doff << 2);
}

static bool _tcp_send_ip_packet(struct mg_connection* c, struct iphdr* ip, const void* data_ptr, size_t data_len) {
  uint32_t tot_len = ntohs(ip->tot_len);
  if (c->is_hexdumping) {
    struct tcphdr* tcp = inet_get_tcp(ip);
    MG_INFO(("\n-- %s %s:%d -> %s:%d %d+%d=%d", (ip->protocol == IPPROTO_TCP)?"tcp":"udp", inet_ntoa(*((struct in_addr*)&ip->saddr)), ntohs(tcp->source), "", ntohs(tcp->dest), tot_len - data_len, data_len, tot_len));
    mg_hexdump(ip, tot_len - data_len);
    if (data_len) {
      mg_hexdump(data_ptr, data_len);
    }
  }
  if (ip->protocol == IPPROTO_TCP) {
    struct tcphdr* tcp = inet_get_tcp(ip);
    MG_DEBUG(("->tcp=%d syn=%d, ack=%d, fin=%d, seq=0x%x, ack_seq=0x%x, len=0x%x", c->id, tcp->syn, tcp->ack, tcp->fin, ntohl(tcp->seq), ntohl(tcp->ack_seq), data_len));
  }

  if (data_ptr == NULL) {
    return mg_send(((struct mgr_userdata*)c->mgr->userdata)->tcpc, ip, tot_len);
  }
  else {
    bool rv = mg_send(((struct mgr_userdata*)c->mgr->userdata)->tcpc, ip, tot_len - data_len);
    if (rv) {
      rv = mg_send(((struct mgr_userdata*)c->mgr->userdata)->tcpc, data_ptr, data_len);
    }
    return rv;
  }
}

static void _ws_open(struct mg_connection* c) {
  struct conn_userdata* ud = (struct conn_userdata*)(c + 1);
  ud->is_ws_opened = 1;

  if (ud->ip.protocol == IPPROTO_TCP) {
    struct tcphdr* tcp = inet_get_tcp(&ud->ip);
    ud->seq = tcp->seq ^ 0xA5A5A5A5; // TODO: 

    if (tcp->syn) {
      uint8_t ret_buf[52];
      _make_ip_header(&ud->ip, (struct iphdr*)ret_buf, 52); 
      _make_tcp_header(0, tcp, (struct tcphdr*)(ret_buf + 20), ud, NULL, 0); // sync

      _tcp_send_ip_packet(c, (struct iphdr*)ret_buf, NULL, 0);
     }
  }
}
static void _ws_close(struct mg_connection* c) {
  struct conn_userdata* ud = (struct conn_userdata*)(c + 1);
  ud->is_ws_closed = 1;
  // TODO: conn fin
}
static void _ws_msg(struct mg_connection* c, struct mg_ws_message* msg) {
  struct conn_userdata* ud = (struct conn_userdata*)(c + 1);
 
  const char* data_ptr = msg->data.buf;
  size_t data_len = msg->data.len;
  if (!ud->is_ws_received) {
    ud->is_ws_received = 1;
    // 2: version
    data_ptr += 2;
    data_len -= 2;
  }

  uint8_t ret_buf[40];
  _make_ip_header(&ud->ip, (struct iphdr*)ret_buf, 40 + data_len);
  _make_tcp_header(0, inet_get_tcp(&ud->ip), (struct tcphdr*)(ret_buf + 20), ud, data_ptr, data_len); // data
  _tcp_send_ip_packet(c, (struct iphdr*)ret_buf, data_ptr, data_len);
#if TUN2VLESS_CACHE_ON
  icache_add(&ud->icctx, ((struct tcphdr*)(ret_buf + 20))->seq, data_ptr, data_len);
#endif
}

static void ws_fn(struct mg_connection* c, int ev, void* ev_data) {
  if (ev == MG_EV_OPEN) {
    c->is_hexdumping = ((struct mgr_userdata*)c->mgr->userdata)->is_hexdumping;
  }
  else if (ev == MG_EV_CONNECT) {
    struct mg_tls_opts opts = { .name = mg_url_host(((struct mgr_userdata*)c->mgr->userdata)->vlurl) };
    mg_tls_init(c, &opts);
  }
  else if (ev == MG_EV_ERROR) {
    // On error, log error message
    MG_ERROR(("%p %s", c->fd, (char*)ev_data));
  }
  else if (ev == MG_EV_WS_OPEN) {
    // When websocket handshake is successful, send message
    _ws_open(c);
  }
  else if (ev == MG_EV_WS_MSG) {
    // When we get echo response, print it
    _ws_msg(c, (struct mg_ws_message*)ev_data);
  }
  else if (ev == MG_EV_POLL) {
    if (((struct conn_userdata*)(c + 1))->is_ws_closed) {
      mg_close_conn(c);
    }
  }

  if (ev == MG_EV_ERROR || ev == MG_EV_CLOSE) {
    mg_tls_free(c);
    _ws_close(c);
  }
}

static struct mg_connection* _ws_find_conn(struct mg_mgr* mgr, struct iphdr* ip) {
  struct tcphdr* tcp = inet_get_tcp(ip);
  struct iphdr* cip;
  struct tcphdr* ctcp;
  struct mg_connection* c;
  for (c = mgr->conns; c != NULL; c = c->next) {
    cip = &((struct conn_userdata*)(c + 1))->ip;
    if ((ip->protocol == cip->protocol) && (ip->saddr == cip->saddr) && (ip->daddr == cip->daddr)) {
      ctcp = inet_get_tcp(cip);
      if ((tcp->source == ctcp->source) && (tcp->dest == ctcp->dest)){
        return c;
      }
    }
  }
  return NULL;
}

static bool _ws_send_ip_packet(struct mg_connection* c, struct iphdr* ip, uint32_t offset) {
  struct conn_userdata *ud = (struct conn_userdata*)(c + 1);
  uint32_t tot_len = ntohs(ip->tot_len);
 
  memcpy(&ud->ip, ip, offset); // save ip tcp/udp head
  if (tot_len > offset) {
    bool rv = false;
    if (!ud->is_ws_sent) {
      ud->is_ws_sent = 1;

      /**
       * https://xtls.github.io/development/protocols/vless.html
       * 1 字节        16 字节         1 字节            M 字节       1 字节    2 字节    1 字节    S 字节    X 字节
       * 协议版本    等价 UUID    附加信息长度 M    附加信息ProtoBuf    指令        端口      地址类型    地址    请求数据
      */
      uint8_t* tbuf = (uint8_t*)malloc(26 + tot_len - offset);
      if (tbuf != NULL) {
        tbuf[0] = 0x01;
        memcpy(tbuf + 1, ((struct mgr_userdata*)c->mgr->userdata)->vlguid, 16);
        tbuf[17] = 0x00;
        tbuf[18] = ((&ud->ip)->protocol == IPPROTO_TCP)? 0x01 : 0x02; // cmd: 1-TCP, 2-UDP, 3-MUX
        *((uint16_t*)(tbuf + 19)) = (inet_get_tcp(ip))->dest;
        tbuf[21] = 0x01; // addrType: 1-IPV4, 2-domain, ipv6
        *((uint32_t*)(tbuf + 22)) = ip->daddr;

        memcpy(tbuf + 26, ((uint8_t*)ip) + offset, tot_len - offset);
        rv = mg_ws_send(c, tbuf, 26 + tot_len - offset, WEBSOCKET_OP_BINARY);
        free(tbuf);
      }
    }
    else {
      rv = mg_ws_send(c, ((uint8_t*)ip) + offset, tot_len - offset, WEBSOCKET_OP_BINARY);
    }
    return rv;
  }
  return false;
}

static void do_ip_packet(struct mg_connection* c, struct iphdr* ip) {
  if (ip->version == 4) { // 只处理Ipv4
    uint8_t* dst = (uint8_t*)&(ip->daddr);
    if ((dst[0] == 10) || ((dst[0] == 192) && (dst[1] == 168)) || ((dst[0] == 172) && ((dst[1] & 0xF0) == 0x10))) {
      // 内网IP地址
    }
    else if (((dst[0] == 224) && (dst[1] == 0) && (dst[2] == 0)) || (dst[0] == 239)) {
      // 预留的组播地址 | 本地管理组播地址
    }
    else if (ip->protocol == IPPROTO_TCP) {
      struct tcphdr* tcp = inet_get_tcp(ip);
      uint32_t tot_len = ntohs(ip->tot_len);
      uint32_t offset = (ip->ihl + tcp->doff) << 2;

      if (((struct mgr_userdata*)c->mgr->userdata)->is_hexdumping) {
        MG_INFO(("\n-- tcp %s:%d <- %s:%d %d=%d+%d", inet_ntoa(*((struct in_addr*)&ip->daddr)), ntohs(tcp->dest), "", ntohs(tcp->source), tot_len, offset, tot_len - offset));
        mg_hexdump(ip, tot_len);
      }

      struct mg_connection* nc = _ws_find_conn(c->mgr, ip);
      if (nc == NULL) {
        if (tcp->syn) {
          nc = mg_ws_connect(c->mgr, ((struct mgr_userdata*)c->mgr->userdata)->vlurl, ws_fn, NULL, NULL);
        }
        else {
          MG_DEBUG(("<-tcp=%d syn=%d, ack=%d, fin=%d, seq=0x%x, ack_seq=0x%x, len=0x%x", 0, tcp->syn, tcp->ack, tcp->fin, ntohl(tcp->seq), ntohl(tcp->ack_seq), tot_len - offset));
          //uint8_t ret_buf[40];
          //tcp->fin = 1;
          //_make_ip_header(ip, (struct iphdr*)ret_buf, 40);
          //_make_tcp_header(tcp, (struct tcphdr*)(ret_buf + 20), tcp->ack_seq, NULL, 0); // ack
          //if (((struct mgr_userdata*)c->mgr->userdata)->is_hexdumping) {
          //  mg_hexdump(ret_buf, 40);
          //}
          //_tcp_send_ip_packet(c, (struct iphdr*)ret_buf, NULL, 0);
          return;
        }
      }
      MG_DEBUG(("<-tcp=%d syn=%d, ack=%d, fin=%d, seq=0x%x, ack_seq=0x%x, len=0x%x", nc->id, tcp->syn, tcp->ack, tcp->fin, ntohl(tcp->seq), ntohl(tcp->ack_seq), tot_len - offset));

      struct conn_userdata* ud = (struct conn_userdata*)(nc + 1);
      bool rv =_ws_send_ip_packet(nc, ip, offset);
      
      if (rv && tcp->seq != ud->ack_seq) {
        MG_ERROR(("<-tcp=%d off=%d seq incorrect!!!", nc->id, offset));
      }
      if (tcp->ack && (tcp->doff > 5) && (tcp->ack_seq != ud->seq)) {
        MG_ERROR(("<-tcp=%d off=%d ack_seq incorrect!!!", nc->id, offset)); // TODO:
#if TUN2VLESS_CACHE_ON
        //if (ud->is_ack_nack == 2) {
          //ud->is_ack_nack = 0;
          struct icacheitem* item = icache_find(&ud->icctx, tcp->ack_seq);
          if (item != NULL) {
            uint8_t ret_buf[40];
            _make_ip_header(ip, (struct iphdr*)ret_buf, 40 + item->len);
            _make_tcp_header(MAKE_TCP_HEADER_OP_RESEND, tcp, (struct tcphdr*)(ret_buf + 20), ud, item->data, item->len); // ack + data

            _tcp_send_ip_packet(nc, (struct iphdr*)ret_buf, item->data, item->len);
          }
        //}
#endif
      }
      else if (rv || tcp->fin ){
        uint8_t ret_buf[40];
        _make_ip_header(ip, (struct iphdr*)ret_buf, 40);
        _make_tcp_header(0, tcp, (struct tcphdr*)(ret_buf + 20), ud, NULL, 0); // ack
       
        _tcp_send_ip_packet(nc, (struct iphdr*)ret_buf, NULL, 0);

        if (tcp->fin){
          // send data ...

          _make_ip_header(ip, (struct iphdr*)ret_buf, 40);
          _make_tcp_header(MAKE_TCP_HEADER_OP_FIN, tcp, (struct tcphdr*)(ret_buf + 20), ud, NULL, 0); // fin

          _tcp_send_ip_packet(nc, (struct iphdr*)ret_buf, NULL, 0);
          mg_close_conn(nc);
        }
      }
    }
    else if (ip->protocol == IPPROTO_UDP) {
      struct udphdr* udp = inet_get_udp(ip);
      uint32_t tot_len = ntohs(ip->tot_len);
      uint32_t offset = (ip->ihl + 2) << 2;

      if (((struct mgr_userdata*)c->mgr->userdata)->is_hexdumping) {
        MG_INFO(("\n-- udp %s:%d <- %s:%d %d=%d+%d", inet_ntoa(*((struct in_addr*)&ip->daddr)), ntohs(udp->dest), "", ntohs(udp->source), tot_len, offset, tot_len - offset));
        mg_hexdump(ip, tot_len);
      }

      struct mg_connection* nc = _ws_find_conn(c->mgr, ip);
      if (nc == NULL) {
        nc = mg_ws_connect(c->mgr, ((struct mgr_userdata*)c->mgr->userdata)->vlurl, ws_fn, NULL, NULL);
      }
      // TODO: 
    }
  }
}

static void tcp_fn(struct mg_connection* c, int ev, void* ev_data) {
  if (ev == MG_EV_OPEN) {
    //c->is_hexdumping = 1;
    if (c->is_listening) {
      ((struct mgr_userdata*)c->mgr->userdata)->tcpport = ntohs(c->loc.port);
    }
    else { // accepted
      ((struct mgr_userdata*)c->mgr->userdata)->tcpc = c;
      // 关闭listen的socket
      mg_close_conn(c->mgr->conns->next);
    }
  }
  else if (ev == MG_EV_READ) {
    // IP报文
    while (1) {
      struct iphdr* ip = (struct iphdr*)c->recv.buf;
      uint16_t tot_len = ntohs(ip->tot_len);
      if ((tot_len >= 20) && (c->recv.len >= tot_len)) {
        do_ip_packet(c, ip);
        c->recv.len -= tot_len;
        if (c->recv.len > 0) {
          memmove(c->recv.buf, c->recv.buf + tot_len, c->recv.len);
          continue;
        }
      }
      break;
    }
  }
  else if ((ev == MG_EV_CLOSE) || (ev == MG_EV_ERROR)) {
    if (c->is_accepted) {
      *(bool*)c->fn_data = true;  // Signal that we're done
    }
  }
}

static void* thread_function(void* param) {
  bool done = false;        // Event handler flips it to true
  struct mg_mgr mgr;
  mg_mgr_init(&mgr);
  mgr.userdata = param;
  mgr.extraconnsize = sizeof(struct conn_userdata); // save ip head
  mg_listen(&mgr, ((struct mgr_userdata*)param)->tcpsvr, tcp_fn, &done);
  while (!done) {
    mg_mgr_poll(&mgr, 10000);
  }
  mg_mgr_free(&mgr);
  return NULL;
}


static void _get_opts(int argc, char* argv[], const char* names[], char* outs[]) {
  for (int i = 0; i < (argc - 1); i++) {
    for (int j = 0; names[j]; j++) {
      if (lstrcmpA(argv[i], names[j]) == 0) {
        outs[j] = argv[++i];
      }
    }
  }
}

int main(int argc, char* argv[]) {
#if (TUN2VLESS_MAIN_MODE == 1)
  return tun_main(argc, argv, 55551);
#else
  const char* ParamNames[] = { "-loglevel", "-tcpsvr", "-vlurl", "-vlguid", NULL };
  char* ParamVals[5] = { NULL, "tcp://127.0.0.1", NULL, NULL, NULL };
  _get_opts(argc, argv, ParamNames, ParamVals);
 
  if ((ParamVals[2] == NULL) || (ParamVals[3] == NULL)) {
    printf("usage: -vlurl xx -vlguid xx\n");
    return 1;
  }

  // 日志设置
  if (ParamVals[0]) {
    mg_log_set(atoi(ParamVals[0])); // MG_LL_VERBOSE
  }

  struct mgr_userdata ud = { .tcpsvr = ParamVals[1], .vlurl = ParamVals[2] };
  mg_base64_decode(ParamVals[3], strlen(ParamVals[3]), ud.vlguid, sizeof(ud.vlguid));
 #if(TUN2VLESS_MAIN_MODE == 2)
  ud.is_hexdumping = mg_log_level >= MG_LL_DEBUG;
  thread_function(&ud);
  return 0;
#endif

  MG_INFO(("main argc=%d\n", argc));

  start_thread(thread_function, &ud);

  usleep(100000);

  int ret = tun_main(argc, argv, ud.tcpport); 
  MG_INFO(("tun_main ret=%d\n", ret));

  usleep(100000);
  return ret;
#endif
}
