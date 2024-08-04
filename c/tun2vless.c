
#include "./mongoose/src/event.h"
#include "./mongoose/src/http.h"
#include "./mongoose/src/ws.h"
#include "./mongoose/src/tls.h"
#include "./mongoose/src/url.h"
#include "./mongoose/src/base64.h"
#include "./mongoose/src/log.h"

#include <lwip/sys.h>
#include <lwip/init.h>
#include <lwip/tcp.h>
#include <lwip/udp.h>
#include <lwip/nd6.h>
#include <lwip/netif.h>
#include <lwip/ip4_frag.h>
#include <lwip/ip6_frag.h>
#include <lwip/priv/tcp_priv.h>


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
  const char* tcpsvr; // pipe: vless or socks5 <-> tun
  const char* socks5; // tcp://address:port
  const char* vlurl; // vless url
  uint8_t vlguid[16+4]; // base64
  uint16_t tcpport; // 0: 随机端口
  uint16_t is_hexdumping : 1; // 
  uint16_t is_hexdumping_socks5 : 1;
  uint16_t flags_rfu : 14;
  struct mg_connection* c_pipe;

  struct netif netif; // lwip
  struct tcp_pcb* tcp;
  struct udp_pcb* udp;
};

struct conn_userdata {
  uint32_t is_proxy_opened : 1; // 代理进入交换数据状态
  uint32_t is_proxy_closed : 1; // rfu
  uint32_t is_ws_opened : 1;
  uint32_t is_ws_sent : 1; // rfu
  uint32_t is_ws_received : 1;
  uint32_t is_socks_agreement : 1;
  uint32_t is_socks_authentication : 1; // rfu
  uint32_t is_socks_request : 1;
  uint32_t flags_rfu : 8;
  uint32_t dest_port; // 目的端口
  ip_addr_t dest_addr; // 目的IP
  uint64_t at_ping; // 
  struct pbuf* queue; // 缓存待发数据（在代理为建立前）
  struct tcp_pcb* tcp;
  struct udp_pcb* udp;
  size_t ring_buf_wp; // 环形缓冲区-写位置
  size_t ring_buf_max_size; // 环形缓冲区-最大长度
  uint8_t* ring_buf_ptr; // 环形缓冲区
};
#define get_mgr_ud(mgr) ((struct mgr_userdata*)(((struct mg_mgr*)(mgr))->userdata))


static size_t _proxy_send(struct mg_connection* c, const uint8_t* buf, size_t len);
// 进入代理状态，处理待发送数据
static void _proxy_open(struct mg_connection* c) {
  struct conn_userdata* ud = (struct conn_userdata*)(c + 1);
  struct pbuf* p;

  ud->is_proxy_opened = 1;

  for (p = ud->queue; p; p = p->next) {
    _proxy_send(c, p->payload, p->len);
  }

  //pbuf_free_header(ud->queue, ud->queue->tot_len);
  ud->queue = NULL;
}
// 关闭代理（tcp/udp），释放资源，标记待关闭的连接
static void _proxy_close(struct mg_connection* c) {
  struct conn_userdata* ud = (struct conn_userdata*)(c + 1);
  ud->is_proxy_closed = 1;
  if (ud->tcp != NULL) {
    tcp_recv(ud->tcp, NULL);
    tcp_sent(ud->tcp, NULL);
    tcp_err(ud->tcp, NULL);
    tcp_abort(ud->tcp);
    ud->tcp = NULL;
  }
  if (ud->udp != NULL) {
    udp_recv(ud->udp, NULL, NULL);
    udp_remove(ud->udp);
    ud->udp = NULL;
  }
  if (ud->ring_buf_ptr != NULL) {
    free(ud->ring_buf_ptr);
    ud->ring_buf_ptr = NULL;
  }
  c->is_closing = 1;
}

// 代理发送
static size_t _proxy_send(struct mg_connection* c, const uint8_t* buf, size_t len) {
  struct conn_userdata* ud = (struct conn_userdata*)(c + 1);
  size_t rv;

  if (get_mgr_ud(c->mgr)->is_hexdumping) {
    MG_INFO(("\n--%d proxy_send from tcp pcb=%p or udp pcb=%p, len=%d", c->id, ud->tcp, ud->udp, len));
    mg_hexdump(buf, len);
  }

  if (c->is_websocket) {
    rv = mg_ws_send(c, buf, len, WEBSOCKET_OP_BINARY);
  }
  else {
    rv = mg_send(c, buf, len)? len : 0;
  }

  if (rv < len) {
    MG_ERROR(("[%d]mg_ws_send error rv=%d", c->id, rv));
  }

  if (ud->tcp != NULL) {
    tcp_recved(ud->tcp, (u16_t)len);
  }
  return rv;
}

// 代理接收转发
static void _proxy_msg(struct mg_connection* c, const char* data_ptr, size_t data_len) {
  struct conn_userdata* ud = (struct conn_userdata*)(c + 1);

  if (get_mgr_ud(c->mgr)->is_hexdumping) {
    MG_INFO(("\n-- %d proxy_msg to tcp pcb=%p or udp pcb=%p, data_len=%d", c->id, ud->tcp, ud->udp, data_len));
    mg_hexdump(data_ptr, data_len);
  }

  if (ud->tcp) {
    err_t err;
    size_t spc_size = ud->ring_buf_max_size - ud->ring_buf_wp;

    if (data_len < spc_size)
    {
      memcpy(ud->ring_buf_ptr + ud->ring_buf_wp, data_ptr, data_len);
      err = tcp_write(ud->tcp, ud->ring_buf_ptr + ud->ring_buf_wp, (u16_t)data_len, 0);
      ud->ring_buf_wp += data_len;
    }
    else
    {
     if (spc_size > 0) {
        memcpy(ud->ring_buf_ptr + ud->ring_buf_wp, data_ptr, spc_size);
        err = tcp_write(ud->tcp, ud->ring_buf_ptr + ud->ring_buf_wp, (u16_t)spc_size, 0);
      }
      else {
        err = 0;
      }
      memcpy(ud->ring_buf_ptr, data_ptr + spc_size, data_len - spc_size);
      err |= tcp_write(ud->tcp, ud->ring_buf_ptr, (u16_t)(data_len - spc_size), 0);
      ud->ring_buf_wp = data_len - spc_size;
    }

    if (err != ERR_OK) {
      MG_ERROR(("[%d]tcp_write error pcb=%p, rv=%d", c->id, ud->tcp, err));
    }
    err = tcp_output(ud->tcp);
    if (err != ERR_OK) {
      MG_ERROR(("[%d]tcp_output error pcb=%p, rv=%d", c->id, ud->tcp, err));
    }
  }
  else if (ud->udp) {
    struct pbuf* buf = pbuf_alloc(PBUF_TRANSPORT, (u16_t)data_len, PBUF_RAM);
    if (buf) {
      err_t err;
      memcpy(buf->payload, data_ptr, data_len);
      buf->len = (u16_t)data_len;
      err = udp_sendfrom(ud->udp, buf, &(ud->dest_addr), ud->dest_port);
      if (err != ERR_OK) {
        MG_ERROR(("[%d]udp_send error pcb=%p, rv=%d", c->id, ud->udp, err));
      }
      pbuf_free(buf);
    }
  }
}


// wss-vless代理处理过程
static void _proxy_ws_fn(struct mg_connection* c, int ev, void* ev_data) {
  struct conn_userdata* ud = (struct conn_userdata*)(c + 1);

  if (ev == MG_EV_OPEN) {
    //c->is_hexdumping = ((struct mgr_userdata*)c->mgr->userdata)->is_hexdumping;
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
    ud->is_ws_opened = 1;
    ud->at_ping = mg_millis();
  }
  else if (ev == MG_EV_WS_MSG) {
    // When we get echo response, print it
    struct mg_ws_message* msg = (struct mg_ws_message*)ev_data;
    if (!ud->is_ws_received) {
      ud->is_ws_received = 1;
      // 2: version
      _proxy_msg(c, msg->data.buf+2, msg->data.len-2);
    }
    else {
      _proxy_msg(c, msg->data.buf, msg->data.len);
    }
  }
  else if (ev == MG_EV_POLL) {
    uint64_t ms = mg_millis();
    if (ms > (ud->at_ping + 6000)) {
      ud->at_ping = ms;
      mg_ws_send(c, "PING", 4, WEBSOCKET_OP_PING);
    }
  }

  if (ev == MG_EV_ERROR || ev == MG_EV_CLOSE) {
    c->is_tls_hs = 0;
    mg_tls_free(c);
    _proxy_close(c);
  }
  else {
    if (ud->is_ws_opened && !(ud->is_proxy_opened) && ud->queue != NULL) {
      struct pbuf* p = ud->queue;
     
      if (get_mgr_ud(c->mgr)->is_hexdumping) {
        MG_INFO(("\n--%d proxy_send0 from tcp pcb=%p or udp pcb=%p, len=%d", c->id, ud->tcp, ud->udp, p->len));
        mg_hexdump(p->payload, p->len);
      }

      /**
        * https://xtls.github.io/development/protocols/vless.html
        * 1 字节        16 字节         1 字节            M 字节       1 字节    2 字节    1 字节    S 字节    X 字节
        * 协议版本    等价 UUID    附加信息长度 M    附加信息ProtoBuf    指令        端口      地址类型    地址    请求数据
      */
      uint8_t* tbuf = (uint8_t*)malloc(26 + p->len);
      if (tbuf != NULL) {
        tbuf[0] = 0x01;
        memcpy(tbuf + 1, ((struct mgr_userdata*)c->mgr->userdata)->vlguid, 16);
        tbuf[17] = 0x00;
        tbuf[18] = (ud->tcp != NULL)? 0x01 : 0x02; // cmd: 1-TCP, 2-UDP, 3-MUX
        *((uint16_t*)(tbuf + 19)) = htons(ud->dest_port);
        tbuf[21] = 0x01; // addrType: 1-IPV4, 2-domain, ipv6
        *((uint32_t*)(tbuf + 22)) = ip_2_ip4(&(ud->dest_addr))->addr;        

        memcpy(tbuf + 26, p->payload, p->len);
        mg_ws_send(c, tbuf, 26 + p->len, WEBSOCKET_OP_BINARY);
        free(tbuf);

        if (ud->tcp != NULL) {
          tcp_recved(ud->tcp, (u16_t)(p->len));
        }
      }

      ud->queue = p->next;
      _proxy_open(c);
    }
  }
}

// socks5代理处理过程
static void _proxy_socks5_fn(struct mg_connection* c, int ev, void* ev_data) {
  if (ev == MG_EV_OPEN) {
    c->is_hexdumping = ((struct mgr_userdata*)c->mgr->userdata)->is_hexdumping_socks5;
  }
  else if (ev == MG_EV_CONNECT) {
    mg_send(c, "\x05\x01\x00", 3); // VER | NMETHODS | METHODS 
  }
  else if (ev == MG_EV_READ) {
    struct conn_userdata* ud = (struct conn_userdata*)(c + 1);
    if (ud->is_proxy_opened) {
      _proxy_msg(c, c->recv.buf, c->recv.len);
      c->recv.len = 0;
    }
    else {
      uint8_t tbuf[64];
      if (!(ud->is_socks_agreement)) {
        // VER | METHOD
        if ((c->recv.len >= 2) && (c->recv.buf[0] == 0x05) && (c->recv.buf[1] == 0x00)) {
          ud->is_socks_agreement = 1;
          mg_iobuf_del(&(c->recv), 0, 2);

          // VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT 
          tbuf[0] = 0x05;
          tbuf[1] = (ud->tcp)? 0x01 : 0x03; // 0x01表示CONNECT请求, 0x02表示BIND请求, 0x03表示UDP转发
          tbuf[2] = 0x00;
          tbuf[3] = 0x01; // 0x01表示IPv4地址，0x03表示域名， 0x04表示IPv6地址
          *((uint32_t*)(tbuf + 4)) = ip_2_ip4(&(ud->dest_addr))->addr;
          *((uint16_t*)(tbuf + 8)) = htons(ud->dest_port);
          mg_send(c, tbuf, 10);
        }
      }
      else if (!(ud->is_socks_request)) {
        // VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT
        if ((c->recv.len >= 10) && (c->recv.buf[0] == 0x05) && (c->recv.buf[1] == 0x00)) {
          size_t addr_len = (c->recv.buf[3] == 0x01) ? 4 : ((c->recv.buf[3] == 0x03) ? (1 + c->recv.buf[4]) : 16);
          if ((6 + addr_len) <= c->recv.len) {
            struct pbuf* p = ud->queue;

            ud->is_socks_request = 1;
            mg_iobuf_del(&(c->recv), 0, 6+ addr_len);

            _proxy_open(c);
          }
        }
      }
    }
  }

  if (ev == MG_EV_ERROR || ev == MG_EV_CLOSE) {
    _proxy_close(c);
  }
}


// 管道（与tun之间数据交互）处理过程
static void pipe_tcp_fn(struct mg_connection* c, int ev, void* ev_data) {
  if (ev == MG_EV_OPEN) {
    c->is_hexdumping = ((struct mgr_userdata*)c->mgr->userdata)->is_hexdumping;
    if (c->is_listening) {
      ((struct mgr_userdata*)c->mgr->userdata)->tcpport = ntohs(c->loc.port);
    }
    else { // accepted
      ((struct mgr_userdata*)c->mgr->userdata)->c_pipe = c;
      // 关闭listen的socket
      mg_close_conn(c->mgr->conns->next);
    }
  }
  else if (ev == MG_EV_READ) {
    // IP报文
    struct pbuf* buf;
    struct netif* netif = &(((struct mgr_userdata*)c->mgr->userdata)->netif);

    buf = pbuf_alloc(PBUF_RAW, (u16_t)(c->recv.len), PBUF_RAM);
    if (!buf) {
      MG_ERROR(("tcp tunnel alloc"));
      pbuf_free(buf);
      return;
    }

    memcpy(buf->payload, c->recv.buf, c->recv.len);
    buf->len = (u16_t)(c->recv.len);
    if (netif->input(buf, netif) != ERR_OK) {
      MG_ERROR(("tcp tunnel netif->input error"));
      pbuf_free(buf);
    }

    c->recv.len = 0;
  }
  else if ((ev == MG_EV_CLOSE) || (ev == MG_EV_ERROR)) {
    if (c->is_accepted) {
      *(bool*)c->fn_data = true;  // Signal that we're done
    }
  }
}

// 以下为netif相关函数，基于lwip实现
static err_t netif_output_handler(struct netif* netif, struct pbuf* p){
  ssize_t s =0;
  struct mg_connection* c = get_mgr_ud(netif->state)->c_pipe;
  
  for (; p; p = p->next) {
#if 0
    if (c->is_hexdumping) {
      MG_INFO(("\n-- %d -> %d", c->id, p->len));
      mg_hexdump(p->payload, p->len);
    }
#endif
    if ((((uint8_t *)(p->payload))[0] != 0x60) && c && mg_send(c, p->payload, p->len)) {
      s += p->len;
    }
  }

  if (s <= 0) {
    MG_ERROR(("tcp tunnel write error, s=%d", s));
    return ERR_IF;
  }

  //stat_rx_packets++;
  //stat_rx_bytes += s;

  return ERR_OK;
}

static err_t netif_output_v4_handler(struct netif* netif, struct pbuf* p, const ip4_addr_t* ipaddr){
  return netif_output_handler(netif, p);
}
#if LWIP_IPV6
static err_t netif_output_v6_handler(struct netif* netif, struct pbuf* p, const ip6_addr_t* ipaddr){
  return netif_output_handler(netif, p);
}
#endif
static err_t netif_init_handler(struct netif* netif){
  netif->output = netif_output_v4_handler;
#if LWIP_IPV6
  netif->output_ip6 = netif_output_v6_handler;
#endif
  return ERR_OK;
}

static err_t lwip_tcp_recv_handler(void* arg, struct tcp_pcb* pcb, struct pbuf* p, err_t err){
  struct mg_connection* c = (struct mg_connection*)arg;
  struct conn_userdata* ud = (struct conn_userdata*)(c + 1);

  if (!p) {
    _proxy_close(c);
    return ERR_OK;
  }

  MG_INFO(("%d tcp pcb=%p, ud->is_proxy_opened=%d, ud->queue=%p", c->id, pcb, ud->is_proxy_opened, ud->queue));

  if (!ud->is_proxy_opened) {
    if (!ud->queue) {
      ud->queue = p;
    }
    else {
      if (ud->queue->tot_len > TCP_WND_MAX(pcb))
        return ERR_WOULDBLOCK;
      pbuf_cat(ud->queue, p);
    }
    return ERR_OK;
  }
  else {
    for (; p; p = p->next) {
      _proxy_send(c, p->payload, p->len);
    }
    return ERR_OK;
  }
}

static void lwip_tcp_err_handler(void* arg, err_t err){
  struct mg_connection* c = (struct mg_connection*)arg;

  _proxy_close(c);
}

static err_t lwip_tcp_accept_handler(void* arg, struct tcp_pcb* pcb, err_t err){
  struct mg_connection* nc;
  struct conn_userdata* ud;

  if (err != ERR_OK) {
    return err;
  }

  if (get_mgr_ud(arg)->socks5 != NULL) {
    nc = mg_connect((struct mg_mgr*)arg, get_mgr_ud(arg)->socks5, _proxy_socks5_fn, NULL);
  }
  else {
    nc = mg_ws_connect((struct mg_mgr*)arg, get_mgr_ud(arg)->vlurl, _proxy_ws_fn, NULL, NULL);
  }
  if (nc == NULL) {
    return ERR_MEM;
  }
  ud = (struct conn_userdata*)(nc + 1);
  ud->dest_port = pcb->local_port;
  ip_addr_set_ipaddr(&ud->dest_addr, &pcb->local_ip);
  ud->tcp = pcb;
  ud->ring_buf_wp = 0;
  ud->ring_buf_max_size = tcp_sndbuf(pcb);
  ud->ring_buf_ptr = (uint8_t*)malloc(ud->ring_buf_max_size);
  MG_INFO(("%d mg_[ws_]connect tcp pcb=%p, ud->ring_buf_max_size=%d", nc->id, pcb, ud->ring_buf_max_size));

  tcp_arg(pcb, nc);
  tcp_recv(pcb, lwip_tcp_recv_handler);
  //tcp_sent(pcb, lwip_tcp_sent_handler);
  tcp_err(pcb, lwip_tcp_err_handler);

  return ERR_OK;
}

static void lwip_udp_recv_handler(void* arg, struct udp_pcb* pcb, struct pbuf* p, const ip_addr_t* addr, u16_t port) {
  struct mg_connection* c = (struct mg_connection*)arg;
  struct conn_userdata* ud = (struct conn_userdata*)(c + 1);

  if (!p) {
    _proxy_close(c);
    return;
  }

  MG_INFO(("%d udp pcb=%p, ud->is_proxy_opened=%d, ud->queue=%p", c->id, pcb, ud->is_proxy_opened, ud->queue));

  if (ud->dest_port == 0) {
    ud->dest_port = pcb->local_port;
    ip_addr_set_ipaddr(&ud->dest_addr, &pcb->local_ip);
  }

  if (!ud->is_proxy_opened) {
    if (!ud->queue) {
      ud->queue = p;
    }
    else {
      pbuf_cat(ud->queue, p);
    }
  }
  else {
    for (; p; p = p->next) {
      _proxy_send(c, p->payload, p->len);
    }
  }
}

static void lwip_udp_accept_handler(void* arg, struct udp_pcb* pcb, struct pbuf* p, const ip_addr_t* addr, u16_t port) {
  struct mg_connection* nc;
  struct conn_userdata* ud;

  MG_DEBUG(("pcb=%p, p=%p, addr=%p, port=%d", pcb, p, addr, port));
  if (p) return;

  if (get_mgr_ud(arg)->socks5 != NULL) {
    nc = mg_connect((struct mg_mgr*)arg, get_mgr_ud(arg)->socks5, _proxy_socks5_fn, NULL);
  }
  else {
    nc = mg_ws_connect((struct mg_mgr*)arg, get_mgr_ud(arg)->vlurl, _proxy_ws_fn, NULL, NULL);
  }
  if (nc == NULL) {
    return;
  }
  ud = (struct conn_userdata*)(nc + 1);
  ud->udp = pcb;
  MG_INFO(("%d mg_[ws_]connect tcp pcb=%p, ud->ring_buf_max_size=%d", nc->id, pcb, ud->ring_buf_max_size));

  udp_recv(pcb, lwip_udp_recv_handler, nc);
}

static int lwip_gateway_init(struct mg_mgr* mgr){
  struct netif* netif = &(get_mgr_ud(mgr)->netif);
  struct tcp_pcb* tcp = get_mgr_ud(mgr)->tcp;
  struct udp_pcb* udp = get_mgr_ud(mgr)->udp;
  ip4_addr_t addr4, mask, gw;
#if LWIP_IPV6
  ip6_addr_t addr6;
#endif
  netif_add_noaddr(netif, mgr, netif_init_handler, ip_input);

  ip4_addr_set_loopback(&addr4);
  ip4_addr_set_any(&mask);
  ip4_addr_set_any(&gw);
  netif_set_addr(netif, &addr4, &mask, &gw);
#if LWIP_IPV6
  ip6_addr_set_loopback(&addr6);
  netif_add_ip6_address(netif, &addr6, NULL);
#endif
  netif_set_up(netif);
  netif_set_link_up(netif);
  netif_set_default(netif);
  netif_set_flags(netif, NETIF_FLAG_PRETEND_TCP);

  tcp = tcp_new_ip_type(IPADDR_TYPE_ANY);
  tcp_bind_netif(tcp, netif);
  tcp_bind(tcp, NULL, 0);
  tcp = tcp_listen(tcp);
  tcp_arg(tcp, mgr);
  tcp_accept(tcp, lwip_tcp_accept_handler);

  udp = udp_new_ip_type(IPADDR_TYPE_ANY);
  udp_bind_netif(udp, netif);
  udp_bind(udp, NULL, 0);
  udp_recv(udp, lwip_udp_accept_handler, mgr);

  return 0;
}

static void lwip_gateway_fini(struct mg_mgr* mgr){
  struct netif* netif = &(get_mgr_ud(mgr)->netif);
  struct tcp_pcb* tcp = get_mgr_ud(mgr)->tcp;
  struct udp_pcb* udp = get_mgr_ud(mgr)->udp;

  udp_remove(udp);
  tcp_close(tcp);
  netif_remove(netif);
}

static void lwip_timer_fn(void* arg) {
  static unsigned int i = 0;
  tcp_tmr();

  if (((++i) & 3) == 0) {
#if IP_REASSEMBLY
    ip_reass_tmr();
#endif
//#if LWIP_IPV6
//    nd6_tmr();
//#if LWIP_IPV6_REASS
//    ip6_reass_tmr();
//#endif
//#endif
  }
}

// 工作线程
static void* thread_function(void* param) {
  bool done = false;        // Event handler flips it to true
  struct mg_mgr mgr;
  mg_mgr_init(&mgr);
  mgr.userdata = param;
  mgr.extraconnsize = sizeof(struct conn_userdata); // save ud
  sys_init();
  lwip_init();
  lwip_gateway_init(&mgr);
  mg_timer_add(&mgr, TCP_TMR_INTERVAL, MG_TIMER_REPEAT, lwip_timer_fn, &mgr); // interval
  mg_listen(&mgr, ((struct mgr_userdata*)param)->tcpsvr, pipe_tcp_fn, &done);
  while (!done) {
    mg_mgr_poll(&mgr, 50);
  }
  lwip_gateway_fini(&mgr);
  mg_mgr_free(&mgr);
  return NULL;
}

// 解析main的输入参数
static void _get_opts(int argc, char* argv[], const char* names[], char* outs[]) {
  for (int i = 0; i < (argc - 1); i++) {
    for (int j = 0; names[j]; j++) {
      if (strcmp(argv[i], names[j]) == 0) {
        outs[j] = argv[++i];
      }
    }
  }
}

// 程序入口，支持双进程编译（#define TUN2VLESS_MAIN_MODE  0// 1-TUN, 2-VLESS）
int main(int argc, char* argv[]) {
#if (TUN2VLESS_MAIN_MODE == 1)
  return tun_main(argc, argv, 55551);
#else
  const char* ParamNames[] = { "-loglevel", "-tcpsvr", "-vlurl", "-vlguid", "-socks5", NULL };
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

  struct mgr_userdata ud = { .tcpsvr = ParamVals[1], .vlurl = ParamVals[2], .socks5 = ParamVals[4] };
  mg_base64_decode(ParamVals[3], strlen(ParamVals[3]), ud.vlguid, sizeof(ud.vlguid));
  ud.is_hexdumping = mg_log_level > MG_LL_DEBUG;
  //ud.is_hexdumping_socks5 = 1;

#if(TUN2VLESS_MAIN_MODE == 2)
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
