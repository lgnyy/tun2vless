
#pragma once

#include <memory.h>
#include <stdint.h>

#ifndef ICACHE_MAX_ITEM_COUNT
#define ICACHE_MAX_ITEM_COUNT 10
#endif
#ifndef ICACHE_MAX_BUFFER_SIZE
#define ICACHE_MAX_BUFFER_SIZE 0x4000
#endif

struct icacheitem {
  uint32_t seq;
  uint32_t len;
  void* data;
};
struct icachectx {
  uint32_t item_offset;
  uint32_t buffer_offset;
  struct icacheitem items[ICACHE_MAX_ITEM_COUNT];
  char buffer[ICACHE_MAX_BUFFER_SIZE];
};

static void icache_add(struct icachectx* ctx, uint32_t seq, const void* data, uint32_t len) {
  struct icacheitem* item = ctx->items + ctx->item_offset;
  item->seq = seq;
  item->len = len;
  if ((ICACHE_MAX_BUFFER_SIZE - ctx->buffer_offset) >= len) {
    item->data = ctx->buffer + ctx->buffer_offset;
    memcpy(ctx->buffer + ctx->buffer_offset, data, len);
    ctx->buffer_offset += len;
  }
  else if (len <= ICACHE_MAX_BUFFER_SIZE){
    item->data = ctx->buffer;
    memcpy(ctx->buffer, data, len);
    ctx->buffer_offset = len;
  }

  if (++(ctx->item_offset) == ICACHE_MAX_ITEM_COUNT) {
    ctx->item_offset = 0;
  };
}

static struct icacheitem* icache_find(struct icachectx* ctx, uint32_t seq) {
  uint32_t i;
  for (i = 0; i < ICACHE_MAX_ITEM_COUNT; i++) {
    if (ctx->items[i].seq == seq) {
      return ctx->items + i;
    }
  }
  return NULL;
}
