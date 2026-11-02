#include "lab.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

static bool ip_parse_range(const char *start, const char *end, uint32_t *addr)
{
  uint32_t parsed = 0;
  const char *cursor = start;

  for (unsigned int octet_index = 0; octet_index < 4; octet_index++)
  {
    if (cursor == end || *cursor < '0' || *cursor > '9')
    {
      return false;
    }

    if (*cursor == '0' && cursor + 1 < end && cursor[1] >= '0' && cursor[1] <= '9')
    {
      return false;
    }

    unsigned int octet = 0;
    unsigned int digit_count = 0;
    while (cursor < end && *cursor >= '0' && *cursor <= '9')
    {
      if (digit_count == 3)
      {
        return false;
      }

      octet = octet * 10U + (unsigned int)(*cursor - '0');
      if (octet > 255U)
      {
        return false;
      }

      digit_count++;
      cursor++;
    }

    parsed = (parsed << 8) | octet;
    if (octet_index < 3)
    {
      if (cursor == end || *cursor != '.')
      {
        return false;
      }
      cursor++;
    }
    else if (cursor != end)
    {
      return false;
    }
  }

  *addr = parsed;
  return true;
}

bool ip_parse(const char *text, uint32_t *addr)
{
  if (text == NULL || addr == NULL)
  {
    return false;
  }

  const char *end = text;
  while (*end != '\0')
  {
    end++;
  }

  uint32_t parsed;
  if (!ip_parse_range(text, end, &parsed))
  {
    return false;
  }

  *addr = parsed;
  return true;
}

void ip_format(uint32_t addr, char out[IP_STR_LEN])
{
  if (out == NULL)
  {
    return;
  }

  (void)snprintf(out, IP_STR_LEN, "%u.%u.%u.%u",
                 (unsigned int)((addr >> 24) & 0xFFU),
                 (unsigned int)((addr >> 16) & 0xFFU),
                 (unsigned int)((addr >> 8) & 0xFFU),
                 (unsigned int)(addr & 0xFFU));
}

bool cidr_parse(const char *text, cidr_t *block)
{
  if (text == NULL || block == NULL)
  {
    return false;
  }

  const char *slash = text;
  while (*slash != '\0' && *slash != '/')
  {
    slash++;
  }
  if (*slash != '/')
  {
    return false;
  }

  uint32_t address;
  if (!ip_parse_range(text, slash, &address))
  {
    return false;
  }

  const char *prefix_text = slash + 1;
  if (*prefix_text == '\0' ||
      (*prefix_text == '0' && prefix_text[1] != '\0') ||
      *prefix_text < '0' || *prefix_text > '9')
  {
    return false;
  }

  unsigned int prefix = 0;
  for (const char *cursor = prefix_text; *cursor != '\0'; cursor++)
  {
    if (*cursor < '0' || *cursor > '9')
    {
      return false;
    }
    prefix = prefix * 10U + (unsigned int)(*cursor - '0');
    if (prefix > 32U)
    {
      return false;
    }
  }

  cidr_t parsed = { .addr = address, .prefix = (uint8_t)prefix };
  *block = parsed;
  return true;
}

void cidr_format(cidr_t block, char out[CIDR_STR_LEN])
{
  if (out == NULL)
  {
    return;
  }

  ip_format(block.addr, out);
  size_t used = 0;
  while (out[used] != '\0')
  {
    used++;
  }
  unsigned int prefix = block.prefix > 32U ? 32U : block.prefix;
  (void)snprintf(out + used, CIDR_STR_LEN - used, "/%u", prefix);
}

uint32_t cidr_mask(uint8_t prefix)
{
  if (prefix == 0)
  {
    return 0;
  }
  if (prefix > 32)
  {
    prefix = 32;
  }
  return UINT32_MAX << (32U - prefix);
}

uint32_t cidr_network(cidr_t block)
{
  return block.addr & cidr_mask(block.prefix);
}

uint32_t cidr_broadcast(cidr_t block)
{
  return block.addr | ~cidr_mask(block.prefix);
}

uint32_t cidr_first_host(cidr_t block)
{
  if (block.prefix >= 31)
  {
    return cidr_network(block);
  }
  return cidr_network(block) + 1U;
}

uint32_t cidr_last_host(cidr_t block)
{
  uint32_t broadcast = cidr_broadcast(block);
  if (block.prefix >= 31)
  {
    return broadcast;
  }
  return broadcast - 1U;
}

uint64_t cidr_host_count(cidr_t block)
{
  if (block.prefix >= 32)
  {
    return 1;
  }
  if (block.prefix == 31)
  {
    return 2;
  }
  return (UINT64_C(1) << (32U - block.prefix)) - 2U;
}

bool cidr_contains(cidr_t block, uint32_t addr)
{
  uint32_t mask = cidr_mask(block.prefix);
  return (addr & mask) == (block.addr & mask);
}

bool cidr_is_network(cidr_t block)
{
  return cidr_network(block) == block.addr;
}

bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out)
{
  if (out == NULL || block.prefix > 32 || !cidr_is_network(block) ||
      n == 0 || (n & (n - 1U)) != 0 || i >= n)
  {
    return false;
  }

  unsigned int borrowed = 0;
  for (uint32_t count = n; count > 1; count >>= 1)
  {
    borrowed++;
  }
  unsigned int new_prefix = (unsigned int)block.prefix + borrowed;
  if (new_prefix > 32U)
  {
    return false;
  }

  unsigned int host_bits = 32U - new_prefix;
  uint64_t subnet_size = UINT64_C(1) << host_bits;
  cidr_t subnet = {
    .addr = (uint32_t)((uint64_t)block.addr + (uint64_t)i * subnet_size),
    .prefix = (uint8_t)new_prefix
  };
  *out = subnet;
  return true;
}

bool route_parse(const char *line, route_t *route)
{
  if (line == NULL || route == NULL)
  {
    return false;
  }

  const char *end = line + strlen(line);
  while (end > line && isspace((unsigned char)end[-1]))
  {
    end--;
  }

  const char *cursor = line;
  while (cursor < end && isspace((unsigned char)*cursor))
  {
    cursor++;
  }

  const char *fields[3];
  size_t lengths[3];
  for (size_t field = 0; field < 3; field++)
  {
    if (cursor == end || *cursor == ' ' || *cursor == '\t')
    {
      return false;
    }

    fields[field] = cursor;
    while (cursor < end && *cursor != ' ' && *cursor != '\t')
    {
      cursor++;
    }
    lengths[field] = (size_t)(cursor - fields[field]);

    if (field < 2)
    {
      if (cursor == end || (*cursor != ' ' && *cursor != '\t'))
      {
        return false;
      }
      while (*cursor == ' ' || *cursor == '\t')
      {
        cursor++;
      }
    }
  }

  if (cursor != end || lengths[2] == 0 || lengths[2] >= DEV_NAME_LEN)
  {
    return false;
  }
  for (size_t index = 0; index < lengths[2]; index++)
  {
    if (isspace((unsigned char)fields[2][index]))
    {
      return false;
    }
  }

  route_t parsed = {0};
  if (lengths[0] == sizeof("default") - 1 &&
      memcmp(fields[0], "default", sizeof("default") - 1) == 0)
  {
    parsed.dest = (cidr_t){ .addr = 0, .prefix = 0 };
  }
  else
  {
    char destination[CIDR_STR_LEN];
    if (lengths[0] >= sizeof(destination))
    {
      return false;
    }
    memcpy(destination, fields[0], lengths[0]);
    destination[lengths[0]] = '\0';
    if (!cidr_parse(destination, &parsed.dest) || !cidr_is_network(parsed.dest))
    {
      return false;
    }
  }

  if (lengths[1] == sizeof("direct") - 1 &&
      memcmp(fields[1], "direct", sizeof("direct") - 1) == 0)
  {
    parsed.gateway = 0;
  }
  else
  {
    char gateway[IP_STR_LEN];
    if (lengths[1] >= sizeof(gateway))
    {
      return false;
    }
    memcpy(gateway, fields[1], lengths[1]);
    gateway[lengths[1]] = '\0';
    if (!ip_parse(gateway, &parsed.gateway))
    {
      return false;
    }
  }

  memcpy(parsed.dev, fields[2], lengths[2]);
  parsed.dev[lengths[2]] = '\0';
  *route = parsed;
  return true;
}

struct fwd_table
{
  route_t *routes;
  size_t count;
  size_t capacity;
};

static bool table_next_capacity(size_t capacity, size_t *new_capacity)
{
  size_t next = capacity == 0 ? 8 : capacity * 2;
  if (next < capacity || next > SIZE_MAX / sizeof(route_t))
  {
    return false;
  }
  *new_capacity = next;
  return true;
}

static bool table_grow(fwd_table_t *table)
{
  size_t new_capacity;
  if (!table_next_capacity(table->capacity, &new_capacity))
  {
    return false;
  }

  route_t *routes = realloc(table->routes, new_capacity * sizeof(*routes));
  if (routes == NULL)
  {
    // GCOVR_EXCL_START
    return false;
    // GCOVR_EXCL_STOP
  }

  table->routes = routes;
  table->capacity = new_capacity;
  return true;
}

static bool table_append(fwd_table_t *table, const route_t *route)
{
  if (table->count == table->capacity && !table_grow(table))
  {
    return false;
  }
  table->routes[table->count] = *route;
  table->count++;
  return true;
}

#ifdef TEST
bool lab_test_capacity_overflow(void)
{
  size_t max_routes = SIZE_MAX / sizeof(route_t);
  route_t route = { .dest = { .addr = 0, .prefix = 0 } };
  fwd_table_t table = {
    .count = SIZE_MAX / 2 + 1,
    .capacity = SIZE_MAX / 2 + 1
  };
  bool overflow_rejected = !table_append(&table, &route);
  table.count = max_routes / 2 + 1;
  table.capacity = max_routes / 2 + 1;
  return overflow_rejected && !table_append(&table, &route);
}
#endif

fwd_table_t *table_create(void)
{
  return calloc(1, sizeof(fwd_table_t));
}

void table_destroy(fwd_table_t *table)
{
  if (table != NULL)
  {
    free(table->routes);
    free(table);
  }
}

size_t table_count(const fwd_table_t *table)
{
  return table == NULL ? 0 : table->count;
}

bool table_add(fwd_table_t *table, const route_t *route)
{
  if (table == NULL || route == NULL || route->dest.prefix > 32 ||
      !cidr_is_network(route->dest))
  {
    return false;
  }

  for (size_t index = 0; index < table->count; index++)
  {
    if (table->routes[index].dest.addr == route->dest.addr &&
        table->routes[index].dest.prefix == route->dest.prefix)
    {
      return false;
    }
  }

  return table_append(table, route);
}

bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line)
{
  if (bad_line != NULL)
  {
    *bad_line = 0;
  }
  if (table == NULL || in == NULL)
  {
    return false;
  }

  char *line = NULL;
  size_t capacity = 0;
  size_t line_number = 0;
  bool success = true;
  ssize_t length;

  while ((length = getline(&line, &capacity, in)) >= 0)
  {
    line_number++;

    char *comment = strchr(line, '#');
    if (comment != NULL)
    {
      *comment = '\0';
    }

    const char *cursor = line;
    while (isspace((unsigned char)*cursor))
    {
      cursor++;
    }
    if (*cursor == '\0')
    {
      continue;
    }

    route_t route;
    if (!route_parse(line, &route) || !table_add(table, &route))
    {
      if (bad_line != NULL)
      {
        *bad_line = line_number;
      }
      success = false;
      break;
    }
  }

  if (success && (ferror(in) || !feof(in)))
  {
    success = false;
  }
  free(line);
  return success;
}

const route_t *table_lookup(const fwd_table_t *table, uint32_t dest)
{
  if (table == NULL)
  {
    return NULL;
  }

  const route_t *best = NULL;
  for (size_t index = 0; index < table->count; index++)
  {
    const route_t *route = &table->routes[index];
    if (cidr_contains(route->dest, dest) &&
        (best == NULL || route->dest.prefix > best->dest.prefix))
    {
      best = route;
    }
  }
  return best;
}
