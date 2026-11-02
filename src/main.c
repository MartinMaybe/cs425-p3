#include "lab.h"
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef TEST
#define main main_exclude
#endif

static void print_usage(FILE *out)
{
  (void)fprintf(out,
                "Usage: myapp info <address>/<prefix>\n"
                "       myapp split <network>/<prefix> <count>\n"
                "       myapp lookup <table-file> <address>...\n");
}

static int run_info(const char *text)
{
  cidr_t block;
  if (!cidr_parse(text, &block))
  {
    (void)fprintf(stderr, "myapp: invalid CIDR block: %s\n", text);
    return 1;
  }

  char address[IP_STR_LEN];
  char netmask[IP_STR_LEN];
  char network[IP_STR_LEN];
  char broadcast[IP_STR_LEN];
  char first_host[IP_STR_LEN];
  char last_host[IP_STR_LEN];
  ip_format(block.addr, address);
  ip_format(cidr_mask(block.prefix), netmask);
  ip_format(cidr_network(block), network);
  ip_format(cidr_broadcast(block), broadcast);
  ip_format(cidr_first_host(block), first_host);
  ip_format(cidr_last_host(block), last_host);

  (void)printf("address    %s\n"
               "prefix     /%u\n"
               "netmask    %s\n"
               "network    %s\n"
               "broadcast  %s\n"
               "first host %s\n"
               "last host  %s\n"
               "hosts      %" PRIu64 "\n",
               address, (unsigned int)block.prefix, netmask, network,
               broadcast, first_host, last_host, cidr_host_count(block));
  return 0;
}

static bool parse_count(const char *text, uint32_t *count)
{
  if (text == NULL || *text == '\0' || count == NULL)
  {
    return false;
  }

  uint32_t parsed = 0;
  for (const char *cursor = text; *cursor != '\0'; cursor++)
  {
    if (*cursor < '0' || *cursor > '9')
    {
      return false;
    }
    uint32_t digit = (uint32_t)(*cursor - '0');
    if (parsed > (UINT32_MAX - digit) / 10U)
    {
      return false;
    }
    parsed = parsed * 10U + digit;
  }

  if (parsed == 0 || (parsed & (parsed - 1U)) != 0)
  {
    return false;
  }
  *count = parsed;
  return true;
}

static int run_split(const char *text, const char *count_text)
{
  cidr_t block;
  uint32_t count;
  if (!cidr_parse(text, &block))
  {
    (void)fprintf(stderr, "myapp: invalid CIDR block: %s\n", text);
    return 1;
  }
  if (!cidr_is_network(block))
  {
    (void)fprintf(stderr, "myapp: split requires a network address: %s\n", text);
    return 1;
  }
  if (!parse_count(count_text, &count))
  {
    (void)fprintf(stderr, "myapp: count must be a positive power of two: %s\n",
                  count_text);
    return 1;
  }

  for (uint32_t index = 0; index < count; index++)
  {
    cidr_t subnet;
    if (!cidr_subnet(block, count, index, &subnet))
    {
      (void)fprintf(stderr,
                    "myapp: cannot split %s into %" PRIu32 " subnets\n",
                    text, count);
      return 1;
    }

    char formatted[CIDR_STR_LEN];
    cidr_format(subnet, formatted);
    (void)puts(formatted);
  }
  return 0;
}

static int run_lookup(int argc, char **argv)
{
  const char *path = argv[2];
  FILE *input = fopen(path, "r");
  if (input == NULL)
  {
    (void)fprintf(stderr, "myapp: %s: %s\n", path, strerror(errno));
    return 2;
  }

  fwd_table_t *table = table_create();
  if (table == NULL)
  {
    (void)fprintf(stderr, "myapp: could not allocate forwarding table\n");
    (void)fclose(input);
    return 2;
  }

  size_t bad_line = 0;
  if (!table_load(table, input, &bad_line))
  {
    if (bad_line != 0)
    {
      (void)fprintf(stderr, "myapp: %s:%zu: not a valid route\n", path, bad_line);
    }
    else
    {
      (void)fprintf(stderr, "myapp: %s: could not read forwarding table\n", path);
    }
    table_destroy(table);
    (void)fclose(input);
    return 2;
  }
  (void)fclose(input);

  bool malformed = false;
  bool unreachable = false;
  for (int index = 3; index < argc; index++)
  {
    uint32_t address;
    if (!ip_parse(argv[index], &address))
    {
      (void)fprintf(stderr, "myapp: invalid address: %s\n", argv[index]);
      malformed = true;
      continue;
    }

    const route_t *route = table_lookup(table, address);
    if (route == NULL)
    {
      (void)printf("unreachable\n");
      unreachable = true;
      continue;
    }

    char gateway[IP_STR_LEN];
    if (route->gateway != 0)
    {
      ip_format(route->gateway, gateway);
      (void)printf("%s via %s dev %s\n", argv[index], gateway, route->dev);
    }
    else
    {
      (void)printf("%s dev %s\n", argv[index], route->dev);
    }
  }

  table_destroy(table);
  if (malformed)
  {
    return 1;
  }
  return unreachable ? 3 : 0;
}

int main(int argc, char **argv)
{
  if (argc == 1)
  {
    print_usage(stdout);
    return 0;
  }

  if (strcmp(argv[1], "info") == 0)
  {
    if (argc != 3)
    {
      (void)fprintf(stderr, "myapp: info requires one CIDR block\n");
      print_usage(stderr);
      return 1;
    }
    return run_info(argv[2]);
  }
  if (strcmp(argv[1], "split") == 0)
  {
    if (argc != 4)
    {
      (void)fprintf(stderr, "myapp: split requires a network and count\n");
      print_usage(stderr);
      return 1;
    }
    return run_split(argv[2], argv[3]);
  }
  if (strcmp(argv[1], "lookup") == 0)
  {
    if (argc < 4)
    {
      (void)fprintf(stderr, "myapp: lookup requires a table file and address\n");
      print_usage(stderr);
      return 1;
    }
    return run_lookup(argc, argv);
  }

  (void)fprintf(stderr, "myapp: unknown command: %s\n", argv[1]);
  print_usage(stderr);
  return 1;
}
