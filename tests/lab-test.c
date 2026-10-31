#include <stdio.h>
#include "harness/unity.h"
#include "../src/lab.h"


void setUp(void) {
  printf("Setting up tests...\n");
}

void tearDown(void) {
  printf("Tearing down tests...\n");
}

void test_ip_parse_and_format(void) {
  const char *invalid[] = {
    "1.2.3", "1.2.3.4.5", "1..2.3", "256.1.1.1", "010.0.0.1",
    "1.2.3.4x", "+1.2.3.4", "1.2.3.-4", "1.2.3.4 ", ""
  };
  uint32_t addr = 0xDEADBEEFU;

  TEST_ASSERT_TRUE(ip_parse("192.168.1.10", &addr));
  TEST_ASSERT_EQUAL_HEX32(0xC0A8010AU, addr);
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    addr = 0xDEADBEEFU;
    TEST_ASSERT_FALSE(ip_parse(invalid[i], &addr));
    TEST_ASSERT_EQUAL_HEX32(0xDEADBEEFU, addr);
  }
  TEST_ASSERT_FALSE(ip_parse(NULL, &addr));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4", NULL));

  char formatted[IP_STR_LEN];
  ip_format(0xC0A8010AU, formatted);
  TEST_ASSERT_EQUAL_STRING("192.168.1.10", formatted);
  ip_format(0xFFFFFFFFU, formatted);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255", formatted);
}

void test_cidr_parse_and_format(void) {
  const char *invalid[] = {
    "1.2.3.4/33", "1.2.3.4/024", "1.2.3.4/", "1.2.3/24",
    "1.2.3.4/-1", "1.2.3.4/1x", "1.2.3.4/00", "1.2.3.4/000",
    "1.2.3.4/256", "1.2.3.4/24/1"
  };
  cidr_t block = { .addr = 0xDEADBEEFU, .prefix = 17 };

  TEST_ASSERT_TRUE(cidr_parse("132.178.227.11/25", &block));
  TEST_ASSERT_EQUAL_HEX32(0x84B2E30BU, block.addr);
  TEST_ASSERT_EQUAL_UINT32(25U, block.prefix);
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    block.addr = 0xDEADBEEFU;
    block.prefix = 17;
    TEST_ASSERT_FALSE(cidr_parse(invalid[i], &block));
    TEST_ASSERT_EQUAL_HEX32(0xDEADBEEFU, block.addr);
    TEST_ASSERT_EQUAL_UINT32(17U, block.prefix);
  }
  TEST_ASSERT_TRUE(cidr_parse("0.0.0.0/0", &block));
  TEST_ASSERT_EQUAL_UINT32(0U, block.prefix);
  TEST_ASSERT_FALSE(cidr_parse(NULL, &block));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/24", NULL));

  char formatted[CIDR_STR_LEN];
  cidr_format((cidr_t){ .addr = 0xFFFFFFFFU, .prefix = 32 }, formatted);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255/32", formatted);
  cidr_format((cidr_t){ .addr = 0x01020304U, .prefix = 255 }, formatted);
  TEST_ASSERT_EQUAL_STRING("1.2.3.4/32", formatted);
}

void test_cidr_subnet_arithmetic(void) {
  TEST_ASSERT_EQUAL_HEX32(0U, cidr_mask(0));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFF00U, cidr_mask(24));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFU, cidr_mask(32));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFU, cidr_mask(255));

  cidr_t block = { .addr = 0xC0A8017BU, .prefix = 24 };
  TEST_ASSERT_EQUAL_HEX32(0xC0A80100U, cidr_network(block));
  TEST_ASSERT_EQUAL_HEX32(0xC0A801FFU, cidr_broadcast(block));
  TEST_ASSERT_EQUAL_HEX32(0xC0A80101U, cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(0xC0A801FEU, cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(254U, cidr_host_count(block));
  TEST_ASSERT_TRUE(cidr_contains(block, 0xC0A80100U));
  TEST_ASSERT_TRUE(cidr_contains(block, 0xC0A801FFU));
  TEST_ASSERT_FALSE(cidr_contains(block, 0xC0A80200U));
  TEST_ASSERT_FALSE(cidr_is_network(block));
  block.addr = 0xC0A80100U;
  TEST_ASSERT_TRUE(cidr_is_network(block));

  block.addr = 0x01020304U;
  block.prefix = 0;
  TEST_ASSERT_EQUAL_UINT64(4294967294ULL, cidr_host_count(block));
  TEST_ASSERT_EQUAL_HEX32(1U, cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFU, cidr_broadcast(block));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFEU, cidr_last_host(block));
  TEST_ASSERT_TRUE(cidr_contains(block, 0x89ABCDEFU));
  TEST_ASSERT_FALSE(cidr_is_network(block));

  block = (cidr_t){ .addr = 0xC0000200U, .prefix = 31 };
  TEST_ASSERT_EQUAL_HEX32(0xC0000200U, cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(0xC0000201U, cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(2U, cidr_host_count(block));
  block.prefix = 32;
  TEST_ASSERT_EQUAL_HEX32(0xC0000200U, cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(0xC0000200U, cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(1U, cidr_host_count(block));

  cidr_t subnet = { .addr = 0xDEADBEEFU, .prefix = 17 };
  block = (cidr_t){ .addr = 0xC0A80000U, .prefix = 24 };
  TEST_ASSERT_TRUE(cidr_subnet(block, 4, 0, &subnet));
  TEST_ASSERT_EQUAL_HEX32(0xC0A80000U, subnet.addr);
  TEST_ASSERT_EQUAL_UINT32(26U, subnet.prefix);
  TEST_ASSERT_TRUE(cidr_subnet(block, 4, 3, &subnet));
  TEST_ASSERT_EQUAL_HEX32(0xC0A800C0U, subnet.addr);
  TEST_ASSERT_EQUAL_UINT32(26U, subnet.prefix);

  block = (cidr_t){ .addr = 0, .prefix = 0 };
  TEST_ASSERT_TRUE(cidr_subnet(block, 0x80000000U, 0x7FFFFFFFU, &subnet));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFEU, subnet.addr);
  TEST_ASSERT_EQUAL_UINT32(31U, subnet.prefix);

  subnet = (cidr_t){ .addr = 0xDEADBEEFU, .prefix = 17 };
  TEST_ASSERT_FALSE(cidr_subnet(block, 3, 0, &subnet));
  TEST_ASSERT_EQUAL_HEX32(0xDEADBEEFU, subnet.addr);
  TEST_ASSERT_EQUAL_UINT32(17U, subnet.prefix);
  TEST_ASSERT_FALSE(cidr_subnet(block, 4, 4, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet((cidr_t){ .addr = 1, .prefix = 24 }, 2, 0, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet((cidr_t){ .addr = 0, .prefix = 32 }, 2, 0, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet(block, 1, 0, NULL));
}

void test_route_parse_and_table(void) {
  route_t route = {
    .dest = { .addr = 0xDEADBEEFU, .prefix = 17 },
    .gateway = 0x12345678U,
    .dev = "keep"
  };
  TEST_ASSERT_TRUE(route_parse("  default\t132.178.227.1 eno1 \r\n", &route));
  TEST_ASSERT_EQUAL_HEX32(0U, route.dest.addr);
  TEST_ASSERT_EQUAL_UINT32(0U, route.dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(0x84B2E301U, route.gateway);
  TEST_ASSERT_EQUAL_STRING("eno1", route.dev);

  TEST_ASSERT_TRUE(route_parse("10.1.2.0/24 direct eth2\n", &route));
  TEST_ASSERT_EQUAL_HEX32(0x0A010200U, route.dest.addr);
  TEST_ASSERT_EQUAL_UINT32(24U, route.dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(0U, route.gateway);
  TEST_ASSERT_EQUAL_STRING("eth2", route.dev);

  const char *invalid[] = {
    "", "default direct", "default direct eth0 extra",
    "10.1.2.1/24 direct eth0", "10.0.0.0/8 256.1.1.1 eth0",
    "10.0.0.0/8 direct", "10.0.0.0/8 direct eth0123456789012"
  };
  for (size_t index = 0; index < sizeof(invalid) / sizeof(invalid[0]); index++) {
    route.dest.addr = 0xDEADBEEFU;
    route.dest.prefix = 17;
    route.gateway = 0x12345678U;
    (void)snprintf(route.dev, sizeof(route.dev), "%s", "keep");
    TEST_ASSERT_FALSE(route_parse(invalid[index], &route));
    TEST_ASSERT_EQUAL_HEX32(0xDEADBEEFU, route.dest.addr);
    TEST_ASSERT_EQUAL_UINT32(17U, route.dest.prefix);
    TEST_ASSERT_EQUAL_HEX32(0x12345678U, route.gateway);
    TEST_ASSERT_EQUAL_STRING("keep", route.dev);
  }
  TEST_ASSERT_FALSE(route_parse(NULL, &route));
  TEST_ASSERT_FALSE(route_parse("default direct eth0", NULL));

  fwd_table_t *table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_EQUAL_UINT32(0U, table_count(table));
  TEST_ASSERT_EQUAL_UINT32(0U, table_count(NULL));
  TEST_ASSERT_FALSE(table_add(NULL, &route));
  TEST_ASSERT_FALSE(table_add(table, NULL));

  const char *routes[] = {
    "10.0.0.0/8 10.1.0.1 eth1",
    "default 132.178.227.1 eno1",
    "10.1.2.128/25 10.1.2.1 eth2",
    "10.1.0.0/16 direct eth1",
    "10.1.2.0/24 direct eth2",
    "192.168.0.0/16 10.1.0.1 eth1",
    "132.178.227.0/25 direct eno1"
  };
  for (size_t index = 0; index < sizeof(routes) / sizeof(routes[0]); index++) {
    TEST_ASSERT_TRUE(route_parse(routes[index], &route));
    TEST_ASSERT_TRUE(table_add(table, &route));
  }
  TEST_ASSERT_EQUAL_UINT32(7U, table_count(table));
  TEST_ASSERT_FALSE(table_add(table, &route));
  TEST_ASSERT_FALSE(table_add(table, &(route_t){
    .dest = { .addr = 0x0A000001U, .prefix = 8 },
    .gateway = 0,
    .dev = "bad"
  }));
  TEST_ASSERT_FALSE(table_add(table, &(route_t){
    .dest = { .addr = 0x0A000000U, .prefix = 33 },
    .gateway = 0,
    .dev = "bad"
  }));

  const route_t *found = table_lookup(table, 0x0A010281U);
  TEST_ASSERT_NOT_NULL(found);
  TEST_ASSERT_EQUAL_UINT32(25U, found->dest.prefix);
  TEST_ASSERT_EQUAL_STRING("eth2", found->dev);
  found = table_lookup(table, 0x0A010240U);
  TEST_ASSERT_NOT_NULL(found);
  TEST_ASSERT_EQUAL_UINT32(24U, found->dest.prefix);
  found = table_lookup(table, 0x0A010340U);
  TEST_ASSERT_NOT_NULL(found);
  TEST_ASSERT_EQUAL_UINT32(16U, found->dest.prefix);
  found = table_lookup(table, 0x0B000001U);
  TEST_ASSERT_NOT_NULL(found);
  TEST_ASSERT_EQUAL_UINT32(0U, found->dest.prefix);
  found = table_lookup(table, 0xC0000201U);
  TEST_ASSERT_NOT_NULL(found);
  TEST_ASSERT_EQUAL_UINT32(0U, found->dest.prefix);
  TEST_ASSERT_NULL(table_lookup(NULL, 0));
  table_destroy(table);
  table_destroy(NULL);

  FILE *input = tmpfile();
  TEST_ASSERT_NOT_NULL(input);
  fputs("# example routes\n"
        "default 132.178.227.1 eno1\n"
        "10.0.0.0/8 direct eth1 # inline comment\n"
        "\t \n"
        "192.168.0.0/16 10.1.0.1 eth1\n", input);
  rewind(input);
  table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  size_t bad_line = 99;
  TEST_ASSERT_TRUE(table_load(table, input, &bad_line));
  TEST_ASSERT_EQUAL_UINT32(0U, bad_line);
  TEST_ASSERT_EQUAL_UINT32(3U, table_count(table));
  fclose(input);

  table_destroy(table);
  table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  input = tmpfile();
  TEST_ASSERT_NOT_NULL(input);
  fputs("default direct eth0\n10.0.0.0/8 direct eth1\n"
        "10.0.0.1/8 direct eth2\n192.168.0.0/16 direct eth3\n", input);
  rewind(input);
  bad_line = 99;
  TEST_ASSERT_FALSE(table_load(table, input, &bad_line));
  TEST_ASSERT_EQUAL_UINT32(3U, bad_line);
  TEST_ASSERT_EQUAL_UINT32(2U, table_count(table));
  fclose(input);

  bad_line = 99;
  TEST_ASSERT_FALSE(table_load(NULL, NULL, &bad_line));
  TEST_ASSERT_EQUAL_UINT32(0U, bad_line);
  table_destroy(table);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_ip_parse_and_format);
  RUN_TEST(test_cidr_parse_and_format);
  RUN_TEST(test_cidr_subnet_arithmetic);
  RUN_TEST(test_route_parse_and_table);
  return UNITY_END();
}
