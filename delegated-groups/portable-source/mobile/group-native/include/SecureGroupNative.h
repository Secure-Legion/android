#ifndef SECURE_GROUP_NATIVE_H
#define SECURE_GROUP_NATIVE_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// Pure bounded operation: no I/O, networking, mutable group registry or trust
// installation. Secret pointers are separate from JSON and are never logged.
int32_t sl_desktop_group_protocol(const uint8_t *request, uint32_t request_len,
  const uint8_t *signing_seed, uint32_t signing_seed_len,
  const uint8_t *group_key, uint32_t group_key_len,
  uint8_t *output, uint32_t *output_len);
#ifdef __cplusplus
}
#endif
#endif
