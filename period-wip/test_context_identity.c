#define _GNU_SOURCE
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef uintptr_t (*context_function)(void);

__attribute__((noinline)) static uintptr_t call_site_a(context_function function) {
  uintptr_t result = function();
  __asm__ volatile ("" : "+r" (result));
  return result;
}

__attribute__((noinline)) static uintptr_t call_site_b(context_function function) {
  uintptr_t result = function();
  __asm__ volatile ("" : "+r" (result));
  return result;
}

int main(int argc, char **argv) {
  if (argc != 2) return 2;
  void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!library) {
    fprintf(stderr, "%s\n", dlerror());
    return 3;
  }
  context_function function = (context_function)dlsym(library, "_Z16get_context_hashv");
  if (!function) return 4;
  uintptr_t a = 0;
  uintptr_t b = 0;
  for (int i = 0; i < 20; ++i) {
    uintptr_t current_a = call_site_a(function);
    uintptr_t current_b = call_site_b(function);
    if (i == 0) {
      a = current_a;
      b = current_b;
    } else if (current_a != a || current_b != b) {
      return 5;
    }
  }
  if (a == b) return 6;
  printf("%" PRIuPTR " %" PRIuPTR "\n", a, b);
  return dlclose(library) ? 7 : 0;
}
