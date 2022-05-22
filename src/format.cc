// Formatting library for C++
//
// Copyright (c) 2012 - 2016, Victor Zverovich
// All rights reserved.
//
// For the license information refer to format.h.

#include "fmt/format-inl.h"
#ifdef SMALL_STRINGS_POOL
#include <mutex>
#include <vector>
#include "fmt/args.h"
#endif

FMT_BEGIN_NAMESPACE
namespace detail {

template FMT_API auto dragonbox::to_decimal(float x) noexcept
    -> dragonbox::decimal_fp<float>;
template FMT_API auto dragonbox::to_decimal(double x) noexcept
    -> dragonbox::decimal_fp<double>;

#ifndef FMT_STATIC_THOUSANDS_SEPARATOR
template FMT_API locale_ref::locale_ref(const std::locale& loc);
template FMT_API auto locale_ref::get<std::locale>() const -> std::locale;
#endif

// Explicit instantiations for char.

template FMT_API auto thousands_sep_impl(locale_ref)
    -> thousands_sep_result<char>;
template FMT_API auto decimal_point_impl(locale_ref) -> char;

template FMT_API void buffer<char>::append(const char*, const char*);

// DEPRECATED!
// There is no correspondent extern template in format.h because of
// incompatibility between clang and gcc (#2377).
template FMT_API void vformat_to(buffer<char>&, string_view,
                                 basic_format_args<FMT_BUFFER_CONTEXT(char)>,
                                 locale_ref);

template FMT_API auto format_float(double, int, float_specs, buffer<char>&)
    -> int;
template FMT_API auto format_float(long double, int, detail::float_specs,
                                   buffer<char>&) -> int;

// Explicit instantiations for wchar_t.

template FMT_API auto thousands_sep_impl(locale_ref)
    -> thousands_sep_result<wchar_t>;
template FMT_API auto decimal_point_impl(locale_ref) -> wchar_t;

template FMT_API void buffer<wchar_t>::append(const wchar_t*, const wchar_t*);

#ifdef SMALL_STRINGS_POOL
/// This special mutex has priority inheritance to improve latency.
class pi_mutex {
private:
  pthread_mutex_t m{};

public:
  pi_mutex(const pi_mutex&) = delete;
  pi_mutex& operator=(const pi_mutex&) = delete;

  explicit pi_mutex() {
    ::pthread_mutexattr_t mutex_attr;
    ::pthread_mutexattr_init(&mutex_attr);
    ::pthread_mutexattr_setprotocol(&mutex_attr, PTHREAD_PRIO_INHERIT);
    ::pthread_mutex_init(&m, &mutex_attr);
  }

  ~pi_mutex() { ::pthread_mutex_destroy(&m); }

  /// Mutex lock.
  void lock() { ::pthread_mutex_lock(&m); }

  /// Mutex unlock.
  void unlock() { ::pthread_mutex_unlock(&m); }

  /// Mutex try lock. Returns true if the lock was obtained, false otherwise.
  bool try_lock() { return (::pthread_mutex_trylock(&m) == 0); }

  /// Accessor to the raw mutex structure.
  pthread_mutex_t* raw() { return &m; }
  [[nodiscard]] const pthread_mutex_t* raw() const { return &m; }
};

#define NODE_POOL_SIZE (10000u)
static constexpr uint8_t memory_heap_tag = 0xAA;
class dyn_node_pool {
  /// The extra byte is used to store the memory tag at position 0 in the array.
  using type = std::array<uint8_t, dynamic_arg_list::max_pool_node_size + 1>;

public:
  dyn_node_pool() {
    pool.resize(NODE_POOL_SIZE);
    free_list.reserve(NODE_POOL_SIZE);
    for (auto& elem : pool) {
      free_list.push_back(elem.data());
    }
  }

  dyn_node_pool(const dyn_node_pool&) = delete;
  dyn_node_pool(dyn_node_pool&&) = delete;
  dyn_node_pool& operator=(dyn_node_pool&&) = delete;
  dyn_node_pool& operator=(const dyn_node_pool&) = delete;

  void* alloc(std::size_t sz) {
    FMT_ASSERT(sz <= dynamic_arg_list::max_pool_node_size,
               "Object is too large to fit in the pool");

    std::lock_guard<pi_mutex> lock(m);
    if (free_list.empty()) {
      // Tag that this allocation was performed by the heap.
      auto *p = new type;
      (*p)[0] = memory_heap_tag;
      return p->data() + 1;
    }

    auto* p = free_list.back();
    free_list.pop_back();

    // Tag that this allocation was performed by the pool.
    p[0] = 0;
    return p + 1;
  }

  void dealloc(void* p) {
    if (!p) {
      return;
    }

    uint8_t* base_ptr = reinterpret_cast<uint8_t*>(p) - 1;
    if (*base_ptr == memory_heap_tag) {
      // This pointer was allocated using the heap.
      delete reinterpret_cast<type *>(base_ptr);
      return;
    }

    std::lock_guard<pi_mutex> lock(m);
    free_list.push_back(base_ptr);
  }

private:
  std::vector<type> pool;
  std::vector<uint8_t *> free_list;
  mutable pi_mutex m;
};

static dyn_node_pool node_pool; // NOLINT(cert-err58-cpp)

void* dynamic_arg_list::allocate_from_pool(std::size_t sz) {
  return node_pool.alloc(sz);
}

void dynamic_arg_list::free_from_pool(void* ptr) {
  return node_pool.dealloc(ptr);
}

#endif

}  // namespace detail
FMT_END_NAMESPACE
