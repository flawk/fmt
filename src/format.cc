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

// DEPRECATED!
template <typename T = void> struct basic_data {
  FMT_API static constexpr const char digits[100][2] = {
      {'0', '0'}, {'0', '1'}, {'0', '2'}, {'0', '3'}, {'0', '4'}, {'0', '5'},
      {'0', '6'}, {'0', '7'}, {'0', '8'}, {'0', '9'}, {'1', '0'}, {'1', '1'},
      {'1', '2'}, {'1', '3'}, {'1', '4'}, {'1', '5'}, {'1', '6'}, {'1', '7'},
      {'1', '8'}, {'1', '9'}, {'2', '0'}, {'2', '1'}, {'2', '2'}, {'2', '3'},
      {'2', '4'}, {'2', '5'}, {'2', '6'}, {'2', '7'}, {'2', '8'}, {'2', '9'},
      {'3', '0'}, {'3', '1'}, {'3', '2'}, {'3', '3'}, {'3', '4'}, {'3', '5'},
      {'3', '6'}, {'3', '7'}, {'3', '8'}, {'3', '9'}, {'4', '0'}, {'4', '1'},
      {'4', '2'}, {'4', '3'}, {'4', '4'}, {'4', '5'}, {'4', '6'}, {'4', '7'},
      {'4', '8'}, {'4', '9'}, {'5', '0'}, {'5', '1'}, {'5', '2'}, {'5', '3'},
      {'5', '4'}, {'5', '5'}, {'5', '6'}, {'5', '7'}, {'5', '8'}, {'5', '9'},
      {'6', '0'}, {'6', '1'}, {'6', '2'}, {'6', '3'}, {'6', '4'}, {'6', '5'},
      {'6', '6'}, {'6', '7'}, {'6', '8'}, {'6', '9'}, {'7', '0'}, {'7', '1'},
      {'7', '2'}, {'7', '3'}, {'7', '4'}, {'7', '5'}, {'7', '6'}, {'7', '7'},
      {'7', '8'}, {'7', '9'}, {'8', '0'}, {'8', '1'}, {'8', '2'}, {'8', '3'},
      {'8', '4'}, {'8', '5'}, {'8', '6'}, {'8', '7'}, {'8', '8'}, {'8', '9'},
      {'9', '0'}, {'9', '1'}, {'9', '2'}, {'9', '3'}, {'9', '4'}, {'9', '5'},
      {'9', '6'}, {'9', '7'}, {'9', '8'}, {'9', '9'}};
  FMT_API static constexpr const char hex_digits[] = "0123456789abcdef";
  FMT_API static constexpr const char signs[4] = {0, '-', '+', ' '};
  FMT_API static constexpr const char left_padding_shifts[5] = {31, 31, 0, 1,
                                                                0};
  FMT_API static constexpr const char right_padding_shifts[5] = {0, 31, 0, 1,
                                                                 0};
  FMT_API static constexpr const unsigned prefixes[4] = {0, 0, 0x1000000u | '+',
                                                         0x1000000u | ' '};
};

#ifdef FMT_SHARED
// Required for -flto, -fivisibility=hidden and -shared to work
extern template struct basic_data<void>;
#endif

#if __cplusplus < 201703L
// DEPRECATED! These are here only for ABI compatiblity.
template <typename T> constexpr const char basic_data<T>::digits[][2];
template <typename T> constexpr const char basic_data<T>::hex_digits[];
template <typename T> constexpr const char basic_data<T>::signs[];
template <typename T> constexpr const char basic_data<T>::left_padding_shifts[];
template <typename T>
constexpr const char basic_data<T>::right_padding_shifts[];
template <typename T> constexpr const unsigned basic_data<T>::prefixes[];
#endif

template FMT_API dragonbox::decimal_fp<float> dragonbox::to_decimal(
    float x) noexcept;
template FMT_API dragonbox::decimal_fp<double> dragonbox::to_decimal(
    double x) noexcept;
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

// Workaround a bug in MSVC2013 that prevents instantiation of format_float.
int (*instantiate_format_float)(double, int, detail::float_specs,
                                detail::buffer<char>&) = detail::format_float;

#ifndef FMT_STATIC_THOUSANDS_SEPARATOR
template FMT_API detail::locale_ref::locale_ref(const std::locale& loc);
template FMT_API std::locale detail::locale_ref::get<std::locale>() const;
#endif

// Explicit instantiations for char.

template FMT_API auto detail::thousands_sep_impl(locale_ref)
    -> thousands_sep_result<char>;
template FMT_API char detail::decimal_point_impl(locale_ref);

template FMT_API void detail::buffer<char>::append(const char*, const char*);

// DEPRECATED!
// There is no correspondent extern template in format.h because of
// incompatibility between clang and gcc (#2377).
template FMT_API void detail::vformat_to(
    detail::buffer<char>&, string_view,
    basic_format_args<FMT_BUFFER_CONTEXT(char)>, detail::locale_ref);

template FMT_API int detail::format_float(double, int, detail::float_specs,
                                          detail::buffer<char>&);
template FMT_API int detail::format_float(long double, int, detail::float_specs,
                                          detail::buffer<char>&);

// Explicit instantiations for wchar_t.

template FMT_API auto detail::thousands_sep_impl(locale_ref)
    -> thousands_sep_result<wchar_t>;
template FMT_API wchar_t detail::decimal_point_impl(locale_ref);

template FMT_API void detail::buffer<wchar_t>::append(const wchar_t*,
                                                      const wchar_t*);

template struct detail::basic_data<void>;

FMT_END_NAMESPACE
