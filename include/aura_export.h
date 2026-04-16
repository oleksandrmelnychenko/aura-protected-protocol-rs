#pragma once

#if defined(_WIN32) || defined(__CYGWIN__)
  #if defined(AURA_EXPORTS)
    #define AURA_API __declspec(dllexport)
  #elif defined(AURA_SHARED)
    #define AURA_API __declspec(dllimport)
  #else
    #define AURA_API
  #endif
#elif defined(__GNUC__) && __GNUC__ >= 4
  #define AURA_API __attribute__((visibility("default")))
#else
  #define AURA_API
#endif
