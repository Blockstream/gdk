#ifndef GDK_GSL_WRAPPER_HPP
#define GDK_GSL_WRAPPER_HPP
#pragma once

#if __clang__
#pragma clang diagnostic push
#if __clang_major__ < 6
#pragma clang diagnostic ignored "-Wunknown-attributes"
#endif
#endif

#include <gsl/narrow>
#include <gsl/pointers>
#include <gsl/span>

#if __clang__
#pragma clang diagnostic pop
#endif

#endif
