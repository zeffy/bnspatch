// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

#pragma once
#include "../preprocessor.h"

MUU_DISABLE_WARNINGS;
#include <climits>
#include <cfloat>
#include <limits>
MUU_ENABLE_WARNINGS;

/// \cond

#ifndef MUU_DISABLE_ENVIRONMENT_CHECKS

	#define MUU_ENV_MESSAGE                                                                                            \
		"If you're seeing this error it's because you're using muu on an environment/platform/compiler that doesn't "  \
		"conform to one of the 'ground truths' assumed by the library. Essentially this just means that I don't have " \
		"the resources to test on many platforms, but I wish I did! You can try disabling the checks by defining "     \
		"MUU_DISABLE_ENVIRONMENT_CHECKS, but your mileage may vary. Please consider filing an issue at "               \
		"https://github.com/marzer/muu/issues to help me improve support for your target environment. Thanks!"

	#define MUU_ENV_CHECK(cond) static_assert(cond, MUU_ENV_MESSAGE)

MUU_ENV_CHECK(CHAR_BIT == 8);
MUU_ENV_CHECK(FLT_RADIX == 2);
MUU_ENV_CHECK('A' == 65);
MUU_ENV_CHECK(sizeof(wchar_t) == MUU_WCHAR_BYTES);
MUU_ENV_CHECK(sizeof(wchar_t) * CHAR_BIT == MUU_WCHAR_BITS);
MUU_ENV_CHECK(std::numeric_limits<float>::is_iec559);
MUU_ENV_CHECK(std::numeric_limits<double>::is_iec559);

	#undef MUU_ENV_CHECK
	#undef MUU_ENV_MESSAGE
#endif // !MUU_DISABLE_ENVIRONMENT_CHECKS

/// \endcond
