// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

/// \file
/// \brief Functions to simplify working with characters (code units).

#pragma once
#include "impl/unicode_char.h"
#include "impl/unicode_wchar_t.h"
#include "impl/unicode_char16_t.h"
#include "impl/unicode_char32_t.h"
#if MUU_HAS_CHAR8
	#include "impl/unicode_char8_t.h"
#endif
