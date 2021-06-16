// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

/// \file
/// \brief The bare-minimum include for forward declarations of muu functions and types.

#pragma once
#include "preprocessor.h"
#include "impl/environment_checks.h"

//======================================================================================================================
// NON-MUU TYPEDEFS AND FORWARD DECLARATIONS
//======================================================================================================================
/// \cond
// undocumented forward declarations are hidden from doxygen because they fuck it up =/
MUU_DISABLE_WARNINGS;

#include <cstdint>
#include <cstddef>

namespace std
{
	template <typename>
	struct pointer_traits;
	template <typename, size_t>
	class array;
}

#if MUU_WINDOWS

	#ifndef _MINWINDEF_
extern "C" {
	using ULONG	  = unsigned long;
	using PULONG  = ULONG*;
	using USHORT  = unsigned short;
	using PUSHORT = USHORT*;
	using UCHAR	  = unsigned char;
	using PUCHAR  = UCHAR*;
	using DWORD	  = unsigned long;
	using BOOL	  = int;
	using BYTE	  = unsigned char;
	using WORD	  = unsigned short;
	using FLOAT	  = float;
	using PFLOAT  = FLOAT*;
	using PBOOL	  = BOOL*;
	using LPBOOL  = BOOL*;
	using PBYTE	  = BYTE*;
	using LPBYTE  = BYTE*;
	using PINT	  = int*;
	using LPINT	  = int*;
	using PWORD	  = WORD*;
	using LPWORD  = WORD*;
	using LPLONG  = long*;
	using PDWORD  = DWORD*;
	using LPDWORD = DWORD*;
	using LPVOID  = void*;
	using LPCVOID = const void*;
	using INT	  = int;
	using UINT	  = unsigned int;
	using PUINT	  = unsigned int*;
}
	#endif // !_MINWINDEF_

	#ifndef __unknwnbase_h__
struct IUnknown;
	#endif

#endif // MUU_WINDOWS

MUU_ENABLE_WARNINGS;
/// \endcond

//======================================================================================================================
// TYPEDEFS AND FORWARD DECLARATIONS
//======================================================================================================================

/// \addtogroup core			Core
/// \brief		Small, generally-useful functions and types.
/// @{

/// \defgroup	meta			Metafunctions and type traits
/// \brief		Type traits and metaprogramming utilities.
/// \remarks	Many of these are mirrors of (or supplementary to) traits found in the standard library's
///				`<type_traits>`, but with simpler/saner default behaviour (e.g. most of the `is_X` metafunctions do
///				not make a distinction between T and T&).

/// @}

/// \defgroup	constants		Constants
/// \brief		Compile-time constant values (Pi, et cetera.).

/// \defgroup	hashing			Hashing
/// \brief		Utilities for generating (non-cryptographic) hashes.

/// \defgroup	mem				Memory management
/// \brief		Utilities for allocating, destroying and manipulating memory.

/// \brief	The root namespace for all muu functions and types.
namespace muu
{
#if MUU_HAS_INT128
	/// \brief	A 128-bit signed integer.
	/// \ingroup core
	///
	/// \availability This typedef is only present when 128-bit integers are supported by your target platform.
	/// 		 You can check support using #MUU_HAS_INT128.
	using int128_t = __int128_t;

	/// \brief	A 128-bit unsigned integer.
	/// \ingroup core
	///
	/// \availability This typedef is only present when 128-bit integers are supported by your target platform.
	/// 		 You can check support using #MUU_HAS_INT128.
	using uint128_t = __uint128_t;
#endif

#if MUU_HAS_FLOAT128
	/// \brief	A 128-bit quad-precision float.
	/// \ingroup core
	///
	/// \availability This typedef is only present when 128-bit floats are supported by your target platform.
	/// 		 You can check support using #MUU_HAS_FLOAT128.
	using float128_t = __float128;
#endif

	/// \brief	Allows the library to implicitly convert via bit casting in some situations.
	/// \ingroup meta
	///
	/// \tparam From	The source type.
	/// \tparam To		The destination type.
	///
	/// \detail \cpp
	///
	/// #include <muu/vector.h>
	///
	/// using vec3i = muu::vector<int, 3>;
	///
	/// struct Foo
	/// {
	///		int a, b, c;
	/// };
	///
	/// namespace muu
	/// {
	/// 	template <> inline constexpr bool allow_implicit_bit_cast<Foo, vec3i> = true;
	/// };
	///
	/// Foo foo{ 1, 2, 3 };
	/// vec3i bar = foo;
	///
	/// \ecpp
	///
	/// \note You do not need to pepper your codebase with this.
	/// 	  It is only used in a few highly-specialized situations:
	/// 	  - muu::bounding_box constructor
	/// 	  - muu::matrix constructor
	/// 	  - muu::oriented_bounding_box constructor
	/// 	  - muu::plane constructor
	/// 	  - muu::quaternion constructor
	/// 	  - muu::vector constructor
	template <typename From, typename To>
	inline constexpr bool allow_implicit_bit_cast = false;

	/// \brief Literal operators.
	inline namespace literals
	{
	}

	/// \brief Build environment information (compiler, date/time, support for various things...)
	/// \ingroup constants
	namespace build
	{
	}

	/// \brief	A typed container for static constants, similar to std::numeric_limits.
	/// \ingroup constants
	template <typename T>
	struct constants
	{};
	template <typename T>
	struct constants<T&> : constants<T>
	{};
	template <typename T>
	struct constants<T&&> : constants<T>
	{};
	template <typename T>
	struct constants<const T> : constants<T>
	{};
	template <typename T>
	struct constants<volatile T> : constants<T>
	{};
	template <typename T>
	struct constants<const volatile T> : constants<T>
	{};
}

//======================================================================================================================
// TYPEDEFS AND FORWARD DECLARATIONS - UNDOCUMENTED
//======================================================================================================================
/// \cond

namespace muu
{
	using ::std::size_t;
	using ::std::intptr_t;
	using ::std::uintptr_t;
	using ::std::ptrdiff_t;
	using ::std::nullptr_t;
	using ::std::int8_t;
	using ::std::int16_t;
	using ::std::int32_t;
	using ::std::int64_t;
	using ::std::uint8_t;
	using ::std::uint16_t;
	using ::std::uint32_t;
	using ::std::uint64_t;
	using ::std::int_least8_t;
	using ::std::int_least16_t;
	using ::std::int_least32_t;
	using ::std::int_least64_t;
	using ::std::uint_least8_t;
	using ::std::uint_least16_t;
	using ::std::uint_least32_t;
	using ::std::uint_least64_t;
	using ::std::int_fast8_t;
	using ::std::int_fast16_t;
	using ::std::int_fast32_t;
	using ::std::int_fast64_t;
	using ::std::uint_fast8_t;
	using ::std::uint_fast16_t;
	using ::std::uint_fast32_t;
	using ::std::uint_fast64_t;
	using ::std::intmax_t;
	using ::std::uintmax_t;

	inline constexpr size_t dynamic_extent = static_cast<size_t>(-1);

	namespace impl
	{
		template <size_t = sizeof(wchar_t)>
		struct wchar_code_unit_;
		template <>
		struct wchar_code_unit_<sizeof(char32_t)>
		{
			using type = char32_t;
		};
		template <>
		struct wchar_code_unit_<sizeof(char16_t)>
		{
			using type = char16_t;
		};
		template <>
		struct wchar_code_unit_<sizeof(unsigned char)>
		{
			using type = unsigned char;
		};
		using wchar_code_unit = typename wchar_code_unit_<>::type;
	}

	MUU_ABI_VERSION_START(0);

	struct half;
	struct semver;
	struct uuid;
	template <typename>
	struct axis_angle_rotation;
	template <typename>
	struct euler_rotation;
	template <typename, size_t>
	struct vector;
	template <typename>
	struct quaternion;
	template <typename, size_t, size_t>
	struct matrix;
	template <typename... T>
	struct type_list;

	template <typename>
	struct plane;
	template <typename>
	struct triangle;
	template <typename>
	struct bounding_sphere;
	template <typename>
	struct bounding_box;
	template <typename>
	struct oriented_bounding_box;

	class bitset;
	class blob;
	class sha1;
	class string_param;
	class thread_pool;
	template <typename, typename>
	class compressed_pair;
	template <typename>
	class emplacement_array;
	template <size_t>
	class fnv1a;
	template <size_t>
	class hash_combiner;
	template <typename>
	class scope_guard;
	template <typename>
	class scope_fail;
	template <typename>
	class scope_success;
	template <typename, size_t>
	class tagged_ptr;

	template <typename, size_t = dynamic_extent>
	class span;

	MUU_ABI_VERSION_END;

	namespace impl
	{
		MUU_ABI_VERSION_START(0);

		template <typename>
		struct basic_accumulator;
		template <typename>
		struct kahan_accumulator;
		template <typename, size_t>
		struct vector_accumulator;

		MUU_ABI_VERSION_END;

		template <typename T>
		struct default_accumulator
		{
			using type = basic_accumulator<T>;
		};
		template <>
		struct default_accumulator<float>
		{
			using type = kahan_accumulator<float>;
		};
		template <>
		struct default_accumulator<double>
		{
			using type = kahan_accumulator<double>;
		};
		template <>
		struct default_accumulator<long double>
		{
			using type = kahan_accumulator<long double>;
		};
		template <>
		struct default_accumulator<half>
		{
			using type = kahan_accumulator<half>;
		};
#if MUU_HAS_FP16
		template <>
		struct default_accumulator<__fp16>
		{
			using type = kahan_accumulator<__fp16>;
		};
#endif
#if MUU_HAS_FLOAT16
		template <>
		struct default_accumulator<_Float16>
		{
			using type = kahan_accumulator<_Float16>;
		};
#endif
#if MUU_HAS_FLOAT128
		template <>
		struct default_accumulator<float128_t>
		{
			using type = kahan_accumulator<float128_t>;
		};
#endif

		template <typename Scalar, size_t Dimensions>
		struct default_accumulator<muu::vector<Scalar, Dimensions>>
		{
			using type = vector_accumulator<Scalar, Dimensions>;
		};
	}

	MUU_ABI_VERSION_START(0);

	template <typename T, typename = typename impl::default_accumulator<T>::type>
	class accumulator;

	MUU_ABI_VERSION_END;
}

/// \endcond
