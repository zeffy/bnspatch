// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

/// \file
/// \brief Math functions, mostly constexpr-friendly alternatives to functions from `<cmath>`.

#pragma once
#include "core.h"

MUU_DISABLE_WARNINGS;
#include <cmath>
#if MUU_HAS_QUADMATH
	#include <quadmath.h>
#endif
#if MUU_MSVC && MUU_MSVC >= 1928
	#define MUU_HAS_MSVC_INTRINSICS 1
	#include <intrin0.h>
#else
	#define MUU_HAS_MSVC_INTRINSICS 0
#endif
MUU_ENABLE_WARNINGS;

#include "impl/header_start.h"
MUU_FORCE_NDEBUG_OPTIMIZATIONS;
MUU_DISABLE_ARITHMETIC_WARNINGS;

namespace muu
{
	namespace build
	{
		/// \brief	True if some math functions (sin, cos, sqrt etc.) can be used in constexpr contexts
		/// 		on this compiler.
		inline constexpr bool supports_constexpr_math = build::supports_is_constant_evaluated;
	}

	/// \addtogroup		math			Math
	/// \brief			Math functions and types.
	/// @{

#if 1 // infinity_or_nan -----------------------------------------------------------------------------------------------
	/// \addtogroup		infinity_or_nan		infinity_or_nan()
	/// \brief			Checks for infinities and not-a-numbers (NaN).
	/// \availability	Older compilers won't provide the necessary machinery for infinity and NaN checks
	/// 				to work in constexpr contexts. You can check for constexpr support by examining
	/// 				build::supports_constexpr_infinity_or_nan.
	/// @{

	/// \cond
	namespace impl
	{
		MUU_PRAGMA_GCC(push_options)
		MUU_PRAGMA_GCC(optimize("-fno-finite-math-only"))

		template <size_t TotalBits, size_t SignificandBits>
		struct infinity_or_nan_traits;

		template <>
		struct infinity_or_nan_traits<16, 11>
		{
			static constexpr auto mask = 0b0111110000000000_u16;
		};

		template <>
		struct infinity_or_nan_traits<32, 24>
		{
			static constexpr auto mask = 0b01111111100000000000000000000000_u32;
		};

		template <>
		struct infinity_or_nan_traits<64, 53>
		{
			static constexpr auto mask = 0b0111111111110000000000000000000000000000000000000000000000000000_u64;
		};

		template <>
		struct infinity_or_nan_traits<80, 64>
		{
			struct mask_type
			{
				uint16_t value[5];
			};
			static constexpr mask_type mask = { 0x0000_u16, 0x0000_u16, 0x0000_u16, 0x8000_u16, 0x7FFF_u16 };

			MUU_NODISCARD
			MUU_ATTR(pure)
			MUU_ALWAYS_INLINE
			static constexpr bool MUU_VECTORCALL check(const mask_type& mask_) noexcept
			{
				return (mask_.value[3] & mask.value[3]) == mask.value[3]
					&& (mask_.value[4] & mask.value[4]) == mask.value[4];
			}
		};

		template <>
		struct infinity_or_nan_traits<128, 64>
		{
	#if MUU_HAS_INT128
			static constexpr uint128_t mask = pack(0x0000000000007FFF_u64, 0x8000000000000000_u64);
	#else
			struct mask_type
			{
				uint64_t value[2];
			};
			static constexpr mask_type mask = { 0x8000000000000000_u64, 0x0000000000007FFF_u64 };

			MUU_NODISCARD
			MUU_ATTR(pure)
			MUU_ALWAYS_INLINE
			static constexpr bool MUU_VECTORCALL check(const mask_type& mask_) noexcept
			{
				return (mask_.value[0] & mask.value[0]) == mask.value[0]
					&& (mask_.value[1] & mask.value[1]) == mask.value[1];
			}

	#endif
		};

		template <>
		struct infinity_or_nan_traits<128, 113>
		{
	#if MUU_HAS_INT128
			static constexpr uint128_t mask = pack(0x7FFF000000000000_u64, 0x0000000000000000_u64);
	#else
			struct mask_type
			{
				uint64_t value[2];
			};
			static constexpr mask_type mask = { 0x0000000000000000_u64, 0x7FFF000000000000_u64 };

			MUU_NODISCARD
			MUU_ATTR(pure)
			MUU_ALWAYS_INLINE
			static constexpr bool MUU_VECTORCALL check(const mask_type& mask_) noexcept
			{
				return (mask_.value[1] & mask.value[1]) == mask.value[1];
			}
	#endif
		};

		template <typename T>
		struct infinity_or_nan_traits_typed
			: infinity_or_nan_traits<sizeof(T) * CHAR_BIT, constants<T>::significand_digits>
		{};

		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr bool MUU_VECTORCALL infinity_or_nan_(T val) noexcept
		{
			static_assert(is_floating_point<T> && !std::is_same_v<T, half>);

			// Q:  "what about fpclassify, isnan, isinf??"
			// A1: They're not constexpr
			// A2: They don't work reliably with -ffast-math
			// A3: https://godbolt.org/z/P9GGdK

			using traits	= infinity_or_nan_traits_typed<T>;
			using mask_type = std::remove_const_t<decltype(traits::mask)>;

			if constexpr (is_integral<mask_type>)
			{
				return (muu::bit_cast<mask_type>(val) & traits::mask) == traits::mask;
			}
			else
			{
				return traits::check(muu::bit_cast<mask_type>(val));
			}
		}

		template <typename T>
		using has_static_infinity_or_nan_ = decltype(static_cast<bool>(T::infinity_or_nan(std::declval<const T&>())));

		template <typename T>
		using has_member_infinity_or_nan_ = decltype(static_cast<bool>(std::declval<const T&>().infinity_or_nan()));

		template <typename T>
		inline constexpr bool has_builtin_infinity_or_nan = false;
		template <typename T, size_t D>
		inline constexpr bool has_builtin_infinity_or_nan<vector<T, D>> = true;
		template <typename T>
		inline constexpr bool has_builtin_infinity_or_nan<quaternion<T>> = true;
		template <typename T, size_t R, size_t C>
		inline constexpr bool has_builtin_infinity_or_nan<matrix<T, R, C>> = true;
		template <typename T>
		inline constexpr bool has_builtin_infinity_or_nan<bounding_box<T>> = true;
		template <typename T>
		inline constexpr bool has_builtin_infinity_or_nan<oriented_bounding_box<T>> = true;

		template <typename T>
		inline constexpr bool has_specialized_infinity_or_nan =
			(std::is_class_v<T> || std::is_union_v<T>)		//
			&&!has_builtin_infinity_or_nan<remove_cvref<T>> //
			&& (is_detected<impl::has_static_infinity_or_nan_, T> || is_detected<impl::has_member_infinity_or_nan_, T>);

		MUU_PRAGMA_GCC(pop_options) // -fno-finite-math-only
	}
	/// \endcond

	/// \brief	Returns true if a float is infinity or NaN.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr bool MUU_VECTORCALL infinity_or_nan(float x) noexcept
	{
		return impl::infinity_or_nan_(x);
	}

	/// \brief	Returns true if a double is infinity or NaN.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr bool MUU_VECTORCALL infinity_or_nan(double x) noexcept
	{
		return impl::infinity_or_nan_(x);
	}

	/// \brief	Returns true if a long double is infinity or NaN.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr bool MUU_VECTORCALL infinity_or_nan(long double x) noexcept
	{
		return impl::infinity_or_nan_(x);
	}

	#if MUU_HAS_FLOAT128

	/// \brief	Returns true if a float128_t is infinity or NaN.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr bool MUU_VECTORCALL infinity_or_nan(float128_t x) noexcept
	{
		return impl::infinity_or_nan_(x);
	}

	#endif

	#if MUU_HAS_FLOAT16

	/// \brief	Returns true if a _Float16 is infinity or NaN.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr bool MUU_VECTORCALL infinity_or_nan(_Float16 x) noexcept
	{
		return impl::infinity_or_nan_(x);
	}

	#endif

	#if MUU_HAS_FP16

	/// \brief	Returns true if a __fp16 is infinity or NaN.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr bool MUU_VECTORCALL infinity_or_nan(__fp16 x) noexcept
	{
		return impl::infinity_or_nan_(x);
	}

	#endif

	/// \brief	Returns true if an arithmetic value is infinity or NaN.
	MUU_CONSTRAINED_TEMPLATE(is_arithmetic<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr bool infinity_or_nan(T x) noexcept
	{
		if constexpr (is_floating_point<T>)
			return impl::infinity_or_nan_(x);
		else
		{
			MUU_UNUSED(x);
			return false;
		}
	}

	/// \brief	Checks if an object is infinity or NaN.
	///
	/// \tparam	T		The object type.
	/// \param 	obj		The object.
	///
	/// \returns	The result `T::infinity_or_nan(obj)` or `obj.infinity_or_nan()` (coerced to bool).
	MUU_CONSTRAINED_TEMPLATE_2(impl::has_specialized_infinity_or_nan<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr bool infinity_or_nan(const T& obj) noexcept
	{
		if constexpr (is_detected<impl::has_static_infinity_or_nan_, T>)
			return static_cast<bool>(T::infinity_or_nan(obj));
		else
			return static_cast<bool>(obj.infinity_or_nan());
	}

	/** @} */ // math::infinity_or_nan
	/** @} */ // math

	namespace build
	{
		/// \brief	True if using infinity_or_nan() in constexpr contexts is supported on this compiler.
		inline constexpr bool supports_constexpr_infinity_or_nan = //
			build::supports_constexpr_bit_cast					   //
			&& (!MUU_CLANG || MUU_CLANG != 12) /* constexpr bit cast seems to be broken in clang 12 */
			;
	}

	/// \addtogroup	math
	/// @{
#endif // infinity_or_nan

#if 1 // abs -----------------------------------------------------------------------------------------------------------
	/// \addtogroup		abs		abs()
	/// \brief			Constexpr-friendly alternatives to std::abs.
	/// @{

	/// \cond
	namespace impl
	{
		MUU_PUSH_PRECISE_MATH;

		template <typename T>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL consteval_abs(T x) noexcept
		{
			static_assert(is_signed<T>);

			if constexpr (is_floating_point<T>)
			{
				if (x == T{}) // negative zero
					return T{};
			}
			return x < T{} ? -x : x;
		}

		MUU_POP_PRECISE_MATH;

		template <typename T>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		MUU_ATTR(flatten)
		constexpr T MUU_VECTORCALL abs_(T x) noexcept
		{
			static_assert(is_signed<T>);

			if (MUU_INTELLISENSE || !build::supports_is_constant_evaluated || is_constant_evaluated())
				return consteval_abs(x);
			else
			{
				if constexpr (0)
					static_assert(always_false<T>);
	#if (MUU_CLANG || MUU_GCC)
				else if constexpr (std::is_same_v<T, float>)
					return __builtin_fabsf(x);
				else if constexpr (std::is_same_v<T, double>)
					return __builtin_fabs(x);
				else if constexpr (std::is_same_v<T, long double>)
					return __builtin_fabsl(x);
	#endif
				else if constexpr (is_standard_arithmetic<T>)
					return std::abs(x);
	#if MUU_HAS_QUADMATH
				else if constexpr (std::is_same_v<float128_t, T>)
					return ::fabsq(x);
	#endif
				else
					return consteval_abs(x);
			}
		}
	}
	/// \endcond

	/// \brief	Returns the absolute value of a float.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr float MUU_VECTORCALL abs(float x) noexcept
	{
		return impl::abs_(x);
	}

	/// \brief	Returns the absolute value of a double.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr double MUU_VECTORCALL abs(double x) noexcept
	{
		return impl::abs_(x);
	}

	/// \brief	Returns the absolute value of a long double.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr long double MUU_VECTORCALL abs(long double x) noexcept
	{
		return impl::abs_(x);
	}

	#if MUU_HAS_FLOAT128

	/// \brief	Returns the absolute value of a float128_t.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr float128_t MUU_VECTORCALL abs(float128_t x) noexcept
	{
		return impl::abs_(x);
	}

	#endif

	#if MUU_HAS_FLOAT16

	/// \brief	Returns the absolute value of a _Float16.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr _Float16 MUU_VECTORCALL abs(_Float16 x) noexcept
	{
		return impl::abs_(x);
	}

	#endif

	#if MUU_HAS_FP16

	/// \brief	Returns the absolute value of an __fp16.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr __fp16 MUU_VECTORCALL abs(__fp16 x) noexcept
	{
		return impl::abs_(x);
	}

	#endif

	/// \brief	Returns the absolute value of a signed char.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr signed char MUU_VECTORCALL abs(signed char x) noexcept
	{
		return static_cast<signed char>(impl::abs_(static_cast<int>(x)));
	}

	/// \brief	Returns the absolute value of a short.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr short MUU_VECTORCALL abs(short x) noexcept
	{
		return static_cast<short>(impl::abs_(static_cast<int>(x)));
	}

	/// \brief	Returns the absolute value of an int.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr int MUU_VECTORCALL abs(int x) noexcept
	{
		return impl::abs_(x);
	}

	/// \brief	Returns the absolute value of a long.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr long MUU_VECTORCALL abs(long x) noexcept
	{
		return impl::abs_(x);
	}

	/// \brief	Returns the absolute value of a long long.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr long long MUU_VECTORCALL abs(long long x) noexcept
	{
		return impl::abs_(x);
	}

	/// \brief	Returns the absolute value of an integral type.
	MUU_CONSTRAINED_TEMPLATE(is_integral<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr T MUU_VECTORCALL abs(T x) noexcept
	{
		if constexpr (is_signed<T>)
			return impl::abs_(x);
		else
			return x;
	}

	/** @} */ // math::abs
#endif		  // abs

#if 1 // approx_equal --------------------------------------------------------------------------------------------------
	/// \addtogroup		approx_equal	approx_equal()
	/// \brief Checks if floating-point values are approximately equal.
	/// @{

	/// \brief	Returns true if two floats are approximately equal.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr bool MUU_VECTORCALL approx_equal(float a, float b, float epsilon = default_epsilon<float>) noexcept
	{
		return abs(b - a) < epsilon;
	}

	/// \brief	Returns true if two doubles are approximately equal.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr bool MUU_VECTORCALL approx_equal(double a, double b, double epsilon = default_epsilon<double>) noexcept
	{
		return abs(b - a) < epsilon;
	}

	/// \brief	Returns true if two long doubles are approximately equal.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr bool MUU_VECTORCALL approx_equal(long double a,
											   long double b,
											   long double epsilon = default_epsilon<long double>) noexcept
	{
		return abs(b - a) < epsilon;
	}

	#if MUU_HAS_FLOAT128

	/// \brief	Returns true if two float128_ts are approximately equal.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr bool MUU_VECTORCALL approx_equal(float128_t a,
											   float128_t b,
											   float128_t epsilon = default_epsilon<float128_t>) noexcept
	{
		return abs(b - a) < epsilon;
	}

	#endif

	#if MUU_HAS_FLOAT16

	/// \brief	Returns true if two _Float16s are approximately equal.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr bool MUU_VECTORCALL approx_equal(_Float16 a,
											   _Float16 b,
											   _Float16 epsilon = default_epsilon<_Float16>) noexcept
	{
		return abs(b - a) < epsilon;
	}

	#endif

	#if MUU_HAS_FP16

	/// \brief	Returns true if two __fp16 are approximately equal.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr bool MUU_VECTORCALL approx_equal(__fp16 a, __fp16 b, __fp16 epsilon = default_epsilon<__fp16>) noexcept
	{
		return abs(b - a) < epsilon;
	}

	#endif

	/// \brief	Returns true if two scalar values are approximately equal.
	/// \remark This reduces to `a == b` for non-float types.
	MUU_CONSTRAINED_TEMPLATE((std::is_scalar_v<T> && std::is_scalar_v<U>), typename T, typename U)
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ALWAYS_INLINE
	constexpr bool MUU_VECTORCALL approx_equal(T a, U b) noexcept
	{
		if constexpr (is_scoped_enum<T> || is_scoped_enum<U>)
			return approx_equal(unwrap(a), unwrap(b));
		else if constexpr (is_floating_point<T> || is_floating_point<U>)
		{
			using type = impl::highest_ranked<T, U>;
			return approx_equal(static_cast<type>(a), static_cast<type>(b));
		}
		else
			return a == b;
	}

	/** @} */ // math::approx_equal
#endif		  // approx_equal

#if 1 // approx_zero ---------------------------------------------------------------------------------------------------
	/// \addtogroup		approx_zero	approx_zero()
	/// \brief Checks if floating-point values are approximately equal to zero.
	/// @{

	/// \brief	Returns true if a float is approximately equal to zero.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ALWAYS_INLINE
	constexpr bool MUU_VECTORCALL approx_zero(float x, float epsilon = default_epsilon<float>) noexcept
	{
		return approx_equal(x, 0.0f, epsilon);
	}

	/// \brief	Returns true if a double is approximately equal to zero.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ALWAYS_INLINE
	constexpr bool MUU_VECTORCALL approx_zero(double x, double epsilon = default_epsilon<double>) noexcept
	{
		return approx_equal(x, 0.0, epsilon);
	}

	/// \brief	Returns true if a long double is approximately equal to zero.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ALWAYS_INLINE
	constexpr bool MUU_VECTORCALL approx_zero(long double x,
											  long double epsilon = default_epsilon<long double>) noexcept
	{
		return approx_equal(x, 0.0L, epsilon);
	}

	#if MUU_HAS_FLOAT128

	/// \brief	Returns true if a float128_t is approximately equal to zero.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ALWAYS_INLINE
	constexpr bool MUU_VECTORCALL approx_zero(float128_t x, float128_t epsilon = default_epsilon<float128_t>) noexcept
	{
		return approx_equal(x, float128_t{}, epsilon);
	}

	#endif

	#if MUU_HAS_FLOAT16

	/// \brief	Returns true if a _Float16 is approximately equal to zero.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ALWAYS_INLINE
	constexpr bool MUU_VECTORCALL approx_zero(_Float16 x, _Float16 epsilon = default_epsilon<_Float16>) noexcept
	{
		return approx_equal(x, _Float16{}, epsilon);
	}

	#endif

	#if MUU_HAS_FP16

	/// \brief	Returns true if a __fp16 is approximately equal to zero.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ALWAYS_INLINE
	constexpr bool MUU_VECTORCALL approx_zero(__fp16 x, __fp16 epsilon = default_epsilon<__fp16>) noexcept
	{
		return approx_equal(x, __fp16{}, epsilon);
	}

	#endif

	/// \brief	Returns true if a scalar value is approximately equal to zero.
	/// \remark This reduces to `a == 0` for non-float types.
	MUU_CONSTRAINED_TEMPLATE(std::is_scalar_v<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ALWAYS_INLINE
	constexpr bool MUU_VECTORCALL approx_zero(T x) noexcept
	{
		static_assert(!is_floating_point<T>); // should have selected a specific overload

		if constexpr (is_scoped_enum<T>)
			return !unwrap(x);
		else
			return !x;
	}

	/** @} */ // math::approx_equal
#endif		  // approx_equal

#if 1 // floor ---------------------------------------------------------------------------------------------------------
	/// \addtogroup		floor		floor()
	/// \brief			Constexpr-friendly alternatives to std::floor.
	/// @{

	/// \cond
	namespace impl
	{
		MUU_PUSH_PRECISE_MATH;

		template <typename T>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL consteval_floor(T x) noexcept
		{
			static_assert(is_floating_point<T>);

			if (x == T{} || x != x) // accounts for -0.0 and NaN
				return x;

			return static_cast<T>(static_cast<intmax_t>(x) - static_cast<intmax_t>(x < static_cast<intmax_t>(x)));
		}

		MUU_POP_PRECISE_MATH;

		template <typename T>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		MUU_ATTR(flatten)
		constexpr T MUU_VECTORCALL floor_(T x) noexcept
		{
			static_assert(is_floating_point<T>);

			if (MUU_INTELLISENSE || !build::supports_is_constant_evaluated || is_constant_evaluated())
				return consteval_floor(x);
			else
			{
				if constexpr (0)
					static_assert(always_false<T>);
	#if MUU_HAS_MSVC_INTRINSICS
				else if constexpr (std::is_same_v<T, float>)
					return __floorf(x);
				else if constexpr (std::is_same_v<T, double>)
					return __floor(x);
				else if constexpr (std::is_same_v<T, long double>)
					return static_cast<long double>(__floor(static_cast<double>(x)));
	#elif (MUU_CLANG || MUU_GCC)
				else if constexpr (std::is_same_v<T, float>)
					return __builtin_floorf(x);
				else if constexpr (std::is_same_v<T, double>)
					return __builtin_floor(x);
				else if constexpr (std::is_same_v<T, long double>)
					return __builtin_floorl(x);
	#endif
				else if constexpr (is_standard_arithmetic<T>)
					return std::floor(x);
	#if MUU_HAS_QUADMATH
				else if constexpr (std::is_same_v<float128_t, T>)
					return ::floorq(x);
	#endif
				else
					return consteval_floor(x);
			}
		}
	}
	/// \endcond

	/// \brief	Returns the floor of a float value.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr float MUU_VECTORCALL floor(float x) noexcept
	{
		return impl::floor_(x);
	}

	/// \brief	Returns the floor of a double value.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr double MUU_VECTORCALL floor(double x) noexcept
	{
		return impl::floor_(x);
	}

	/// \brief	Returns the floor of a long double value.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr long double MUU_VECTORCALL floor(long double x) noexcept
	{
		return impl::floor_(x);
	}

	#if MUU_HAS_FLOAT128

	/// \brief	Returns the floor of a float128_t value.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr float128_t MUU_VECTORCALL floor(float128_t x) noexcept
	{
		return impl::floor_(x);
	}

	#endif

	#if MUU_HAS_FLOAT16

	/// \brief	Returns the floor of a _Float16 value.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr _Float16 MUU_VECTORCALL floor(_Float16 x) noexcept
	{
		return impl::floor_(x);
	}

	#endif

	#if MUU_HAS_FP16

	/// \brief	Returns the floor of a __fp16 value.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr __fp16 MUU_VECTORCALL floor(__fp16 x) noexcept
	{
		return impl::floor_(x);
	}

	#endif

	/// \brief	Returns the floor of an integral value.
	MUU_CONSTRAINED_TEMPLATE(is_integral<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr double MUU_VECTORCALL floor(T x) noexcept
	{
		return impl::floor_(static_cast<double>(x));
	}

	/** @} */ // math::floor
#endif		  // floor

#if 1 // ceil ----------------------------------------------------------------------------------------------------------
	/// \addtogroup		ceil		ceil()
	/// \brief			Constexpr-friendly alternatives to std::ceil.
	/// @{

	/// \cond
	namespace impl
	{
		MUU_PUSH_PRECISE_MATH;

		template <typename T>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL consteval_ceil(T x) noexcept
		{
			static_assert(is_floating_point<T>);

			if (x == T{} || x != x) // accounts for -0.0 and NaN
				return x;

			return static_cast<T>(static_cast<intmax_t>(x) + static_cast<intmax_t>(x > static_cast<intmax_t>(x)));
		}

		MUU_POP_PRECISE_MATH;

		template <typename T>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		MUU_ATTR(flatten)
		constexpr T MUU_VECTORCALL ceil_(T x) noexcept
		{
			static_assert(is_floating_point<T>);

			if (MUU_INTELLISENSE || !build::supports_is_constant_evaluated || is_constant_evaluated())
				return consteval_ceil(x);
			else
			{
				if constexpr (0)
					static_assert(always_false<T>);
	#if MUU_HAS_MSVC_INTRINSICS
				else if constexpr (std::is_same_v<T, float>)
					return __ceilf(x);
				else if constexpr (std::is_same_v<T, double>)
					return __ceil(x);
				else if constexpr (std::is_same_v<T, long double>)
					return static_cast<long double>(__ceil(static_cast<double>(x)));
	#elif (MUU_CLANG || MUU_GCC)
				else if constexpr (std::is_same_v<T, float>)
					return __builtin_ceilf(x);
				else if constexpr (std::is_same_v<T, double>)
					return __builtin_ceil(x);
				else if constexpr (std::is_same_v<T, long double>)
					return __builtin_ceill(x);
	#endif
				else if constexpr (is_standard_arithmetic<T>)
					return std::ceil(x);
	#if MUU_HAS_QUADMATH
				else if constexpr (std::is_same_v<float128_t, T>)
					return ::ceilq(x);
	#endif
				else
					return consteval_ceil(x);
			}
		}
	}
	/// \endcond

	/// \brief	Returns the ceiling of a float value.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr float MUU_VECTORCALL ceil(float x) noexcept
	{
		return impl::ceil_(x);
	}

	/// \brief	Returns the ceiling of a double value.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr double MUU_VECTORCALL ceil(double x) noexcept
	{
		return impl::ceil_(x);
	}

	/// \brief	Returns the ceiling of a long double value.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr long double MUU_VECTORCALL ceil(long double x) noexcept
	{
		return impl::ceil_(x);
	}

	#if MUU_HAS_FLOAT128

	/// \brief	Returns the ceiling of a float128_t value.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr float128_t MUU_VECTORCALL ceil(float128_t x) noexcept
	{
		return impl::ceil_(x);
	}

	#endif

	#if MUU_HAS_FLOAT16

	/// \brief	Returns the ceiling of a _Float16 value.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr _Float16 MUU_VECTORCALL ceil(_Float16 x) noexcept
	{
		return impl::ceil_(x);
	}

	#endif

	#if MUU_HAS_FP16

	/// \brief	Returns the ceiling of a __fp16 value.
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr __fp16 MUU_VECTORCALL ceil(__fp16 x) noexcept
	{
		return impl::ceil_(x);
	}

	#endif

	/// \brief	Returns the ceiling of an integral value.
	MUU_CONSTRAINED_TEMPLATE(is_integral<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr double MUU_VECTORCALL ceil(T x) noexcept
	{
		return impl::ceil_(static_cast<double>(x));
	}

	/** @} */ // math::ceil
#endif		  // ceil

#if 1 // sqrt ----------------------------------------------------------------------------------------------------------
	/// \addtogroup		sqrt	sqrt()
	/// \brief			Constexpr-friendly alternatives to std::sqrt.
	/// \availability	Older compilers won't provide the necessary machinery for sqrt to work in constexpr contexts.
	/// 				You can check for constexpr support by examining build::supports_constexpr_math.
	/// @{

	/// \cond
	namespace impl
	{
		// this is way too high on purpose- the algorithms early-out
		inline constexpr intmax_t max_constexpr_math_iterations = 100;

		MUU_PUSH_PRECISE_MATH;

		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL consteval_sqrt(T x)
		{
			MUU_FMA_BLOCK;
			static_assert(std::is_same_v<impl::highest_ranked<T, long double>, T>);

			if (x == T{} || x != x) // accounts for -0.0 and NaN
				return x;
			if (x < T{})
			{
	#if MUU_HAS_EXCEPTIONS
				throw "consteval_sqrt() input out-of-range"; // force compilation failure
	#else
				return constants<T>::nan;
	#endif
			}
			if (x == T{ 1 })
				return T{ 1 };

			// Newton-Raphson method: https://en.wikipedia.org/wiki/Newton%27s_method
			T curr = x;
			T prev = T{};
			for (intmax_t i = 0; i < max_constexpr_math_iterations && curr != prev; i++)
			{
				MUU_FMA_BLOCK;
				prev = curr;
				curr = constants<T>::one_over_two * (curr + x / curr);
			}
			return curr;
		}

		MUU_POP_PRECISE_MATH;

		template <typename T>
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL sqrt_(T x) noexcept
		{
			static_assert(is_floating_point<T> && !std::is_same_v<T, half>);

			if (MUU_INTELLISENSE || (build::supports_is_constant_evaluated && is_constant_evaluated()))
			{
				using type = highest_ranked<T, long double>;
				return static_cast<T>(consteval_sqrt<type>(x));
			}
			else
			{
				if constexpr (is_standard_arithmetic<T>)
					return std::sqrt(x);
	#if MUU_HAS_QUADMATH
				else if constexpr (std::is_same_v<float128_t, T>)
					return ::sqrtq(x);
	#endif
				else
					return static_cast<T>(std::sqrt(static_cast<clamp_to_standard_float<T>>(x)));
			}
		}
	}
	/// \endcond

	/// \brief	Returns the square-root of a float.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr float MUU_VECTORCALL sqrt(float x) noexcept
	{
		return impl::sqrt_(x);
	}

	/// \brief	Returns the square-root of a double.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr double MUU_VECTORCALL sqrt(double x) noexcept
	{
		return impl::sqrt_(x);
	}

	/// \brief	Returns the square-root of a long double.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr long double MUU_VECTORCALL sqrt(long double x) noexcept
	{
		return impl::sqrt_(x);
	}

	#if MUU_HAS_FLOAT128

	/// \brief	Returns the square-root of a float128_t.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr float128_t MUU_VECTORCALL sqrt(float128_t x) noexcept
	{
		return impl::sqrt_(x);
	}

	#endif

	#if MUU_HAS_FLOAT16

	/// \brief	Returns the square-root of a _Float16.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr _Float16 MUU_VECTORCALL sqrt(_Float16 x) noexcept
	{
		return impl::sqrt_(x);
	}

	#endif

	#if MUU_HAS_FP16

	/// \brief	Returns the square-root of a __fp16.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr __fp16 MUU_VECTORCALL sqrt(__fp16 x) noexcept
	{
		return impl::sqrt_(x);
	}

	#endif

	/// \brief	Returns the square-root of an integral value.
	MUU_CONSTRAINED_TEMPLATE(is_integral<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr double MUU_VECTORCALL sqrt(T x) noexcept
	{
		return impl::sqrt_(static_cast<double>(x));
	}

	/** @} */ // math::sqrt
#endif		  // sqrt

#if 1 // cos -----------------------------------------------------------------------------------------------------------
	/// \addtogroup		cos		cos()
	/// \brief			Constexpr-friendly alternatives to std::cos.
	/// \availability	Older compilers won't provide the necessary machinery for trig functions to work in constexpr
	/// 				contexts. You can check for constexpr support by examining build::supports_constexpr_math.
	/// @{

	/// \cond
	namespace impl
	{
		MUU_PUSH_PRECISE_MATH;

		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL consteval_sin(T);

		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL consteval_tan(T);

		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL consteval_cos(T x)
		{
			MUU_FMA_BLOCK;
			static_assert(std::is_same_v<impl::highest_ranked<T, long double>, T>);

			if (x < T{} || x > constants<T>::two_pi) // normalize to [0, 2 pi]
				x -= constants<T>::two_pi * floor_(x * constants<T>::one_over_two_pi);
			if (x == T{} || x == constants<T>::two_pi)
				return T{ 1 };
			if (x == constants<T>::pi_over_two || x == constants<T>::three_pi_over_two)
				return T{};
			if (x == constants<T>::pi)
				return T{ -1 };

			// reduce input range for faster convergence
			// (see http://mathonweb.com/help_ebook/html/algorithms.htm)
			if (x > constants<T>::pi_over_two && x < constants<T>::pi) // quadrant 2
				return -consteval_cos(constants<T>::pi - x);
			if (x > constants<T>::pi && x < constants<T>::three_pi_over_two) // quadrant 3
				return -consteval_cos(x - constants<T>::pi);
			if (x > constants<T>::three_pi_over_two && x < constants<T>::two_pi) // quadrant 4
				return consteval_cos(constants<T>::two_pi - x);
			if (x > constants<T>::pi_over_four && x < constants<T>::pi_over_two)
				return consteval_sin(constants<T>::pi_over_two - x);

			// taylor series: https://en.wikipedia.org/wiki/Taylor_series#Trigonometric_functions
			T term = -x * x / T{ 2 };
			T sum  = T{ 1 } + term;
			for (intmax_t i = 2; i < max_constexpr_math_iterations; i++)
			{
				MUU_FMA_BLOCK;
				const auto prev = sum;
				term *= -x * x / (T{ 2 } * i * (T{ 2 } * i - T{ 1 }));
				sum += term;
				if (sum == prev)
					break;
			}
			return sum;
		}

		MUU_POP_PRECISE_MATH;

		template <typename T>
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL cos_(T x) noexcept
		{
			static_assert(is_floating_point<T> && !std::is_same_v<T, half>);

			if (MUU_INTELLISENSE || (build::supports_is_constant_evaluated && is_constant_evaluated()))
			{
				using type = highest_ranked<T, long double>;
				return static_cast<T>(consteval_cos(static_cast<type>(x)));
			}
			else
			{
				if constexpr (is_standard_arithmetic<T>)
					return std::cos(x);
	#if MUU_HAS_QUADMATH
				else if constexpr (std::is_same_v<float128_t, T>)
					return ::cosq(x);
	#endif
				else
					return static_cast<T>(std::cos(static_cast<clamp_to_standard_float<T>>(x)));
			}
		}
	}
	/// \endcond

	/// \brief	Returns the cosine of a float.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr float MUU_VECTORCALL cos(float x) noexcept
	{
		return impl::cos_(x);
	}

	/// \brief	Returns the cosine of a double.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr double MUU_VECTORCALL cos(double x) noexcept
	{
		return impl::cos_(x);
	}

	/// \brief	Returns the cosine of a long double.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr long double MUU_VECTORCALL cos(long double x) noexcept
	{
		return impl::cos_(x);
	}

	#if MUU_HAS_FLOAT128

	/// \brief	Returns the cosine of a float128_t.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr float128_t MUU_VECTORCALL cos(float128_t x) noexcept
	{
		return impl::cos_(x);
	}

	#endif

	#if MUU_HAS_FLOAT16

	/// \brief	Returns the cosine of a _Float16.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr _Float16 MUU_VECTORCALL cos(_Float16 x) noexcept
	{
		return impl::cos_(x);
	}

	#endif

	#if MUU_HAS_FP16

	/// \brief	Returns the cosine of a __fp16.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr __fp16 MUU_VECTORCALL cos(__fp16 x) noexcept
	{
		return impl::cos_(x);
	}

	#endif

	/// \brief	Returns the cosine of an integral value.
	MUU_CONSTRAINED_TEMPLATE(is_integral<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr double MUU_VECTORCALL cos(T x) noexcept
	{
		return impl::cos_(static_cast<double>(x));
	}

	/** @} */ // math::cos
#endif		  // cos

#if 1 // sin -----------------------------------------------------------------------------------------------------------
	/// \addtogroup		sin		sin()
	/// \brief			Constexpr-friendly alternatives to std::sin.
	/// \availability	Older compilers won't provide the necessary machinery for trig functions to work in constexpr
	/// 				contexts. You can check for constexpr support by examining build::supports_constexpr_math.
	/// @{

	/// \cond
	namespace impl
	{
		MUU_PUSH_PRECISE_MATH;

		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL consteval_sin(T x)
		{
			MUU_FMA_BLOCK;
			static_assert(std::is_same_v<impl::highest_ranked<T, long double>, T>);

			if (x == T{} || x != x) // accounts for -0.0 and NaN
				return x;
			if (x < T{} || x > constants<T>::two_pi) // normalize to [0, 2 pi]
				x -= constants<T>::two_pi * floor_(x * constants<T>::one_over_two_pi);
			if (x == constants<T>::pi)
				return T{};
			if (x == constants<T>::pi_over_two)
				return T{ 1 };
			if (x == constants<T>::three_pi_over_two)
				return T{ -1 };

			// reduce input range for faster convergence
			// (see http://mathonweb.com/help_ebook/html/algorithms.htm)
			if (x > constants<T>::pi_over_two && x < constants<T>::pi) // quadrant 2
				return consteval_sin(constants<T>::pi - x);
			if (x > constants<T>::pi && x < constants<T>::three_pi_over_two) // quadrant 3
				return -consteval_sin(x - constants<T>::pi);
			if (x > constants<T>::three_pi_over_two && x < constants<T>::two_pi) // quadrant 4
				return -consteval_sin(constants<T>::two_pi - x);
			if (x > constants<T>::pi_over_four && x < constants<T>::pi_over_two)
				return consteval_cos(constants<T>::pi_over_two - x);

			// taylor series: https://en.wikipedia.org/wiki/Taylor_series#Trigonometric_functions
			T term	 = x;
			T sum	 = x;
			int sign = -1;
			for (intmax_t i = 3; i < max_constexpr_math_iterations * 2; i += 2, sign = -sign)
			{
				MUU_FMA_BLOCK;
				const auto prev = sum;
				term			= -term * x * x / (i * (i - T{ 1 }));
				sum += term;
				if (sum == prev)
					break;
			}
			return sum;
		}

		MUU_POP_PRECISE_MATH;

		template <typename T>
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL sin_(T x) noexcept
		{
			static_assert(is_floating_point<T> && !std::is_same_v<T, half>);

			if (MUU_INTELLISENSE || (build::supports_is_constant_evaluated && is_constant_evaluated()))
			{
				using type = highest_ranked<T, long double>;
				return static_cast<T>(consteval_sin(static_cast<type>(x)));
			}
			else
			{
				if constexpr (is_standard_arithmetic<T>)
					return std::sin(x);
	#if MUU_HAS_QUADMATH
				else if constexpr (std::is_same_v<float128_t, T>)
					return ::sinq(x);
	#endif
				else
					return static_cast<T>(std::sin(static_cast<clamp_to_standard_float<T>>(x)));
			}
		}
	}
	/// \endcond

	/// \brief	Returns the sine of a float.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr float MUU_VECTORCALL sin(float x) noexcept
	{
		return impl::sin_(x);
	}

	/// \brief	Returns the sine of a double.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr double MUU_VECTORCALL sin(double x) noexcept
	{
		return impl::sin_(x);
	}

	/// \brief	Returns the sine of a long double.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr long double MUU_VECTORCALL sin(long double x) noexcept
	{
		return impl::sin_(x);
	}

	#if MUU_HAS_FLOAT128

	/// \brief	Returns the sine of a float128_t.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr float128_t MUU_VECTORCALL sin(float128_t x) noexcept
	{
		return impl::sin_(x);
	}

	#endif

	#if MUU_HAS_FLOAT16

	/// \brief	Returns the sine of a _Float16.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr _Float16 MUU_VECTORCALL sin(_Float16 x) noexcept
	{
		return impl::sin_(x);
	}

	#endif

	#if MUU_HAS_FP16

	/// \brief	Returns the sine of a __fp16.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr __fp16 MUU_VECTORCALL sin(__fp16 x) noexcept
	{
		return impl::sin_(x);
	}

	#endif

	/// \brief	Returns the sine of an integral value.
	MUU_CONSTRAINED_TEMPLATE(is_integral<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr double MUU_VECTORCALL sin(T x) noexcept
	{
		return impl::sin_(static_cast<double>(x));
	}

	/** @} */ // math::sin
#endif		  // sin

#if 1 // tan -----------------------------------------------------------------------------------------------------------
	/// \addtogroup		tan		tan()
	/// \brief			Constexpr-friendly alternatives to std::tan.
	/// \availability	Older compilers won't provide the necessary machinery for trig functions to work in constexpr
	/// 				contexts. You can check for constexpr support by examining build::supports_constexpr_math.
	/// @{

	/// \cond
	namespace impl
	{
		MUU_PUSH_PRECISE_MATH;

		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL consteval_tan(T x)
		{
			MUU_FMA_BLOCK;
			static_assert(std::is_same_v<impl::highest_ranked<T, long double>, T>);

			if (x == T{} || x != x) // accounts for -0.0 and NaN
				return x;
			if (x < T{} || x > constants<T>::pi) // normalize to [0, pi]
				x -= constants<T>::pi * floor_(x * constants<T>::one_over_pi);
			if (x == constants<T>::pi)
				return T{};
			// if (x == constants<T>::pi_over_two)
			//	return static_cast<T>(16331239353195370.0L);
			if (x == constants<T>::pi_over_four)
				return T{ 1 };
			if (x == constants<T>::pi_over_eight)
				return constants<T>::sqrt_two - T{ 1 };

			// reduce input range for faster convergence
			// (see http://mathonweb.com/help_ebook/html/algorithms.htm)
			if (x > constants<T>::pi_over_two && x < constants<T>::pi) // quadrant 2
				return -consteval_tan(constants<T>::pi - x);
			if (x > constants<T>::pi_over_four && x < constants<T>::pi_over_two)
				return T{ 1 } / consteval_tan(constants<T>::pi_over_two - x);
			if (x > constants<T>::pi_over_eight && x < constants<T>::pi_over_four)
			{
				MUU_FMA_BLOCK;
				const auto x_ = consteval_tan(x / T{ 2 });
				return (x_ + x_) / (T{ 1 } - x_ * x_);
			}

			return consteval_sin(x) / consteval_cos(x);
		}

		MUU_POP_PRECISE_MATH;

		template <typename T>
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL tan_(T x) noexcept
		{
			static_assert(is_floating_point<T> && !std::is_same_v<T, half>);

			if (MUU_INTELLISENSE || (build::supports_is_constant_evaluated && is_constant_evaluated()))
			{
				using type = highest_ranked<T, long double>;
				return static_cast<T>(consteval_tan(static_cast<type>(x)));
			}
			else
			{
				if constexpr (is_standard_arithmetic<T>)
					return std::tan(x);
	#if MUU_HAS_QUADMATH
				else if constexpr (std::is_same_v<float128_t, T>)
					return ::tanq(x);
	#endif
				else
					return static_cast<T>(std::tan(static_cast<clamp_to_standard_float<T>>(x)));
			}
		}
	}
	/// \endcond

	/// \brief	Returns the tangent of a float.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr float MUU_VECTORCALL tan(float x) noexcept
	{
		return impl::tan_(x);
	}

	/// \brief	Returns the tangent of a double.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr double MUU_VECTORCALL tan(double x) noexcept
	{
		return impl::tan_(x);
	}

	/// \brief	Returns the tangent of a long double.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr long double MUU_VECTORCALL tan(long double x) noexcept
	{
		return impl::tan_(x);
	}

	#if MUU_HAS_FLOAT128

	/// \brief	Returns the tangent of a float128_t.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr float128_t MUU_VECTORCALL tan(float128_t x) noexcept
	{
		return impl::tan_(x);
	}

	#endif

	#if MUU_HAS_FLOAT16

	/// \brief	Returns the tangent of a _Float16.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr _Float16 MUU_VECTORCALL tan(_Float16 x) noexcept
	{
		return impl::tan_(x);
	}

	#endif

	#if MUU_HAS_FP16

	/// \brief	Returns the tangent of a __fp16.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr __fp16 MUU_VECTORCALL tan(__fp16 x) noexcept
	{
		return impl::tan_(x);
	}

	#endif

	/// \brief	Returns the tangent of an integral value.
	MUU_CONSTRAINED_TEMPLATE(is_integral<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr double MUU_VECTORCALL tan(T x) noexcept
	{
		return impl::tan_(static_cast<double>(x));
	}

	/** @} */ // math::tan
#endif		  // tan

#if 1 // acos ----------------------------------------------------------------------------------------------------------
	/// \addtogroup		acos		acos()
	/// \brief			Constexpr-friendly alternatives to std::acos.
	/// \availability	Older compilers won't provide the necessary machinery for trig functions to work in constexpr
	/// 				contexts. You can check for constexpr support by examining build::supports_constexpr_math.
	/// @{

	/// \cond
	namespace impl
	{
		MUU_PUSH_PRECISE_MATH;

		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL consteval_asin(T);

		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL consteval_atan(T);

		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL consteval_acos(T x)
		{
			static_assert(std::is_same_v<impl::highest_ranked<T, long double>, T>);

			if (!between(x, T{ -1 }, T{ 1 }))
			{
	#if MUU_HAS_EXCEPTIONS
				throw "consteval_acos() input out-of-range"; // force compilation failure
	#else
				return constants<T>::nan;
	#endif
			}
			if (x == T{ -1 })
				return constants<T>::pi;
			if (x == T{ 1 })
				return constants<T>::zero;

			return constants<T>::pi_over_two - consteval_asin(x);
		}

		MUU_POP_PRECISE_MATH;

		template <typename T>
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL acos_(T x) noexcept
		{
			static_assert(is_floating_point<T> && !std::is_same_v<T, half>);

			if (MUU_INTELLISENSE || (build::supports_is_constant_evaluated && is_constant_evaluated()))
			{
				using type = highest_ranked<T, long double>;
				return static_cast<T>(consteval_acos(static_cast<type>(x)));
			}
			else
			{
				if constexpr (is_standard_arithmetic<T>)
					return std::acos(x);
	#if MUU_HAS_QUADMATH
				else if constexpr (std::is_same_v<float128_t, T>)
					return ::acosq(x);
	#endif
				else
					return static_cast<T>(std::acos(static_cast<clamp_to_standard_float<T>>(x)));
			}
		}
	}
	/// \endcond

	/// \brief	Returns the arc cosine of a float.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr float MUU_VECTORCALL acos(float x) noexcept
	{
		return impl::acos_(x);
	}

	/// \brief	Returns the arc cosine of a double.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr double MUU_VECTORCALL acos(double x) noexcept
	{
		return impl::acos_(x);
	}

	/// \brief	Returns the arc cosine of a long double.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr long double MUU_VECTORCALL acos(long double x) noexcept
	{
		return impl::acos_(x);
	}

	#if MUU_HAS_FLOAT128

	/// \brief	Returns the arc cosine of a float128_t.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr float128_t MUU_VECTORCALL acos(float128_t x) noexcept
	{
		return impl::acos_(x);
	}

	#endif

	#if MUU_HAS_FLOAT16

	/// \brief	Returns the arc cosine of a _Float16.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr _Float16 MUU_VECTORCALL acos(_Float16 x) noexcept
	{
		return impl::acos_(x);
	}

	#endif

	#if MUU_HAS_FP16

	/// \brief	Returns the arc cosine of a __fp16.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr __fp16 MUU_VECTORCALL acos(__fp16 x) noexcept
	{
		return impl::acos_(x);
	}

	#endif

	/// \brief	Returns the arc cosine of an integral value.
	MUU_CONSTRAINED_TEMPLATE(is_integral<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr double MUU_VECTORCALL acos(T x) noexcept
	{
		return impl::acos_(static_cast<double>(x));
	}

	/** @} */ // math::acos
#endif		  // acos

#if 1 // asin ----------------------------------------------------------------------------------------------------------
	/// \addtogroup		asin		asin()
	/// \brief			Constexpr-friendly alternatives to std::asin.
	/// \availability	Older compilers won't provide the necessary machinery for trig functions to work in constexpr
	/// 				contexts. You can check for constexpr support by examining build::supports_constexpr_math.
	/// @{

	/// \cond
	namespace impl
	{
		MUU_PUSH_PRECISE_MATH;

		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL consteval_asin(T x)
		{
			MUU_FMA_BLOCK;
			static_assert(std::is_same_v<impl::highest_ranked<T, long double>, T>);

			if (x == T{} || x != x) // accounts for -0.0 and NaN
				return x;
			if (!between(x, T{ -1 }, T{ 1 }))
			{
	#if MUU_HAS_EXCEPTIONS
				throw "consteval_asin() input out-of-range"; // force compilation failure
	#else
				return constants<T>::nan;
	#endif
			}
			if (x == T{ -1 })
				return -constants<T>::pi_over_two;
			if (x == T{ 1 })
				return constants<T>::pi_over_two;

			// use trig identities outside of [-1/sqrt(2), 1/sqrt(2)] for faster convergence
			// (see: https://stackoverflow.com/a/20196782)
			if (x > constants<T>::one_over_sqrt_two)
				return constants<T>::pi_over_two - consteval_asin(consteval_sqrt(T{ 1 } - x * x));
			if (x < -constants<T>::one_over_sqrt_two)
				return -constants<T>::pi_over_two + consteval_asin(consteval_sqrt(T{ 1 } - x * x));

			// taylor series: https://en.wikipedia.org/wiki/Taylor_series#Trigonometric_functions
			T sum  = x;
			T term = x * x * x / T{ 2 };
			for (intmax_t i = 1; i < max_constexpr_math_iterations * 2; i += 2)
			{
				MUU_FMA_BLOCK;
				const T prev = sum;
				sum += term * static_cast<T>(i) / static_cast<T>(i + 2);
				term *= x * x * static_cast<T>(i) / static_cast<T>(i + 3);
				if (prev == sum)
					break;
			}
			return sum;
		}

		MUU_POP_PRECISE_MATH;

		template <typename T>
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL asin_(T x) noexcept
		{
			static_assert(is_floating_point<T> && !std::is_same_v<T, half>);

			if (MUU_INTELLISENSE || (build::supports_is_constant_evaluated && is_constant_evaluated()))
			{
				using type = highest_ranked<T, long double>;
				return static_cast<T>(consteval_asin(static_cast<type>(x)));
			}
			else
			{
				if constexpr (is_standard_arithmetic<T>)
					return std::asin(x);
	#if MUU_HAS_QUADMATH
				else if constexpr (std::is_same_v<float128_t, T>)
					return ::asinq(x);
	#endif
				else
					return static_cast<T>(std::asin(static_cast<clamp_to_standard_float<T>>(x)));
			}
		}
	}
	/// \endcond

	/// \brief	Returns the arc sine of a float.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr float MUU_VECTORCALL asin(float x) noexcept
	{
		return impl::asin_(x);
	}

	/// \brief	Returns the arc sine of a double.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr double MUU_VECTORCALL asin(double x) noexcept
	{
		return impl::asin_(x);
	}

	/// \brief	Returns the arc sine of a long double.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr long double MUU_VECTORCALL asin(long double x) noexcept
	{
		return impl::asin_(x);
	}

	#if MUU_HAS_FLOAT128

	/// \brief	Returns the arc sine of a float128_t.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr float128_t MUU_VECTORCALL asin(float128_t x) noexcept
	{
		return impl::asin_(x);
	}

	#endif

	#if MUU_HAS_FLOAT16

	/// \brief	Returns the arc sine of a _Float16.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr _Float16 MUU_VECTORCALL asin(_Float16 x) noexcept
	{
		return impl::asin_(x);
	}

	#endif

	#if MUU_HAS_FP16

	/// \brief	Returns the arc sine of a __fp16.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr __fp16 MUU_VECTORCALL asin(__fp16 x) noexcept
	{
		return impl::asin_(x);
	}

	#endif

	/// \brief	Returns the arc sine of an integral value.
	MUU_CONSTRAINED_TEMPLATE(is_integral<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr double MUU_VECTORCALL asin(T x) noexcept
	{
		return impl::asin_(static_cast<double>(x));
	}

	/** @} */ // math::asin
#endif		  // asin

#if 1 // atan ----------------------------------------------------------------------------------------------------------
	/// \addtogroup		atan		atan()
	/// \brief			Constexpr-friendly alternatives to std::atan.
	/// \availability	Older compilers won't provide the necessary machinery for trig functions to work in constexpr
	/// 				contexts. You can check for constexpr support by examining build::supports_constexpr_math.
	/// @{

	/// \cond
	namespace impl
	{
		MUU_PUSH_PRECISE_MATH;

		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL consteval_atan(T x)
		{
			MUU_FMA_BLOCK;
			static_assert(std::is_same_v<impl::highest_ranked<T, long double>, T>);

			if (x == T{} || x != x) // accounts for -0.0 and NaN
				return x;
			if (x == constants<T>::infinity)
				return constants<T>::pi_over_two;
			if (x == constants<T>::negative_infinity)
				return -constants<T>::pi_over_two;
			if (x == T{ 1 })
				return constants<T>::pi_over_four;

			// reduce the input value range for faster convergence
			// (see http://mathonweb.com/help_ebook/html/algorithms.htm)
			if (x < T{})
				return -consteval_atan(-x);
			if (x > T{ 1 })
				return constants<T>::pi_over_two - consteval_atan(T{ 1 } / x);
			if (x > (T{ 2 } - constants<T>::sqrt_three))
				return constants<T>::pi_over_six
					 + consteval_atan(((constants<T>::sqrt_three * x) - T{ 1 }) / (constants<T>::sqrt_three + x));

			// Euler's series: https://en.wikipedia.org/wiki/Inverse_trigonometric_functions#Infinite_series
			const auto x_sq = x * x;
			const auto mult = x / (T{ 1 } + x_sq);
			T prod			= T{ 1 };
			T sum			= T{ 1 };
			for (intmax_t i = 1; i <= max_constexpr_math_iterations; i++)
			{
				MUU_FMA_BLOCK;
				const T prev = sum;
				prod *= (T{ 2 } * static_cast<T>(i) * x_sq) / ((T{ 2 } * static_cast<T>(i) + T{ 1 }) * (x_sq + T{ 1 }));
				sum += prod;
				if (sum == prev)
					break;
			}
			return sum * mult;
		}

		MUU_POP_PRECISE_MATH;

		template <typename T>
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL atan_(T x) noexcept
		{
			static_assert(is_floating_point<T> && !std::is_same_v<T, half>);

			if (MUU_INTELLISENSE || (build::supports_is_constant_evaluated && is_constant_evaluated()))
			{
				using type = highest_ranked<T, long double>;
				return static_cast<T>(consteval_atan(static_cast<type>(x)));
			}
			else
			{
				if constexpr (is_standard_arithmetic<T>)
					return std::atan(x);
	#if MUU_HAS_QUADMATH
				else if constexpr (std::is_same_v<float128_t, T>)
					return ::atanq(x);
	#endif
				else
					return static_cast<T>(std::atan(static_cast<clamp_to_standard_float<T>>(x)));
			}
		}
	}
	/// \endcond

	/// \brief	Returns the arc tangent of a float.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr float MUU_VECTORCALL atan(float x) noexcept
	{
		return impl::atan_(x);
	}

	/// \brief	Returns the arc tangent of a double.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr double MUU_VECTORCALL atan(double x) noexcept
	{
		return impl::atan_(x);
	}

	/// \brief	Returns the arc tangent of a long double.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr long double MUU_VECTORCALL atan(long double x) noexcept
	{
		return impl::atan_(x);
	}

	#if MUU_HAS_FLOAT128

	/// \brief	Returns the arc tangent of a float128_t.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr float128_t MUU_VECTORCALL atan(float128_t x) noexcept
	{
		return impl::atan_(x);
	}

	#endif

	#if MUU_HAS_FLOAT16

	/// \brief	Returns the arc tangent of a _Float16.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr _Float16 MUU_VECTORCALL atan(_Float16 x) noexcept
	{
		return impl::atan_(x);
	}

	#endif

	#if MUU_HAS_FP16

	/// \brief	Returns the arc tangent of a __fp16.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr __fp16 MUU_VECTORCALL atan(__fp16 x) noexcept
	{
		return impl::atan_(x);
	}

	#endif

	/// \brief	Returns the arc tangent of an integral value.
	MUU_CONSTRAINED_TEMPLATE(is_integral<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr double MUU_VECTORCALL atan(T x) noexcept
	{
		return impl::atan_(static_cast<double>(x));
	}

	/** @} */ // math::atan
#endif		  // atan

#if 1 // atan2 ---------------------------------------------------------------------------------------------------------
	/// \addtogroup		atan2		atan2()
	/// \brief			Constexpr-friendly alternatives to std::atan2.
	/// \availability	Older compilers won't provide the necessary machinery for trig functions to work in constexpr
	/// 				contexts. You can check for constexpr support by examining build::supports_constexpr_math.
	/// @{

	/// \cond
	namespace impl
	{
		MUU_PUSH_PRECISE_MATH;

		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL consteval_atan2(T y, T x)
		{
			static_assert(std::is_same_v<impl::highest_ranked<T, long double>, T>);

			if (x != x) // nan
				return x;
			if (y != y) // nan
				return y;

			// https://en.wikipedia.org/wiki/Atan2
			if (x > T{})
				return consteval_atan(y / x);
			if (x < T{} && y >= T{})
				return consteval_atan(y / x) + constants<T>::pi;
			if (x < T{} && y < T{})
				return consteval_atan(y / x) - constants<T>::pi;
			if (x == T{} && y > T{})
				return constants<T>::pi_over_two;
			if (x == T{} && y < T{})
				return -constants<T>::pi_over_two;

	#if MUU_HAS_EXCEPTIONS
			throw "consteval_atan2() input out-of-range"; // force compilation failure
	#else
			return constants<T>::nan;
	#endif
		}

		MUU_POP_PRECISE_MATH;

		template <typename T>
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL atan2_(T y, T x) noexcept
		{
			static_assert(is_floating_point<T> && !std::is_same_v<T, half>);

			if (MUU_INTELLISENSE || (build::supports_is_constant_evaluated && is_constant_evaluated()))
			{
				using type = highest_ranked<T, long double>;
				return static_cast<T>(consteval_atan2(static_cast<type>(y), static_cast<type>(x)));
			}
			else
			{
				if constexpr (is_standard_arithmetic<T>)
					return std::atan2(y, x);
	#if MUU_HAS_QUADMATH
				else if constexpr (std::is_same_v<float128_t, T>)
					return ::atan2q(y, x);
	#endif
				else
				{
					using type = clamp_to_standard_float<T>;
					return static_cast<T>(std::atan2(static_cast<type>(y), static_cast<type>(x)));
				}
			}
		}
	}
	/// \endcond

	/// \brief	Returns the arc tangent of a float.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr float MUU_VECTORCALL atan2(float y, float x) noexcept
	{
		return impl::atan2_(y, x);
	}

	/// \brief	Returns the arc tangent of a double.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr double MUU_VECTORCALL atan2(double y, double x) noexcept
	{
		return impl::atan2_(y, x);
	}

	/// \brief	Returns the arc tangent of a long double.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr long double MUU_VECTORCALL atan2(long double y, long double x) noexcept
	{
		return impl::atan2_(y, x);
	}

	#if MUU_HAS_FLOAT128

	/// \brief	Returns the arc tangent of a float128_t.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr float128_t MUU_VECTORCALL atan2(float128_t y, float128_t x) noexcept
	{
		return impl::atan2_(y, x);
	}

	#endif

	#if MUU_HAS_FLOAT16

	/// \brief	Returns the arc tangent of a _Float16.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr _Float16 MUU_VECTORCALL atan2(_Float16 y, _Float16 x) noexcept
	{
		return impl::atan2_(y, x);
	}

	#endif

	#if MUU_HAS_FP16

	/// \brief	Returns the arc tangent of a __fp16.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr __fp16 MUU_VECTORCALL atan2(__fp16 y, __fp16 x) noexcept
	{
		return impl::atan2_(y, x);
	}

	#endif

	/// \brief	Returns the arc tangent of two arithmetic values.
	///
	/// \details Integer arguments are promoted to double.
	MUU_CONSTRAINED_TEMPLATE((all_arithmetic<X, Y>), typename X, typename Y)
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr auto MUU_VECTORCALL atan2(Y y, X x) noexcept
	{
		using return_type = impl::std_math_common_type<X, Y>;
		return impl::atan2_(static_cast<return_type>(y), static_cast<return_type>(x));
	}

	/** @} */ // math::atan2
#endif		  // atan2

#if 1 // lerp ----------------------------------------------------------------------------------------------------------
	/// \addtogroup		lerp	lerp()
	/// \brief Linear interpolations al a C++20's std::lerp.
	/// \remark	Despite being stand-ins for C++20's std::lerp, these functions do _not_ make the same
	/// 		guarantees about infinities and NaN's. Garbage-in, garbage-out.
	/// @{

	/// \brief	Returns a linear interpolation between two floats.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr float MUU_VECTORCALL lerp(float start, float finish, float alpha) noexcept
	{
		MUU_FMA_BLOCK;
		return start * (1.0f - alpha) + finish * alpha;
	}

	/// \brief	Returns a linear interpolation between two doubles.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr double MUU_VECTORCALL lerp(double start, double finish, double alpha) noexcept
	{
		MUU_FMA_BLOCK;
		return start * (1.0 - alpha) + finish * alpha;
	}

	/// \brief	Returns a linear interpolation between two long doubles.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr long double MUU_VECTORCALL lerp(long double start, long double finish, long double alpha) noexcept
	{
		MUU_FMA_BLOCK;
		return start * (1.0L - alpha) + finish * alpha;
	}

	#if MUU_HAS_FLOAT128

	/// \brief	Returns a linear interpolation between two float128_ts.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr float128_t MUU_VECTORCALL lerp(float128_t start, float128_t finish, float128_t alpha) noexcept
	{
		MUU_FMA_BLOCK;
		return start * (float128_t{ 1 } - alpha) + finish * alpha;
	}

	#endif

	#if MUU_HAS_FLOAT16

	/// \brief	Returns a linear interpolation between two _Float16s.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr _Float16 MUU_VECTORCALL lerp(_Float16 start, _Float16 finish, _Float16 alpha) noexcept
	{
		return static_cast<_Float16>(
			lerp(static_cast<float>(start), static_cast<float>(finish), static_cast<float>(alpha)));
	}

	#endif

	#if MUU_HAS_FP16

	/// \brief	Returns a linear interpolation between two __fp16s.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr __fp16 MUU_VECTORCALL lerp(__fp16 start, __fp16 finish, __fp16 alpha) noexcept
	{
		return static_cast<__fp16>(
			lerp(static_cast<float>(start), static_cast<float>(finish), static_cast<float>(alpha)));
	}

	#endif

	/// \brief	Returns a linear interpolation between two arithmetic values.
	///
	/// \details Integer arguments are promoted to double.
	MUU_CONSTRAINED_TEMPLATE((all_arithmetic<T, U, V>), typename T, typename U, typename V)
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr auto MUU_VECTORCALL lerp(T start, U finish, V alpha) noexcept
	{
		using return_type		= impl::std_math_common_type<T, U, V>;
		using intermediate_type = impl::promote_if_small_float<return_type>;
		return static_cast<return_type>(lerp(static_cast<intermediate_type>(start),
											 static_cast<intermediate_type>(finish),
											 static_cast<intermediate_type>(alpha)));
	}

	/** @} */ // math::lerp
#endif		  // lerp

#if 1 // normalize_angle -----------------------------------------------------------------------------------------------
	/// \addtogroup		normalize_angle		normalize_angle()
	/// \brief			Normalizes angles, wrapping their values to the range `[0.0, 2 * pi)`.
	/// @{

	/// \cond
	namespace impl
	{
		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL normalize_angle_(T val) noexcept
		{
			static_assert(muu::is_floating_point<T>);
			static_assert(std::is_same_v<impl::highest_ranked<T, float>, T>);

			if (val < T{} || val >= constants<T>::two_pi)
				val -= constants<T>::two_pi * muu::floor(val * constants<T>::one_over_two_pi);
			return val;
		}
	}
	/// \endcond

	/// \brief	Normalizes the angle value of a float.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr float MUU_VECTORCALL normalize_angle(float x) noexcept
	{
		return impl::normalize_angle_(x);
	}

	/// \brief	Normalizes the angle value of a double.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr double MUU_VECTORCALL normalize_angle(double x) noexcept
	{
		return impl::normalize_angle_(x);
	}

	/// \brief	Normalizes the angle value of a long double.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr long double MUU_VECTORCALL normalize_angle(long double x) noexcept
	{
		return impl::normalize_angle_(x);
	}

	#if MUU_HAS_FLOAT128

	/// \brief	Normalizes the angle value of a float128_t.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr float128_t MUU_VECTORCALL normalize_angle(float128_t x) noexcept
	{
		return impl::normalize_angle_(x);
	}

	#endif

	#if MUU_HAS_FLOAT16

	/// \brief	Normalizes the angle value of a _Float16.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr _Float16 MUU_VECTORCALL normalize_angle(_Float16 x) noexcept
	{
		return static_cast<_Float16>(impl::normalize_angle_(static_cast<float>(x)));
	}

	#endif

	#if MUU_HAS_FP16

	/// \brief	Normalizes the angle value of a __fp16.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr __fp16 MUU_VECTORCALL normalize_angle(__fp16 x) noexcept
	{
		return static_cast<__fp16>(impl::normalize_angle_(static_cast<float>(x)));
	}

	#endif

	/// \brief	Normalizes the angle of an integral value.
	MUU_CONSTRAINED_TEMPLATE(is_integral<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr double MUU_VECTORCALL normalize_angle(T x) noexcept
	{
		return impl::normalize_angle_(static_cast<double>(x));
	}

	/** @} */ // math::normalize_angle
#endif		  // normalize_angle

#if 1 // normalize_angle_signed ----------------------------------------------------------------------------------------
	/// \addtogroup		normalize_angle_signed		normalize_angle_signed()
	/// \brief			Normalizes angles, wrapping their values to the range `[-pi, pi)`.
	/// @{

	/// \cond
	namespace impl
	{
		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL normalize_angle_signed_(T val) noexcept
		{
			static_assert(muu::is_floating_point<T>);
			static_assert(std::is_same_v<impl::highest_ranked<T, float>, T>);

			if (val < -constants<T>::pi || val >= constants<T>::pi)
			{
				val += constants<T>::pi;
				val -= constants<T>::two_pi * muu::floor(val * constants<T>::one_over_two_pi);
				val -= constants<T>::pi;
			}
			return val;
		}
	}
	/// \endcond

	/// \brief	Normalizes the angle value of a float.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr float MUU_VECTORCALL normalize_angle_signed(float x) noexcept
	{
		return impl::normalize_angle_signed_(x);
	}

	/// \brief	Normalizes the angle value of a double.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr double MUU_VECTORCALL normalize_angle_signed(double x) noexcept
	{
		return impl::normalize_angle_signed_(x);
	}

	/// \brief	Normalizes the angle value of a long double.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr long double MUU_VECTORCALL normalize_angle_signed(long double x) noexcept
	{
		return impl::normalize_angle_signed_(x);
	}

	#if MUU_HAS_FLOAT128

	/// \brief	Normalizes the angle value of a float128_t.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr float128_t MUU_VECTORCALL normalize_angle_signed(float128_t x) noexcept
	{
		return impl::normalize_angle_signed_(x);
	}

	#endif

	#if MUU_HAS_FLOAT16

	/// \brief	Normalizes the angle value of a _Float16.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr _Float16 MUU_VECTORCALL normalize_angle_signed(_Float16 x) noexcept
	{
		return static_cast<_Float16>(impl::normalize_angle_signed_(static_cast<float>(x)));
	}

	#endif

	#if MUU_HAS_FP16

	/// \brief	Normalizes the angle value of a __fp16.
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr __fp16 MUU_VECTORCALL normalize_angle_signed(__fp16 x) noexcept
	{
		return static_cast<__fp16>(impl::normalize_angle_signed_(static_cast<float>(x)));
	}

	#endif

	/// \brief	Normalizes the angle of an integral value.
	MUU_CONSTRAINED_TEMPLATE(is_integral<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr double MUU_VECTORCALL normalize_angle_signed(T x) noexcept
	{
		return impl::normalize_angle_signed_(static_cast<double>(x));
	}

	/** @} */ // math::normalize_angle_signed
#endif		  // normalize_angle_signed

	/** @} */ // math
}

MUU_RESET_NDEBUG_OPTIMIZATIONS;
#include "impl/header_end.h"

#undef MUU_HAS_MSVC_INTRINSICS
