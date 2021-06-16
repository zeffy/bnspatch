// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

/// \file
/// \brief  Contains the definition of muu::vector.

/*
	VECTOR CLASS DESIGN - KEY POINTS

	a.k.a. pre-emptive answers to "why is _____ implemented like that?"

	-	Vectors of <= 4 dimensions have named members x,y,z and w, whereas those with dimensions > 4
		have a single values[] array. This is accomplished by the use of specialized base class templates.
		While complicating the main class implementation somewhat, it is a great usability boon since in general being
		able to refer to component 0 like "vec.x" is much more ergonomic than vec[0] or vec.get<0>().
		Implementation complexity is largely addressed by the use of some generic function body implementation macros.

	-	"Why not just make them a union?"
		Because unions in C++ are a complicated mess, and almost impossible to use if you value any sort of constexpr.

	-	"Macros??"
		Yes. I could have gone all FP and used a bunch of lambdas but they only get optimized out when the optimizer is
		actually run; debug builds still have a bunch of nested calls and lambda instantiations. Macros + 'if constexpr'
		end up being much more debug friendly.

	-	Some functions use constraints to select overloads that take things either by reference or value, with the value
		overloads being 'hidden' from doxygen and intellisense. The value overloads are optimizations to take
		advantage of __vectorcall on windows, and only apply to float, double and long double vectors of <= 4 dimensions
		since the're considered "Homogeneous Vector Aggreggates" and must be passed by value to be properly vectorized.
		- __vectorcall: https://docs.microsoft.com/en-us/cpp/cpp/vectorcall?view=vs-2019
		- vectorizer sandbox: https://godbolt.org/z/vn8aKv (change vector_param_mode to see the effect in the MSVC tab)

	-	You'll see intermediate_float used instead of scalar_type or delta_type in a few places. It's a 'better' type
		used for intermediate floating-point values where precision loss or unnecessary cast round-tripping is to be
   avoided. generally: when scalar_type is a float >= 32 bits: intermediate_float == scalar_type when scalar_type is a
   float < 32 bits: intermediate_float == float when scalar_type is integral: intermediate_float == double.

	-	Some code is statically switched/branched according to whether a static_cast<> is necessary; this is to avoid
		unnecessary codegen and improve debug build performance for non-trivial scalar_types (e.g. muu::half).
*/

#pragma once
#include "impl/vector_types_common.h"
#include "impl/header_start.h"
MUU_FORCE_NDEBUG_OPTIMIZATIONS;
MUU_DISABLE_SHADOW_WARNINGS;
MUU_DISABLE_SUGGEST_WARNINGS;
MUU_DISABLE_ARITHMETIC_WARNINGS;
MUU_PRAGMA_MSVC(float_control(except, off))
MUU_PRAGMA_MSVC(float_control(precise, off))

//======================================================================================================================
// IMPLEMENTATION DETAILS
#if 1

/// \cond

// helper macros -------------------------------------------------------------------------------------------------------

	#define COMPONENTWISE_AND(func)                                                                                    \
		if constexpr (Dimensions == 1)                                                                                 \
			return func(x);                                                                                            \
		if constexpr (Dimensions == 2)                                                                                 \
			return (func(x)) && (func(y));                                                                             \
		if constexpr (Dimensions == 3)                                                                                 \
			return (func(x)) && (func(y)) && (func(z));                                                                \
		if constexpr (Dimensions == 4)                                                                                 \
			return (func(x)) && (func(y)) && (func(z)) && (func(w));                                                   \
		if constexpr (Dimensions > 4)                                                                                  \
		{                                                                                                              \
			MUU_PRAGMA_MSVC(omp simd)                                                                                  \
			for (size_t i = 0; i < Dimensions; i++)                                                                    \
				if (!(func(values[i])))                                                                                \
					return false;                                                                                      \
			return true;                                                                                               \
		}                                                                                                              \
		static_assert(true)

	#define COMPONENTWISE_OR(func)                                                                                     \
		if constexpr (Dimensions == 1)                                                                                 \
			return func(x);                                                                                            \
		if constexpr (Dimensions == 2)                                                                                 \
			return (func(x)) || (func(y));                                                                             \
		if constexpr (Dimensions == 3)                                                                                 \
			return (func(x)) || (func(y)) || (func(z));                                                                \
		if constexpr (Dimensions == 4)                                                                                 \
			return (func(x)) || (func(y)) || (func(z)) || (func(w));                                                   \
		if constexpr (Dimensions > 4)                                                                                  \
		{                                                                                                              \
			MUU_PRAGMA_MSVC(omp simd)                                                                                  \
			for (size_t i = 0; i < Dimensions; i++)                                                                    \
				if (func(values[i]))                                                                                   \
					return true;                                                                                       \
			return false;                                                                                              \
		}                                                                                                              \
		static_assert(true)

	#define COMPONENTWISE_ACCUMULATE(func, op)                                                                         \
		if constexpr (Dimensions == 1)                                                                                 \
		{                                                                                                              \
			MUU_FMA_BLOCK;                                                                                             \
			return func(x);                                                                                            \
		}                                                                                                              \
		if constexpr (Dimensions == 2)                                                                                 \
		{                                                                                                              \
			MUU_FMA_BLOCK;                                                                                             \
			return (func(x))op(func(y));                                                                               \
		}                                                                                                              \
		if constexpr (Dimensions == 3)                                                                                 \
		{                                                                                                              \
			MUU_FMA_BLOCK;                                                                                             \
			return (func(x))op(func(y)) op(func(z));                                                                   \
		}                                                                                                              \
		if constexpr (Dimensions == 4)                                                                                 \
		{                                                                                                              \
			MUU_FMA_BLOCK;                                                                                             \
			return (func(x))op(func(y)) op(func(z)) op(func(w));                                                       \
		}                                                                                                              \
		if constexpr (Dimensions > 4)                                                                                  \
		{                                                                                                              \
			MUU_FMA_BLOCK;                                                                                             \
			auto val = func(values[0]);                                                                                \
			MUU_PRAGMA_MSVC(omp simd)                                                                                  \
			for (size_t i = 1; i < Dimensions; i++)                                                                    \
			{                                                                                                          \
				MUU_FMA_BLOCK;                                                                                         \
				val op## = func(values[i]);                                                                            \
			}                                                                                                          \
			return val;                                                                                                \
		}                                                                                                              \
		static_assert(true)

	#define NULL_TRANSFORM(x) x

	#define COMPONENTWISE_CASTING_OP_BRANCH(func, transformer, x_selector)                                             \
		using func_type = decltype(func(x_selector));                                                                  \
		if constexpr (!std::is_same_v<func_type, Scalar>)                                                              \
		{                                                                                                              \
			transformer(func, static_cast<Scalar>);                                                                    \
		}                                                                                                              \
		else                                                                                                           \
		{                                                                                                              \
			transformer(func, NULL_TRANSFORM);                                                                         \
		}                                                                                                              \
		static_assert(true)

	#define COMPONENTWISE_CASTING_OP(func, transformer)                                                                \
		if constexpr (Dimensions <= 4)                                                                                 \
		{                                                                                                              \
			COMPONENTWISE_CASTING_OP_BRANCH(func, transformer, x);                                                     \
		}                                                                                                              \
		else                                                                                                           \
		{                                                                                                              \
			COMPONENTWISE_CASTING_OP_BRANCH(func, transformer, values[0]);                                             \
		}                                                                                                              \
		static_assert(true)

	#define COMPONENTWISE_CONSTRUCT_WITH_TRANSFORM(func, xform)                                                        \
		if constexpr (Dimensions == 1)                                                                                 \
		{                                                                                                              \
			MUU_FMA_BLOCK;                                                                                             \
			return vector{ xform(func(x)) };                                                                           \
		}                                                                                                              \
		if constexpr (Dimensions == 2)                                                                                 \
		{                                                                                                              \
			MUU_FMA_BLOCK;                                                                                             \
			return vector{ xform(func(x)), xform(func(y)) };                                                           \
		}                                                                                                              \
		if constexpr (Dimensions == 3)                                                                                 \
		{                                                                                                              \
			MUU_FMA_BLOCK;                                                                                             \
			return vector{ xform(func(x)), xform(func(y)), xform(func(z)) };                                           \
		}                                                                                                              \
		if constexpr (Dimensions == 4)                                                                                 \
		{                                                                                                              \
			MUU_FMA_BLOCK;                                                                                             \
			return vector{ xform(func(x)), xform(func(y)), xform(func(z)), xform(func(w)) };                           \
		}                                                                                                              \
		if constexpr (Dimensions > 4)                                                                                  \
		{                                                                                                              \
			MUU_FMA_BLOCK;                                                                                             \
			return vector{ impl::componentwise_func_tag{},                                                             \
						   [&](size_t i) noexcept                                                                      \
						   {                                                                                           \
							   MUU_FMA_BLOCK;                                                                          \
							   return xform(func(values[i]));                                                          \
						   } };                                                                                        \
		}                                                                                                              \
		static_assert(true)

	#define COMPONENTWISE_CONSTRUCT(func) COMPONENTWISE_CASTING_OP(func, COMPONENTWISE_CONSTRUCT_WITH_TRANSFORM)

	#define COMPONENTWISE_ASSIGN_WITH_TRANSFORM(func, xform)                                                           \
		if constexpr (Dimensions <= 4)                                                                                 \
		{                                                                                                              \
			{                                                                                                          \
				MUU_FMA_BLOCK;                                                                                         \
				base::x = xform(func(x));                                                                              \
			}                                                                                                          \
			if constexpr (Dimensions >= 2)                                                                             \
			{                                                                                                          \
				MUU_FMA_BLOCK;                                                                                         \
				base::y = xform(func(y));                                                                              \
			}                                                                                                          \
			if constexpr (Dimensions >= 3)                                                                             \
			{                                                                                                          \
				MUU_FMA_BLOCK;                                                                                         \
				base::z = xform(func(z));                                                                              \
			}                                                                                                          \
			if constexpr (Dimensions == 4)                                                                             \
			{                                                                                                          \
				MUU_FMA_BLOCK;                                                                                         \
				base::w = xform(func(w));                                                                              \
			}                                                                                                          \
		}                                                                                                              \
		else                                                                                                           \
		{                                                                                                              \
			MUU_PRAGMA_MSVC(omp simd)                                                                                  \
			for (size_t i = 0; i < Dimensions; i++)                                                                    \
			{                                                                                                          \
				MUU_FMA_BLOCK;                                                                                         \
				base::values[i] = xform(func(values[i]));                                                              \
			}                                                                                                          \
		}                                                                                                              \
		return *this

	#define COMPONENTWISE_ASSIGN(func) COMPONENTWISE_CASTING_OP(func, COMPONENTWISE_ASSIGN_WITH_TRANSFORM)

	#define SPECIALIZED_IF(cond) , bool = (cond)

// internal bits -------------------------------------------------------------------------------------------------------

namespace muu::impl
{
	struct value_fill_tag
	{};
	struct zero_fill_tag
	{};
	struct array_cast_tag
	{};
	struct tuple_cast_tag
	{};
	struct componentwise_func_tag
	{};
	struct tuple_concat_tag
	{};

	MUU_ABI_VERSION_START(0);

	template <typename Scalar, size_t Dimensions>
	struct MUU_TRIVIAL_ABI vector_ //
	{
		static_assert(Dimensions > 4);

		Scalar values[Dimensions];

		vector_() noexcept = default;

		explicit constexpr vector_(zero_fill_tag) noexcept //
			: values{}
		{}

		template <size_t... Indices>
		explicit constexpr vector_(Scalar fill, std::index_sequence<Indices...>) noexcept
			: values{ (MUU_UNUSED(Indices), fill)... }
		{
			static_assert(sizeof...(Indices) <= Dimensions);
		}

		explicit constexpr vector_(value_fill_tag, Scalar fill) noexcept
			: vector_{ fill, std::make_index_sequence<Dimensions>{} }
		{}

		explicit constexpr vector_(Scalar x_, Scalar y_ = Scalar{}, Scalar z_ = Scalar{}, Scalar w_ = Scalar{}) noexcept
			: values{ x_, y_, z_, w_ }
		{}

		template <typename... T>
		explicit constexpr vector_(Scalar x_, Scalar y_, Scalar z_, Scalar w_, const T&... vals) noexcept
			: values{ x_, y_, z_, w_, static_cast<Scalar>(vals)... }
		{
			static_assert(sizeof...(T) <= Dimensions - 4);
		}

		template <typename T, size_t... Indices>
		explicit constexpr vector_(array_cast_tag, std::index_sequence<Indices...>, const T& arr) noexcept
			: values{ static_cast<Scalar>(arr[Indices])... }
		{
			static_assert(sizeof...(Indices) <= Dimensions);
		}

		template <typename T, size_t... Indices>
		explicit constexpr vector_(tuple_cast_tag, std::index_sequence<Indices...>, const T& tpl) noexcept
			: values{ static_cast<Scalar>(get_from_tuple_like<Indices>(tpl))... }
		{
			static_assert(sizeof...(Indices) <= Dimensions);
		}

		template <typename Func, size_t... Indices>
		explicit constexpr vector_(componentwise_func_tag, std::index_sequence<Indices...>, Func&& func) noexcept
			: values{ func(std::integral_constant<size_t, Indices>{})... }
		{
			static_assert(sizeof...(Indices) <= Dimensions);
		}

		template <typename T1, typename T2, size_t... Indices1, size_t... Indices2>
		explicit constexpr vector_(tuple_concat_tag,
								   std::index_sequence<Indices1...>,
								   const T1& tpl1,
								   std::index_sequence<Indices2...>,
								   const T2& tpl2) noexcept
			: values{ static_cast<Scalar>(get_from_tuple_like<Indices1>(tpl1))...,
					  static_cast<Scalar>(get_from_tuple_like<Indices2>(tpl2))... }
		{
			static_assert((sizeof...(Indices1) + sizeof...(Indices2)) <= Dimensions);
		}

		template <typename T, size_t... Indices, typename... V>
		explicit constexpr vector_(tuple_concat_tag,
								   std::index_sequence<Indices...>,
								   const T& tpl,
								   const V&... vals) noexcept
			: values{ static_cast<Scalar>(get_from_tuple_like<Indices>(tpl))..., static_cast<Scalar>(vals)... }
		{
			static_assert((sizeof...(Indices) + sizeof...(V)) <= Dimensions);
		}
	};

	template <typename Scalar>
	struct MUU_TRIVIAL_ABI vector_<Scalar, 1> //
	{
		Scalar x;

		vector_() noexcept = default;

		explicit constexpr vector_(zero_fill_tag) noexcept //
			: x{}
		{}

		explicit constexpr vector_(value_fill_tag, Scalar x_) noexcept //
			: x{ x_ }
		{}

		explicit constexpr vector_(Scalar x_) noexcept //
			: x{ x_ }
		{}

		template <typename T, size_t... Indices>
		explicit constexpr vector_(array_cast_tag, std::index_sequence<Indices...>, const T& arr) noexcept
			: vector_{ static_cast<Scalar>(arr[Indices])... }
		{
			static_assert(sizeof...(Indices) == 1);
		}

		template <typename T, size_t... Indices>
		explicit constexpr vector_(tuple_cast_tag, std::index_sequence<Indices...>, const T& tpl) noexcept
			: vector_{ static_cast<Scalar>(get_from_tuple_like<Indices>(tpl))... }
		{
			static_assert(sizeof...(Indices) == 1);
		}
	};

	template <typename Scalar>
	struct MUU_TRIVIAL_ABI vector_<Scalar, 2> //
	{
		Scalar x;
		Scalar y;

		vector_() noexcept = default;

		explicit constexpr vector_(zero_fill_tag) noexcept //
			: x{},
			  y{}
		{}

		explicit constexpr vector_(value_fill_tag, Scalar fill) noexcept //
			: x{ fill },
			  y{ fill }
		{}

		explicit constexpr vector_(Scalar x_, Scalar y_ = Scalar{}) noexcept //
			: x{ x_ },
			  y{ y_ }
		{}

		template <typename T, size_t... Indices>
		explicit constexpr vector_(array_cast_tag, std::index_sequence<Indices...>, const T& arr) noexcept
			: vector_{ static_cast<Scalar>(arr[Indices])... }
		{
			static_assert(sizeof...(Indices) <= 2);
		}

		template <typename T, size_t... Indices>
		explicit constexpr vector_(tuple_cast_tag, std::index_sequence<Indices...>, const T& tpl) noexcept
			: vector_{ static_cast<Scalar>(get_from_tuple_like<Indices>(tpl))... }
		{
			static_assert(sizeof...(Indices) <= 2);
		}

		template <typename T1, typename T2, size_t... Indices1, size_t... Indices2>
		explicit constexpr vector_(tuple_concat_tag,
								   std::index_sequence<Indices1...>,
								   const T1& tpl1,
								   std::index_sequence<Indices2...>,
								   const T2& tpl2) noexcept
			: vector_{ static_cast<Scalar>(get_from_tuple_like<Indices1>(tpl1))...,
					   static_cast<Scalar>(get_from_tuple_like<Indices2>(tpl2))... }
		{
			static_assert((sizeof...(Indices1) + sizeof...(Indices2)) <= 2);
		}

		template <typename T, size_t... Indices, typename... V>
		explicit constexpr vector_(tuple_concat_tag,
								   std::index_sequence<Indices...>,
								   const T& tpl,
								   const V&... vals) noexcept
			: vector_{ static_cast<Scalar>(get_from_tuple_like<Indices>(tpl))..., static_cast<Scalar>(vals)... }
		{
			static_assert((sizeof...(Indices) + sizeof...(V)) <= 2);
		}
	};

	template <typename Scalar>
	struct MUU_TRIVIAL_ABI vector_<Scalar, 3> //
	{
		Scalar x;
		Scalar y;
		Scalar z;

		vector_() noexcept = default;

		explicit constexpr vector_(zero_fill_tag) noexcept //
			: x{},
			  y{},
			  z{}
		{}

		explicit constexpr vector_(value_fill_tag, Scalar fill) noexcept //
			: x{ fill },
			  y{ fill },
			  z{ fill }
		{}

		explicit constexpr vector_(Scalar x_, Scalar y_ = Scalar{}, Scalar z_ = Scalar{}) noexcept
			: x{ x_ },
			  y{ y_ },
			  z{ z_ }
		{}

		template <typename T, size_t... Indices>
		explicit constexpr vector_(array_cast_tag, std::index_sequence<Indices...>, const T& arr) noexcept
			: vector_{ static_cast<Scalar>(arr[Indices])... }
		{
			static_assert(sizeof...(Indices) <= 3);
		}

		template <typename T, size_t... Indices>
		explicit constexpr vector_(tuple_cast_tag, std::index_sequence<Indices...>, const T& tpl) noexcept
			: vector_{ static_cast<Scalar>(get_from_tuple_like<Indices>(tpl))... }
		{
			static_assert(sizeof...(Indices) <= 3);
		}

		template <typename T1, typename T2, size_t... Indices1, size_t... Indices2>
		explicit constexpr vector_(tuple_concat_tag,
								   std::index_sequence<Indices1...>,
								   const T1& tpl1,
								   std::index_sequence<Indices2...>,
								   const T2& tpl2) noexcept
			: vector_{ static_cast<Scalar>(get_from_tuple_like<Indices1>(tpl1))...,
					   static_cast<Scalar>(get_from_tuple_like<Indices2>(tpl2))... }
		{
			static_assert((sizeof...(Indices1) + sizeof...(Indices2)) <= 3);
		}

		template <typename T, size_t... Indices, typename... V>
		explicit constexpr vector_(tuple_concat_tag,
								   std::index_sequence<Indices...>,
								   const T& tpl,
								   const V&... vals) noexcept
			: vector_{ static_cast<Scalar>(get_from_tuple_like<Indices>(tpl))..., static_cast<Scalar>(vals)... }
		{
			static_assert((sizeof...(Indices) + sizeof...(V)) <= 3);
		}
	};

	template <typename Scalar>
	struct MUU_TRIVIAL_ABI vector_<Scalar, 4> //
	{
		Scalar x;
		Scalar y;
		Scalar z;
		Scalar w;

		vector_() noexcept = default;

		explicit constexpr vector_(zero_fill_tag) noexcept //
			: x{},
			  y{},
			  z{},
			  w{}
		{}

		explicit constexpr vector_(value_fill_tag, Scalar fill) noexcept //
			: x{ fill },
			  y{ fill },
			  z{ fill },
			  w{ fill }
		{}

		explicit constexpr vector_(Scalar x_, Scalar y_ = Scalar{}, Scalar z_ = Scalar{}, Scalar w_ = Scalar{}) noexcept
			: x{ x_ },
			  y{ y_ },
			  z{ z_ },
			  w{ w_ }
		{}

		template <typename T, size_t... Indices>
		explicit constexpr vector_(array_cast_tag, std::index_sequence<Indices...>, const T& arr) noexcept
			: vector_{ static_cast<Scalar>(arr[Indices])... }
		{
			static_assert(sizeof...(Indices) <= 4);
		}

		template <typename T, size_t... Indices>
		explicit constexpr vector_(tuple_cast_tag, std::index_sequence<Indices...>, const T& tpl) noexcept
			: vector_{ static_cast<Scalar>(get_from_tuple_like<Indices>(tpl))... }
		{
			static_assert(sizeof...(Indices) <= 4);
		}

		template <typename T1, typename T2, size_t... Indices1, size_t... Indices2>
		explicit constexpr vector_(tuple_concat_tag,
								   std::index_sequence<Indices1...>,
								   const T1& tpl1,
								   std::index_sequence<Indices2...>,
								   const T2& tpl2) noexcept
			: vector_{ static_cast<Scalar>(get_from_tuple_like<Indices1>(tpl1))...,
					   static_cast<Scalar>(get_from_tuple_like<Indices2>(tpl2))... }
		{
			static_assert((sizeof...(Indices1) + sizeof...(Indices2)) <= 4);
		}

		template <typename T, size_t... Indices, typename... V>
		explicit constexpr vector_(tuple_concat_tag,
								   std::index_sequence<Indices...>,
								   const T& tpl,
								   const V&... vals) noexcept
			: vector_{ static_cast<Scalar>(get_from_tuple_like<Indices>(tpl))..., static_cast<Scalar>(vals)... }
		{
			static_assert((sizeof...(Indices) + sizeof...(V)) <= 4);
		}
	};

	MUU_ABI_VERSION_END;

	template <typename Scalar, size_t Dimensions>
	inline constexpr bool is_hva<vector_<Scalar, Dimensions>> = can_be_hva_of<Scalar, vector_<Scalar, Dimensions>>;

	template <typename Scalar, size_t Dimensions>
	inline constexpr bool is_hva<vector<Scalar, Dimensions>> = is_hva<vector_<Scalar, Dimensions>>;

	template <typename Scalar, size_t Dimensions>
	struct vectorcall_param_<vector<Scalar, Dimensions>>
	{
		using type = std::conditional_t<pass_vectorcall_by_value<vector_<Scalar, Dimensions>>,
										vector<Scalar, Dimensions>,
										const vector<Scalar, Dimensions>&>;
	};
}

namespace muu
{
	template <typename From, typename Scalar, size_t Dimensions>
	inline constexpr bool allow_implicit_bit_cast<From, impl::vector_<Scalar, Dimensions>> =
		allow_implicit_bit_cast<From, vector<Scalar, Dimensions>>;
}

/// \endcond

	#ifndef SPECIALIZED_IF
		#define SPECIALIZED_IF(cond)
	#endif

#endif //===============================================================================================================

//======================================================================================================================
// VECTOR CLASS
#if 1

namespace muu
{
	MUU_ABI_VERSION_START(0);

	/// \brief An N-dimensional vector.
	/// \ingroup math
	///
	/// \tparam	Scalar      The vector's scalar component type.
	/// \tparam Dimensions  The number of dimensions.
	template <typename Scalar, size_t Dimensions>
	struct MUU_TRIVIAL_ABI vector MUU_HIDDEN_BASE(impl::vector_<Scalar, Dimensions>)
	{
		static_assert(!std::is_reference_v<Scalar>, "Vector scalar type cannot be a reference");
		static_assert(!std::is_const_v<Scalar> //
						  && !std::is_volatile_v<Scalar>,
					  "Vector scalar type cannot be const- or volatile-qualified");
		static_assert(std::is_trivially_constructible_v<Scalar>	  //
						  && std::is_trivially_copyable_v<Scalar> //
						  && std::is_trivially_destructible_v<Scalar>,
					  "Vector scalar type must be trivially constructible, copyable and destructible");
		static_assert(Dimensions >= 1, "Vectors must have at least one dimension");

		/// \brief The number of scalar components stored in this vector.
		static constexpr size_t dimensions = Dimensions;

		/// \brief The type of each scalar component stored in this vector.
		using scalar_type = Scalar;

		/// \brief The scalar type used for length, distance, blend factors, etc. Always floating-point.
		using delta_type = std::conditional_t<is_integral<scalar_type>, double, scalar_type>;

		/// \brief The scalar type used for products (dot, cross, etc.). Always signed.
		using product_type = std::
			conditional_t<is_integral<scalar_type>, impl::highest_ranked<make_signed<scalar_type>, int>, scalar_type>;

		/// \brief The vector type with #scalar_type == #product_type and the same number of #dimensions as this one.
		using vector_product = vector<product_type, dimensions>;

		/// \brief Compile-time constants for this vector type.
		using constants = muu::constants<vector>;

		/// \brief A LegacyRandomAccessIterator for the scalar components in the vector.
		using iterator = scalar_type*;

		/// \brief A const LegacyRandomAccessIterator for the scalar components in the vector.
		using const_iterator = const scalar_type*;

	  private:
		template <typename S, size_t D>
		friend struct vector;
		template <typename S>
		friend struct quaternion;
		template <typename S, size_t R, size_t C>
		friend struct matrix;
		template <typename S>
		friend struct plane;

		using base = impl::vector_<scalar_type, Dimensions>;
		static_assert(sizeof(base) == (sizeof(scalar_type) * Dimensions), "Vectors should not have padding");

		using intermediate_product = impl::promote_if_small_float<product_type>;
		static_assert(is_floating_point<intermediate_product> == is_floating_point<scalar_type>);

		using intermediate_float = impl::promote_if_small_float<delta_type>;
		static_assert(is_floating_point<delta_type>);
		static_assert(is_floating_point<intermediate_float>);

		using scalar_constants = muu::constants<scalar_type>;

	  public:
	#ifdef DOXYGEN

		/// \brief The vector's 0th scalar component (when #dimensions &lt;= 4).
		scalar_type x;
		/// \brief The vector's 1st scalar component (when #dimensions == 2, 3 or 4).
		scalar_type y;
		/// \brief The vector's 2nd scalar component (when #dimensions == 3 or 4).
		scalar_type z;
		/// \brief The vector's 3rd scalar component (when #dimensions == 4).
		scalar_type w;
		/// \brief The vector's scalar component array (when #dimensions &gt;= 5).
		scalar_type values[dimensions];

	#endif // DOXYGEN

	#if 1 // constructors ----------------------------------------------------------------------------------------------

	  private:
		template <typename Func>
		explicit constexpr vector(impl::componentwise_func_tag, Func&& func) noexcept
			: base{ impl::componentwise_func_tag{}, std::make_index_sequence<Dimensions>{}, static_cast<Func&&>(func) }
		{}

	  public:
		/// \brief Default constructor. Scalar components are not initialized.
		vector() noexcept = default;

		/// \brief Copy constructor.
		MUU_NODISCARD_CTOR
		constexpr vector(const vector&) noexcept = default;

		/// \brief Copy-assigment operator.
		constexpr vector& operator=(const vector&) noexcept = default;

		/// \brief	Constructs a vector with all scalar components set to the same value.
		///
		/// \param	fill	The value used to initialize each of the vector's scalar components.
		MUU_NODISCARD_CTOR
		explicit constexpr vector(scalar_type fill) noexcept //
			: base{ impl::value_fill_tag{}, fill }
		{}

		/// \brief		Constructs a vector from two scalar values.
		/// \details	Any scalar components not covered by the constructor's parameters are initialized to zero.
		///
		/// \param	x		Initial value for the vector's first scalar component.
		/// \param	y		Initial value for the vector's second scalar component.
		///
		/// \availability		This constructor is only available when #dimensions &gt;= 2.
		MUU_LEGACY_REQUIRES(Dims >= 2, size_t Dims = Dimensions)
		MUU_NODISCARD_CTOR
		constexpr vector(scalar_type x, scalar_type y) noexcept MUU_REQUIRES(Dimensions >= 2) : base{ x, y }
		{}

		/// \brief		Constructs a vector from three scalar values.
		/// \details	Any scalar components not covered by the constructor's parameters are initialized to zero.
		///
		/// \param	x		Initial value for the vector's first scalar component.
		/// \param	y		Initial value for the vector's second scalar component.
		/// \param	z		Initial value for the vector's third scalar component.
		///
		/// \availability		This constructor is only available when #dimensions &gt;= 3.
		MUU_LEGACY_REQUIRES(Dims >= 3, size_t Dims = Dimensions)
		MUU_NODISCARD_CTOR
		constexpr vector(scalar_type x, scalar_type y, scalar_type z) noexcept MUU_REQUIRES(Dimensions >= 3)
			: base{ x, y, z }
		{}

		/// \brief		Constructs a vector from four scalar values.
		/// \details	Any scalar components not covered by the constructor's parameters are initialized to zero.
		///
		/// \param	x		Initial value for the vector's first scalar component.
		/// \param	y		Initial value for the vector's second scalar component.
		/// \param	z		Initial value for the vector's third scalar component.
		/// \param	w		Initial value for the vector's fourth scalar component.
		///
		/// \availability			This constructor is only available when #dimensions &gt;= 4.
		MUU_LEGACY_REQUIRES(Dims >= 4, size_t Dims = Dimensions)
		MUU_NODISCARD_CTOR
		constexpr vector(scalar_type x, scalar_type y, scalar_type z, scalar_type w) noexcept
			MUU_REQUIRES(Dimensions >= 4)
			: base{ x, y, z, w }
		{}

		/// \brief		Constructs a vector from five or more scalar values.
		/// \details	Any scalar components not covered by the constructor's parameters are initialized to zero.
		///
		/// \tparam T		Types convertible to #scalar_type.
		/// \param	x		Initial value for the vector's first scalar component.
		/// \param	y		Initial value for the vector's second scalar component.
		/// \param	z		Initial value for the vector's third scalar component.
		/// \param	w		Initial value for the vector's fourth scalar component.
		/// \param	vals	Initial values for the vector's remaining scalar components.
		///
		/// \availability			This constructor is only available when #dimensions &gt;= 5.
		MUU_CONSTRAINED_TEMPLATE((Dims >= (4 + sizeof...(T)) //
								  && all_convertible_to<Scalar, const T...>),
								 typename... T //
									 MUU_HIDDEN_PARAM(size_t Dims = Dimensions))
		MUU_NODISCARD_CTOR
		constexpr vector(scalar_type x, scalar_type y, scalar_type z, scalar_type w, const T&... vals) noexcept
			: base{ x, y, z, w, vals... }
		{}

		/// \brief Constructs a vector from a raw array of scalars.
		/// \details	Any scalar components not covered by the constructor's parameters are initialized to zero.
		///
		/// \tparam N		The number of elements in the array.
		/// \param	arr		Array of values used to initialize the vector's scalar components.
		MUU_CONSTRAINED_TEMPLATE((Dimensions > N || (Dimensions == N && !build::supports_constexpr_bit_cast)), size_t N)
		MUU_NODISCARD_CTOR
		explicit constexpr vector(const scalar_type (&arr)[N]) noexcept
			: base{ impl::array_cast_tag{}, std::make_index_sequence<N>{}, arr }
		{}

		/// \cond

		MUU_CONSTRAINED_TEMPLATE_2((Dimensions == N && build::supports_constexpr_bit_cast), size_t N)
		MUU_NODISCARD_CTOR
		explicit constexpr vector(const scalar_type (&arr)[N]) noexcept //
			: base{ muu::bit_cast<base>(arr) }
		{}

		/// \endcond

		/// \brief Constructs a vector from a raw array of scalars.
		/// \details	Any scalar components not covered by the constructor's parameters are initialized to zero.
		///
		/// \tparam T		A type convertible to #scalar_type.
		/// \tparam N		The number of elements in the array.
		/// \param	arr		Array of values used to initialize the vector's scalar components.
		MUU_CONSTRAINED_TEMPLATE((Dimensions >= N						 //
								  && all_convertible_to<Scalar, const T> //
								  && !std::is_same_v<remove_cv<T>, Scalar>),
								 typename T,
								 size_t N)
		MUU_NODISCARD_CTOR
		explicit constexpr vector(const T (&arr)[N]) noexcept
			: base{ impl::array_cast_tag{}, std::make_index_sequence<N>{}, arr }
		{}

		/// \brief Constructs a vector from a std::array of scalars.
		/// \details	Any scalar components not covered by the constructor's parameters are initialized to zero.
		///
		/// \tparam N		The number of elements in the array.
		/// \param	arr		Array of values used to initialize the vector's scalar components.
		MUU_CONSTRAINED_TEMPLATE((Dimensions > N || (Dimensions == N && !build::supports_constexpr_bit_cast)), size_t N)
		MUU_NODISCARD_CTOR
		explicit constexpr vector(const std::array<scalar_type, N>& arr) noexcept
			: base{ impl::array_cast_tag{}, std::make_index_sequence<N>{}, arr }
		{}

		/// \cond

		MUU_CONSTRAINED_TEMPLATE_2((Dimensions == N && build::supports_constexpr_bit_cast), size_t N)
		MUU_NODISCARD_CTOR
		explicit constexpr vector(const std::array<scalar_type, N>& arr) noexcept //
			: base{ muu::bit_cast<base>(arr) }
		{}

		/// \endcond

		/// \brief Constructs a vector from a std::array of scalars.
		/// \details	Any scalar components not covered by the constructor's parameters are initialized to zero.
		///
		/// \tparam T		A type convertible to #scalar_type.
		/// \tparam N		The number of elements in the array.
		/// \param	arr		Array of values used to initialize the vector's scalar components.
		MUU_CONSTRAINED_TEMPLATE((Dimensions >= N						 //
								  && all_convertible_to<Scalar, const T> //
								  && !std::is_same_v<remove_cv<T>, Scalar>),
								 typename T,
								 size_t N)
		MUU_NODISCARD_CTOR
		explicit constexpr vector(const std::array<T, N>& arr) noexcept
			: base{ impl::array_cast_tag{}, std::make_index_sequence<N>{}, arr }
		{}

		/// \brief Constructs a vector from any tuple-like or implicitly bit-castable type.
		///
		/// \tparam T	A tuple-like or bit-castable type.
		///
		/// \details	Any scalar components not covered by the constructor's parameters are initialized to zero.
		///
		/// \note		This constructor is implicit when given an implicitly bit-castable type, `explicit` otherwise.
		///
		/// \see muu::allow_implicit_bit_cast
		MUU_CONSTRAINED_TEMPLATE((!impl::is_vector_<T>							//
								  && (std::is_class_v<T> || std::is_union_v<T>) //
								  &&is_tuple_like<T>							//
								  && Dimensions >= tuple_size<T>				//
								  && !allow_implicit_bit_cast<T, vector>),
								 typename T)
		MUU_NODISCARD_CTOR
		explicit constexpr vector(const T& tuple_or_bitcastable) noexcept
			: base{ impl::tuple_cast_tag{}, std::make_index_sequence<tuple_size<T>>{}, tuple_or_bitcastable }
		{}

		/// \cond

		MUU_CONSTRAINED_TEMPLATE_2((!impl::is_vector_<T>						  //
									&& (std::is_class_v<T> || std::is_union_v<T>) //
									&&allow_implicit_bit_cast<T, vector>		  //
									&& (!is_tuple_like<T> || (tuple_size<T> > Dimensions))),
								   typename T)
		MUU_NODISCARD_CTOR
		/*implicit*/
		constexpr vector(const T& bitcastable) noexcept //
			: base{ muu::bit_cast<base>(bitcastable) }
		{
			static_assert(sizeof(T) == sizeof(base), "Bit-castable types must be the same size as the vector");
			static_assert(std::is_trivially_copyable_v<T>, "Bit-castable types must be trivially-copyable");
		}

		/// \endcond

		/// \brief Enlarging/truncating/converting constructor.
		/// \details Copies source vector's scalar components, casting if necessary:
		/// \cpp
		/// vector<float, 3> xyz  = { 1, 2, 3 };
		/// vector<float, 2> xy   = { xyz }; // { 1, 2 }
		/// vector<float, 4> xyzw = { xyz }; // { 1, 2, 3, 0 }
		/// auto rect   = vector{ point1, point2 }; // { 1, 2, 10, 15 }
		/// \ecpp
		/// Any scalar components not covered by the constructor's parameters are initialized to zero.
		///
		/// \tparam	S		Source vector's #scalar_type.
		/// \tparam	D		Source vector's dimensions.
		/// \param 	vec		Source vector.
		template <typename S, size_t D>
		MUU_NODISCARD_CTOR
		explicit constexpr vector(const vector<S, D>& vec) noexcept
			: base{ impl::tuple_cast_tag{}, std::make_index_sequence<(D < Dimensions ? D : Dimensions)>{}, vec }
		{}

		/// \brief	Concatenating constructor.
		/// \details Copies the scalar components from vector 1 and then vector 2 contiguously into the new vector:
		/// \cpp
		/// vector<float, 2> point1 = { 1, 2 };
		/// vector<float, 2> point2 = { 10, 15 };
		/// vector<float, 4> rect   = { point1, point2 }; // { 1, 2, 10, 15 }
		/// \ecpp
		/// Any scalar components not covered by the constructor's parameters are initialized to zero.
		///
		/// \tparam	S1  	Vector 1's #scalar_type.
		/// \tparam	D1		Vector 1's #dimensions.
		/// \tparam	S2  	Vector 2's #scalar_type.
		/// \tparam	D2		Vector 2's #dimensions.
		/// \param 	vec1	Vector 1.
		/// \param 	vec2	Vector 2.
		MUU_CONSTRAINED_TEMPLATE(Dimensions >= D1 + D2, typename S1, size_t D1, typename S2, size_t D2)
		MUU_NODISCARD_CTOR
		constexpr vector(const vector<S1, D1>& vec1, const vector<S2, D2>& vec2) noexcept
			: base{ impl::tuple_concat_tag{},
					std::make_index_sequence<D1>{},
					vec1,
					std::make_index_sequence<D2>{},
					vec2 }
		{}

		/// \brief	Appending constructor.
		/// \details Copies the scalar components from the vector and then the
		/// 		 list of scalars contiguously into the new vector:
		/// \cpp
		/// vector<float, 2> point = { 1, 2 };
		/// vector<float, 4> rect  = { point, 10, 15 }; // { 1, 2, 10, 15 }
		/// \ecpp
		/// Any scalar components not covered by the constructor's parameters are initialized to zero.
		///
		/// \tparam	S	  	Vector's #scalar_type.
		/// \tparam	D		Vector's #dimensions.
		/// \tparam T		Types convertible to #scalar_type.
		/// \param 	vec		A vector.
		/// \param 	vals	Scalar values.
		MUU_CONSTRAINED_TEMPLATE((Dimensions >= D + sizeof...(T) //
								  && all_convertible_to<Scalar, const T...>),
								 typename S,
								 size_t D,
								 typename... T)
		MUU_NODISCARD_CTOR
		constexpr vector(const vector<S, D>& vec, const T&... vals) noexcept
			: base{ impl::tuple_concat_tag{}, std::make_index_sequence<D>{}, vec, vals... }
		{}

		/// \brief Constructs a vector from a pointer to scalars.
		/// \details	Any scalar components not covered by the constructor's parameters are initialized to zero.
		///
		/// \tparam T			Type convertible to #scalar_type.
		/// \param	vals		Pointer to values to copy.
		/// \param	num			Number of values to copy.
		MUU_CONSTRAINED_TEMPLATE((all_convertible_to<Scalar, const T>), typename T)
		MUU_NODISCARD_CTOR
		MUU_ATTR(nonnull)
		vector(const T* vals, size_t num) noexcept
		{
			MUU_ASSUME(vals != nullptr);
			MUU_ASSUME(num <= Dimensions);
			MUU_ASSUME(reinterpret_cast<uintptr_t>(vals) % alignof(T) == 0_sz);

			if constexpr (std::is_same_v<remove_cv<T>, Scalar>)
				std::memcpy(this, vals, sizeof(scalar_type) * num);
			else
			{
				for (size_t i = 0; i < num; i++)
					operator[](i) = static_cast<scalar_type>(vals[i]);
			}

			if (num < Dimensions)
				memset(pointer_cast<std::byte*>(this) + num * sizeof(scalar_type),
					   0,
					   (Dimensions - num) * sizeof(scalar_type));
		}

		/// \brief Constructs a vector from a pointer to scalars.
		///
		/// \tparam T			Type convertible to #scalar_type.
		/// \param	vals		Pointer to values to copy.
		MUU_CONSTRAINED_TEMPLATE((all_convertible_to<Scalar, const T>), typename T)
		MUU_NODISCARD_CTOR
		MUU_ATTR(nonnull)
		explicit constexpr vector(const T* MUU_HIDDEN(const&) vals) noexcept
			: base{ impl::array_cast_tag{}, std::make_index_sequence<Dimensions>{}, vals }
		{}

		/// \brief Constructs a vector from a statically-sized muu::span.
		/// \details	Any scalar components not covered by the constructor's parameters are initialized to zero.
		///
		/// \tparam T			Type convertible to #scalar_type.
		/// \tparam N			The number of elements covered by the span.
		/// \param	vals		A span representing the values to copy.
		MUU_CONSTRAINED_TEMPLATE((Dimensions >= N						 //
								  && all_convertible_to<Scalar, const T> //
								  && N != dynamic_extent),
								 typename T,
								 size_t N)
		MUU_NODISCARD_CTOR
		explicit constexpr vector(const muu::span<T, N>& vals) noexcept
			: base{ impl::array_cast_tag{}, std::make_index_sequence<N>{}, vals }
		{}

		/// \brief Constructs a vector from a dynamically-sized muu::span.
		/// \details			Any scalar components not covered by the constructor's parameters are initialized to zero.
		///
		/// \tparam T			Type convertible to #scalar_type.
		/// \param	vals		A span representing the values to copy.
		MUU_CONSTRAINED_TEMPLATE((all_convertible_to<Scalar, const T>), typename T)
		MUU_NODISCARD_CTOR
		explicit constexpr vector(const muu::span<T>& vals) noexcept //
			: vector{ vals.data(), vals.size() }
		{}

	#endif // constructors

	#if 1 // scalar component accessors --------------------------------------------------------------------------------

	  private:
		template <size_t Index, typename T>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		static constexpr auto& do_get(T& vec) noexcept
		{
			static_assert(Index < Dimensions, "Element index out of range");

			if constexpr (Dimensions <= 4)
			{
				if constexpr (Index == 0)
					return vec.x;
				if constexpr (Index == 1)
					return vec.y;
				if constexpr (Index == 2)
					return vec.z;
				if constexpr (Index == 3)
					return vec.w;
			}
			else
				return vec.values[Index];
		}

		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr auto& do_array_operator(T& vec, size_t idx) noexcept
		{
			MUU_ASSUME(idx < Dimensions);

			if constexpr (Dimensions <= 4)
			{
				if (/*!build::supports_is_constant_evaluated ||*/ is_constant_evaluated())
				{
					switch (idx)
					{
						case 0: return vec.x;
						case 1:
							if constexpr (Dimensions > 1)
								return vec.y;
							else
								MUU_UNREACHABLE;
						case 2:
							if constexpr (Dimensions > 2)
								return vec.z;
							else
								MUU_UNREACHABLE;
						case 3:
							if constexpr (Dimensions > 3)
								return vec.w;
							else
								MUU_UNREACHABLE;
						default: MUU_UNREACHABLE;
					}
				}
				else
					return *(&vec.x + idx);
			}
			else
				return vec.values[idx];
		}

	  public:
		/// \brief Gets a reference to the scalar component at a specific index.
		///
		/// \tparam Index  The index of the scalar component to retrieve, where x == 0, y == 1, etc.
		///
		/// \return  A reference to the selected scalar component.
		template <size_t Index>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		MUU_ATTR(flatten)
		constexpr const scalar_type& get() const noexcept
		{
			return do_get<Index>(*this);
		}

		/// \brief Gets a reference to the scalar component at a specific index.
		///
		/// \tparam Index  The index of the scalar component to retrieve, where x == 0, y == 1, etc.
		///
		/// \return  A reference to the selected scalar component.
		template <size_t Index>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		MUU_ATTR(flatten)
		constexpr scalar_type& get() noexcept
		{
			return do_get<Index>(*this);
		}

		/// \brief Gets a reference to the Nth scalar component.
		///
		/// \param idx  The index of the scalar component to retrieve, where x == 0, y == 1, etc.
		///
		/// \return  A reference to the selected scalar component.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr const scalar_type& operator[](size_t idx) const noexcept
		{
			return do_array_operator(*this, idx);
		}

		/// \brief Gets a reference to the Nth scalar component.
		///
		/// \param idx  The index of the scalar component to retrieve, where x == 0, y == 1, etc.
		///
		/// \return  A reference to the selected scalar component.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr scalar_type& operator[](size_t idx) noexcept
		{
			return do_array_operator(*this, idx);
		}

		/// \brief Returns a pointer to the first scalar component in the vector.
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		MUU_ATTR(flatten)
		constexpr const scalar_type* data() const noexcept
		{
			return &do_get<0>(*this);
		}

		/// \brief Returns a pointer to the first scalar component in the vector.
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		MUU_ATTR(flatten)
		constexpr scalar_type* data() noexcept
		{
			return &do_get<0>(*this);
		}

	#endif // scalar component accessors

	#if 1 // equality --------------------------------------------------------------------------------------------------

		/// \brief		Returns true if two vectors are exactly equal.
		///
		/// \remarks	This is a componentwise exact equality check;
		/// 			if you want an epsilon-based "near-enough" for floating-point vectors, use #approx_equal().
		MUU_CONSTRAINED_TEMPLATE((!MUU_HAS_VECTORCALL
								  || impl::pass_vectorcall_by_reference<vector, vector<T, Dimensions>>),
								 typename T)
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr bool operator==(const vector& lhs, const vector<T, dimensions>& rhs) noexcept
		{
			// clang-format off
			if constexpr (std::is_same_v<scalar_type, T>)
			{
				#define VEC_FUNC(member) lhs.member == rhs.member
				COMPONENTWISE_AND(VEC_FUNC);
				#undef VEC_FUNC
			}
			else
			{
				using type = impl::equality_check_type<scalar_type, T>;

				#define VEC_FUNC(member) static_cast<type>(lhs.member) == static_cast<type>(rhs.member)
				COMPONENTWISE_AND(VEC_FUNC);
				#undef VEC_FUNC
			}
			// clang-format on
		}

		#if MUU_HAS_VECTORCALL

		MUU_CONSTRAINED_TEMPLATE_2((impl::pass_vectorcall_by_value<vector, vector<T, Dimensions>>), typename T)
		MUU_NODISCARD
		MUU_ATTR(const)
		friend constexpr bool MUU_VECTORCALL operator==(vector lhs, vector<T, dimensions> rhs) noexcept
		{
			// clang-format off
			if constexpr (std::is_same_v<scalar_type, T>)
			{
				#define VEC_FUNC(member) lhs.member == rhs.member
				COMPONENTWISE_AND(VEC_FUNC);
				#undef VEC_FUNC
			}
			else
			{
				using type = impl::equality_check_type<scalar_type, T>;

				#define VEC_FUNC(member) static_cast<type>(lhs.member) == static_cast<type>(rhs.member)
				COMPONENTWISE_AND(VEC_FUNC);
				#undef VEC_FUNC
			}
			// clang-format on
		}

		#endif // MUU_HAS_VECTORCALL

		/// \brief	Returns true if two vectors are not exactly equal.
		///
		/// \remarks	This is a componentwise exact inequality check;
		/// 			if you want an epsilon-based "near-enough" for floating-point vectors, use #approx_equal().
		MUU_CONSTRAINED_TEMPLATE((!MUU_HAS_VECTORCALL
								  || impl::pass_vectorcall_by_reference<vector, vector<T, Dimensions>>),
								 typename T)
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr bool operator!=(const vector& lhs, const vector<T, dimensions>& rhs) noexcept
		{
			return !(lhs == rhs);
		}

		#if MUU_HAS_VECTORCALL

		MUU_CONSTRAINED_TEMPLATE_2((impl::pass_vectorcall_by_value<vector, vector<T, Dimensions>>), typename T)
		MUU_NODISCARD
		MUU_ATTR(const)
		friend constexpr bool MUU_VECTORCALL operator!=(vector lhs, vector<T, dimensions> rhs) noexcept
		{
			return !(lhs == rhs);
		}

		#endif // MUU_HAS_VECTORCALL

		/// \brief	Returns true if all the scalar components of a vector are exactly zero.
		///
		/// \remarks	This is a componentwise exact equality check;
		/// 			if you want an epsilon-based "near-enough" for floating-point vectors, use #approx_zero().
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL zero(MUU_VC_PARAM(vector) v) noexcept
		{
				// clang-format off
			#define VEC_FUNC(member) v.member == scalar_type{}
			COMPONENTWISE_AND(VEC_FUNC);
			#undef VEC_FUNC
			// clang-format on
		}

		/// \brief	Returns true if all the scalar components of the vector are exactly zero.
		///
		/// \remarks	This is a componentwise exact equality check;
		/// 			if you want an epsilon-based "near-enough" for floating-point vectors, use #approx_zero().
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool zero() const noexcept
		{
			return zero(*this);
		}

		/// \brief	Returns true if any of the scalar components of a vector are infinity or NaN.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL infinity_or_nan(MUU_VC_PARAM(vector) v) noexcept
		{
			// clang-format off
			if constexpr (is_floating_point<scalar_type>)
			{
				#define VEC_FUNC(member) muu::infinity_or_nan(v.member)
				COMPONENTWISE_OR(VEC_FUNC);
				#undef VEC_FUNC
			}
			else
			{
				MUU_UNUSED(v);
				return false;
			}
			// clang-format on
		}

		/// \brief	Returns true if any of the scalar components of the vector are infinity or NaN.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool infinity_or_nan() const noexcept
		{
			if constexpr (is_floating_point<scalar_type>)
				return infinity_or_nan(*this);
			else
				return false;
		}

	#endif // equality

	#if 1 // approx_equal ----------------------------------------------------------------------------------------------

		/// \brief	Returns true if two vectors are approximately equal.
		///
		/// \availability		This function is only available when at least one of #scalar_type
		///						and `T` is a floating-point type.
		MUU_CONSTRAINED_TEMPLATE((any_floating_point<Scalar, T> //
								  && (!MUU_HAS_VECTORCALL
									  || impl::pass_vectorcall_by_reference<vector, vector<T, Dimensions>>)),
								 typename T)
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL approx_equal(
			const vector& v1,
			const vector<T, dimensions>& v2,
			epsilon_type<scalar_type, T> epsilon = default_epsilon<scalar_type, T>) noexcept
		{
			// clang-format off
			if constexpr (std::is_same_v<scalar_type, T>)
			{
				#define VEC_FUNC(member) muu::approx_equal(v1.member, v2.member, epsilon)
				COMPONENTWISE_AND(VEC_FUNC);
				#undef VEC_FUNC
			}
			else
			{
				using type = impl::equality_check_type<scalar_type, T>;

				#define VEC_FUNC(member) muu::approx_equal(static_cast<type>(v1.member),\
															static_cast<type>(v2.member),\
															static_cast<type>(epsilon))
				COMPONENTWISE_AND(VEC_FUNC);
				#undef VEC_FUNC
			}
			// clang-format on
		}

		#if MUU_HAS_VECTORCALL

		MUU_CONSTRAINED_TEMPLATE_2((any_floating_point<Scalar, T> //
									&& (impl::pass_vectorcall_by_value<vector, vector<T, Dimensions>>)),
								   typename T)
		MUU_NODISCARD
		MUU_ATTR(const)
		static constexpr bool MUU_VECTORCALL approx_equal(
			vector v1,
			vector<T, dimensions> v2,
			epsilon_type<scalar_type, T> epsilon = default_epsilon<scalar_type, T>) noexcept
		{
			// clang-format off
			if constexpr (std::is_same_v<scalar_type, T>)
			{
				#define VEC_FUNC(member) muu::approx_equal(v1.member, v2.member, epsilon)
				COMPONENTWISE_AND(VEC_FUNC);
				#undef VEC_FUNC
			}
			else
			{
				using type = impl::equality_check_type<scalar_type, T>;

				#define VEC_FUNC(member) muu::approx_equal(static_cast<type>(v1.member),\
															static_cast<type>(v2.member),\
															static_cast<type>(epsilon))
				COMPONENTWISE_AND(VEC_FUNC);
				#undef VEC_FUNC
			}
			// clang-format on
		}

		#endif // MUU_HAS_VECTORCALL

		/// \brief	Returns true if the vector is approximately equal to another.
		///
		/// \availability		This function is only available when at least one of #scalar_type
		///						and `T` is a floating-point type.
		MUU_CONSTRAINED_TEMPLATE((any_floating_point<Scalar, T> //
								  && (!MUU_HAS_VECTORCALL
									  || impl::pass_vectorcall_by_reference<vector<T, Dimensions>>)),
								 typename T)
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool MUU_VECTORCALL approx_equal(
			const vector<T, dimensions>& v,
			epsilon_type<scalar_type, T> epsilon = default_epsilon<scalar_type, T>) const noexcept
		{
			return approx_equal(*this, v, epsilon);
		}

		#if MUU_HAS_VECTORCALL

		MUU_CONSTRAINED_TEMPLATE_2((any_floating_point<Scalar, T> //
									&& impl::pass_vectorcall_by_value<vector<T, Dimensions>>),
								   typename T)
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool MUU_VECTORCALL approx_equal(
			vector<T, dimensions> v,
			epsilon_type<scalar_type, T> epsilon = default_epsilon<scalar_type, T>) const noexcept
		{
			return approx_equal(*this, v, epsilon);
		}

		#endif // MUU_HAS_VECTORCALL

		/// \brief	Returns true if all the scalar components in a vector are approximately equal to zero.
		///
		/// \availability		This function is only available when #scalar_type is a floating-point type.
		MUU_LEGACY_REQUIRES(is_floating_point<T>, typename T = Scalar)
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL approx_zero(MUU_VC_PARAM(vector) v,
														 scalar_type epsilon = default_epsilon<scalar_type>) noexcept
			MUU_REQUIRES(is_floating_point<Scalar>)
		{
				// clang-format off
			#define VEC_FUNC(member) muu::approx_zero(v.member, epsilon)
			COMPONENTWISE_AND(VEC_FUNC);
			#undef VEC_FUNC
			// clang-format on
		}

		/// \brief	Returns true if all the scalar components in the vector are approximately equal to zero.
		///
		/// \availability		This function is only available when #scalar_type is a floating-point type.
		MUU_LEGACY_REQUIRES(is_floating_point<T>, typename T = Scalar)
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool MUU_VECTORCALL approx_zero(scalar_type epsilon = default_epsilon<scalar_type>) const noexcept
			MUU_REQUIRES(is_floating_point<Scalar>)
		{
			return approx_zero(*this, epsilon);
		}

	#endif // approx_equal

	#if 1 // length and distance ---------------------------------------------------------------------------------------

	  private:
		template <typename T = intermediate_float>
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr T MUU_VECTORCALL raw_length_squared(MUU_VC_PARAM(vector) v) noexcept
		{
			static_assert(std::is_same_v<impl::highest_ranked<T, intermediate_float>, T>); // non-truncating

				// clang-format off
			#define VEC_FUNC(member) static_cast<T>(v.member) * static_cast<T>(v.member)
			COMPONENTWISE_ACCUMULATE(VEC_FUNC, +);
			#undef VEC_FUNC
			// clang-format on
		}

		template <typename T = intermediate_float>
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr T MUU_VECTORCALL raw_length(MUU_VC_PARAM(vector) v) noexcept
		{
			static_assert(std::is_same_v<impl::highest_ranked<T, intermediate_float>, T>); // non-truncating

			if constexpr (Dimensions == 1)
				return static_cast<T>(v.x);
			else
				return muu::sqrt(raw_length_squared<T>(v));
		}

		template <typename T = intermediate_float>
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr T MUU_VECTORCALL raw_distance_squared(MUU_VC_PARAM(vector) p1,
															   MUU_VC_PARAM(vector) p2) noexcept
		{
			static_assert(std::is_same_v<impl::highest_ranked<T, intermediate_float>, T>); // non-truncating

			constexpr auto subtract_and_square = [](scalar_type lhs, scalar_type rhs) noexcept -> T
			{
				MUU_FMA_BLOCK;

				const T temp = static_cast<T>(lhs) - static_cast<T>(rhs);
				return temp * temp;
			};

				// clang-format off
			#define VEC_FUNC(member) subtract_and_square(p2.member, p1.member)
			COMPONENTWISE_ACCUMULATE(VEC_FUNC, +);
			#undef VEC_FUNC
			// clang-format on
		}

		template <typename T = intermediate_float>
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr T MUU_VECTORCALL raw_distance(MUU_VC_PARAM(vector) p1, MUU_VC_PARAM(vector) p2) noexcept
		{
			static_assert(std::is_same_v<impl::highest_ranked<T, intermediate_float>, T>); // non-truncating

			if constexpr (Dimensions == 1)
				return static_cast<T>(p2.x) - static_cast<T>(p1.x);
			else
				return muu::sqrt(raw_distance_squared<T>(p1, p2));
		}

	  public:
		/// \brief	Returns the squared length (magnitude) of a vector.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr delta_type MUU_VECTORCALL length_squared(MUU_VC_PARAM(vector) v) noexcept
		{
			return static_cast<delta_type>(raw_length_squared(v));
		}

		/// \brief	Returns the squared length (magnitude) of the vector.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr delta_type length_squared() const noexcept
		{
			return static_cast<delta_type>(raw_length_squared(*this));
		}

		/// \brief	Returns the length (magnitude) of a vector.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr delta_type MUU_VECTORCALL length(MUU_VC_PARAM(vector) v) noexcept
		{
			return static_cast<delta_type>(raw_length(v));
		}

		/// \brief	Returns the length (magnitude) of the vector.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr delta_type length() const noexcept
		{
			return static_cast<delta_type>(raw_length(*this));
		}

		/// \brief	Returns the squared distance between two point vectors.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr delta_type MUU_VECTORCALL distance_squared(MUU_VC_PARAM(vector) p1,
																	MUU_VC_PARAM(vector) p2) noexcept
		{
			return static_cast<delta_type>(raw_distance_squared(p1, p2));
		}

		/// \brief	Returns the squared distance between this and another point vector.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr delta_type MUU_VECTORCALL distance_squared(MUU_VC_PARAM(vector) p) const noexcept
		{
			return static_cast<delta_type>(raw_distance_squared(*this, p));
		}

		/// \brief	Returns the squared distance between two point vectors.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr delta_type MUU_VECTORCALL distance(MUU_VC_PARAM(vector) p1, MUU_VC_PARAM(vector) p2) noexcept
		{
			return static_cast<delta_type>(raw_distance(p1, p2));
		}

		/// \brief	Returns the squared distance between this and another point vector.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr delta_type MUU_VECTORCALL distance(MUU_VC_PARAM(vector) p) const noexcept
		{
			return static_cast<delta_type>(raw_distance(*this, p));
		}

	#endif // length and distance

	#if 1 // dot and cross products ------------------------------------------------------------------------------------

	  private:
		template <typename T = intermediate_product>
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr T MUU_VECTORCALL raw_dot(MUU_VC_PARAM(vector) v1, MUU_VC_PARAM(vector) v2) noexcept
		{
			static_assert(std::is_same_v<impl::highest_ranked<T, intermediate_product>, T>); // non-truncating

			using mult_type = decltype(scalar_type{} * scalar_type{});

			// clang-format off
			if constexpr (std::is_same_v<mult_type, T>)
			{
				#define VEC_FUNC(member) v1.member* v2.member
				COMPONENTWISE_ACCUMULATE(VEC_FUNC, +);
				#undef VEC_FUNC
			}
			else
			{
				#define VEC_FUNC(member) static_cast<T>(v1.member) * static_cast<T>(v2.member)
				COMPONENTWISE_ACCUMULATE(VEC_FUNC, +);
				#undef VEC_FUNC
			}
			// clang-format on
		}

	  public:
		/// \brief	Returns the dot product of two vectors.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr product_type MUU_VECTORCALL dot(MUU_VC_PARAM(vector) v1, MUU_VC_PARAM(vector) v2) noexcept
		{
			return static_cast<product_type>(raw_dot(v1, v2));
		}

		/// \brief	Returns the dot product of this and another vector.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr product_type MUU_VECTORCALL dot(MUU_VC_PARAM(vector) v) const noexcept
		{
			return static_cast<product_type>(raw_dot(*this, v));
		}

		/// \brief	Returns the cross product of two vectors.
		///
		/// \availability		This function is only available when #dimensions == 3.
		MUU_LEGACY_REQUIRES(Dim == 3, size_t Dim = Dimensions)
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector<product_type, 3> MUU_VECTORCALL cross(MUU_VC_PARAM(vector) lhs,
																	  MUU_VC_PARAM(vector) rhs) noexcept
			MUU_REQUIRES(Dimensions == 3)
		{
			return impl::raw_cross<vector<product_type, 3>>(lhs, rhs);
		}

		/// \brief	Returns the cross product of this vector and another.
		///
		/// \availability		This function is only available when #dimensions == 3.
		MUU_LEGACY_REQUIRES(Dim == 3, size_t Dim = Dimensions)
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr vector<product_type, 3> MUU_VECTORCALL cross(MUU_VC_PARAM(vector) v) const noexcept
			MUU_REQUIRES(Dimensions == 3)
		{
			return impl::raw_cross<vector<product_type, 3>>(*this, v);
		}

	#endif // dot and cross products

	#if 1 // addition --------------------------------------------------------------------------------------------------

		/// \brief Returns the componentwise addition of two vectors.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr vector MUU_VECTORCALL operator+(MUU_VC_PARAM(vector) lhs, MUU_VC_PARAM(vector) rhs) noexcept
		{
			// clang-format off
			if constexpr (impl::is_small_float_<scalar_type>)
			{
				#define VEC_FUNC(member) static_cast<float>(lhs.member) + static_cast<float>(rhs.member)
				COMPONENTWISE_CONSTRUCT(VEC_FUNC);
				#undef VEC_FUNC
			}
			else
			{
				#define VEC_FUNC(member) lhs.member + rhs.member
				COMPONENTWISE_CONSTRUCT(VEC_FUNC);
				#undef VEC_FUNC
			}
			// clang-format on
		}

		/// \brief Componentwise adds another vector to this one.
		constexpr vector& MUU_VECTORCALL operator+=(MUU_VC_PARAM(vector) rhs) noexcept
		{
			// clang-format off
			if constexpr (impl::is_small_float_<scalar_type>)
			{
				#define VEC_FUNC(member) static_cast<float>(base::member) + static_cast<float>(rhs.member)
				COMPONENTWISE_ASSIGN(VEC_FUNC);
				#undef VEC_FUNC
			}
			else
			{
				#define VEC_FUNC(member) base::member + rhs.member
				COMPONENTWISE_ASSIGN(VEC_FUNC);
				#undef VEC_FUNC
			}
			// clang-format on
		}

		/// \brief Returns a componentwise copy of a vector.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr vector operator+() const noexcept
		{
			return *this;
		}

	#endif // addition

	#if 1 // subtraction -----------------------------------------------------------------------------------------------

		/// \brief Returns the componentwise subtraction of one vector from another.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr vector MUU_VECTORCALL operator-(MUU_VC_PARAM(vector) lhs, MUU_VC_PARAM(vector) rhs) noexcept
		{
			// clang-format off
			if constexpr (impl::is_small_float_<scalar_type>)
			{
				#define VEC_FUNC(member) static_cast<float>(lhs.member) - static_cast<float>(rhs.member)
				COMPONENTWISE_CONSTRUCT(VEC_FUNC);
				#undef VEC_FUNC
			}
			else
			{
				#define VEC_FUNC(member) lhs.member - rhs.member
				COMPONENTWISE_CONSTRUCT(VEC_FUNC);
				#undef VEC_FUNC
			}
			// clang-format on
		}

		/// \brief Componentwise subtracts another vector from this one.
		constexpr vector& MUU_VECTORCALL operator-=(MUU_VC_PARAM(vector) rhs) noexcept
		{
			// clang-format off
			if constexpr (impl::is_small_float_<scalar_type>)
			{
				#define VEC_FUNC(member) static_cast<float>(base::member) - static_cast<float>(rhs.member)
				COMPONENTWISE_ASSIGN(VEC_FUNC);
				#undef VEC_FUNC
			}
			else
			{
				#define VEC_FUNC(member) base::member - rhs.member
				COMPONENTWISE_ASSIGN(VEC_FUNC);
				#undef VEC_FUNC
			}
			// clang-format on
		}

		/// \brief Returns the componentwise negation of a vector.
		MUU_LEGACY_REQUIRES(is_signed<T>, typename T = Scalar)
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr vector operator-() const noexcept MUU_REQUIRES(is_signed<Scalar>)
		{
				// clang-format off
			#define VEC_FUNC(member) -base::member
			COMPONENTWISE_CONSTRUCT(VEC_FUNC);
			#undef VEC_FUNC
			// clang-format on
		}

	#endif // subtraction

	#if 1 // multiplication -------------------------------------------------------------------------------------------

		/// \brief Returns the componentwise multiplication of two vectors.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr vector MUU_VECTORCALL operator*(MUU_VC_PARAM(vector) lhs, MUU_VC_PARAM(vector) rhs) noexcept
		{
			// clang-format off
			if constexpr (impl::is_small_float_<scalar_type>)
			{
				#define VEC_FUNC(member) static_cast<float>(lhs.member) * static_cast<float>(rhs.member)
				COMPONENTWISE_CONSTRUCT(VEC_FUNC);
				#undef VEC_FUNC
			}
			else
			{
				#define VEC_FUNC(member) lhs.member* rhs.member
				COMPONENTWISE_CONSTRUCT(VEC_FUNC);
				#undef VEC_FUNC
			}
			// clang-format on
		}

		/// \brief Componentwise multiplies this vector by another.
		constexpr vector& MUU_VECTORCALL operator*=(MUU_VC_PARAM(vector) rhs) noexcept
		{
			// clang-format off
			if constexpr (impl::is_small_float_<scalar_type>)
			{
				#define VEC_FUNC(member) static_cast<float>(base::member) * static_cast<float>(rhs.member)
				COMPONENTWISE_ASSIGN(VEC_FUNC);
				#undef VEC_FUNC
			}
			else
			{
				#define VEC_FUNC(member) base::member* rhs.member
				COMPONENTWISE_ASSIGN(VEC_FUNC);
				#undef VEC_FUNC
			}
			// clang-format on
		}

	  private:
		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector MUU_VECTORCALL raw_multiply_scalar(MUU_VC_PARAM(vector) lhs, T rhs) noexcept
		{
			using type = set_signed<
				impl::highest_ranked<decltype(scalar_type{} * impl::promote_if_small_float<T>{}), intermediate_product>,
				is_signed<scalar_type> || is_signed<T>>;

			// clang-format off
			if constexpr (all_same<type, scalar_type, T>)
			{
				#define VEC_FUNC(member) lhs.member* rhs
				COMPONENTWISE_CONSTRUCT(VEC_FUNC);
				#undef VEC_FUNC
			}
			else
			{
				const auto rhs_ = static_cast<type>(rhs);
				#define VEC_FUNC(member) static_cast<type>(lhs.member) * rhs_
				COMPONENTWISE_CONSTRUCT(VEC_FUNC);
				#undef VEC_FUNC
			}
			// clang-format on
		}

		template <typename T>
		constexpr vector& MUU_VECTORCALL raw_multiply_assign_scalar(T rhs) noexcept
		{
			using type = set_signed<
				impl::highest_ranked<decltype(scalar_type{} * impl::promote_if_small_float<T>{}), intermediate_product>,
				is_signed<scalar_type> || is_signed<T>>;

			// clang-format off
			if constexpr (all_same<type, scalar_type, T>)
			{
				#define VEC_FUNC(member) base::member* rhs
				COMPONENTWISE_ASSIGN(VEC_FUNC);
				#undef VEC_FUNC
			}
			else
			{
				const auto rhs_ = static_cast<type>(rhs);
				#define VEC_FUNC(member) static_cast<type>(base::member) * rhs_
				COMPONENTWISE_ASSIGN(VEC_FUNC);
				#undef VEC_FUNC
			}
			// clang-format on
		}

	  public:
		/// \brief Returns the componentwise multiplication of a vector and a scalar.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr vector MUU_VECTORCALL operator*(MUU_VC_PARAM(vector) lhs, scalar_type rhs) noexcept
		{
			return raw_multiply_scalar(lhs, rhs);
		}

		/// \brief Returns the componentwise multiplication of a vector and a scalar.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr vector MUU_VECTORCALL operator*(scalar_type lhs, MUU_VC_PARAM(vector) rhs) noexcept
		{
			return raw_multiply_scalar(rhs, lhs);
		}

		/// \brief Componentwise multiplies this vector by a scalar.
		constexpr vector& MUU_VECTORCALL operator*=(scalar_type rhs) noexcept
		{
			return raw_multiply_assign_scalar(rhs);
		}

	#endif // multiplication

	#if 1 // division -------------------------------------------------------------------------------------------------

		/// \brief Returns the componentwise division of one vector by another.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr vector MUU_VECTORCALL operator/(MUU_VC_PARAM(vector) lhs, MUU_VC_PARAM(vector) rhs) noexcept
		{
			// clang-format off
			if constexpr (impl::is_small_float_<scalar_type>)
			{
				#define VEC_FUNC(member) static_cast<float>(lhs.member) / static_cast<float>(rhs.member)
				COMPONENTWISE_CONSTRUCT(VEC_FUNC);
				#undef VEC_FUNC
			}
			else
			{
				#define VEC_FUNC(member) lhs.member / rhs.member
				COMPONENTWISE_CONSTRUCT(VEC_FUNC);
				#undef VEC_FUNC
			}
			// clang-format on
		}

		/// \brief Componentwise divides this vector by another.
		constexpr vector& MUU_VECTORCALL operator/=(MUU_VC_PARAM(vector) rhs) noexcept
		{
			// clang-format off
			if constexpr (impl::is_small_float_<scalar_type>)
			{
				#define VEC_FUNC(member) static_cast<float>(base::member) / static_cast<float>(rhs.member)
				COMPONENTWISE_ASSIGN(VEC_FUNC);
				#undef VEC_FUNC
			}
			else
			{
				#define VEC_FUNC(member) base::member / rhs.member
				COMPONENTWISE_ASSIGN(VEC_FUNC);
				#undef VEC_FUNC
			}
			// clang-format on
		}

	  private:
		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector MUU_VECTORCALL raw_divide_scalar(MUU_VC_PARAM(vector) lhs, T rhs) noexcept
		{
			using type = set_signed<
				impl::highest_ranked<decltype(scalar_type{} / impl::promote_if_small_float<T>{}), intermediate_product>,
				is_signed<scalar_type> || is_signed<T>>;

			// clang-format off
			if constexpr (is_floating_point<type>)
			{
				return raw_multiply_scalar(lhs, type{ 1 } / static_cast<type>(rhs));
			}
			else if constexpr (all_same<type, scalar_type, T>)
			{
				#define VEC_FUNC(member) lhs.member / rhs
				COMPONENTWISE_CONSTRUCT(VEC_FUNC);
				#undef VEC_FUNC
			}
			else
			{
				const auto rhs_ = static_cast<type>(rhs);
				#define VEC_FUNC(member) static_cast<type>(lhs.member) / rhs_
				COMPONENTWISE_CONSTRUCT(VEC_FUNC);
				#undef VEC_FUNC
			}
			// clang-format on
		}

		template <typename T>
		constexpr vector& MUU_VECTORCALL raw_divide_assign_scalar(T rhs) noexcept
		{
			using type = set_signed<
				impl::highest_ranked<decltype(scalar_type{} / impl::promote_if_small_float<T>{}), intermediate_product>,
				is_signed<scalar_type> || is_signed<T>>;

			// clang-format off
			if constexpr (is_floating_point<type>)
			{
				return raw_multiply_assign_scalar(type{ 1 } / static_cast<type>(rhs));
			}
			else if constexpr (all_same<type, scalar_type, T>)
			{
				#define VEC_FUNC(member) base::member / rhs
				COMPONENTWISE_ASSIGN(VEC_FUNC);
				#undef VEC_FUNC
			}
			else
			{
				const auto rhs_ = static_cast<type>(rhs);
				#define VEC_FUNC(member) static_cast<type>(base::member) / rhs_
				COMPONENTWISE_ASSIGN(VEC_FUNC);
				#undef VEC_FUNC
			}
			// clang-format on
		}

	  public:
		/// \brief Returns the componentwise division of a vector and a scalar.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr vector MUU_VECTORCALL operator/(MUU_VC_PARAM(vector) lhs, scalar_type rhs) noexcept
		{
			return raw_divide_scalar(lhs, rhs);
		}

		/// \brief Componentwise divides this vector by a scalar.
		constexpr vector& MUU_VECTORCALL operator/=(scalar_type rhs) noexcept
		{
			return raw_divide_assign_scalar(rhs);
		}

	#endif // division

	#if 1 // modulo ---------------------------------------------------------------------------------------------------

		/// \brief Returns the remainder of componentwise dividing of one vector by another.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr vector MUU_VECTORCALL operator%(MUU_VC_PARAM(vector) lhs, MUU_VC_PARAM(vector) rhs) noexcept
		{
				// clang-format off
			#define VEC_FUNC(member) impl::raw_modulo(lhs.member, rhs.member)
			COMPONENTWISE_CONSTRUCT(VEC_FUNC);
			#undef VEC_FUNC
			// clang-format on
		}

		/// \brief Assigns the result of componentwise dividing this vector by another.
		constexpr vector& MUU_VECTORCALL operator%=(MUU_VC_PARAM(vector) rhs) noexcept
		{
				// clang-format off
			#define VEC_FUNC(member) impl::raw_modulo(base::member, rhs.member)
			COMPONENTWISE_ASSIGN(VEC_FUNC);
			#undef VEC_FUNC
			// clang-format on
		}

		/// \brief Returns the remainder of componentwise dividing vector by a scalar.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr vector MUU_VECTORCALL operator%(MUU_VC_PARAM(vector) lhs, scalar_type rhs) noexcept
		{
				// clang-format off
			#define VEC_FUNC(member) impl::raw_modulo(lhs.member, rhs)
			COMPONENTWISE_CONSTRUCT(VEC_FUNC);
			#undef VEC_FUNC
			// clang-format on
		}

		/// \brief Assigns the result of componentwise dividing this vector by a scalar.
		constexpr vector& MUU_VECTORCALL operator%=(scalar_type rhs) noexcept
		{
				// clang-format off
			#define VEC_FUNC(member) impl::raw_modulo(base::member, rhs)
			COMPONENTWISE_ASSIGN(VEC_FUNC);
			#undef VEC_FUNC
			// clang-format on
		}

	#endif // modulo

	#if 1 // bitwise shifts ----------------------------------------------------------------------------------------

		/// \brief Returns a vector with each scalar component left-shifted the given number of bits.
		///
		/// \availability		This function is only available when #scalar_type is an integral type.
		MUU_LEGACY_REQUIRES(is_integral<T>, typename T = Scalar)
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr vector MUU_VECTORCALL operator<<(MUU_VC_PARAM(vector) lhs, product_type rhs) noexcept
			MUU_REQUIRES(is_integral<Scalar>)
		{
			MUU_ASSUME(rhs >= 0);

				// clang-format off
			#define VEC_FUNC(member) lhs.member << rhs
			COMPONENTWISE_CONSTRUCT(VEC_FUNC);
			#undef VEC_FUNC
			// clang-format on
		}

		/// \brief Componentwise left-shifts each scalar component in the vector by the given number of bits.
		///
		/// \availability		This function is only available when #scalar_type is an integral type.
		MUU_LEGACY_REQUIRES(is_integral<T>, typename T = Scalar)
		constexpr vector& MUU_VECTORCALL operator<<=(product_type rhs) noexcept MUU_REQUIRES(is_integral<Scalar>)
		{
			MUU_ASSUME(rhs >= 0);

				// clang-format off
			#define VEC_FUNC(member) base::member << rhs
			COMPONENTWISE_ASSIGN(VEC_FUNC);
			#undef VEC_FUNC
			// clang-format on
		}

		/// \brief Returns a vector with each scalar component right-shifted the given number of bits.
		///
		/// \availability		This function is only available when #scalar_type is an integral type.
		MUU_LEGACY_REQUIRES(is_integral<T>, typename T = Scalar)
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr vector MUU_VECTORCALL operator>>(MUU_VC_PARAM(vector) lhs, product_type rhs) noexcept
			MUU_REQUIRES(is_integral<Scalar>)
		{
			MUU_ASSUME(rhs >= 0);

				// clang-format off
			#define VEC_FUNC(member) lhs.member >> rhs
			COMPONENTWISE_CONSTRUCT(VEC_FUNC);
			#undef VEC_FUNC
			// clang-format on
		}

		/// \brief Componentwise right-shifts each scalar component in the vector by the given number of bits.
		///
		/// \availability		This function is only available when #scalar_type is an integral type.
		MUU_LEGACY_REQUIRES(is_integral<T>, typename T = Scalar)
		constexpr vector& MUU_VECTORCALL operator>>=(product_type rhs) noexcept MUU_REQUIRES(is_integral<Scalar>)
		{
			MUU_ASSUME(rhs >= 0);

				// clang-format off
			#define VEC_FUNC(member) base::member >> rhs
			COMPONENTWISE_ASSIGN(VEC_FUNC);
			#undef VEC_FUNC
			// clang-format on
		}

	#endif // bitwise shifts

	#if 1 // normalization --------------------------------------------------------------------------------------------

		/// \brief	Normalizes a vector.
		///
		/// \param v			The vector to normalize.
		/// \param length_out	An output param to receive the length of the vector pre-normalization.
		///
		/// \return		A normalized copy of the input vector.
		///
		/// \availability This function is only available when #scalar_type is a floating-point type.
		MUU_LEGACY_REQUIRES(is_floating_point<T>, typename T = Scalar)
		MUU_NODISCARD
		static constexpr vector MUU_VECTORCALL normalize(MUU_VC_PARAM(vector) v, delta_type& length_out) noexcept
			MUU_REQUIRES(is_floating_point<Scalar>)
		{
			if constexpr (Dimensions == 1)
			{
				length_out = static_cast<delta_type>(v.x);
				return vector{ scalar_constants::one };
			}
			else
			{
				const auto len = raw_length(v);
				length_out	   = static_cast<delta_type>(len);
				return raw_divide_scalar(v, len);
			}
		}

		/// \brief	Normalizes a vector.
		///
		/// \param v	The vector to normalize.
		///
		/// \return		A normalized copy of the input vector.
		///
		/// \availability This function is only available when #scalar_type is a floating-point type.
		MUU_LEGACY_REQUIRES(is_floating_point<T>, typename T = Scalar)
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector MUU_VECTORCALL normalize(MUU_VC_PARAM(vector) v) noexcept
			MUU_REQUIRES(is_floating_point<Scalar>)
		{
			if constexpr (Dimensions == 1)
			{
				MUU_UNUSED(v);
				return vector{ scalar_constants::one };
			}
			else
				return raw_divide_scalar(v, raw_length(v));
		}

		/// \brief	Normalizes the vector (in-place).
		///
		/// \param length_out	An output param to receive the length of the vector pre-normalization.
		///
		/// \return	A reference to the vector.
		///
		/// \availability This function is only available when #scalar_type is a floating-point type.
		MUU_LEGACY_REQUIRES(is_floating_point<T>, typename T = Scalar)
		constexpr vector& normalize(delta_type& length_out) noexcept MUU_REQUIRES(is_floating_point<Scalar>)
		{
			if constexpr (Dimensions == 1)
			{
				length_out = static_cast<delta_type>(base::x);
				base::x	   = scalar_constants::one;
				return *this;
			}
			else
			{
				const auto len = raw_length(*this);
				length_out	   = static_cast<delta_type>(len);
				return raw_divide_assign_scalar(len);
			}
		}

		/// \brief	Normalizes the vector (in-place).
		///
		/// \return	A reference to the vector.
		///
		/// \availability This function is only available when #scalar_type is a floating-point type.
		MUU_LEGACY_REQUIRES(is_floating_point<T>, typename T = Scalar)
		constexpr vector& normalize() noexcept MUU_REQUIRES(is_floating_point<Scalar>)
		{
			if constexpr (Dimensions == 1)
			{
				base::x = scalar_constants::one;
				return *this;
			}
			else
				return raw_divide_assign_scalar(raw_length(*this));
		}

		/// \brief	Normalizes a vector using a pre-calculated squared-length.
		///
		/// \param v			The vector to normalize.
		/// \param v_lensq		The pre-calculated squared-length of `v`.
		///
		/// \return		A normalized copy of the input vector.
		///
		/// \availability This function is only available when #scalar_type is a floating-point type.
		MUU_LEGACY_REQUIRES(is_floating_point<T>, typename T = Scalar)
		MUU_NODISCARD
		static constexpr vector MUU_VECTORCALL normalize_lensq(MUU_VC_PARAM(vector) v, delta_type v_lensq) noexcept
			MUU_REQUIRES(is_floating_point<Scalar>)
		{
			return raw_divide_scalar(v, muu::sqrt(static_cast<intermediate_float>(v_lensq)));
		}

		/// \brief	Normalizes the vector using a pre-calculated squared-length (in-place).
		///
		/// \param lensq		The pre-calculated squared-length of the vector.
		///
		/// \return	A reference to the vector.
		///
		/// \availability This function is only available when #scalar_type is a floating-point type.
		MUU_LEGACY_REQUIRES(is_floating_point<T>, typename T = Scalar)
		constexpr vector& MUU_VECTORCALL normalize_lensq(delta_type lensq) noexcept
			MUU_REQUIRES(is_floating_point<Scalar>)
		{
			return raw_divide_assign_scalar(muu::sqrt(static_cast<intermediate_float>(lensq)));
		}

		/// \brief Returns true if a vector is normalized (i.e. has a length of 1).
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL normalized(MUU_VC_PARAM(vector) v) noexcept
		{
			if constexpr (is_integral<scalar_type>)
			{
				if constexpr (Dimensions == 1)
					return v.x == scalar_type{ 1 };
				else
				{
					using sum_type = decltype(scalar_type{} + scalar_type{});
					sum_type sum{};
					for (size_t i = 0u; i < dimensions && sum > sum_type{ 1 }; i++)
					{
						if constexpr (muu::is_signed<scalar_type>)
							sum += muu::abs(v[i]);
						else
							sum += v[i];
					}
					return sum == sum_type{ 1 };
				}
			}
			else
			{
				if constexpr (Dimensions == 1)
					return muu::approx_equal(static_cast<intermediate_float>(v.x), intermediate_float{ 1 });
				else
				{
					constexpr auto epsilon = intermediate_float{ 1 }
										   / (100ull * (sizeof(scalar_type) >= sizeof(float) ? 10000ull : 1ull)
											  * (sizeof(scalar_type) >= sizeof(double) ? 10000ull : 1ull));

					return muu::approx_equal(raw_length_squared(v), intermediate_float{ 1 }, epsilon);
				}
			}
		}

		/// \brief Returns true if the vector is normalized (i.e. has a length of 1).
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool normalized() const noexcept
		{
			return normalized(*this);
		}

		[[deprecated]] MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL unit_length(MUU_VC_PARAM(vector) v) noexcept
		{
			return normalized(v);
		}

		[[deprecated]] MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool unit_length() const noexcept
		{
			return normalized(*this);
		}

	#endif // normalization

	#if 1 // direction ------------------------------------------------------------------------------------------------

		/// \brief		Returns the normalized direction vector from one position to another.
		///
		/// \param	from			The start position.
		/// \param	to				The end position.
		/// \param	distance_out	An output param to receive the distance between the two points.
		///
		/// \return		A normalized direction vector pointing from the start position to the end position.
		///
		/// \availability		This function is only available when #dimensions == 2 or 3.
		MUU_LEGACY_REQUIRES((Dim == 2 || Dim == 3), size_t Dim = Dimensions)
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector_product MUU_VECTORCALL direction(MUU_VC_PARAM(vector) from,
																 MUU_VC_PARAM(vector) to,
																 delta_type& distance_out) noexcept
			MUU_REQUIRES(Dimensions == 2 || Dimensions == 3)
		{
			// all are the same type - only happens with float, double, long double etc.
			if constexpr (all_same<scalar_type, intermediate_float, delta_type>)
			{
				return vector_product::normalize(to - from, distance_out);
			}

			// only intermediate type is different - half, _Float16, __fp16
			else if constexpr (std::is_same_v<scalar_type, delta_type>)
			{
				using ivec = vector<intermediate_float, dimensions>;
				intermediate_float dist{};
				vector_product result{ ivec::normalize(ivec{ to } - ivec{ from }, dist) };
				distance_out = static_cast<delta_type>(dist);
				return result;
			}

			// only scalar_type is different - integers.
			else if constexpr (std::is_same_v<delta_type, intermediate_float>)
			{
				return vector_product::normalize(vector_product{ to } - vector_product{ from }, distance_out);
			}
		}

		/// \brief		Returns the normalized direction vector from one position to another.
		///
		/// \param	from			The start position.
		/// \param	to				The end position.
		///
		/// \return		A normalized direction vector pointing from the start position to the end position.
		///
		/// \availability		This function is only available when #dimensions == 2 or 3.
		MUU_LEGACY_REQUIRES((Dim == 2 || Dim == 3), size_t Dim = Dimensions)
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector_product MUU_VECTORCALL direction(MUU_VC_PARAM(vector) from,
																 MUU_VC_PARAM(vector) to) noexcept
			MUU_REQUIRES(Dimensions == 2 || Dimensions == 3)
		{
			// all are the same type - only happens with float, double, long double etc.
			if constexpr (all_same<scalar_type, intermediate_float, delta_type>)
			{
				return vector_product::normalize(to - from);
			}

			// only intermediate type is different - half, _Float16, __fp16
			else if constexpr (std::is_same_v<scalar_type, delta_type>)
			{
				using ivec = vector<intermediate_float, dimensions>;
				return vector_product{ ivec::normalize(ivec{ to } - ivec{ from }) };
			}

			// only scalar_type is different - integers.
			else if constexpr (std::is_same_v<delta_type, intermediate_float>)
			{
				return vector_product::normalize(vector_product{ to } - vector_product{ from });
			}
		}

		/// \brief		Returns the normalized direction vector from this position to another.
		///
		/// \param	to				The end position.
		/// \param	distance_out	An output param to receive the distance between the two points.
		///
		/// \availability		This function is only available when #dimensions == 2 or 3.
		MUU_LEGACY_REQUIRES((Dim == 2 || Dim == 3), size_t Dim = Dimensions)
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr vector_product MUU_VECTORCALL direction(MUU_VC_PARAM(vector) to,
														  delta_type& distance_out) const noexcept
			MUU_REQUIRES(Dimensions == 2 || Dimensions == 3)
		{
			return direction(*this, to, distance_out);
		}

		/// \brief		Returns the normalized direction vector from this position to another.
		///
		/// \param	to				The end position.
		///
		/// \availability		This function is only available when #dimensions == 2 or 3.
		MUU_LEGACY_REQUIRES((Dim == 2 || Dim == 3), size_t Dim = Dimensions)
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr vector_product MUU_VECTORCALL direction(MUU_VC_PARAM(vector) to) const noexcept
			MUU_REQUIRES(Dimensions == 2 || Dimensions == 3)
		{
			return direction(*this, to);
		}

	#endif // direction

	#if 1 // iterators ------------------------------------------------------------------------------------------------

		/// \brief Returns an iterator to the first scalar component in the vector.
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		constexpr iterator begin() noexcept
		{
			return data();
		}

		/// \brief Returns an iterator to the one-past-the-last scalar component in the vector.
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		constexpr iterator end() noexcept
		{
			return begin() + Dimensions;
		}

		/// \brief Returns a const iterator to the first scalar component in the vector.
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		constexpr const_iterator begin() const noexcept
		{
			return data();
		}

		/// \brief Returns a const iterator to the one-past-the-last scalar component in the vector.
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		constexpr const_iterator end() const noexcept
		{
			return begin() + Dimensions;
		}

	#endif // iterators

	#if 1 // min, max and clamp ---------------------------------------------------------------------------------------

		/// \brief	Returns the componentwise minimum of two vectors.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector MUU_VECTORCALL min(MUU_VC_PARAM(vector) v1, MUU_VC_PARAM(vector) v2) noexcept
		{
				// clang-format off
			#define VEC_FUNC(member) muu::min(v1.member, v2.member)
			COMPONENTWISE_CONSTRUCT(VEC_FUNC);
			#undef VEC_FUNC
			// clang-format on
		}

		/// \brief	Returns the componentwise maximum of two vectors.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector MUU_VECTORCALL max(MUU_VC_PARAM(vector) v1, MUU_VC_PARAM(vector) v2) noexcept
		{
				// clang-format off
			#define VEC_FUNC(member) muu::max(v1.member, v2.member)
			COMPONENTWISE_CONSTRUCT(VEC_FUNC);
			#undef VEC_FUNC
			// clang-format on
		}

		/// \brief	Componentwise clamps a vector between two others.
		///
		/// \param v		The vector being clamped.
		/// \param low		The low bound of the clamp operation.
		/// \param high		The high bound of the clamp operation.
		///
		/// \return	A vector containing the scalar components from `v` clamped inside the given bounds.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector MUU_VECTORCALL clamp(MUU_VC_PARAM(vector) v,
													 MUU_VC_PARAM(vector) low,
													 MUU_VC_PARAM(vector) high) noexcept
		{
				// clang-format off
			#define VEC_FUNC(member) muu::clamp(v.member, low.member, high.member)
			COMPONENTWISE_CONSTRUCT(VEC_FUNC);
			#undef VEC_FUNC
			// clang-format on
		}

		/// \brief	Componentwise clamps the vector between two others (in-place).
		///
		/// \param low		The low bound of the clamp operation.
		/// \param high		The high bound of the clamp operation.
		///
		/// \return	A reference to the vector.
		constexpr vector& MUU_VECTORCALL clamp(MUU_VC_PARAM(vector) low, MUU_VC_PARAM(vector) high) noexcept
		{
				// clang-format off
			#define VEC_FUNC(member) muu::clamp(base::member, low.member, high.member)
			COMPONENTWISE_ASSIGN(VEC_FUNC);
			#undef VEC_FUNC
			// clang-format on
		}

	#endif // min, max and clamp

	#if 1 // swizzles -------------------------------------------------------------------------------------------------
		/// \name Swizzles
		///@{

		/// \brief Creates a vector by selecting and re-packing scalar components from
		/// 	   another vector in an abitrary order.
		///
		/// \tparam	Indices		Indices of the scalar components from the source vector
		/// 					in the order they're to be re-packed.
		/// \param v			The source vector.
		///
		/// \details \cpp
		///
		/// auto v = vector{ 10, 7, 5, 9 };
		/// //                ^  ^  ^  ^
		/// // indices:       0  1  2  3
		///
		/// using vec4 = decltype(v);
		///
		///	std::cout << "swizzle<0>:          " << vec4::swizzle<0>(v)          << "\n";
		///	std::cout << "swizzle<1, 0>:       " << vec4::swizzle<1, 0>(v)       << "\n";
		///	std::cout << "swizzle<3, 2, 3>:    " << vec4::swizzle<3, 2, 3>(v)    << "\n";
		///	std::cout << "swizzle<0, 1, 0, 1>: " << vec4::swizzle<0, 1, 0, 1>(v) << "\n";
		/// \ecpp
		///
		/// \out
		/// swizzle<0>:          { 10 }
		/// swizzle<1, 0>:       { 7, 10 }
		/// swizzle<3, 2, 3>:    { 9, 5, 9 }
		/// swizzle<0, 1, 0, 1>: { 10, 7, 10, 7 }
		/// \eout
		///
		/// \return  A vector composed from the desired 'swizzle' of the source vector.
		template <size_t... Indices>
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector<scalar_type, sizeof...(Indices)> MUU_VECTORCALL swizzle(MUU_VC_PARAM(vector) v) noexcept
		{
			static_assert(sizeof...(Indices) > 0_sz, "At least one scalar index must be specified.");
			static_assert((true && ... && (Indices < Dimensions)),
						  "One or more of the scalar indices was out-of-range");

			return vector<scalar_type, sizeof...(Indices)>{ v.template get<Indices>()... };
		}

		/// \brief Creates a vector by selecting and re-packing the
		/// 	   scalar components from this vector in an abitrary order.
		///
		/// \tparam	Indices		Indices of the scalar components in the order they're to be re-packed.
		///
		/// \details \cpp
		///
		/// auto v = vector{ 10, 7, 5, 9 };
		/// //                ^  ^  ^  ^
		/// // indices:       0  1  2  3
		///
		///	std::cout << "swizzle<0>:          " << v.swizzle<0>(v)          << "\n";
		///	std::cout << "swizzle<1, 0>:       " << v.swizzle<1, 0>(v)       << "\n";
		///	std::cout << "swizzle<3, 2, 3>:    " << v.swizzle<3, 2, 3>(v)    << "\n";
		///	std::cout << "swizzle<0, 1, 0, 1>: " << v.swizzle<0, 1, 0, 1>(v) << "\n";
		/// \ecpp
		///
		/// \out
		/// swizzle<0>:          { 10 }
		/// swizzle<1, 0>:       { 7, 10 }
		/// swizzle<3, 2, 3>:    { 9, 5, 9 }
		/// swizzle<0, 1, 0, 1>: { 10, 7, 10, 7 }
		/// \eout
		///
		/// \return  A vector composed from the desired 'swizzle' of this one.
		template <size_t... Indices>
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr vector<scalar_type, sizeof...(Indices)> swizzle() const noexcept
		{
			return swizzle<Indices...>(*this);
		}

		/// \brief Returns a two-dimensional vector containing `{ x, y }`.
		MUU_LEGACY_REQUIRES(Dims >= 2, size_t Dims = Dimensions)
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr vector<scalar_type, 2> xy() const noexcept MUU_REQUIRES(Dimensions >= 2)
		{
			return vector<scalar_type, 2>{ get<0>(), get<1>() };
		}

		/// \brief Returns a two-dimensional vector containing `{ x, z }`.
		MUU_LEGACY_REQUIRES(Dims >= 3, size_t Dims = Dimensions)
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr vector<scalar_type, 2> xz() const noexcept MUU_REQUIRES(Dimensions >= 3)
		{
			return vector<scalar_type, 2>{ get<0>(), get<2>() };
		}

		/// \brief Returns a two-dimensional vector containing `{ y, x }`.
		MUU_LEGACY_REQUIRES(Dims >= 2, size_t Dims = Dimensions)
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr vector<scalar_type, 2> yx() const noexcept MUU_REQUIRES(Dimensions >= 2)
		{
			return vector<scalar_type, 2>{ get<1>(), get<0>() };
		}

		/// \brief Returns a three-dimensional vector containing `{ x, y, z }`.
		MUU_LEGACY_REQUIRES(Dims >= 3, size_t Dims = Dimensions)
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr vector<scalar_type, 3> xyz() const noexcept MUU_REQUIRES(Dimensions >= 3)
		{
			return vector<scalar_type, 3>{ get<0>(), get<1>(), get<2>() };
		}

		/// \brief Returns a four-dimensional vector containing `{ x, y, z, 1 }`.
		MUU_LEGACY_REQUIRES(Dims >= 3, size_t Dims = Dimensions)
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr vector<scalar_type, 4> xyz1() const noexcept MUU_REQUIRES(Dimensions >= 3)
		{
			return vector<scalar_type, 4>{ get<0>(), get<1>(), get<2>(), scalar_constants::one };
		}

		/// \brief Returns a four-dimensional vector containing `{ x, y, z, 0 }`.
		MUU_LEGACY_REQUIRES(Dims >= 3, size_t Dims = Dimensions)
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr vector<scalar_type, 4> xyz0() const noexcept MUU_REQUIRES(Dimensions >= 3)
		{
			return vector<scalar_type, 4>{ get<0>(), get<1>(), get<2>(), scalar_constants::zero };
		}

	///@}
	#endif // swizzles

	#if 1 // misc -----------------------------------------------------------------------------------------------------

		/// \brief Writes a vector out to a text stream.
		template <typename Char, typename Traits>
		friend std::basic_ostream<Char, Traits>& operator<<(std::basic_ostream<Char, Traits>& os, const vector& v)
		{
			impl::print_vector(os, v.data(), Dimensions);
			return os;
		}

		/// \brief	Performs a linear interpolation between two vectors.
		///
		/// \param	start	The value at the start of the interpolation range.
		/// \param	finish	The value at the end of the interpolation range.
		/// \param	alpha 	The blend factor.
		///
		/// \returns	A vector with values derived from a linear interpolation from `start` to `finish`.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector MUU_VECTORCALL lerp(MUU_VC_PARAM(vector) start,
													MUU_VC_PARAM(vector) finish,
													delta_type alpha) noexcept
		{
			using type			 = intermediate_float;
			const auto inv_alpha = type{ 1 } - static_cast<type>(alpha);

				// clang-format off
			#define VEC_FUNC(member)                                                                                    \
				static_cast<type>(start.member) * inv_alpha + static_cast<type>(finish.member) * static_cast<type>(alpha)
			COMPONENTWISE_CONSTRUCT(VEC_FUNC);
			#undef VEC_FUNC
			// clang-format on
		}

		/// \brief	Linearly interpolates this vector towards another (in-place).
		///
		/// \param	target	The 'target' value for the interpolation.
		/// \param	alpha 	The blend factor.
		///
		/// \return	A reference to the vector.
		constexpr vector& MUU_VECTORCALL lerp(vector target, delta_type alpha) noexcept
		{
			using type			 = intermediate_float;
			const auto inv_alpha = type{ 1 } - static_cast<type>(alpha);

				// clang-format off
			#define VEC_FUNC(member)                                                                                    \
				static_cast<type>(base::member) * inv_alpha + static_cast<type>(target.member) * static_cast<type>(alpha)
			COMPONENTWISE_ASSIGN(VEC_FUNC);
			#undef VEC_FUNC
			// clang-format on
		}

		/// \brief	Calculates the angle between two vectors.
		///
		/// \param	v1		A vector.
		/// \param	v2		A vector.
		///
		/// \returns	The angle between `v1` and `v2` (in radians).
		///
		/// \remarks	The angle returned is the unsigned angle between the two vectors;
		/// 			the smaller of the two possible angles between the two vectors is used.
		/// 			The result is never greater than `pi` radians (180 degrees).
		///
		/// \availability		This function is only available when #dimensions == 2 or 3.
		MUU_LEGACY_REQUIRES((Dim == 2 || Dim == 3), size_t Dim = Dimensions)
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr delta_type MUU_VECTORCALL angle(MUU_VC_PARAM(vector) v1, MUU_VC_PARAM(vector) v2) noexcept
			MUU_REQUIRES(Dimensions == 2 || Dimensions == 3)
		{
			// law of cosines
			// https://stackoverflow.com/questions/10507620/finding-the-angle-between-vectors

			// intermediate calcs are done using doubles because anything else is far too imprecise
			using calc_type			= impl::highest_ranked<intermediate_float, double>;
			const calc_type divisor = raw_length<calc_type>(v1) * raw_length<calc_type>(v2);
			if (divisor == calc_type{})
				return delta_type{};

			return static_cast<delta_type>(muu::acos(muu::clamp(raw_dot<calc_type>(v1, v2) / divisor,
																-muu::constants<calc_type>::one,
																muu::constants<calc_type>::one)));
		}

		/// \brief	Calculates the angle between this vector and another.
		///
		/// \param	v	A vector.
		///
		/// \returns	The angle between this vector and `v` (in radians).
		///
		/// \remarks	The angle returned is the unsigned angle between the two vectors;
		/// 			the smaller of the two possible angles between the two vectors is used.
		/// 			The result is never greater than `pi` radians (180 degrees).
		///
		/// \availability		This function is only available when #dimensions == 2 or 3.
		MUU_LEGACY_REQUIRES((Dim == 2 || Dim == 3), size_t Dim = Dimensions)
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr delta_type MUU_VECTORCALL angle(MUU_VC_PARAM(vector) v) const noexcept
			MUU_REQUIRES(Dimensions == 2 || Dimensions == 3)
		{
			return angle(*this, v);
		}

		/// \brief	Returns a vector with all scalar components set to their absolute values.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector MUU_VECTORCALL abs(MUU_VC_PARAM(vector) v) noexcept
		{
			// clang-format off
			if constexpr (is_signed<scalar_type>)
			{
				#define VEC_FUNC(member) muu::abs(v.member)
				COMPONENTWISE_CONSTRUCT(VEC_FUNC);
				#undef VEC_FUNC
			}
			else
				return v;
			// clang-format on
		}

		/// \brief	Returns a copy of this vector with all scalar components set to their absolute values.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr vector abs() const noexcept
		{
			if constexpr (is_signed<scalar_type>)
				return abs(*this);
			else
				return *this;
		}

		/// \brief	Returns a vector with all scalar components set to the lowest integer not less than their original
		/// values.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector MUU_VECTORCALL ceil(MUU_VC_PARAM(vector) v) noexcept
		{
			// clang-format off
			if constexpr (is_floating_point<scalar_type>)
			{
				#define VEC_FUNC(member) muu::ceil(v.member)
				COMPONENTWISE_CONSTRUCT(VEC_FUNC);
				#undef VEC_FUNC
			}
			else
				return v;
			// clang-format on
		}

		/// \brief	Returns a copy of the vector with all scalar components set to the lowest integer not less than
		/// their original values.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr vector ceil() const noexcept
		{
			if constexpr (is_floating_point<scalar_type>)
				return ceil(*this);
			else
				return *this;
		}

		/// \brief	Returns a vector with all scalar components set to the highest integer not greater than their
		/// original values.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector MUU_VECTORCALL floor(MUU_VC_PARAM(vector) v) noexcept
		{
			// clang-format off
			if constexpr (is_floating_point<scalar_type>)
			{
				#define VEC_FUNC(member) muu::floor(v.member)
				COMPONENTWISE_CONSTRUCT(VEC_FUNC);
				#undef VEC_FUNC
			}
			else
				return v;
			// clang-format on
		}

		/// \brief	Returns a copy of the vector with all scalar components set to the highest integer not greater than
		/// their original values.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr vector floor() const noexcept
		{
			if constexpr (is_floating_point<scalar_type>)
				return floor(*this);
			else
				return *this;
		}

	#endif // misc
	};

	/// \cond

	MUU_CONSTRAINED_TEMPLATE((all_arithmetic<T, U, V...>), typename T, typename U, typename... V)
	vector(T, U, V...)->vector<impl::highest_ranked<T, U, V...>, 2 + sizeof...(V)>;

	MUU_CONSTRAINED_TEMPLATE(is_arithmetic<T>, typename T)
	vector(T)->vector<std::remove_cv_t<T>, 1>;

	template <typename T, size_t N>
	vector(const T (&)[N]) -> vector<std::remove_cv_t<T>, N>;

	template <typename T, size_t N>
	vector(const std::array<T, N>&) -> vector<std::remove_cv_t<T>, N>;

	template <typename T, typename U>
	vector(const std::pair<T, U>&) -> vector<impl::highest_ranked<T, U>, 2>;

	template <typename... T>
	vector(const std::tuple<T...>&) -> vector<impl::highest_ranked<T...>, sizeof...(T)>;

	template <typename S1, size_t D1, typename S2, size_t D2>
	vector(const vector<S1, D1>&, const vector<S2, D2>&) -> vector<impl::highest_ranked<S1, S2>, D1 + D2>;

	template <typename S, size_t D, typename... T>
	vector(const vector<S, D>&, T...) -> vector<impl::highest_ranked<S, T...>, D + sizeof...(T)>;

	MUU_CONSTRAINED_TEMPLATE(N != dynamic_extent, typename T, size_t N)
	vector(const muu::span<T, N>&)->vector<T, N>;

	/// \endcond

	MUU_ABI_VERSION_END;
}

namespace std
{
	/// \brief Specialization of std::tuple_size for muu::vector.
	template <typename Scalar, size_t Dimensions>
	struct tuple_size<muu::vector<Scalar, Dimensions>>
	{
		static constexpr size_t value = Dimensions;
	};

	/// \brief Specialization of std::tuple_element for muu::vector.
	template <size_t I, typename Scalar, size_t Dimensions>
	struct tuple_element<I, muu::vector<Scalar, Dimensions>>
	{
		static_assert(I < Dimensions);
		using type = Scalar;
	};
}

#endif //===============================================================================================================

//======================================================================================================================
// CONSTANTS
#if 1

MUU_PUSH_PRECISE_MATH;

namespace muu
{
	namespace impl
	{
		/// \cond

		template <typename Scalar, size_t Dimensions>
		struct integer_limits<vector<Scalar, Dimensions>>
		{
			using type	  = vector<Scalar, Dimensions>;
			using scalars = integer_limits<Scalar>;

			static constexpr type lowest  = type{ scalars::lowest };
			static constexpr type highest = type{ scalars::highest };
		};

		template <typename Scalar, size_t Dimensions>
		struct integer_positive_constants<vector<Scalar, Dimensions>>
		{
			using type	  = vector<Scalar, Dimensions>;
			using scalars = integer_positive_constants<Scalar>;

			static constexpr type zero		  = type{ scalars::zero };
			static constexpr type one		  = type{ scalars::one };
			static constexpr type two		  = type{ scalars::two };
			static constexpr type three		  = type{ scalars::three };
			static constexpr type four		  = type{ scalars::four };
			static constexpr type five		  = type{ scalars::five };
			static constexpr type six		  = type{ scalars::six };
			static constexpr type seven		  = type{ scalars::seven };
			static constexpr type eight		  = type{ scalars::eight };
			static constexpr type nine		  = type{ scalars::nine };
			static constexpr type ten		  = type{ scalars::ten };
			static constexpr type one_hundred = type{ scalars::one_hundred };
		};

		template <typename Scalar, size_t Dimensions>
		struct floating_point_traits<vector<Scalar, Dimensions>> : floating_point_traits<Scalar>
		{};

		template <typename Scalar, size_t Dimensions>
		struct floating_point_special_constants<vector<Scalar, Dimensions>>
		{
			using type	  = vector<Scalar, Dimensions>;
			using scalars = floating_point_special_constants<Scalar>;

			static constexpr type nan				= type{ scalars::nan };
			static constexpr type signaling_nan		= type{ scalars::signaling_nan };
			static constexpr type infinity			= type{ scalars::infinity };
			static constexpr type negative_infinity = type{ scalars::negative_infinity };
			static constexpr type negative_zero		= type{ scalars::negative_zero };
		};

		template <typename Scalar, size_t Dimensions>
		struct floating_point_named_constants<vector<Scalar, Dimensions>>
		{
			using type	  = vector<Scalar, Dimensions>;
			using scalars = floating_point_named_constants<Scalar>;

			static constexpr type one_over_two		   = type{ scalars::one_over_two };
			static constexpr type two_over_three	   = type{ scalars::two_over_three };
			static constexpr type two_over_five		   = type{ scalars::two_over_five };
			static constexpr type sqrt_two			   = type{ scalars::sqrt_two };
			static constexpr type one_over_sqrt_two	   = type{ scalars::one_over_sqrt_two };
			static constexpr type one_over_three	   = type{ scalars::one_over_three };
			static constexpr type three_over_two	   = type{ scalars::three_over_two };
			static constexpr type three_over_four	   = type{ scalars::three_over_four };
			static constexpr type three_over_five	   = type{ scalars::three_over_five };
			static constexpr type sqrt_three		   = type{ scalars::sqrt_three };
			static constexpr type one_over_sqrt_three  = type{ scalars::one_over_sqrt_three };
			static constexpr type pi				   = type{ scalars::pi };
			static constexpr type one_over_pi		   = type{ scalars::one_over_pi };
			static constexpr type pi_over_two		   = type{ scalars::pi_over_two };
			static constexpr type pi_over_three		   = type{ scalars::pi_over_three };
			static constexpr type pi_over_four		   = type{ scalars::pi_over_four };
			static constexpr type pi_over_five		   = type{ scalars::pi_over_five };
			static constexpr type pi_over_six		   = type{ scalars::pi_over_six };
			static constexpr type pi_over_seven		   = type{ scalars::pi_over_seven };
			static constexpr type pi_over_eight		   = type{ scalars::pi_over_eight };
			static constexpr type sqrt_pi			   = type{ scalars::sqrt_pi };
			static constexpr type one_over_sqrt_pi	   = type{ scalars::one_over_sqrt_pi };
			static constexpr type two_pi			   = type{ scalars::two_pi };
			static constexpr type sqrt_two_pi		   = type{ scalars::sqrt_two_pi };
			static constexpr type one_over_sqrt_two_pi = type{ scalars::one_over_sqrt_two_pi };
			static constexpr type one_over_three_pi	   = type{ scalars::one_over_three_pi };
			static constexpr type three_pi_over_two	   = type{ scalars::three_pi_over_two };
			static constexpr type three_pi_over_four   = type{ scalars::three_pi_over_four };
			static constexpr type three_pi_over_five   = type{ scalars::three_pi_over_five };
			static constexpr type e					   = type{ scalars::e };
			static constexpr type one_over_e		   = type{ scalars::one_over_e };
			static constexpr type e_over_two		   = type{ scalars::e_over_two };
			static constexpr type e_over_three		   = type{ scalars::e_over_three };
			static constexpr type e_over_four		   = type{ scalars::e_over_four };
			static constexpr type e_over_five		   = type{ scalars::e_over_five };
			static constexpr type e_over_six		   = type{ scalars::e_over_six };
			static constexpr type sqrt_e			   = type{ scalars::sqrt_e };
			static constexpr type one_over_sqrt_e	   = type{ scalars::one_over_sqrt_e };
			static constexpr type phi				   = type{ scalars::phi };
			static constexpr type one_over_phi		   = type{ scalars::one_over_phi };
			static constexpr type phi_over_two		   = type{ scalars::phi_over_two };
			static constexpr type phi_over_three	   = type{ scalars::phi_over_three };
			static constexpr type phi_over_four		   = type{ scalars::phi_over_four };
			static constexpr type phi_over_five		   = type{ scalars::phi_over_five };
			static constexpr type phi_over_six		   = type{ scalars::phi_over_six };
			static constexpr type sqrt_phi			   = type{ scalars::sqrt_phi };
			static constexpr type one_over_sqrt_phi	   = type{ scalars::one_over_sqrt_phi };
			static constexpr type degrees_to_radians   = type{ scalars::degrees_to_radians };
			static constexpr type radians_to_degrees   = type{ scalars::radians_to_degrees };
		};

		template <typename Scalar,
				  size_t Dimensions,
				  int = (is_floating_point<Scalar> ? 2 : (is_signed<Scalar> ? 1 : 0))>
		struct vector_constants_base : unsigned_integral_constants<vector<Scalar, Dimensions>>
		{};
		template <typename Scalar, size_t Dimensions>
		struct vector_constants_base<Scalar, Dimensions, 1> : signed_integral_constants<vector<Scalar, Dimensions>>
		{};
		template <typename Scalar, size_t Dimensions>
		struct vector_constants_base<Scalar, Dimensions, 2> : floating_point_constants<vector<Scalar, Dimensions>>
		{};

		/// \endcond

		template <typename Scalar, size_t Dimensions>
		struct unit_length_ge_1d_vector_constants
		{
			using scalars = muu::constants<Scalar>;

			/// \name Unit vectors
			/// @{

			/// \brief	A unit-length vector representing the X axis.
			static constexpr vector<Scalar, Dimensions> x_axis{ scalars::one, scalars::zero };

			/// @}
		};

		template <typename Scalar, size_t Dimensions SPECIALIZED_IF(Dimensions >= 2)>
		struct unit_length_ge_2d_vector_constants
		{
			using scalars = muu::constants<Scalar>;

			/// \name Unit vectors
			/// @{

			/// \brief	A unit-length vector representing the Y axis.
			static constexpr vector<Scalar, Dimensions> y_axis{ scalars::zero, scalars::one };

			/// @}
		};

		template <typename Scalar, size_t Dimensions SPECIALIZED_IF(Dimensions >= 3)>
		struct unit_length_ge_3d_vector_constants
		{
			using scalars = muu::constants<Scalar>;

			/// \name Unit vectors
			/// @{

			/// \brief	A unit-length vector representing the Z axis.
			static constexpr vector<Scalar, Dimensions> z_axis{ scalars::zero, scalars::zero, scalars::one };

			/// @}
		};

		template <typename Scalar, size_t Dimensions SPECIALIZED_IF(Dimensions >= 4)>
		struct unit_length_ge_4d_vector_constants
		{
			using scalars = muu::constants<Scalar>;

			/// \name Unit vectors
			/// @{

			/// \brief	A unit-length vector representing the W axis.
			static constexpr vector<Scalar, Dimensions> w_axis{ scalars::zero,
																scalars::zero,
																scalars::zero,
																scalars::one };

			/// @}
		};

		template <typename Scalar, size_t Dimensions SPECIALIZED_IF(Dimensions == 2)>
		struct unit_length_2d_vector_constants
		{
			using scalars = muu::constants<Scalar>;

			/// \name Directions
			/// @{

			/// \brief	Right direction (in a top-down screen coordinate system).
			static constexpr vector<Scalar, Dimensions> screen_right{ scalars::one, scalars::zero };

			/// \brief	Down direction (in a top-down screen coordinate system).
			static constexpr vector<Scalar, Dimensions> screen_down{ scalars::zero, scalars::one };

			/// @}
		};

		template <typename Scalar, size_t Dimensions SPECIALIZED_IF(Dimensions == 2 && is_signed<Scalar>)>
		struct unit_length_2d_signed_vector_constants
		{
			using scalars = muu::constants<Scalar>;

			/// \name Directions
			/// @{

			/// \brief	Left direction (in a top-down screen coordinate system).
			static constexpr vector<Scalar, Dimensions> screen_left{ -scalars::one, scalars::zero };

			/// \brief	Up direction (in a top-down screen coordinate system).
			static constexpr vector<Scalar, Dimensions> screen_up{ scalars::zero, -scalars::one };

			/// @}
		};

		template <typename Scalar, size_t Dimensions SPECIALIZED_IF(Dimensions == 3)>
		struct unit_length_3d_vector_constants
		{
			using scalars = muu::constants<Scalar>;

			/// \name Directions
			/// @{

			/// \brief	Backward direction (in a right-handed coordinate system).
			static constexpr vector<Scalar, Dimensions> backward{ scalars::zero, scalars::zero, scalars::one };

			/// @}
		};

		template <typename Scalar, size_t Dimensions SPECIALIZED_IF(Dimensions == 3 && is_signed<Scalar>)>
		struct unit_length_3d_signed_vector_constants
		{
			using scalars = muu::constants<Scalar>;

			/// \name Directions
			/// @{

			/// \brief	Forward direction (in a right-handed coordinate system).
			static constexpr vector<Scalar, Dimensions> forward{ scalars::zero, scalars::zero, -scalars::one };

			/// @}
		};

		template <typename Scalar, size_t Dimensions SPECIALIZED_IF(Dimensions == 2 || Dimensions == 3)>
		struct unit_length_2d_or_3d_vector_constants
		{
			using scalars = muu::constants<Scalar>;

			/// \name Directions
			/// @{

			/// \brief	Right direction (in a right-handed coordinate system).
			static constexpr vector<Scalar, Dimensions> right{ scalars::one, scalars::zero };

			/// \brief	Up direction (in a right-handed coordinate system).
			static constexpr vector<Scalar, Dimensions> up{ scalars::zero, scalars::one };

			/// @}
		};

		template <typename Scalar,
				  size_t Dimensions SPECIALIZED_IF((Dimensions == 2 || Dimensions == 3) && is_signed<Scalar>)>
		struct unit_length_2d_or_3d_signed_vector_constants
		{
			using scalars = muu::constants<Scalar>;

			/// \name Directions
			/// @{

			/// \brief	Left direction (in a right-handed coordinate system).
			static constexpr vector<Scalar, Dimensions> left{ -scalars::one, scalars::zero };

			/// \brief	Down direction (in a right-handed coordinate system).
			static constexpr vector<Scalar, Dimensions> down{ scalars::zero, -scalars::one };

			/// @}
		};

		template <typename Scalar, size_t Dimensions>
		struct unit_length_vector_constants : unit_length_ge_1d_vector_constants<Scalar, Dimensions>,
											  unit_length_ge_2d_vector_constants<Scalar, Dimensions>,
											  unit_length_ge_3d_vector_constants<Scalar, Dimensions>,
											  unit_length_ge_4d_vector_constants<Scalar, Dimensions>,
											  unit_length_2d_vector_constants<Scalar, Dimensions>,
											  unit_length_2d_signed_vector_constants<Scalar, Dimensions>,
											  unit_length_3d_vector_constants<Scalar, Dimensions>,
											  unit_length_3d_signed_vector_constants<Scalar, Dimensions>,
											  unit_length_2d_or_3d_vector_constants<Scalar, Dimensions>,
											  unit_length_2d_or_3d_signed_vector_constants<Scalar, Dimensions>
		{};

		/// \cond

		template <typename Scalar>
		struct unit_length_ge_1d_vector_constants<Scalar, 1>
		{
			using scalars = muu::constants<Scalar>;

			static constexpr vector<Scalar, 1> x_axis{ scalars::one };
		};

		template <typename Scalar, size_t Dimensions>
		struct unit_length_ge_2d_vector_constants<Scalar, Dimensions, false>
		{};

		template <typename Scalar, size_t Dimensions>
		struct unit_length_ge_3d_vector_constants<Scalar, Dimensions, false>
		{};

		template <typename Scalar, size_t Dimensions>
		struct unit_length_ge_4d_vector_constants<Scalar, Dimensions, false>
		{};

		template <typename Scalar, size_t Dimensions>
		struct unit_length_2d_vector_constants<Scalar, Dimensions, false>
		{};

		template <typename Scalar, size_t Dimensions>
		struct unit_length_2d_signed_vector_constants<Scalar, Dimensions, false>
		{};

		template <typename Scalar, size_t Dimensions>
		struct unit_length_3d_vector_constants<Scalar, Dimensions, false>
		{};

		template <typename Scalar, size_t Dimensions>
		struct unit_length_3d_signed_vector_constants<Scalar, Dimensions, false>
		{};

		template <typename Scalar, size_t Dimensions>
		struct unit_length_2d_or_3d_vector_constants<Scalar, Dimensions, false>
		{};

		template <typename Scalar, size_t Dimensions>
		struct unit_length_2d_or_3d_signed_vector_constants<Scalar, Dimensions, false>
		{};

		/// \endcond
	}

	#ifdef DOXYGEN
		#define VECTOR_CONSTANTS_BASES                                                                                 \
			impl::unit_length_vector_constants<Scalar, Dimensions>, impl::integer_limits<vector<Scalar, Dimensions>>,  \
				impl::integer_positive_constants<vector<Scalar, Dimensions>>,                                          \
				impl::floating_point_traits<vector<Scalar, Dimensions>>,                                               \
				impl::floating_point_special_constants<vector<Scalar, Dimensions>>,                                    \
				impl::floating_point_named_constants<vector<Scalar, Dimensions>>
	#else
		#define VECTOR_CONSTANTS_BASES                                                                                 \
			impl::unit_length_vector_constants<Scalar, Dimensions>, impl::vector_constants_base<Scalar, Dimensions>
	#endif

	/// \ingroup	constants
	/// \see		muu::vector
	///
	/// \brief		Vector constants.
	template <typename Scalar, size_t Dimensions>
	struct constants<vector<Scalar, Dimensions>> : VECTOR_CONSTANTS_BASES
	{};

	#undef VECTOR_CONSTANTS_BASES
}

MUU_POP_PRECISE_MATH;

#endif //===============================================================================================================

//======================================================================================================================
// ACCUMULATOR
#if 1

namespace muu::impl
{
	MUU_ABI_VERSION_START(0);

	template <typename Scalar, size_t Dimensions>
	struct vector_accumulator
	{
		using value_type		 = vector<Scalar, Dimensions>;
		using value_param		 = vectorcall_param<value_type>;
		using scalar_accumulator = typename default_accumulator<Scalar>::type;

		scalar_accumulator accumulators[Dimensions];

		constexpr void MUU_VECTORCALL start(value_param sample) noexcept
		{
			accumulators[0].start(sample.template get<0>());
			if constexpr (Dimensions > 1)
				accumulators[1].start(sample.template get<1>());
			if constexpr (Dimensions > 2)
				accumulators[2].start(sample.template get<2>());
			if constexpr (Dimensions > 3)
				accumulators[3].start(sample.template get<3>());
			if constexpr (Dimensions > 4)
			{
				for (size_t i = 4; i < Dimensions; i++)
					accumulators[i].start(sample[i]);
			}
		}

		constexpr void MUU_VECTORCALL add(value_param sample) noexcept
		{
			accumulators[0].add(sample.template get<0>());
			if constexpr (Dimensions > 1)
				accumulators[1].add(sample.template get<1>());
			if constexpr (Dimensions > 2)
				accumulators[2].add(sample.template get<2>());
			if constexpr (Dimensions > 3)
				accumulators[3].add(sample.template get<3>());
			if constexpr (Dimensions > 4)
			{
				for (size_t i = 4; i < Dimensions; i++)
					accumulators[i].add(sample[i]);
			}
		}

		constexpr void add(const vector_accumulator& other) noexcept
		{
			for (size_t i = 0; i < Dimensions; i++)
				accumulators[i].add(other.accumulators[i]);
		}

	  private:
		template <size_t... Indices, typename Func>
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr auto componentwise(std::index_sequence<Indices...>, Func&& func) const noexcept
		{
			return vector{ func(accumulators[Indices])... };
		}

	  public:
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr value_type min() const noexcept
		{
			return componentwise(std::make_index_sequence<Dimensions>{}, [](auto& acc) noexcept { return acc.min(); });
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr value_type max() const noexcept
		{
			return componentwise(std::make_index_sequence<Dimensions>{}, [](auto& acc) noexcept { return acc.max(); });
		}

		using sum_type = vector<decltype(std::declval<scalar_accumulator>().sum()), Dimensions>;

		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr sum_type sum() const noexcept
		{
			return componentwise(std::make_index_sequence<Dimensions>{}, [](auto& acc) noexcept { return acc.sum(); });
		}
	};

	MUU_ABI_VERSION_END;
}

#endif //===============================================================================================================

//======================================================================================================================
// FREE FUNCTIONS
#if 1

namespace muu
{
	/// \ingroup	infinity_or_nan
	/// \relatesalso	muu::vector
	///
	/// \brief	Returns true if any of the scalar components of a vector are infinity or NaN.
	template <typename S, size_t D>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr bool infinity_or_nan(const vector<S, D>& v) noexcept
	{
		if constexpr (is_floating_point<S>)
			return vector<S, D>::infinity_or_nan(v);
		else
		{
			MUU_UNUSED(v);
			return false;
		}
	}

	/// \ingroup	approx_equal
	/// \relatesalso	muu::vector
	///
	/// \brief		Returns true if two vectors are approximately equal.
	///
	/// \availability		This function is only available when at least one of `S` and `T` is a floating-point type.
	MUU_CONSTRAINED_TEMPLATE((any_floating_point<S, T>), typename S, typename T, size_t D)
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr bool MUU_VECTORCALL approx_equal(const vector<S, D>& v1,
											   const vector<T, D>& v2,
											   epsilon_type<S, T> epsilon = default_epsilon<S, T>) noexcept
	{
		return vector<S, D>::approx_equal(v1, v2, epsilon);
	}

	/// \ingroup	approx_zero
	/// \relatesalso	muu::vector
	///
	/// \brief		Returns true if all the scalar components of a vector are approximately equal to zero.
	///
	/// \availability		This function is only available when `S` is a floating-point type.
	MUU_CONSTRAINED_TEMPLATE((is_floating_point<S>), typename S, size_t D)
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr bool MUU_VECTORCALL approx_zero(const vector<S, D>& v, S epsilon = default_epsilon<S>) noexcept
	{
		return vector<S, D>::approx_zero(v, epsilon);
	}

	/// \ingroup	normalized
	/// \relatesalso	muu::vector
	///
	/// \brief Returns true if a vector is normalized (i.e. has a length of 1).
	template <typename S, size_t D>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr bool normalized(const vector<S, D>& v) noexcept
	{
		return vector<S, D>::normalized(v);
	}

	template <typename S, size_t D>
	MUU_NODISCARD
	[[deprecated]] MUU_ATTR(pure)
	constexpr bool unit_length(const vector<S, D>& v) noexcept
	{
		return vector<S, D>::normalized(v);
	}

	/// \relatesalso muu::vector
	///
	/// \brief	Returns the squared length of a vector.
	template <typename S,
			  size_t D //
				  MUU_HIDDEN_PARAM(typename delta_type = typename vector<S, D>::delta_type)>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr delta_type length_squared(const vector<S, D>& v) noexcept
	{
		return vector<S, D>::length_squared(v);
	}

	/// \relatesalso muu::vector
	///
	/// \brief	Returns the length (magnitude) of a vector.
	template <typename S,
			  size_t D //
				  MUU_HIDDEN_PARAM(typename delta_type = typename vector<S, D>::delta_type)>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr delta_type length(const vector<S, D>& v) noexcept
	{
		return vector<S, D>::length(v);
	}

	/// \relatesalso muu::vector
	///
	/// \brief	Returns the squared distance between two point vectors.
	template <typename S,
			  size_t D //
				  MUU_HIDDEN_PARAM(typename delta_type = typename vector<S, D>::delta_type)>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr delta_type distance_squared(const vector<S, D>& p1, const vector<S, D>& p2) noexcept
	{
		return vector<S, D>::distance_squared(p1, p2);
	}

	/// \relatesalso muu::vector
	///
	/// \brief	Returns the distance between two point vectors.
	template <typename S,
			  size_t D //
				  MUU_HIDDEN_PARAM(typename delta_type = typename vector<S, D>::delta_type)>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr delta_type distance(const vector<S, D>& p1, const vector<S, D>& p2) noexcept
	{
		return vector<S, D>::distance(p1, p2);
	}

	/// \relatesalso muu::vector
	///
	/// \brief	Returns the dot product of two vectors.
	template <typename S,
			  size_t D //
				  MUU_HIDDEN_PARAM(typename product_type = typename vector<S, D>::product_type)>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr product_type dot(const vector<S, D>& v1, const vector<S, D>& v2) noexcept
	{
		return vector<S, D>::dot(v1, v2);
	}

	/// \relatesalso muu::vector
	///
	/// \brief	Returns the cross product of two three-dimensional vectors.
	template <typename S //
				  MUU_HIDDEN_PARAM(typename vector_product = typename vector<S, 3>::vector_product)>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr vector_product cross(const vector<S, 3>& lhs, const vector<S, 3>& rhs) noexcept
	{
		return impl::raw_cross<typename vector<S, 3>::vector_product>(lhs, rhs);
	}

	/// \relatesalso muu::vector
	///
	/// \brief	Normalizes a vector.
	///
	/// \param v			The vector to normalize.
	/// \param length_out	An output param to receive the length of the vector pre-normalization.
	///
	/// \return		A normalized copy of the input vector.
	///
	/// \availability This function is only available when `S` is a floating-point type.
	MUU_CONSTRAINED_TEMPLATE(is_floating_point<S>,
							 typename S,
							 size_t D //
								 MUU_HIDDEN_PARAM(typename delta_type = typename vector<S, D>::delta_type))
	MUU_NODISCARD
	constexpr vector<S, D> normalize(const vector<S, D>& v, delta_type& length_out) noexcept
	{
		return vector<S, D>::normalize(v, length_out);
	}

	/// \relatesalso muu::vector
	///
	/// \brief	Normalizes a vector.
	///
	/// \param v	The vector to normalize.
	///
	/// \return		A normalized copy of the input vector.
	///
	/// \availability This function is only available when `S` is a floating-point type.
	MUU_CONSTRAINED_TEMPLATE(is_floating_point<S>, typename S, size_t D)
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr vector<S, D> normalize(const vector<S, D>& v) noexcept
	{
		return vector<S, D>::normalize(v);
	}

	/// \relatesalso muu::vector
	///
	/// \brief		Returns the normalized direction vector from one position to another.
	///
	/// \param	from			The start position.
	/// \param	to				The end position.
	/// \param	distance_out	An output param to receive the distance between the two points.
	///
	/// \return		A normalized direction vector pointing from the start position to the end position.
	///
	/// \availability		This function is only available when `D` == 2 or 3.
	MUU_CONSTRAINED_TEMPLATE((D == 2 || D == 3),
							 typename S,
							 size_t D																			   //
								 MUU_HIDDEN_PARAM(typename vector_product = typename vector<S, D>::vector_product) //
							 MUU_HIDDEN_PARAM(typename delta_type = typename vector<S, D>::delta_type))
	MUU_NODISCARD
	constexpr vector_product direction(const vector<S, D>& from,
									   const vector<S, D>& to,
									   delta_type& distance_out) noexcept
	{
		return vector<S, D>::direction(from, to, distance_out);
	}

	/// \relatesalso muu::vector
	///
	/// \brief		Returns the normalized direction vector from one position to another.
	///
	/// \param	from			The start position.
	/// \param	to				The end position.
	///
	/// \return		A normalized direction vector pointing from the start position to the end position.
	///
	/// \availability		This function is only available when `D` == 2 or 3.
	MUU_CONSTRAINED_TEMPLATE((D == 2 || D == 3),
							 typename S,
							 size_t D //
								 MUU_HIDDEN_PARAM(typename vector_product = typename vector<S, D>::vector_product))
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr vector_product direction(const vector<S, D>& from, const vector<S, D>& to) noexcept
	{
		return vector<S, D>::direction(from, to);
	}

	/// \relatesalso muu::vector
	///
	/// \brief	Returns the componentwise minimum of two vectors.
	template <typename S, size_t D>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr vector<S, D> min(const vector<S, D>& v1, const vector<S, D>& v2) noexcept
	{
		return vector<S, D>::min(v1, v2);
	}

	/// \relatesalso muu::vector
	///
	/// \brief	Returns the componentwise maximum of two vectors.
	template <typename S, size_t D>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr vector<S, D> max(const vector<S, D>& v1, const vector<S, D>& v2) noexcept
	{
		return vector<S, D>::max(v1, v2);
	}

	/// \relatesalso muu::vector
	///
	/// \brief	Componentwise clamps a vector between two others.
	template <typename S, size_t D>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr vector<S, D> clamp(const vector<S, D>& v, const vector<S, D>& low, const vector<S, D>& high) noexcept
	{
		return vector<S, D>::clamp(v, low, high);
	}

	/// \ingroup lerp
	/// \relatesalso muu::vector
	///
	/// \brief	Performs a linear interpolation between two vectors.
	template <typename S,
			  size_t D //
				  MUU_HIDDEN_PARAM(typename delta_type = typename vector<S, D>::delta_type)>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr vector<S, D> MUU_VECTORCALL lerp(const vector<S, D>& start,
											   const vector<S, D>& finish,
											   delta_type alpha) noexcept
	{
		return vector<S, D>::lerp(start, finish, alpha);
	}

	/// \relatesalso muu::vector
	///
	/// \brief	Calculates the angle between two vectors.
	///
	/// \param	v1		A vector.
	/// \param	v2		A vector.
	///
	/// \returns	The angle between `v1` and `v2` (in radians).
	///
	/// \remarks	The angle returned is the unsigned angle between the two vectors;
	/// 			the smaller of the two possible angles between the two vectors is used.
	/// 			The result is never greater than `pi` radians (180 degrees).
	///
	/// \availability		This function is only available when `D` == 2 or 3.
	MUU_CONSTRAINED_TEMPLATE((D == 2 || D == 3),
							 typename S,
							 size_t D //
								 MUU_HIDDEN_PARAM(typename delta_type = typename vector<S, D>::delta_type))
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr delta_type angle(const vector<S, D>& v1, const vector<S, D>& v2) noexcept
	{
		return vector<S, D>::angle(v1, v2);
	}

	/// \ingroup abs
	/// \relatesalso muu::vector
	///
	/// \brief	Returns a copy of a vector with all scalar components set to their absolute values.
	template <typename S, size_t D>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr vector<S, D> abs(const vector<S, D>& v) noexcept
	{
		return vector<S, D>::abs(v);
	}

	/// \ingroup ceil
	/// \relatesalso muu::vector
	///
	/// \brief	Returns a copy of a vector with all scalar components set to the lowest integer not less than their
	/// original values.
	template <typename S, size_t D>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr vector<S, D> ceil(const vector<S, D>& v) noexcept
	{
		return vector<S, D>::ceil(v);
	}

	/// \ingroup floor
	/// \relatesalso muu::vector
	///
	/// \brief	Returns a copy of a vector with all scalar components set to the highest integer not greater than their
	/// original values.
	template <typename S, size_t D>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr vector<S, D> floor(const vector<S, D>& v) noexcept
	{
		return vector<S, D>::floor(v);
	}
}

#endif //===============================================================================================================

#undef COMPONENTWISE_AND
#undef COMPONENTWISE_OR
#undef COMPONENTWISE_ACCUMULATE
#undef COMPONENTWISE_CASTING_OP_BRANCH
#undef COMPONENTWISE_CASTING_OP
#undef COMPONENTWISE_CONSTRUCT_WITH_TRANSFORM
#undef COMPONENTWISE_CONSTRUCT
#undef COMPONENTWISE_ASSIGN_WITH_TRANSFORM
#undef COMPONENTWISE_ASSIGN
#undef NULL_TRANSFORM
#undef SPECIALIZED_IF

MUU_RESET_NDEBUG_OPTIMIZATIONS;
#include "impl/header_end.h"
