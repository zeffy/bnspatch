// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

/// \file
/// \brief  Contains the definition of muu::compressed_pair.

#pragma once
#include "impl/core_meta.h"
#include "impl/header_start.h"
MUU_PRAGMA_CLANG(diagnostic ignored "-Wreorder")
MUU_PRAGMA_GCC(diagnostic ignored "-Wreorder")
MUU_PRAGMA_MSVC(warning(disable : 5038)) // member A will initialized before B

/// \cond
namespace muu::impl
{
	MUU_ABI_VERSION_START(0);

	enum class compressed_pair_flags : unsigned
	{
		none,
		first_empty	 = 1,
		second_empty = 2,
		both_empty	 = first_empty | second_empty
	};
	MUU_MAKE_FLAGS(compressed_pair_flags);

	template <typename First, typename Second>
	MUU_NODISCARD
	MUU_CONSTEVAL
	compressed_pair_flags get_compressed_pair_flags_for() noexcept
	{
		return (std::is_empty_v<First> && !std::is_final_v<First> ? compressed_pair_flags::first_empty
																  : compressed_pair_flags::none)
			 | (std::is_empty_v<Second> && !std::is_final_v<Second> ? compressed_pair_flags::second_empty
																	: compressed_pair_flags::none);
	}

#define COMPRESSED_PAIR_BASE_DEFAULTS(first_initializer, second_initializer)                                           \
                                                                                                                       \
	MUU_CONSTRAINED_TEMPLATE((std::is_constructible_v<First, F&&> && std::is_constructible_v<Second, S&&>),            \
							 typename F,                                                                               \
							 typename S)                                                                               \
	constexpr compressed_pair_base(F&& first_init, S&& second_init) noexcept(                                          \
		std::is_nothrow_constructible_v<First, F&&> && std::is_nothrow_constructible_v<Second, S&&>)                   \
		: first_initializer{ static_cast<F&&>(first_init) },                                                           \
		  second_initializer{ static_cast<S&&>(second_init) }                                                          \
	{}                                                                                                                 \
	compressed_pair_base() = default;                                                                                  \
	MUU_DEFAULT_MOVE(compressed_pair_base);                                                                            \
	MUU_DEFAULT_COPY(compressed_pair_base)

#define COMPRESSED_PAIR_BASE_GETTERS(type, name, expression)                                                           \
	MUU_ALWAYS_INLINE                                                                                                  \
	MUU_ATTR(pure)                                                                                                     \
	constexpr type& get_##name() noexcept                                                                              \
	{                                                                                                                  \
		return expression;                                                                                             \
	}                                                                                                                  \
	MUU_ALWAYS_INLINE                                                                                                  \
	MUU_ATTR(pure)                                                                                                     \
	constexpr const type& get_##name() const noexcept                                                                  \
	{                                                                                                                  \
		return expression;                                                                                             \
	}                                                                                                                  \
	static_assert(true)

	template <typename First,
			  typename Second,
			  compressed_pair_flags Flags = get_compressed_pair_flags_for<First, Second>()>
	struct compressed_pair_base
	{
		static_assert(Flags == compressed_pair_flags::none);
		First first_;
		Second second_;

		COMPRESSED_PAIR_BASE_DEFAULTS(first_, second_);
		COMPRESSED_PAIR_BASE_GETTERS(First, first, first_);
		COMPRESSED_PAIR_BASE_GETTERS(Second, second, second_);
	};

	template <typename First, typename Second>
	struct compressed_pair_base<First, Second, compressed_pair_flags::first_empty> : First
	{
		Second second_;

		COMPRESSED_PAIR_BASE_DEFAULTS(First, second_);
		COMPRESSED_PAIR_BASE_GETTERS(First, first, *this);
		COMPRESSED_PAIR_BASE_GETTERS(Second, second, second_);
	};

	template <typename First, typename Second>
	struct compressed_pair_base<First, Second, compressed_pair_flags::second_empty> : Second
	{
		First first_;

		COMPRESSED_PAIR_BASE_DEFAULTS(first_, Second);
		COMPRESSED_PAIR_BASE_GETTERS(First, first, first_);
		COMPRESSED_PAIR_BASE_GETTERS(Second, second, *this);
	};

	template <typename First, typename Second>
	struct compressed_pair_base<First, Second, compressed_pair_flags::both_empty> : First, Second
	{
		COMPRESSED_PAIR_BASE_DEFAULTS(First, Second);
		COMPRESSED_PAIR_BASE_GETTERS(First, first, *this);
		COMPRESSED_PAIR_BASE_GETTERS(Second, second, *this);
	};

#undef COMPRESSED_PAIR_BASE_DEFAULTS
#undef COMPRESSED_PAIR_BASE_GETTERS

	template <size_t I, typename T>
	MUU_NODISCARD
	MUU_ALWAYS_INLINE
	MUU_ATTR(pure)
	MUU_ATTR(flatten)
	constexpr decltype(auto) compressed_pair_get(T&& cp) noexcept
	{
		static_assert(I <= 1);
		if constexpr (I == 0)
			return static_cast<T&&>(cp).first();
		else
			return static_cast<T&&>(cp).second();
	}

	MUU_ABI_VERSION_END;
}
/// \endcond

namespace muu
{
	MUU_ABI_VERSION_START(0);

	/// \brief	A pair that uses Empty Base Class Optimization
	///			to elide storage for one or both of its members where possible.
	/// \ingroup core
	///
	/// \tparam	First		First member type.
	/// \tparam	Second		Second member type.
	template <typename First, typename Second>
	class compressed_pair //
		MUU_HIDDEN_BASE(private impl::compressed_pair_base<First, Second>)
	{
	  private:
		/// \cond

		using base = impl::compressed_pair_base<First, Second>;

		// mode hook for debuggers etc.
		static constexpr impl::compressed_pair_flags flags_ = impl::get_compressed_pair_flags_for<First, Second>();

		/// \endcond

	  public:
		/// \brief	The pair's first member type.
		using first_type = First;
		/// \brief	The pair's second member type.
		using second_type = Second;

		/// \brief	Default constructor.
		MUU_NODISCARD_CTOR
		compressed_pair() = default;

		/// \brief	Copy constructor.
		MUU_NODISCARD_CTOR
		compressed_pair(const compressed_pair&) = default;

		/// \brief	Move constructor.
		MUU_NODISCARD_CTOR
		compressed_pair(compressed_pair&&) = default;

		/// \brief	Copy-assignment operator.
		compressed_pair& operator=(const compressed_pair&) = default;

		/// \brief	Move-assignment operator.
		compressed_pair& operator=(compressed_pair&&) = default;

		/// \brief	Constructs a compressed pair from two values.
		///
		/// \tparam	F	First member initializer type.
		/// \tparam	S	Second member initializer type.
		/// \param 	first_init 	First member initializer.
		/// \param 	second_init	Second member initializer.
		MUU_CONSTRAINED_TEMPLATE((std::is_constructible_v<base, F&&, S&&>), typename F, typename S)
		MUU_NODISCARD_CTOR
		constexpr compressed_pair(F&& first_init,
								  S&& second_init) noexcept(std::is_nothrow_constructible_v<base, F&&, S&&>)
			: base{ static_cast<F&&>(first_init), static_cast<S&&>(second_init) }
		{}

		/// \brief	Returns an lvalue reference to the first member.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr first_type& first() & noexcept
		{
			return base::get_first();
		}

		/// \brief	Returns an rvalue reference to the first member.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr first_type&& first() && noexcept
		{
			return static_cast<first_type&&>(base::get_first());
		}

		/// \brief	Returns a const lvalue reference to the first member.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr const first_type& first() const& noexcept
		{
			return base::get_first();
		}

		/// \brief	Returns a const rvalue reference to the first member.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr const first_type&& first() const&& noexcept
		{
			return static_cast<const first_type&&>(base::get_first());
		}

		/// \brief	Returns an lvalue reference to the second member.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr second_type& second() & noexcept
		{
			return base::get_second();
		}

		/// \brief	Returns an rvalue reference to the second member.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr second_type&& second() && noexcept
		{
			return static_cast<second_type&&>(base::get_second());
		}

		/// \brief	Returns a const lvalue reference to the second member.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr const second_type& second() const& noexcept
		{
			return base::get_second();
		}

		/// \brief	Returns a const rvalue reference to the second member.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr const second_type&& second() const&& noexcept
		{
			return static_cast<const second_type&&>(base::get_second());
		}

		/// \brief	Returns an lvalue reference to the selected member.
		template <size_t I>
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr auto& get() & noexcept
		{
			return impl::compressed_pair_get<I>(*this);
		}

		/// \brief	Returns an rvalue reference to the selected member.
		template <size_t I>
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr auto&& get() && noexcept
		{
			return impl::compressed_pair_get<I>(static_cast<compressed_pair&&>(*this));
		}

		/// \brief	Returns a const lvalue reference to the selected member.
		template <size_t I>
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr const auto& get() const& noexcept
		{
			return impl::compressed_pair_get<I>(*this);
		}

		/// \brief	Returns a const rvalue reference to the selected member.
		template <size_t I>
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr const auto&& get() const&& noexcept
		{
			return impl::compressed_pair_get<I>(static_cast<const compressed_pair&&>(*this));
		}
	};

	/// \cond

	template <typename F, typename S>
	compressed_pair(const F&, const S&) -> compressed_pair<F, S>;

	/// \endcond

	MUU_ABI_VERSION_END;
}

namespace std
{
	/// \brief Specialization of std::tuple_size for muu::compressed_pair.
	template <typename First, typename Second>
	struct tuple_size<muu::compressed_pair<First, Second>>
	{
		static constexpr size_t value = 2;
	};

	/// \brief Specialization of std::tuple_element for muu::compressed_pair.
	template <size_t I, typename First, typename Second>
	struct tuple_element<I, muu::compressed_pair<First, Second>>
	{
		static_assert(I < 2);
		using type = std::conditional_t<I == 1, Second, First>;
	};
}

#include "impl/header_end.h"
