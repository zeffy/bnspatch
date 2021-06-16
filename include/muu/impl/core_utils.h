// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

#pragma once
#include "core_meta.h"

MUU_DISABLE_WARNINGS;
#if MUU_CLANG >= 8 || MUU_GCC >= 7 || MUU_ICC >= 1910 || MUU_MSVC >= 1914 || MUU_HAS_BUILTIN(launder)
	#define MUU_LAUNDER(...) __builtin_launder(__VA_ARGS__)
#else
	#include <new>
	#ifdef __cpp_lib_launder
		#define MUU_LAUNDER(...) std::launder(__VA_ARGS__)
	#endif
#endif
#ifndef MUU_LAUNDER
	#define MUU_LAUNDER(...) __VA_ARGS__
#endif
MUU_ENABLE_WARNINGS;

#include "header_start.h"
MUU_FORCE_NDEBUG_OPTIMIZATIONS; // these should be considered "intrinsics"

namespace muu
{
#if 1 // to make clang-format behave

	/// \brief	Unwraps an enum to it's raw integer equivalent.
	/// \ingroup core
	///
	/// \tparam	T		An enum type.
	/// \param 	val		The value to unwrap.
	///
	/// \returns	\conditional_return{Enum inputs} `static_cast<std::underlying_type_t<T>>(val)`
	/// 			 <br>
	/// 			\conditional_return{Everything else} `T&&` (a no-op).
	MUU_CONSTRAINED_TEMPLATE(is_enum<T>, typename T)
	MUU_NODISCARD
	MUU_ALWAYS_INLINE
	MUU_ATTR(const)
	constexpr std::underlying_type_t<T> MUU_VECTORCALL unwrap(T val) noexcept
	{
		return static_cast<std::underlying_type_t<T>>(val);
	}

	/// \cond

	MUU_CONSTRAINED_TEMPLATE_2(!is_enum<T>, typename T)
	MUU_NODISCARD
	MUU_ALWAYS_INLINE
	MUU_ATTR(const)
	constexpr T&& unwrap(T&& val) noexcept
	{
		return static_cast<T&&>(val);
	}

	/// \endcond

	/// \brief	Returns the minimum of two values.
	/// \ingroup core
	///
	/// \remark This is equivalent to std::min without requiring you to drag in the enormity of &lt;algorithm&gt;.
	template <typename T>
	MUU_NODISCARD
	MUU_ALWAYS_INLINE
	constexpr const T& min(const T& val1, const T& val2) noexcept
	{
		return val1 < val2 ? val1 : val2;
	}

	/// \brief	Returns the maximum of two values.
	/// \ingroup core
	///
	/// \remark This is equivalent to std::max without requiring you to drag in the enormity of &lt;algorithm&gt;.
	template <typename T>
	MUU_NODISCARD
	MUU_ALWAYS_INLINE
	constexpr const T& max(const T& val1, const T& val2) noexcept
	{
		return val1 < val2 ? val2 : val1;
	}

	/// \brief	Returns a value clamped between two bounds (inclusive).
	/// \ingroup core
	///
	/// \remark This is equivalent to std::clamp without requiring you to drag in the enormity of &lt;algorithm&gt;.
	template <typename T>
	MUU_NODISCARD
	constexpr const T& clamp(const T& val, const T& low, const T& high) noexcept
	{
		return val < low ? low : ((high < val) ? high : val);
	}

	/// \brief	Returns true if a value is between two bounds (inclusive).
	/// \ingroup core
	template <typename T, typename U>
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr bool MUU_VECTORCALL between(T val, U low, U high) noexcept
	{
		if constexpr ((is_arithmetic<T> || is_enum<U>) || (is_arithmetic<T> || is_enum<U>))
		{
			if constexpr (is_enum<T> || is_enum<U>)
				return between(static_cast<std::underlying_type_t<T>>(val),
							   static_cast<std::underlying_type_t<U>>(low),
							   static_cast<std::underlying_type_t<U>>(high));
			else
			{
				using lhs = remove_cvref<T>;
				using rhs = remove_cvref<U>;
				if constexpr (is_signed<lhs> && is_unsigned<rhs>)
				{
					if (val < lhs{})
						return false;
				}
				else if constexpr (is_unsigned<lhs> && is_signed<rhs>)
				{
					if (high < rhs{})
						return false;
				}
				if constexpr (!std::is_same_v<lhs, rhs>)
				{
					using common_type = std::common_type_t<lhs, rhs>;
					return between(static_cast<common_type>(val),
								   static_cast<common_type>(low),
								   static_cast<common_type>(high));
				}
				else
					return low <= val && val <= high;
			}
		}
		else
			return low <= val && val <= high; // user-defined <= operator, ideally
	}

	/// \brief	Equivalent to C++20's std::is_constant_evaluated.
	/// \ingroup core
	///
	/// \remark Compilers typically implement std::is_constant_evaluated as an intrinsic which is
	/// 		 available regardless of the C++ mode. Using this function on these compilers allows
	/// 		 you to get the same behaviour even when you aren't targeting C++20.
	///
	/// \availability On older compilers lacking support for std::is_constant_evaluated this will always return `false`.
	/// 		   You can check for support by examining build::supports_is_constant_evaluated.
	MUU_NODISCARD
	MUU_ALWAYS_INLINE
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr bool is_constant_evaluated() noexcept
	{
	#if MUU_CLANG >= 9 || MUU_GCC >= 9 || MUU_MSVC >= 1925 || MUU_HAS_BUILTIN(is_constant_evaluated)
		return __builtin_is_constant_evaluated();
	#elif defined(__cpp_lib_is_constant_evaluated)
		return std::is_constant_evaluated();
	#else
		return false;
	#endif
	}

	namespace build
	{
		/// \brief	True if is_constant_evaluated() is properly supported on this compiler.
		inline constexpr bool supports_is_constant_evaluated = is_constant_evaluated();
	}

	#define MUU_USE_STD_LAUNDER 0

	/// \brief	Equivalent to C++17's std::launder
	/// \ingroup core
	///
	/// \note	Older implementations don't provide this as an intrinsic or have a placeholder
	/// 		 for it in their standard library. Using this version allows you to get around that
	/// 		 by writing code 'as if' it were there and have it compile just the same.
	template <class T>
	MUU_NODISCARD
	MUU_ALWAYS_INLINE
	MUU_ATTR(flatten)
	constexpr T* launder(T* ptr) noexcept
	{
		static_assert(!std::is_function_v<T> && !std::is_void_v<T>,
					  "launder() may not be used on pointers to functions or void.");

		return MUU_LAUNDER(ptr);
	}

	/// \brief	Casts between pointers, choosing the most appropriate conversion path.
	/// \ingroup core
	///
	/// \details Doing low-level work with pointers often requires a lot of tedious boilerplate,
	/// 		particularly when moving to/from raw byte representations or dealing with `const`.
	/// 		By using `pointer_cast` instead you can eliminate a lot of that boilerplate,
	/// 		since it will do 'the right thing' via some combination of:
	///	| From                    | To                      | Cast              | Note                  |
	///	|-------------------------|-------------------------|-------------------|-----------------------|
	///	| T\*                     | void\*                  | static_cast       |                       |
	///	| void\*                  | T\*                     | static_cast       |                       |
	///	| T\*                     | const T\*               | static_cast       |                       |
	///	| T\*                     | volatile T\*            | static_cast       |                       |
	///	| T\*                     | const volatile T\*      | static_cast       |                       |
	///	| const T\*               | T\*                     | const_cast        |                       |
	///	| volatile T\*            | T\*                     | const_cast        |                       |
	///	| const volatile T\*      | T\*                     | const_cast        |                       |
	///	| Derived\*               | Base\*                  | static_cast       |                       |
	///	| Base\*                  | Derived\*               | dynamic_cast      | Polymorphic bases     |
	///	| Base\*                  | Derived\*               | reinterpret_cast  | Non-polymorphic bases |
	///	| T\*                     | (u)intptr_t             | reinterpret_cast  |                       |
	///	| (u)intptr_t             | T\*                     | reinterpret_cast  |                       |
	///	| void\*                  | T(\*)()                 | reinterpret_cast  | Where supported       |
	///	| T(\*)()                 | void\*                  | reinterpret_cast  | Where supported       |
	///	| T(\*)()                 | T(\*)()noexcept         | reinterpret_cast  |                       |
	///	| T(\*)()noexcept         | T(\*)()                 | static_cast       |                       |
	///	| IUnknown\*              | IUnknown\*              | QueryInterface    | Windows only          |
	///
	///  \warning There are lots of static checks to make sure you don't do something completely insane,
	/// 		 but ultimately the fallback behaviour for casting between unrelated types is to use a
	/// 		 `reinterpret_cast`, and there's nothing stopping you from using multiple `pointer_casts`
	/// 		 through `void*` to make a conversion 'work'. Footguns aplenty!
	///
	/// \tparam To	A pointer or integral type large enough to store a pointer
	/// \tparam From A pointer, array, nullptr_t, or an integral type large enough to store a pointer.
	/// \param from The value being cast.
	///
	/// \return The input casted to the desired type.
	///
	template <typename To, typename From>
	MUU_NODISCARD
	MUU_ALWAYS_INLINE
	MUU_ATTR(flatten)
	constexpr To pointer_cast(From from) noexcept
	{
		static_assert(!std::is_reference_v<To> && !std::is_reference_v<From>, // will never be deduced as a reference
																			  // but it might be specified explicitly
					  "From and To types cannot be references");
		static_assert(!(is_integral<From> && is_integral<To>),
					  "From and To types cannot both be integral types (did you mean static_cast?)");
		static_assert(std::is_pointer_v<To> || (is_integral<To> && sizeof(To) >= sizeof(void*)),
					  "To type must be a pointer or an integral type large enough to store a pointer");
		static_assert(!(!std::is_same_v<From, remove_cv<nullptr_t>> && std::is_same_v<remove_cv<nullptr_t>, To>),
					  "To type cannot be nullptr_t (such a conversion is nonsensical)");
		static_assert(
			std::is_pointer_v<From>										//
				|| (is_integral<From> && sizeof(From) >= sizeof(void*)) //
				|| std::is_same_v<From, remove_cv<nullptr_t>>,
			"From type must be a pointer, array, nullptr_t, or an integral type large enough to store a pointer");
		static_assert(!std::is_member_pointer_v<To> && !std::is_member_pointer_v<From>,
					  "From and To types cannot be pointers to members");

		using from_base = std::remove_pointer_t<From>;
		using to_base	= std::remove_pointer_t<To>;

		static_assert((!std::is_function_v<from_base> || sizeof(From) == sizeof(void*))
						  && (!std::is_function_v<to_base> || sizeof(To) == sizeof(void*)),
					  "Cannot pointer_cast with function pointers on the target platform");

		// same input and output types (no-op)
		if constexpr (std::is_same_v<From, To>)
			return from;

		// nullptr_t -> *
		else if constexpr (std::is_same_v<From, nullptr_t>)
		{
			MUU_UNUSED(from);
			return {};
		}

		// pointer -> integral
		// integral -> pointer
		else if constexpr (is_integral<From> || is_integral<To>)
		{
			static_assert(std::is_pointer_v<To> || std::is_pointer_v<From>);

			// pointer -> integral
			if constexpr (is_integral<To>)
			{
				// widening conversion and enums
				if constexpr (is_enum<To> || sizeof(To) > sizeof(From))
				{
					using cast_t = std::conditional_t<is_signed<To>, intptr_t, uintptr_t>;
					return static_cast<To>(reinterpret_cast<cast_t>(from));
				}
				// integers of the same size
				else
				{
					static_assert(sizeof(To) == sizeof(From));
					return reinterpret_cast<To>(from);
				}
			}

			// integral -> pointer
			else
			{
				// enum -> pointer
				if constexpr (is_enum<From>)
					return pointer_cast<To>(static_cast<std::underlying_type_t<From>>(from));

				// (uintptr_t, intptr_t) -> pointer
				else if constexpr (is_same_as_any<From, uintptr_t, intptr_t>)
					return reinterpret_cast<To>(from);

				// other integers -> pointer
				else
				{
					using cast_t = std::conditional_t<is_signed<From>, intptr_t, uintptr_t>;
					return reinterpret_cast<To>(static_cast<cast_t>(from));
				}
			}
		}

		// pointer -> pointer
		else
		{
			static_assert(std::is_pointer_v<To> && std::is_pointer_v<From>);

			// Foo -> Foo (different cv)
			if constexpr (std::is_same_v<remove_cv<from_base>, remove_cv<to_base>>)
			{
				static_assert(!std::is_same_v<from_base, to_base>);

				// remove const/volatile
				if constexpr (is_const<from_base> || is_volatile<from_base>)
					return static_cast<To>(const_cast<remove_cv<from_base>*>(from));

				// add const/volatile
				else
				{
					static_assert(std::is_same_v<From, remove_cv<from_base>*>);
					static_assert(is_same_as_any<To, const to_base*, const volatile to_base*, volatile to_base*>);
					return static_cast<To>(from);
				}
			}

			// function -> non-function
			// non-function -> function
			// function -> function (different exception specifier)
			else if constexpr (std::is_function_v<from_base> || std::is_function_v<to_base>)
			{
				// function -> function (different exception specifier)
				if constexpr (std::is_function_v<from_base> && std::is_function_v<to_base>)
				{
					static_assert(std::is_same_v<remove_noexcept<from_base>, remove_noexcept<to_base>>,
								  "Cannot cast between pointers to two different function types");

					// function -> function (noexcept)
					if constexpr (std::is_same_v<from_base, remove_noexcept<from_base>>)
						return reinterpret_cast<To>(from);

					// function (noexcept) -> function
					else
						return static_cast<To>(from);
				}

				// function -> non-function
				else if constexpr (std::is_function_v<from_base>)
				{
					static_assert(std::is_void_v<to_base>,
								  "Cannot cast from a function pointer to a type other than void");

					// function -> void
					return static_cast<To>(reinterpret_cast<void*>(from));
				}

				// non-function -> function
				else
				{
					static_assert(std::is_void_v<from_base>,
								  "Cannot cast to a function pointer from a type other than void");

					// void -> function
					return reinterpret_cast<To>(pointer_cast<void*>(from));
				}
			}

			// void -> non-void
			// non-void -> void
			// derived -> base
			else if constexpr (std::is_void_v<from_base>  //
							   || std::is_void_v<to_base> //
							   || inherits_from<to_base, from_base>)
				return pointer_cast<To>(static_cast<rebase_pointer<From, remove_cv<to_base>>>(from));

	#if MUU_WINDOWS

			// IUnknown -> IUnknown (windows only)
			else if constexpr (std::is_class_v<from_base>				 //
							   && std::is_class_v<to_base>				 //
							   && std::is_base_of_v<IUnknown, from_base> //
							   && std::is_base_of_v<IUnknown, to_base>)
			{
				if (!from)
					return nullptr;

				// remove const/volatile from source type
				if constexpr (is_const<from_base> || is_volatile<from_base>)
					return pointer_cast<To>(const_cast<remove_cv<from_base>*>(from));

				// remove const/volatile from destination type
				else if constexpr (is_const<to_base> || is_volatile<to_base>)
					return const_cast<To>(pointer_cast<remove_cv<to_base>*>(from));

				else
				{
					static_assert(!is_const<from_base> && !is_volatile<from_base>);
					static_assert(!is_const<to_base> && !is_volatile<to_base>);

					to_base* to = {};
					if (from->QueryInterface(__uuidof(to_base), reinterpret_cast<void**>(&to)) == 0)
						to->Release(); // QueryInterface adds 1 to ref count on success
					return to;
				}
			}

	#endif // MUU_WINDOWS

			// base -> derived
			else if constexpr (inherits_from<from_base, to_base>)
			{
				if constexpr (std::is_polymorphic_v<from_base>)
					return pointer_cast<To>(dynamic_cast<rebase_pointer<From, remove_cv<to_base>>>(from));
				else
					return pointer_cast<To>(reinterpret_cast<rebase_pointer<From, remove_cv<to_base>>>(from));
			}

			// rank 2+ pointer -> *
			else if constexpr (std::is_pointer_v<from_base>)
			{
				return pointer_cast<To>(static_cast<match_cv<void, from_base>*>(from));
			}

			// * -> rank 2+ pointer
			else if constexpr (std::is_pointer_v<to_base>)
			{
				static_assert(!std::is_pointer_v<from_base>);
				return static_cast<To>(pointer_cast<match_cv<void, to_base>*>(from));
			}

			// Foo -> Bar (unrelated types)
			else
			{
				static_assert(!std::is_same_v<remove_cv<from_base>, remove_cv<to_base>>);
				static_assert(!std::is_pointer_v<from_base>);
				static_assert(!std::is_pointer_v<to_base>);
				return pointer_cast<To>(reinterpret_cast<rebase_pointer<From, remove_cv<to_base>>>(from));
			}
		}
	}

	/// \cond

	template <typename To, typename From, size_t N>
	MUU_NODISCARD
	MUU_ALWAYS_INLINE
	MUU_ATTR(flatten)
	constexpr To pointer_cast(From (&arr)[N]) noexcept
	{
		return pointer_cast<To, From*>(arr);
	}

	template <typename To, typename From, size_t N>
	MUU_NODISCARD
	MUU_ALWAYS_INLINE
	MUU_ATTR(flatten)
	constexpr To pointer_cast(From(&&arr)[N]) noexcept
	{
		return pointer_cast<To, From*>(arr);
	}

	/// \endcond

	/// \brief	Applies a byte offset to a pointer.
	/// \ingroup core
	///
	/// \tparam	T		The type being pointed to.
	/// \tparam	Offset	An integer type.
	/// \param	ptr	The pointer to offset.
	/// \param	offset	The number of bytes to add to the pointer's address.
	///
	/// \return	The cv-correct equivalent of `(T*)((std::byte*)ptr + offset)`.
	///
	/// \warning This function is a simple pointer arithmetic helper; absolutely no consideration
	/// 		 is given to the alignment of the pointed type. If you need to dereference pointers
	/// 		 returned by apply_offset the onus is on you to ensure that the offset made sense
	/// 		 before doing so!
	MUU_CONSTRAINED_TEMPLATE((is_integral<Offset> && is_arithmetic<Offset>), typename T, typename Offset)
	MUU_NODISCARD
	MUU_ALWAYS_INLINE
	MUU_ATTR(const)
	constexpr T* apply_offset(T* ptr, Offset offset) noexcept
	{
		using char_ptr = rebase_pointer<T*, unsigned char>;
		if constexpr (std::is_void_v<T>)
			return static_cast<T*>(static_cast<char_ptr>(ptr) + offset);
		else
			return reinterpret_cast<T*>(reinterpret_cast<char_ptr>(ptr) + offset);
	}

	/// \cond
	namespace impl
	{
		template <typename T>
		using has_pointer_traits_to_address_ =
			decltype(std::pointer_traits<remove_cvref<T>>::to_address(std::declval<remove_cvref<T>>()));
	}
	/// \endcond

	/// \brief Obtain the address represented by p without forming a reference to the pointee.
	/// \ingroup core
	///
	/// \remark This is equivalent to C++20's std::to_address.
	template <typename T>
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr T* to_address(T* p) noexcept
	{
		static_assert(!std::is_function_v<T>, "to_address may not be used on functions.");
		return p;
	}

	/// \brief Obtain the address represented by p without forming a reference to the pointee.
	/// \ingroup core
	///
	/// \remark This is equivalent to C++20's std::to_address.
	template <typename Ptr>
	MUU_NODISCARD
	constexpr auto to_address(const Ptr& p) noexcept
	{
		if constexpr (is_detected<impl::has_pointer_traits_to_address_, Ptr>)
		{
			return std::pointer_traits<Ptr>::to_address(p);
		}
		else
		{
			return to_address(p.operator->());
		}
	}

	/// \brief	Equivalent to C++20's std::assume_aligned.
	/// \ingroup core
	///
	/// \remark Compilers typically implement std::assume_aligned as an intrinsic which is
	/// 		 available regardless of the C++ mode. Using this function on these compilers allows
	/// 		 you to get the same behaviour even when you aren't targeting C++20.
	///
	/// \see [P1007R1: std::assume_aligned](http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2018/p1007r1.pdf)
	template <size_t N, typename T>
	MUU_NODISCARD
	MUU_ALWAYS_INLINE
	MUU_ATTR(assume_aligned(N))
	MUU_ATTR(flatten)
	MUU_ATTR(const)
	constexpr T* assume_aligned(T* ptr) noexcept
	{
		static_assert(N > 0 && (N & (N - 1u)) == 0u, "assume_aligned() requires a power-of-two alignment value.");
		static_assert(!std::is_function_v<T>, "assume_aligned may not be used on functions.");

		MUU_ASSUME((reinterpret_cast<uintptr_t>(ptr) & (N - uintptr_t{ 1 })) == 0);

		if constexpr (std::is_volatile_v<T>)
		{
			return static_cast<T*>(muu::assume_aligned<N>(const_cast<remove_volatile<T>*>(ptr)));
		}
		else
		{
	#if MUU_CLANG || MUU_GCC || MUU_HAS_BUILTIN(assume_aligned)

			return static_cast<T*>(__builtin_assume_aligned(ptr, N));

	#elif MUU_MSVC

			if constexpr (N < 16384)
				return static_cast<T*>(__builtin_assume_aligned(ptr, N));
			else
				return ptr;

	#elif MUU_ICC

			__assume_aligned(ptr, N);
			return ptr;

	#elif defined(__cpp_lib_assume_aligned)

			return std::assume_aligned<N>(ptr);

	#else

			return ptr;

	#endif
		}
	}

	/// \cond
	namespace impl
	{
		template <typename Func, typename T, T... N>
		inline constexpr bool for_sequence_impl_noexcept_ =
			sizeof...(N) == 0 || ((noexcept(std::declval<Func>()(std::integral_constant<T, N>{})) && ...));

		template <typename Func, typename T, T... N>
		constexpr void for_sequence_impl(Func&& func, std::integer_sequence<T, N...>) noexcept(
			for_sequence_impl_noexcept_<Func&&, T, N...>)
		{
			(static_cast<void>(static_cast<Func&&>(func)(std::integral_constant<T, N>{})), ...);
		}

		template <auto N, typename Func>
		inline constexpr bool for_sequence_noexcept_ =
			noexcept(for_sequence_impl(std::declval<Func>(), std::make_integer_sequence<decltype(N), N>{}));

		template <typename Func, typename T, T... N1, typename U, U... N2>
		MUU_NODISCARD
		MUU_CONSTEVAL
		bool for_product_impl_noexcept(std::integer_sequence<T, N1...>, std::integer_sequence<U, N2...>) noexcept
		{
			if constexpr (sizeof...(N1) == 0 || sizeof...(N2) == 0)
				return true;
			else
			{
				bool value = true;

				const auto inner = [&](auto i, auto j) noexcept
				{
					value = noexcept(std::declval<Func>()(std::integral_constant<T, decltype(i)::value>{},
														  std::integral_constant<U, decltype(j)::value>{}))
						 && value;
				};

				const auto outer = [&](auto i) noexcept
				{ (static_cast<void>(inner(i, std::integral_constant<U, N2>{})), ...); };

				(static_cast<void>(outer(std::integral_constant<T, N1>{})), ...);

				return value;
			}
		}

		template <typename Func, typename T, T... N1, typename U, U... N2>
		constexpr void for_product_impl(Func&& func,
										std::integer_sequence<T, N1...>,
										std::integer_sequence<U,
															  N2...>) //
			noexcept(for_product_impl_noexcept<Func&&>(std::integer_sequence<T, N1...>{},
													   std::integer_sequence<U, N2...>{}))
		{
			const auto inner = [&](auto i, auto j)
			{
				static_cast<Func&&>(func)(std::integral_constant<T, decltype(i)::value>{},
										  std::integral_constant<U, decltype(j)::value>{});
			};

			const auto outer = [&](auto i) { (static_cast<void>(inner(i, std::integral_constant<U, N2>{})), ...); };

			(static_cast<void>(outer(std::integral_constant<T, N1>{})), ...);
		}

		template <auto N1, auto N2, typename Func>
		inline constexpr bool for_product_noexcept_ =
			noexcept(for_product_impl(std::declval<Func>(),
									  std::make_integer_sequence<decltype(N1), N1>{},
									  std::make_integer_sequence<decltype(N2), N2>{}));

	}
	/// \endcond

	/// \brief	Generates a series of sequential function calls by pack expansion.
	/// \ingroup core
	///
	/// \details Generates a std::integral_constant sequence, [0...N1), which is passed into the callable: \cpp
	///
	/// auto vals = std::tuple{ 0, "1"sv, 2.3f };
	/// for_sequence<3>([&](auto i)
	/// {
	///		std::cout << std::get<decltype(i)::value>(vals) << "\n";
	/// });
	/// \ecpp
	///
	/// \out
	/// 0
	/// 1
	/// 2.3
	/// \eout
	///
	/// \tparam N		The length of the sequence (the number of calls). Cannot be negative.
	/// \tparam Func	A callable type with the signature `void(auto)`.
	template <auto N, typename Func>
	constexpr void for_sequence(Func&& func) noexcept(impl::for_sequence_noexcept_<N, Func>)
	{
		using n_type = decltype(N);
		static_assert(N >= n_type{}, "N cannot be negative.");

		if constexpr (N > n_type{})
			impl::for_sequence_impl(static_cast<Func&&>(func), std::make_integer_sequence<n_type, N>{});
		else
			MUU_UNUSED(func);
	}

	/// \brief	Generates a series of sequential function calls by pack expansion.
	/// \ingroup core
	///
	/// \details Generates a std::integral_constant product sequence, [0...N1) * [0...N2), which is passed into the callable: \cpp
	///
	/// auto vals_1 = std::pair{ 1, 2 };
	/// auto vals_2 = std::pair{ 3, 4 };
	/// for_product<2, 2>([&](auto i, auto j)
	/// {
	///		const auto lhs = std::get<decltype(i)::value>(vals_1);
	///		const auto rhs = std::get<decltype(j)::value>(vals_2);
	///		std::cout << lhs
	///		          << " * "
	///		          << rhs
	///		          << " = "
	///		          << lhs * rhs;
	/// });
	/// \ecpp
	///
	/// \out
	/// 1 * 3 = 3
	/// 1 * 4 = 4
	/// 2 * 3 = 6
	/// 2 * 4 = 8
	/// \eout
	///
	/// \tparam N1		The length of the LHS sequence. Cannot be negative.
	/// \tparam N2		The length of the RHS sequence. Cannot be negative.
	/// \tparam Func	A callable type with the signature `void(auto, auto)`.
	template <auto N1, auto N2, typename Func>
	constexpr void for_product(Func&& func) noexcept(impl::for_product_noexcept_<N1, N2, Func>)
	{
		using n1_type = decltype(N1);
		static_assert(N1 >= n1_type{}, "N1 cannot be negative.");

		using n2_type = decltype(N2);
		static_assert(N2 >= n2_type{}, "N2 cannot be negative.");

		if constexpr (N1 > n1_type{} && N2 > n2_type{})
			impl::for_product_impl(static_cast<Func&&>(func),
								   std::make_integer_sequence<n1_type, N1>{},
								   std::make_integer_sequence<n2_type, N2>{});
		else
			MUU_UNUSED(func);
	}

	/// \brief	Rounds an unsigned value up to the next multiple of the given alignment.
	/// \ingroup core
	///
	/// \tparam 	Alignment	The alignment to round up to. Must be a power of two.
	/// \tparam	T	An unsigned integer or enum type.
	/// \param 	val	The unsigned value being aligned.
	MUU_CONSTRAINED_TEMPLATE(is_unsigned<T>, size_t Alignment, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr T apply_alignment(T val) noexcept
	{
		static_assert(Alignment, "alignment cannot be zero");
		static_assert((Alignment & (Alignment - 1u)) == 0u, "alignment must be a power of two");

		if constexpr (is_enum<T>)
		{
			return static_cast<T>(apply_alignment(static_cast<std::underlying_type_t<T>>(val)));
		}
		else
		{
			using uint = impl::highest_ranked<T, size_t>;
			return static_cast<T>((val + Alignment - uint{ 1 }) & ~(Alignment - uint{ 1 }));
		}
	}

	/// \brief	Rounds a pointer up to the byte offset that is the next multiple of the given alignment.
	/// \ingroup core
	///
	/// \tparam 		Alignment	The alignment to round up to. Must be a power of two.
	/// \tparam	T		An object type (or void).
	/// \param 	ptr		The pointer being aligned.
	template <size_t Alignment, typename T>
	MUU_NODISCARD
	MUU_ATTR(nonnull)
	MUU_ATTR(returns_nonnull)
	MUU_ATTR(assume_aligned(Alignment))
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr T* apply_alignment(T* ptr) noexcept
	{
		static_assert(!std::is_function_v<T>, "apply_alignment() may not be used on pointers to functions.");
		static_assert(Alignment, "alignment cannot be zero");
		static_assert((Alignment & (Alignment - 1u)) == 0u, "alignment must be a power of two");
		static_assert(Alignment >= alignment_of<std::remove_pointer_t<T>>, "cannot under-align types.");

		return muu::assume_aligned<Alignment>(
			reinterpret_cast<T*>(apply_alignment<Alignment>(reinterpret_cast<uintptr_t>(ptr))));
	}

	/// \brief	Rounds an unsigned value up to the next multiple of the given alignment.
	/// \ingroup core
	///
	/// \tparam	T			An unsigned integer or enum type.
	/// \param 	val			The unsigned value being aligned.
	/// \param 	alignment	The alignment to round up to. Must be a power of two.
	MUU_CONSTRAINED_TEMPLATE(is_unsigned<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR_NDEBUG(const)
	MUU_ATTR_NDEBUG(flatten)
	constexpr T apply_alignment(T val, size_t alignment) noexcept
	{
		MUU_CONSTEXPR_SAFE_ASSERT(alignment && "alignment cannot be zero");
		MUU_CONSTEXPR_SAFE_ASSERT(((alignment & (alignment - 1u)) == 0u) && "alignment must be a power of two");
		MUU_ASSUME(alignment > 0u);
		MUU_ASSUME((alignment & (alignment - 1u)) == 0u);

		if constexpr (is_enum<T>)
		{
			return static_cast<T>(apply_alignment(static_cast<std::underlying_type_t<T>>(val), alignment));
		}
		else
		{
			using uint = impl::highest_ranked<T, size_t>;
			return static_cast<T>((val + alignment - uint{ 1 }) & ~(alignment - uint{ 1 }));
		}
	}

	/// \brief	Rounds a pointer up to the byte offset that is the next multiple of the given alignment.
	/// \ingroup core
	///
	/// \tparam	T			An object type (or void).
	/// \param 	ptr			The pointer being aligned.
	/// \param 	alignment	The alignment to round up to. Must be a power of two.
	template <typename T>
	MUU_ATTR(nonnull)
	MUU_ATTR(returns_nonnull)
	MUU_ATTR_NDEBUG(const)
	MUU_ATTR_NDEBUG(flatten)
	constexpr T* apply_alignment(T* ptr, size_t alignment) noexcept
	{
		static_assert(!std::is_function_v<T>, "apply_alignment() may not be used on pointers to functions.");
		MUU_CONSTEXPR_SAFE_ASSERT(alignment && "alignment cannot be zero");
		MUU_CONSTEXPR_SAFE_ASSERT(((alignment & (alignment - 1u)) == 0u) && "alignment must be a power of two");
		MUU_CONSTEXPR_SAFE_ASSERT(alignment >= alignment_of<std::remove_pointer_t<T>> && "cannot under-align types.");

		return reinterpret_cast<T*>(apply_alignment(reinterpret_cast<uintptr_t>(ptr), alignment));
	}

#endif
}

#undef MUU_LAUNDER

MUU_RESET_NDEBUG_OPTIMIZATIONS;
#include "header_end.h"
