// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

/// \file
/// \brief  Contains the definition of muu::scope_guard.

#pragma once
#include "core.h"
#include "compressed_pair.h"

MUU_DISABLE_WARNINGS;
#include <exception>
MUU_ENABLE_WARNINGS;

#include "impl/header_start.h"

namespace muu
{
	/// \cond
	namespace impl
	{
		MUU_ABI_VERSION_START(0);

		enum class scope_guard_mode : unsigned
		{
			invoke_on_fail,
			invoke_on_success,
			invoke_always,
		};

		template <typename T, scope_guard_mode Mode, bool ExceptionAware = (Mode < scope_guard_mode::invoke_always)>
		struct scope_guard_storage
		{
			compressed_pair<T, bool> func_and_dismissed_;
			int uncaught_exceptions_;

			template <typename U>
			scope_guard_storage(U&& callable) //
				noexcept(std::is_reference_v<T> || std::is_nothrow_constructible_v<T, U&&>)
				: func_and_dismissed_{ static_cast<U&&>(callable), false },
				  uncaught_exceptions_{ std::uncaught_exceptions() }
			{}

			MUU_DEFAULT_MOVE(scope_guard_storage);
			MUU_DELETE_COPY(scope_guard_storage);
		};

		template <typename T, scope_guard_mode Mode>
		struct scope_guard_storage<T, Mode, false>
		{
			compressed_pair<T, bool> func_and_dismissed_;

			template <typename U>
			scope_guard_storage(U&& callable) //
				noexcept(std::is_reference_v<T> || std::is_nothrow_constructible_v<T, U&&>)
				: func_and_dismissed_{ static_cast<U&&>(callable), false }
			{}

			MUU_DEFAULT_MOVE(scope_guard_storage);
			MUU_DELETE_COPY(scope_guard_storage);
		};

		template <typename T,
				  scope_guard_mode Mode,
				  bool Movable =
					  (std::is_reference_v<T> || (std::is_move_constructible_v<T> && std::is_move_assignable_v<T>))>
		struct scope_guard_move : scope_guard_storage<T, Mode>
		{
			using base = scope_guard_storage<T, Mode>;

			template <typename U>
			scope_guard_move(U&& callable) noexcept(std::is_nothrow_constructible_v<base, U&&>)
				: base{ static_cast<U&&>(callable) }
			{}

			scope_guard_move(scope_guard_move&& other) noexcept(std::is_nothrow_move_constructible_v<base>)
				: base{ static_cast<base&&>(other) }
			{
				other.func_and_dismissed_.second() = true;
			}

			scope_guard_move& operator=(scope_guard_move&& rhs) noexcept(std::is_nothrow_move_assignable_v<base>)
			{
				base::operator					 =(static_cast<base&&>(rhs));
				rhs.func_and_dismissed_.second() = true;
				return *this;
			}
		};

		template <typename T, scope_guard_mode Mode>
		struct scope_guard_move<T, Mode, false> : scope_guard_storage<T, Mode>
		{
			using base = scope_guard_storage<T, Mode>;

			template <typename U>
			scope_guard_move(U&& callable) noexcept(std::is_nothrow_constructible_v<base, U&&>)
				: base{ static_cast<U&&>(callable) }
			{}

			MUU_DELETE_MOVE(scope_guard_move);
		};

		template <typename T, scope_guard_mode Mode>
		class scope_guard_ : protected scope_guard_move<T, Mode>
		{
			static_assert(!std::is_rvalue_reference_v<T>,
						  "Callables wrapped by a scope guard may not be rvalue references");
			static_assert(!build::has_exceptions
							  || std::is_nothrow_invocable_v<std::add_lvalue_reference_t<std::remove_reference_t<T>>>,
						  "Callables wrapped by a scope guard must be nothrow-invocable (functions, lambdas, etc.)");
			static_assert(std::is_invocable_v<std::add_lvalue_reference_t<std::remove_reference_t<T>>>,
						  "Callables wrapped by a scope guard must be invocable (functions, lambdas, etc.)");
			static_assert(!build::has_exceptions || std::is_reference_v<T> || std::is_nothrow_destructible_v<T>,
						  "Callables wrapped by a scope guard must be nothrow-destructible");
			static_assert(std::is_reference_v<T> || std::is_destructible_v<T>,
						  "Callables wrapped by a scope guard must be destructible");
			static_assert(Mode <= scope_guard_mode::invoke_always);

			using base = scope_guard_move<T, Mode>;
			static_assert(std::is_reference_v<T> //
						  || (std::is_nothrow_move_constructible_v<base> && std::is_nothrow_move_assignable_v<base>)
								 == (std::is_nothrow_move_constructible_v<T> && std::is_nothrow_move_assignable_v<T>));

		  public:
			template <typename U>
			scope_guard_(U&& callable) noexcept(std::is_nothrow_constructible_v<base, U&&>)
				: base{ static_cast<U&&>(callable) }
			{
				static_assert(muu::is_convertible<U&&, T>,
							  "A scope guard's callable must be constructible from its initializer");
			}

			~scope_guard_() noexcept
			{
				if constexpr (Mode == scope_guard_mode::invoke_on_fail)
				{
					if (base::uncaught_exceptions_ == std::uncaught_exceptions())
						return;
				}
				else if constexpr (Mode == scope_guard_mode::invoke_on_success)
				{
					if (base::uncaught_exceptions_ != std::uncaught_exceptions())
						return;
				}

				if (!base::func_and_dismissed_.second())
					base::func_and_dismissed_.first()();
			}

			void dismiss() noexcept
			{
				base::func_and_dismissed_.second() = true;
			}
		};

		MUU_ABI_VERSION_END;
	}
	/// \endcond

	MUU_ABI_VERSION_START(0);

	/// \brief	Performs actions when going out of scope.
	/// \ingroup core
	///
	/// \details Use a scope_guard to simplify cleanup routines
	/// 		or code that has acquire/release semantics, e.g. locking: \cpp
	///
	/// void do_work()
	/// {
	///		acquire_magic_lock();
	///		muu::scope_guard sg{ release_magic_lock };
	///		something_that_throws();
	/// }
	///
	/// \ecpp
	///
	/// For comparison's sake, here's the same function without a scope_guard: \cpp
	///
	/// void do_work()
	/// {
	///		acquire_magic_lock();
	///		try
	///		{
	///			something_that_throws();
	///		}
	///		catch (...)
	///		{
	///			release_magic_lock();
	///			throw;
	///		}
	///		release_magic_lock();
	/// }
	///
	/// \ecpp
	///
	/// \tparam	T	A `noexcept` function, lambda or other callable not requiring
	/// 			any arguments (e.g. `void() noexcept`)`.
	///
	/// \see
	/// 	- scope_fail
	/// 	- scope_success
	template <typename T>
	class scope_guard //
		MUU_HIDDEN_BASE(public impl::scope_guard_<T, impl::scope_guard_mode::invoke_always>)
	{
		using base = impl::scope_guard_<T, impl::scope_guard_mode::invoke_always>;

	  public:
		/// \brief	Constructs a scope_guard by wrapping a callable.
		///
		/// \tparam	U	 	A function, lambda or other callable with the signature `void() noexcept`.
		///
		/// \param 	func	The callable to invoke when the scope_guard goes out of scope.
		template <typename U>
		MUU_NODISCARD_CTOR
		explicit scope_guard(U&& func) noexcept(std::is_nothrow_constructible_v<base, U&&>)
			: base{ static_cast<U&&>(func) }
		{}

#ifdef DOXYGEN
		/// \brief	Dismisses the scope guard, cancelling invocation of the wrapped callable.
		void dismiss() noexcept;
#endif
	};

	/// \cond

	template <typename R, typename... P>
	scope_guard(R(P...) noexcept) -> scope_guard<R (*)(P...) noexcept>;

	template <typename R, typename... P>
	scope_guard(R(P...)) -> scope_guard<R (*)(P...)>;

	template <typename T>
	scope_guard(T&&) -> scope_guard<T>;

	template <typename T>
	scope_guard(T&) -> scope_guard<T&>;

	/// \endcond

	/// \brief	Performs actions when going out of scope due to an exception being thrown.
	/// \ingroup core
	///
	/// \details Use a scope_fail to simplify cleanup routines
	/// 		or code that has acquire/release semantics: \cpp
	///
	/// void* get_initialized_buffer()
	/// {
	///		void* buffer = acquire(1024);
	///		muu::scope_fail err{ [=]() noexcept { release(buffer); }};
	///		//
	///		// ...a bunch of initialization code that might throw...
	///		//
	///		return buffer;
	/// }
	///
	/// \ecpp
	///
	/// For comparison's sake, here's the same function without a scope_fail: \cpp
	///
	/// void* get_initialized_buffer()
	/// {
	///		void* buffer = acquire(1024);
	///		try
	///		{
	///			//
	///			// ...a bunch of initialization code that might throw...
	///			//
	///		}
	///		catch (...)
	///		{
	///			release(buffer);
	///			throw;
	///		}
	///		return buffer;
	/// }
	///
	/// \ecpp
	///
	/// \tparam	T	A `noexcept` function, lambda or other callable not requiring
	/// 			any arguments (e.g. `void() noexcept`)`.
	///
	/// \see
	/// 	- scope_guard
	/// 	- scope_success
	template <typename T>
	class scope_fail //
		MUU_HIDDEN_BASE(public impl::scope_guard_<T, impl::scope_guard_mode::invoke_on_fail>)
	{
		using base = impl::scope_guard_<T, impl::scope_guard_mode::invoke_on_fail>;

	  public:
		/// \brief	Constructs a scope_fail by wrapping a callable.
		///
		/// \tparam	U	 	A function, lambda or other callable with the signature `void() noexcept`.
		///
		/// \param 	func	The callable to invoke when the scope guard goes out of scope.
		template <typename U>
		MUU_NODISCARD_CTOR
		explicit scope_fail(U&& func) noexcept(std::is_nothrow_constructible_v<base, U&&>)
			: base{ static_cast<U&&>(func) }
		{}

#ifdef DOXYGEN
		/// \brief	Dismisses the scope guard, cancelling invocation of the wrapped callable.
		void dismiss() noexcept;
#endif
	};

	/// \cond

	template <typename R, typename... P>
	scope_fail(R(P...) noexcept) -> scope_fail<R (*)(P...) noexcept>;

	template <typename R, typename... P>
	scope_fail(R(P...)) -> scope_fail<R (*)(P...)>;

	template <typename T>
	scope_fail(T&&) -> scope_fail<T>;

	template <typename T>
	scope_fail(T&) -> scope_fail<T&>;

	/// \endcond

	/// \brief	Performs actions when going out of scope only if no exceptions have been thrown.
	/// \ingroup core
	///
	/// \tparam	T	A `noexcept` function, lambda or other callable not requiring
	/// 			any arguments (e.g. `void() noexcept`)`.
	///
	/// \see
	/// 	- scope_guard
	/// 	- scope_fail
	template <typename T>
	class scope_success //
		MUU_HIDDEN_BASE(public impl::scope_guard_<T, impl::scope_guard_mode::invoke_on_success>)
	{
		using base = impl::scope_guard_<T, impl::scope_guard_mode::invoke_on_success>;

	  public:
		/// \brief	Constructs a scope_success by wrapping a callable.
		///
		/// \tparam	U	 	A function, lambda or other callable with the signature `void() noexcept`.
		///
		/// \param 	func	The callable to invoke when the scope guard goes out of scope.
		template <typename U>
		MUU_NODISCARD_CTOR
		explicit scope_success(U&& func) noexcept(std::is_nothrow_constructible_v<base, U&&>)
			: base{ static_cast<U&&>(func) }
		{}

#ifdef DOXYGEN
		/// \brief	Dismisses the scope guard, cancelling invocation of the wrapped callable.
		void dismiss() noexcept;
#endif
	};

	/// \cond

	template <typename R, typename... P>
	scope_success(R(P...) noexcept) -> scope_success<R (*)(P...) noexcept>;

	template <typename R, typename... P>
	scope_success(R(P...)) -> scope_success<R (*)(P...)>;

	template <typename T>
	scope_success(T&&) -> scope_success<T>;

	template <typename T>
	scope_success(T&) -> scope_success<T&>;

	/// \endcond

	MUU_ABI_VERSION_END;
}

#include "impl/header_end.h"
