// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

/// \file
/// \brief  Contains the definition of muu::span.

#pragma once
#include "core.h"
#include "compressed_pair.h"

MUU_DISABLE_WARNINGS;
#include <iterator>
MUU_ENABLE_WARNINGS;

#include "impl/header_start.h"

#ifdef DOXYGEN
	#define MUU_IDENTITY(...) __VA_ARGS__
#else
	#define MUU_IDENTITY(...) muu::type_identity<__VA_ARGS__>
#endif

namespace muu
{
#ifdef DOXYGEN

	/// \brief Indicates the number of elements covered by a span should be dynamically-determined at runtime.
	///
	/// \ingroup	mem
	inline constexpr size_t dynamic_extent = static_cast<size_t>(-1);
	//(here just for doxygen; actually defined in fwd.h)

#endif // DOXYGEN

	/// \cond
	namespace impl
	{
		struct span_empty_size
		{
			constexpr span_empty_size() noexcept = default;
			constexpr span_empty_size(size_t) noexcept
			{}
		};

		template <typename From, typename To>
		struct is_qualifier_compatible
		{
			static constexpr bool value = true;
		};
		template <typename From, typename To>
		struct is_qualifier_compatible<From, const To>
		{
			static constexpr bool value = true;
		};
		template <typename From, typename To>
		struct is_qualifier_compatible<From, volatile To>
		{
			static constexpr bool value = true;
		};
		template <typename From, typename To>
		struct is_qualifier_compatible<From, const volatile To>
		{
			static constexpr bool value = true;
		};
		template <typename From, typename To>
		struct is_qualifier_compatible<const From, const To>
		{
			static constexpr bool value = true;
		};
		template <typename From, typename To>
		struct is_qualifier_compatible<const From, volatile To>
		{
			static constexpr bool value = false;
		};
		template <typename From, typename To>
		struct is_qualifier_compatible<const From, const volatile To>
		{
			static constexpr bool value = true;
		};
		template <typename From, typename To>
		struct is_qualifier_compatible<volatile From, const To>
		{
			static constexpr bool value = false;
		};
		template <typename From, typename To>
		struct is_qualifier_compatible<volatile From, volatile To>
		{
			static constexpr bool value = true;
		};
		template <typename From, typename To>
		struct is_qualifier_compatible<volatile From, const volatile To>
		{
			static constexpr bool value = true;
		};
		template <typename From, typename To>
		struct is_qualifier_compatible<const volatile From, const To>
		{
			static constexpr bool value = false;
		};
		template <typename From, typename To>
		struct is_qualifier_compatible<const volatile From, volatile To>
		{
			static constexpr bool value = false;
		};
		template <typename From, typename To>
		struct is_qualifier_compatible<const volatile From, const volatile To>
		{
			static constexpr bool value = true;
		};

		template <typename From, typename To>
		inline constexpr bool is_qualifier_conversion_only = std::is_same_v<remove_cvref<From>, remove_cvref<To>>&&
			is_qualifier_compatible<std::remove_reference_t<From>, std::remove_reference_t<To>>::value;

		template <typename T, size_t Extent>
		inline constexpr size_t as_bytes_extent = Extent == dynamic_extent ? dynamic_extent : (sizeof(T) * Extent);
	}
	/// \endcond

	MUU_ABI_VERSION_START(0);

	/// \brief	A non-owning view of contiguous elements.
	/// \ingroup	core mem
	///
	/// \remarks This is equivalent to C++20's std::span.
	///
	/// \tparam	T	  	The span's element type.
	/// \tparam	Extent	The number of elements represented by the span.
	/// 				Use muu::dynamic_extent for dynamically-sized spans.
	template <typename T,
			  size_t Extent
#ifdef DOXYGEN
			  = dynamic_extent
#endif
			  >
	class span
	{
		static_assert(!std::is_reference_v<T>, "Spans cannot store references");

	  public:
		/// \brief The span's element type.
		using element_type = T;

		/// \brief The span's base value type.
		using value_type = std::remove_cv_t<T>;

		/// \brief std::size_t
		using size_type = size_t;

		/// \brief std::ptrdiff_t
		using difference_type = ptrdiff_t;

		/// \brief A pointer to the span's element type.
		using pointer = std::add_pointer_t<T>;

		/// \brief A const pointer to the span's element type.
		using const_pointer = std::add_pointer_t<std::add_const_t<T>>;

		/// \brief A reference to the span's element type.
		using reference = std::add_lvalue_reference_t<T>;

		/// \brief A const reference to the span's element type.
		using const_reference = std::add_lvalue_reference_t<std::add_const_t<T>>;

		/// \brief A LegacyRandomAccessIterator for the elements in the span.
		using iterator = pointer;

		/// \brief std::reverse_iterator<iterator>
		using reverse_iterator = std::reverse_iterator<iterator>;

		/// \brief The number of elements in the span, or muu::dynamic_extent.
		static constexpr size_t extent = Extent;

	  private:
		using pair_size_type = std::conditional_t<Extent == dynamic_extent, size_t, impl::span_empty_size>;
		compressed_pair<pointer, pair_size_type> ptr_and_size{};

	  public:
#if defined(DOXYGEN) || MUU_CONCEPTS

		/// \brief Default constructor.
		/// \availability This constructor is not available for statically-sized spans.
		MUU_NODISCARD_CTOR
		constexpr span() noexcept MUU_REQUIRES(Extent == 0 || Extent == dynamic_extent) = default;

#else

		MUU_LEGACY_REQUIRES((Extent_ == 0 || Extent_ == dynamic_extent), size_t Extent_ = Extent)
		MUU_NODISCARD_CTOR
		constexpr span() noexcept
		{}

#endif

		/// \brief Constructs a span from a contiguous iterator and an element count.
		/// \note This constructor is `explicit` when #extent != #dynamic_extent.
		MUU_CONSTRAINED_TEMPLATE((Extent_ != dynamic_extent														  //
								  && impl::is_qualifier_conversion_only<impl::iter_reference_t<It>, element_type> //
								  && MUU_STD_CONCEPT(std::contiguous_iterator<It>)),							  //
								 typename It MUU_HIDDEN_PARAM(size_t Extent_ = Extent)) // explicit variant
		MUU_NODISCARD_CTOR
		explicit constexpr span(It first, size_t count) noexcept //
			: ptr_and_size{ pointer_cast<pointer>(muu::to_address(first)), count }
		{
			MUU_CONSTEXPR_SAFE_ASSERT(count == Extent
									  && "count must be equal to span extent for statically-sized spans");
			if constexpr (Extent > 0)
				MUU_CONSTEXPR_SAFE_ASSERT((count == 0_sz || ptr_and_size.first() != nullptr)
										  && "a nullptr span is undefined behaviour");
		}

		/// \cond

		MUU_CONSTRAINED_TEMPLATE_2((Extent_ == dynamic_extent														//
									&& impl::is_qualifier_conversion_only<impl::iter_reference_t<It>, element_type> //
									&& MUU_STD_CONCEPT(std::contiguous_iterator<It>)),								//
								   typename It,
								   size_t Extent_ = Extent) // implicit variant
		MUU_NODISCARD_CTOR
		/* implicit */
		constexpr span(It first, size_t count) noexcept //
			: ptr_and_size{ pointer_cast<pointer>(muu::to_address(first)), count }
		{
			MUU_CONSTEXPR_SAFE_ASSERT((count == 0_sz || ptr_and_size.first() != nullptr)
									  && "a nullptr span is undefined behaviour");
		}

		/// \endcond

		/// \brief Constructs a span from a pair of contiguous iterators.
		/// \note This constructor is `explicit` when #extent != #dynamic_extent.
		MUU_CONSTRAINED_TEMPLATE((Extent_ != dynamic_extent														  //
								  && impl::is_qualifier_conversion_only<impl::iter_reference_t<It>, element_type> //
								  && !is_implicitly_convertible<End, size_t>									  //
								  && MUU_STD_CONCEPT(std::contiguous_iterator<It>)								  //
								  && MUU_STD_CONCEPT(std::sized_sentinel_for<End, It>)),
								 typename It,
								 typename End MUU_HIDDEN_PARAM(size_t Extent_ = Extent)) // explicit variant
		MUU_NODISCARD_CTOR
		explicit constexpr span(It first, End last) noexcept(noexcept(last - first))
			: ptr_and_size{ pointer_cast<pointer>(muu::to_address(first)), static_cast<size_t>(last - first) }
		{
			MUU_CONSTEXPR_SAFE_ASSERT(static_cast<size_t>(last - first) == size()
									  && "(last - first) must be equal to span extent for statically-sized spans");
			if constexpr (Extent > 0)
				MUU_CONSTEXPR_SAFE_ASSERT((ptr_and_size.second() == 0_sz || ptr_and_size.first() != nullptr)
										  && "a nullptr span is undefined behaviour");
		}

		/// \cond

		MUU_CONSTRAINED_TEMPLATE_2((Extent_ == dynamic_extent														//
									&& impl::is_qualifier_conversion_only<impl::iter_reference_t<It>, element_type> //
									&& !is_implicitly_convertible<End, size_t>										//
									&& MUU_STD_CONCEPT(std::contiguous_iterator<It>)								//
									&& MUU_STD_CONCEPT(std::sized_sentinel_for<End, It>)),
								   typename It,
								   typename End,
								   size_t Extent_ = Extent) // implicit variant
		MUU_NODISCARD_CTOR
		/* implicit */
		constexpr span(It first, End last) noexcept(noexcept(last - first))
			: ptr_and_size{ pointer_cast<pointer>(muu::to_address(first)), static_cast<size_t>(last - first) }
		{
			MUU_CONSTEXPR_SAFE_ASSERT((ptr_and_size.second() == 0_sz || ptr_and_size.first() != nullptr)
									  && "a nullptr span is undefined behaviour");
		}

		/// \endcond

		/// \brief Constructs a span from an array.
		MUU_CONSTRAINED_TEMPLATE((Extent == dynamic_extent || N == Extent), size_t N)
		MUU_NODISCARD_CTOR
		constexpr span(MUU_IDENTITY(element_type) (&arr)[N]) noexcept //
			: ptr_and_size{ arr, N }
		{}

		/// \brief Constructs a span from an array.
		MUU_CONSTRAINED_TEMPLATE((impl::is_qualifier_conversion_only<U, element_type> //
								  && (Extent == dynamic_extent || N == Extent)),	  //
								 typename U,
								 size_t N)
		MUU_NODISCARD_CTOR
		constexpr span(std::array<U, N>& arr) noexcept //
			: ptr_and_size{ pointer_cast<pointer>(arr.data()), N }
		{}

		/// \brief Constructs a span from an array.
		MUU_CONSTRAINED_TEMPLATE((impl::is_qualifier_conversion_only<std::add_const_t<U>, element_type> //
								  && (Extent == dynamic_extent || N == Extent)),						//
								 typename U,
								 size_t N)
		MUU_NODISCARD_CTOR
		constexpr span(const std::array<U, N>& arr) noexcept //
			: ptr_and_size{ pointer_cast<pointer>(arr.data()), N }
		{}

		/// \brief Constructs a span from another span.
		/// \note This constructor is `explicit` when #extent != #dynamic_extent && E == #dynamic_extent.
		MUU_CONSTRAINED_TEMPLATE((Extent_ != dynamic_extent												  //
								  && E == dynamic_extent												  //
								  && impl::is_qualifier_conversion_only<U, element_type>				  //
								  && (Extent_ == dynamic_extent || E == dynamic_extent || E == Extent_)), //
								 typename U,
								 size_t E MUU_HIDDEN_PARAM(size_t Extent_ = Extent)) // explicit variant
		MUU_NODISCARD_CTOR
		explicit constexpr span(const span<U, E>& s) noexcept
			: ptr_and_size{ pointer_cast<pointer>(s.data()), s.size() }
		{}

		/// \cond

		MUU_CONSTRAINED_TEMPLATE_2((!(Extent_ != dynamic_extent && E == dynamic_extent)						//
									&& impl::is_qualifier_conversion_only<U, element_type>					//
									&& (Extent_ == dynamic_extent || E == dynamic_extent || E == Extent_)), //
								   typename U,
								   size_t E,
								   size_t Extent_ = Extent) // implicit variant
		MUU_NODISCARD_CTOR
		/* implicit */
		constexpr span(const span<U, E>& s) noexcept //
			: ptr_and_size{ pointer_cast<pointer>(s.data()), s.size() }
		{}

		/// \endcond

		/// \brief Copy constructor.
		constexpr span(const span&) noexcept = default;

		/// \brief Copy-assignment operator.
		constexpr span& operator=(const span&) noexcept = default;

		/// \brief Returns the number of elements covered by the span.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr size_t size() const noexcept
		{
			if constexpr (Extent == dynamic_extent)
				return ptr_and_size.second();
			else
				return Extent;
		}

		/// \brief Returns the total size of the elements covered by the span in bytes.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr size_t size_bytes() const noexcept
		{
			if constexpr (Extent == dynamic_extent)
				return ptr_and_size.second() * sizeof(element_type);
			else
				return Extent * sizeof(element_type);
		}

		/// \brief Returns true if the span is empty (i.e. covers zero elements).
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool empty() const noexcept
		{
			return !size();
		}

		/// \brief Returns an iterator to the beginning of the span.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr iterator begin() const noexcept
		{
			return ptr_and_size.first();
		}

		/// \brief Returns an iterator to end of the span.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr iterator end() const noexcept
		{
			return ptr_and_size.first() + size();
		}

		/// \brief Returns a reverse iterator to the beginning of the span.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr reverse_iterator rbegin() const noexcept
		{
			return reverse_iterator{ end() };
		}

		/// \brief Returns a reverse iterator to the end of the span.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr reverse_iterator rend() const noexcept
		{
			return reverse_iterator{ begin() };
		}

		/// \brief Returns a reference to the first element in the span.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr reference front() const noexcept
		{
			return *ptr_and_size.first();
		}

		/// \brief Returns a reference to the last element in the span.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr reference back() const noexcept
		{
			return ptr_and_size.first()[size() - 1u];
		}

		/// \brief Returns a reference to an arbitrary element in the span.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr reference operator[](size_t idx) const noexcept
		{
			return ptr_and_size.first()[idx];
		}

		/// \brief Returns a pointer to the first element in the span.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr pointer data() const noexcept
		{
			return ptr_and_size.first();
		}

		/// \brief Returns a subspan representing the first N elements of this span.
		template <size_t Count>
		MUU_NODISCARD
		MUU_ATTR_NDEBUG(pure)
		constexpr span<element_type, Count> first() const noexcept
		{
			static_assert(Count <= Extent, "span::first() count cannot exceed the size of the source span");
			MUU_CONSTEXPR_SAFE_ASSERT(Count <= size());
			return span<element_type, Count>{ ptr_and_size.first(), Count };
		}

		/// \brief Returns a subspan representing the first N elements of this span.
		MUU_NODISCARD
		MUU_ATTR_NDEBUG(pure)
		constexpr span<element_type> first(size_t count) const noexcept
		{
			MUU_CONSTEXPR_SAFE_ASSERT(count <= size());
			return span<element_type>{ ptr_and_size.first(), count };
		}

		/// \brief Returns a subspan representing the last N elements of this span.
		template <size_t Count>
		MUU_NODISCARD
		MUU_ATTR_NDEBUG(pure)
		constexpr span<element_type, Count> last() const noexcept
		{
			static_assert(Count <= Extent, "span::last() count cannot exceed the size of the source span");
			MUU_CONSTEXPR_SAFE_ASSERT(Count <= size());
			return span<element_type, Count>{ ptr_and_size.first() + (size() - Count), Count };
		}

		/// \brief Returns a subspan representing the last N elements of this span.
		MUU_NODISCARD
		MUU_ATTR_NDEBUG(pure)
		constexpr span<element_type> last(size_t count) const noexcept
		{
			MUU_CONSTEXPR_SAFE_ASSERT(count <= size());
			return span<element_type>{ ptr_and_size.first() + (size() - count), count };
		}

		/// \brief Returns an arbitrary subspan.
		template <size_t Offset, size_t Count = dynamic_extent>
		MUU_NODISCARD
		MUU_ATTR_NDEBUG(pure)
		constexpr auto subspan() const noexcept
		{
			static_assert(Offset < Extent, "span::subspan() Offset cannot exceed the size of the source span");
			static_assert(Count == dynamic_extent || Count <= (Extent - Offset),
						  "span::subspan() Count cannot exceed the size of the source span");

			MUU_CONSTEXPR_SAFE_ASSERT(Offset < size());

			if constexpr (Count == dynamic_extent)
			{
				return span<element_type>{ ptr_and_size.first() + Offset, size() - Offset };
			}
			else
			{
				MUU_CONSTEXPR_SAFE_ASSERT(Count <= (size() - Offset));
				return span<element_type, Count>{ ptr_and_size.first() + Offset, Count };
			}
		}

		/// \brief Returns an arbitrary subspan.
		MUU_NODISCARD
		MUU_ATTR_NDEBUG(pure)
		constexpr span<element_type> subspan(size_t offset, size_t count = dynamic_extent) const noexcept
		{
			MUU_CONSTEXPR_SAFE_ASSERT(offset < size());

			if (count == dynamic_extent)
			{
				return span<element_type>{ ptr_and_size.first() + offset, size() - offset };
			}
			else
			{
				MUU_CONSTEXPR_SAFE_ASSERT(count <= (size() - offset));
				return span<element_type>{ ptr_and_size.first() + offset, count };
			}
		}
	};

	/// \cond

	template <typename T>
	span(T*, size_t) -> span<T>;
	template <typename T, size_t N>
	span(T (&)[N]) -> span<T, N>;
	template <typename T, size_t N>
	span(T(&&)[N]) -> span<T, N>;
	template <typename T, size_t N>
	span(std::array<T, N>&) -> span<T, N>;
	template <typename T, size_t N>
	span(const std::array<T, N>&) -> span<const T, N>;

#if MUU_CONCEPTS
	template <std::contiguous_iterator It, typename E>
	span(It, E) -> span<impl::iter_value_t<It>>;
#else
	template <typename It, typename E>
	span(It, E) -> span<impl::iter_value_t<It>>;
	template <typename It>
	span(It, It) -> span<impl::iter_value_t<It>>;
#endif

	/// \endcond

	MUU_ABI_VERSION_END;

	/// \brief	Convenience alias for `span<const T>`.
	/// \ingroup	mem
	template <typename T>
	using const_span = span<const T>;

	/// \brief	Convenience alias for `span<std::byte>`.
	/// \ingroup	mem
	using byte_span = span<std::byte>;

	/// \brief	Convenience alias for `span<const std::byte>`.
	/// \ingroup	mem
	using const_byte_span = span<const std::byte>;

	/// \brief	Reinterprets a span as an immutable view of the underlying bytes.
	/// \ingroup	mem
	/// \relatesalso	muu::span
	///
	/// \details Equivalent to C++20's std::as_bytes.
	template <typename T, size_t N>
	MUU_NODISCARD
	span<const std::byte, impl::as_bytes_extent<T, N>> as_bytes(span<T, N> s) noexcept
	{
		if constexpr (N == dynamic_extent)
		{
			return span<const std::byte>{ pointer_cast<const std::byte*>(s.data()), s.size_bytes() };
		}
		else
		{
			return span<const std::byte, sizeof(T) * N>{ pointer_cast<const std::byte*>(s.data()), sizeof(T) * N };
		}
	}

	/// \brief	Reinterprets a span as a view of the underlying bytes.
	/// \ingroup	mem
	/// \relatesalso	muu::span
	///
	/// \details Equivalent to C++20's std::as_writable_bytes.
	MUU_CONSTRAINED_TEMPLATE(!std::is_const_v<T>, typename T, size_t N)
	MUU_NODISCARD
	span<std::byte, impl::as_bytes_extent<T, N>> as_writable_bytes(span<T, N> s) noexcept
	{
		if constexpr (N == dynamic_extent)
		{
			return span<std::byte>{ pointer_cast<std::byte*>(s.data()), s.size_bytes() };
		}
		else
		{
			return span<std::byte, sizeof(T) * N>{ pointer_cast<std::byte*>(s.data()), sizeof(T) * N };
		}
	}
}

#undef MUU_IDENTITY

#include "impl/header_end.h"
