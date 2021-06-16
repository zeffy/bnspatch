// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

/// \file
/// \brief  Contains the definition of muu::tagged_ptr.

#pragma once
#include "core.h"

MUU_DISABLE_WARNINGS;
#include <cstring> //memcpy
MUU_ENABLE_WARNINGS;

#include "impl/header_start.h"
MUU_DISABLE_SUGGEST_WARNINGS;
MUU_FORCE_NDEBUG_OPTIMIZATIONS;

/// \cond
namespace muu::impl
{
	MUU_ABI_VERSION_START(0);

	inline constexpr size_t tptr_addr_highest_used_bit = MUU_ARCH_AMD64 ? 47 : build::bitness - 1;
	inline constexpr size_t tptr_addr_used_bits		   = tptr_addr_highest_used_bit + 1;
	inline constexpr size_t tptr_addr_free_bits		   = build::bitness - tptr_addr_used_bits;

	template <size_t MinAlign>
	struct tptr final
	{
		static constexpr size_t tag_bits	= (max(bit_width(MinAlign), 1_sz) - 1_sz) + impl::tptr_addr_free_bits;
		static constexpr uintptr_t tag_mask = bit_fill_right<uintptr_t>(tag_bits);
		static constexpr uintptr_t ptr_mask = ~tag_mask;

		using tag_type = unsigned_integer<muu::clamp(bit_ceil(tag_bits), 8_sz, build::bitness)>;
		static_assert(sizeof(tag_type) <= sizeof(uintptr_t));

		MUU_NODISCARD
		MUU_ATTR_NDEBUG(const)
		static constexpr uintptr_t pack_ptr(void* ptr) noexcept
		{
			MUU_CONSTEXPR_SAFE_ASSERT((!ptr || bit_floor(reinterpret_cast<uintptr_t>(ptr)) >= MinAlign)
									  && "The pointer's address is more strictly aligned than MinAlign");

			if constexpr (tptr_addr_free_bits > 0)
				return (reinterpret_cast<uintptr_t>(ptr) << tptr_addr_free_bits);
			else
				return reinterpret_cast<uintptr_t>(ptr);
		}

		template <typename T>
		MUU_NODISCARD
		MUU_ATTR_NDEBUG(pure)
		static constexpr uintptr_t pack_both(void* ptr, const T& tag) noexcept
		{
			static_assert(std::is_trivially_copyable_v<T>, "The tag type must be trivially copyable");

			if constexpr (is_enum<T>)
				return pack_both(ptr, unwrap(tag));
			else
			{
				MUU_CONSTEXPR_SAFE_ASSERT((!ptr || bit_floor(reinterpret_cast<uintptr_t>(ptr)) >= MinAlign)
										  && "The pointer's address is more strictly aligned than MinAlign");

				if constexpr (is_unsigned<T>)
				{
					if constexpr ((sizeof(T) * build::bits_per_byte) > tag_bits)
						return pack_ptr(ptr) | (static_cast<uintptr_t>(tag) & tag_mask);
					else
						return pack_ptr(ptr) | static_cast<uintptr_t>(tag);
				}
				else // some pod type
				{
					static_assert((sizeof(T) * build::bits_per_byte) <= tag_bits,
								  "The tag type must fit in the available tag bits");
					auto bits = pack_ptr(ptr);
					std::memcpy(&bits, &tag, sizeof(T));
					return bits;
				}
			}
		}

		MUU_NODISCARD
		MUU_ATTR_NDEBUG(const)
		static constexpr uintptr_t set_ptr(uintptr_t bits, void* ptr) noexcept
		{
			return pack_ptr(ptr) | (bits & tag_mask);
		}

		MUU_CONSTRAINED_TEMPLATE(is_unsigned<T>, typename T)
		MUU_NODISCARD
		MUU_ATTR(const)
		static constexpr uintptr_t set_tag(uintptr_t bits, T tag) noexcept
		{
			if constexpr (is_enum<T>)
				return set_tag(bits, unwrap(tag));
			else if constexpr ((sizeof(T) * build::bits_per_byte) > tag_bits)
				return (bits & ptr_mask) | (static_cast<uintptr_t>(tag) & tag_mask);
			else
				return (bits & ptr_mask) | static_cast<uintptr_t>(tag);
		}

		MUU_CONSTRAINED_TEMPLATE_2(!is_unsigned<T>, typename T)
		MUU_NODISCARD
		MUU_ATTR(pure)
		static uintptr_t set_tag(uintptr_t bits, const T& tag) noexcept
		{
			static_assert(std::is_trivially_copyable_v<T>, "The tag type must be trivially copyable");
			static_assert((sizeof(T) * build::bits_per_byte) <= tag_bits,
						  "The tag type must fit in the available tag bits");
			if constexpr ((sizeof(T) * build::bits_per_byte) < tag_bits)
				bits &= ptr_mask;
			std::memcpy(&bits, &tag, sizeof(T));
			return bits;
		}

		MUU_NODISCARD
		MUU_ATTR(const)
		static constexpr uintptr_t get_tag(uintptr_t bits) noexcept
		{
			return bits & tag_mask;
		}

		MUU_NODISCARD
		MUU_ATTR_NDEBUG(const)
		static constexpr bool get_tag_bit(uintptr_t bits, size_t index) noexcept
		{
			MUU_CONSTEXPR_SAFE_ASSERT(index < tag_bits && "Tag bit index out-of-bounds");
			return bits & (uintptr_t{ 1 } << index);
		}

		MUU_NODISCARD
		MUU_ATTR_NDEBUG(const)
		static constexpr uintptr_t set_tag_bit(uintptr_t bits, size_t index, bool state) noexcept
		{
			MUU_CONSTEXPR_SAFE_ASSERT(index < tag_bits && "Tag bit index out-of-bounds");
			if (state)
				return bits | (uintptr_t{ 1 } << index);
			else
				return bits & (~(uintptr_t{ 1 } << index));
		}

		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(const)
		static constexpr T get_tag_as(uintptr_t bits) noexcept
		{
			static_assert(std::is_trivially_copyable_v<T>, "The tag type must be trivially copyable");
			static_assert((sizeof(T) * build::bits_per_byte) <= tag_bits,
						  "The tag type must fit in the available tag bits");

			using intermediate_type = unsigned_integer<(muu::bit_ceil(sizeof(T) * build::bits_per_byte))>;
			static_assert(sizeof(intermediate_type) >= sizeof(T));
			static_assert(sizeof(intermediate_type) <= sizeof(tag_type));

			if constexpr (sizeof(T) == sizeof(intermediate_type))
				return muu::bit_cast<T>(static_cast<intermediate_type>(get_tag(bits)));
			else
			{
				uint8_t bytes[sizeof(T)];
				auto intermediate_bits = static_cast<intermediate_type>(get_tag(bits));
				for (size_t i = 0; i < sizeof(T); i++)
				{
					bytes[i] = static_cast<uint8_t>(intermediate_bits & bit_fill_right<intermediate_type>(8));
					intermediate_bits >>= 8;
				}
				return muu::bit_cast<T>(bytes);
			}
		}

		MUU_NODISCARD
		MUU_ATTR(const)
		static constexpr uintptr_t get_ptr(uintptr_t bits) noexcept
		{
			bits &= ptr_mask;
			if constexpr (tptr_addr_free_bits > 0)
			{
				bits >>= tptr_addr_free_bits;

#if MUU_ARCH_AMD64
				{
					constexpr uintptr_t canon_test = uintptr_t{ 1u } << tptr_addr_highest_used_bit;
					if (bits & canon_test)
					{
						constexpr uintptr_t canon_mask = bit_fill_right<uintptr_t>(tptr_addr_free_bits)
													  << tptr_addr_used_bits;
						bits |= canon_mask;
					}
				}
#endif
			}
			return bits;
		}
	};

	struct MUU_TRIVIAL_ABI tagged_ptr_storage
	{
		uintptr_t bits_;

		constexpr tagged_ptr_storage(uintptr_t bits) noexcept : bits_{ bits }
		{}
	};

	template <typename T, size_t MinAlign, bool = std::is_function_v<T>>
	struct MUU_TRIVIAL_ABI tagged_ptr_to_function : protected tagged_ptr_storage
	{
	  protected:
		using base = tagged_ptr_storage;
		using base::bits_;
		using base::base;

	  public:
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr T* ptr() const noexcept
		{
			using tptr = impl::tptr<MinAlign>;

			return reinterpret_cast<T*>(tptr::get_ptr(bits_));
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr T* get() const noexcept
		{
			return ptr();
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		explicit constexpr operator T*() const noexcept
		{
			return ptr();
		}

		template <typename... U>
		constexpr decltype(auto) operator()(U&&... args) const noexcept(std::is_nothrow_invocable_v<T, U&&...>)
		{
			static_assert(std::is_invocable_v<T, U&&...>);

			return ptr()(static_cast<U&&>(args)...);
		}
	};

	template <typename T, size_t MinAlign>
	struct MUU_TRIVIAL_ABI tagged_ptr_to_function<T, MinAlign, false> : protected tagged_ptr_storage
	{
	  protected:
		using base = tagged_ptr_storage;
		using base::bits_;
		using base::base;

	  public:
		MUU_NODISCARD
		MUU_ATTR(pure)
		MUU_ATTR(assume_aligned(MinAlign))
		constexpr T* ptr() const noexcept
		{
			using tptr = impl::tptr<MinAlign>;

			return muu::assume_aligned<MinAlign>(reinterpret_cast<T*>(tptr::get_ptr(bits_)));
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		MUU_ATTR(assume_aligned(MinAlign))
		constexpr T* get() const noexcept
		{
			return ptr();
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		MUU_ATTR(assume_aligned(MinAlign))
		explicit constexpr operator T*() const noexcept
		{
			return ptr();
		}
	};

	template <typename T, size_t MinAlign, bool = (!std::is_function_v<T> && !std::is_void_v<T>)>
	struct MUU_TRIVIAL_ABI tagged_ptr_to_object : public tagged_ptr_to_function<T, MinAlign>
	{
	  protected:
		using base = tagged_ptr_to_function<T, MinAlign>;
		using base::bits_;

		constexpr tagged_ptr_to_object(uintptr_t bits = {}) noexcept : base{ bits }
		{}

	  public:
		using base::ptr;

		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr T& operator*() const noexcept
		{
			return *ptr();
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr T* operator->() const noexcept
		{
			return ptr();
		}
	};

	template <typename T, size_t MinAlign>
	struct MUU_TRIVIAL_ABI tagged_ptr_to_object<T, MinAlign, false> : public tagged_ptr_to_function<T, MinAlign>
	{
	  protected:
		using base = tagged_ptr_to_function<T, MinAlign>;
		using base::bits_;

		constexpr tagged_ptr_to_object(uintptr_t bits = {}) noexcept : base{ bits }
		{}

	  public:
		using base::ptr;
	};

	MUU_ABI_VERSION_END;

	struct tptr_nullptr_deduced_tag
	{};
}
/// \endcond

namespace muu
{
	MUU_ABI_VERSION_START(0);

	/// \brief	Specialized pointer capable of storing data in the unused bits of a pointer's value.
	/// \ingroup core
	///
	/// \tparam	T			The type being pointed to.
	/// \tparam	MinAlign	Minimum alignment of values stored in the tagged_ptr.
	/// 					Default is alignof(T), but you may override it if you know
	/// 					you will only be storing values with larger alignments.
	///
	/// \see [Tagged pointer](https://en.wikipedia.org/wiki/Tagged_pointer)
	template <typename T, size_t MinAlign = alignment_of<T>>
	class MUU_TRIVIAL_ABI tagged_ptr //
		MUU_HIDDEN_BASE(public impl::tagged_ptr_to_object<T, MinAlign>)
	{
		static_assert(!std::is_same_v<T, impl::tptr_nullptr_deduced_tag>,
					  "Tagged pointers cannot have their type deduced from a nullptr"
					  " (a nullptr is meaningless in this context)");
		static_assert(!std::is_reference_v<T>, "Tagged pointers cannot store references");
		static_assert(MinAlign > 0 && has_single_bit(MinAlign), "Minimum alignment must be a power of two");
		static_assert(std::is_function_v<T> // the default is not strictly the minimum for function pointers
						  || MinAlign >= alignment_of<T>,
					  "Minimum alignment cannot be smaller than the type's actual minimum alignment");
		static_assert(MinAlign > 1 || impl::tptr_addr_free_bits > 0,
					  "Types aligned on a single byte cannot be pointed to by a tagged pointer on the target platform");

	  private:
		using tptr = impl::tptr<MinAlign>;
		using base = impl::tagged_ptr_to_object<T, MinAlign>;
		using base::bits_;

	  public:
		/// \brief	The type being pointed to.
		using element_type = T;

		/// \brief	A pointer to element_type.
		using pointer = std::add_pointer_t<T>;

		/// \brief	A pointer to element_type (const-qualified).
		using const_pointer = std::add_pointer_t<add_const<T>>;

		/// \brief	An integer just large enough to store all the bits in the tag area.
		using tag_type = typename tptr::tag_type;

		/// \brief The minimum alignment of values stored in this pointer.
		static constexpr size_t minimum_alignment = MinAlign;

		/// \brief	The number of tag bits available.
		static constexpr size_t tag_bit_count = tptr::tag_bits;

		/// \brief	The largest integral value that can be stored in the available tag bits.
		static constexpr tag_type max_tag = bit_fill_right<tag_type>(tag_bit_count);

		/// \brief	Constructs a tagged pointer.
		/// \details Tag bits are initialized to zero.
		///
		/// \param	value	The inital address of the pointer's target.
		MUU_NODISCARD_CTOR
		explicit constexpr tagged_ptr(pointer value) noexcept //
			: base{ tptr::pack_ptr(pointer_cast<void*>(value)) }
		{}

		/// \brief	Constructs a tagged pointer.
		///
		/// \tparam	U			An unsigned integral type, or a trivially-copyable type small enough to fit.
		/// \param	value		The inital address of the pointer's target.
		/// \param	tag_value	The initial value of the pointer's tag bits.
		///
		/// \warning If the tag parameter is an integer larger than the available tag bits,
		/// 		 any overflow will be masked out and ignored.
		template <typename U>
		MUU_NODISCARD_CTOR
		constexpr tagged_ptr(pointer value, const U& tag_value) noexcept //
			: base{ tptr::pack_both(pointer_cast<void*>(value), tag_value) }
		{
			static_assert(is_unsigned<U> //
							  || (std::is_trivially_copyable_v<U> && sizeof(U) * build::bits_per_byte <= tag_bit_count),
						  "Tag types must be unsigned integrals or trivially-copyable"
						  " and small enough to fit in the available tag bits");
		}

		/// \brief	Constructs zero-initialized tagged pointer.
		MUU_NODISCARD_CTOR
		constexpr tagged_ptr(nullptr_t) noexcept
		{}

		/// \brief	Constructs zero-initialized tagged pointer.
		MUU_NODISCARD_CTOR
		tagged_ptr() noexcept = default;

		/// \brief	Copy constructor.
		MUU_NODISCARD_CTOR
		tagged_ptr(const tagged_ptr&) noexcept = default;

		/// \brief	Copy-assignment operator.
		tagged_ptr& operator=(const tagged_ptr&) noexcept = default;

		/// \brief	Destructor.
		~tagged_ptr() noexcept = default;

		/// \brief	Sets the target pointer value and all tag bits to zero.
		///
		/// \returns	A reference to the tagged_ptr.
		constexpr tagged_ptr& reset() noexcept
		{
			bits_ = {};
			return *this;
		}

		/// \brief	Resets the target pointer value and sets the tag bits to zero.
		///
		/// \param	value	The new target pointer value.
		///
		/// \returns	A reference to the tagged_ptr.
		constexpr tagged_ptr& reset(pointer value) noexcept
		{
			bits_ = tptr::pack_ptr(pointer_cast<void*>(value));
			return *this;
		}

		/// \brief	Resets the target pointer value and tag.
		///
		/// \tparam	U			An unsigned integral type, or a trivially-copyable type small enough to fit.
		/// \param	value		The new target pointer value.
		/// \param	tag_value	The new tag.
		///
		/// \warning If the tag parameter is an integer larger than the available tag bits,
		/// 		 any overflow will be masked out and ignored.
		///
		/// \returns	A reference to the tagged_ptr.
		template <typename U>
		constexpr tagged_ptr& reset(pointer value, const U& tag_value) noexcept
		{
			static_assert(is_unsigned<U> //
							  || (std::is_trivially_copyable_v<U> && sizeof(U) * build::bits_per_byte <= tag_bit_count),
						  "Tag types must be unsigned integrals or trivially-copyable"
						  " and small enough to fit in the available tag bits");

			bits_ = tptr::pack_both(pointer_cast<void*>(value), tag_value);
			return *this;
		}

#ifndef DOXYGEN

		using base::ptr; // prevent the setter from hiding the getter in the base

#else

		/// \brief	Returns the target pointer value.
		MUU_NODISCARD
		constexpr pointer ptr() const noexcept;

		/// \brief	Returns the target pointer value.
		///
		/// \remarks This is an alias for ptr(); it exists to keep the interface consistent with std::unique_ptr.
		MUU_NODISCARD
		constexpr pointer get() const noexcept;

		/// \brief	Returns the target pointer value.
		MUU_NODISCARD
		explicit constexpr operator pointer() const noexcept;

		/// \brief	Invokes the function call operator on the pointed function.
		///
		/// \tparam U		Argument types.
		/// \param	args	The arguments to pass to the pointed function.
		///
		/// \returns	The return value of the function call.
		///
		/// \availability This operator is only available when the pointed type is a function.
		template <typename... U>
		constexpr decltype(auto) operator()(U&&... args) const
			noexcept(std::is_nothrow_invocable_v<element_type, U&&...>);

		/// \brief	Returns a reference to the pointed object.
		///
		/// \availability This operator is not available for pointers to `void` or functions.
		MUU_NODISCARD
		constexpr element_type& operator*() const noexcept;

		/// \brief	Returns the target pointer value.
		///
		/// \availability This operator is not available for pointers to `void` or functions.
		MUU_NODISCARD
		constexpr pointer operator->() const noexcept;

#endif // DOXYGEN

		/// \brief	Sets the target pointer value, leaving the tag bits unchanged.
		///
		/// \param 	value	The new target pointer value.
		///
		/// \returns	A reference to a tagged_ptr.
		constexpr tagged_ptr& ptr(pointer value) noexcept
		{
			bits_ = tptr::set_ptr(bits_, pointer_cast<void*>(value));
			return *this;
		}

		/// \brief	Sets the target pointer value, leaving the tag bits unchanged.
		///
		/// \param	rhs	The new target pointer value.
		///
		/// \returns	A reference to the tagged_ptr.
		constexpr tagged_ptr& operator=(pointer rhs) noexcept
		{
			return ptr(rhs);
		}

		/// \brief	Sets the target pointer value to nullptr, leaving the tag bits unchanged.
		///
		/// \returns	A reference to the tagged_ptr.
		constexpr tagged_ptr& clear_ptr() noexcept
		{
			bits_ &= tptr::tag_mask;
			return *this;
		}

		/// \brief	Returns the tag bits as an unsigned integer or trivially-copyable type.
		template <typename U = tag_type>
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr U tag() const noexcept
		{
			static_assert(!std::is_reference_v<U>, "Reference types are not allowed");
			static_assert(std::is_trivially_copyable_v<U>, "Tag types must be trivially-copyable");

			if constexpr (is_unsigned<U>)
			{
				static_assert(
					sizeof(U) >= sizeof(tag_type),
					"The destination integer type is not large enough to store the tag without a loss of data");
				return static_cast<U>(tptr::get_tag(bits_));
			}
			else
			{
				static_assert((sizeof(U) * build::bits_per_byte) <= tag_bit_count,
							  "Tag types must fit in the available tag bits");

				return tptr::template get_tag_as<U>(bits_);
			}
		}

		/// \brief	Sets the tag bits, leaving the target pointer value unchanged.
		///
		/// \tparam	U			An unsigned integral type, or a trivially-copyable type small enough to fit.
		/// \param	tag_value	The new value to set for the pointer's tag bits.
		///
		/// \warning If the tag parameter is an integer larger than the available tag bits,
		/// 		 any overflow will be masked out and ignored.
		///
		/// \returns	A reference to the tagged_ptr.
		template <typename U>
		constexpr tagged_ptr& tag(const U& tag_value) noexcept
		{
			static_assert(is_unsigned<U> //
							  || (std::is_trivially_copyable_v<U> && sizeof(U) * build::bits_per_byte <= tag_bit_count),
						  "Tag types must be unsigned integrals or trivially-copyable"
						  " and small enough to fit in the available tag bits");

			bits_ = tptr::set_tag(bits_, tag_value);
			return *this;
		}

		/// \brief	Returns the value of one of the tag bits.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool tag_bit(size_t tag_bit_index) const noexcept
		{
			return tptr::get_tag_bit(bits_, tag_bit_index);
		}

		/// \brief	Sets the value of one of the tag bits.
		///
		/// \param	tag_bit_index	Zero-based index of the tag bit.
		/// \param	val		   		The bit state to set.
		///
		/// \returns	A reference to the tagged_ptr.
		///
		/// \warning Using the pointer's tag to store a small POD type is generally incompatible with setting
		/// 		 individual tag bits, as one is likely to render the other meaningless. Mix methodologies with
		/// 		 caution!
		constexpr tagged_ptr& tag_bit(size_t tag_bit_index, bool val) noexcept
		{
			bits_ = tptr::set_tag_bit(bits_, tag_bit_index, val);
			return *this;
		}

		/// \brief	Sets the tag bits to zero, leaving the target pointer value unchanged.
		///
		/// \returns	A reference to the tagged_ptr.
		constexpr tagged_ptr& clear_tag() noexcept
		{
			bits_ &= tptr::ptr_mask;
			return *this;
		}

		/// \brief	Returns true if the target pointer value is not nullptr.
		MUU_NODISCARD
		MUU_ATTR(pure)
		explicit constexpr operator bool() const noexcept
		{
			return bits_ & tptr::ptr_mask;
		}

		/// \brief	Returns true if a tagged_ptr and raw pointer refer to the same address.
		MUU_NODISCARD
		MUU_ATTR(const)
		friend constexpr bool operator==(tagged_ptr lhs, const_pointer rhs) noexcept
		{
			return lhs.ptr() == rhs;
		}

		/// \brief	Returns true if a tagged_ptr and raw pointer do not refer to the same address.
		MUU_NODISCARD
		MUU_ATTR(const)
		friend constexpr bool operator!=(tagged_ptr lhs, const_pointer rhs) noexcept
		{
			return lhs.ptr() != rhs;
		}

		/// \brief	Returns true if a tagged_ptr and raw pointer refer to the same address.
		MUU_NODISCARD
		MUU_ATTR(const)
		friend constexpr bool operator==(const_pointer lhs, tagged_ptr rhs) noexcept
		{
			return lhs == rhs.ptr();
		}

		/// \brief	Returns true if a tagged_ptr and raw pointer do not refer to the same address.
		MUU_NODISCARD
		MUU_ATTR(const)
		friend constexpr bool operator!=(const_pointer lhs, tagged_ptr rhs) noexcept
		{
			return lhs != rhs.ptr();
		}

		/// \brief	Returns true if two tagged_ptrs are equal (including their tag bits).
		MUU_NODISCARD
		MUU_ATTR(const)
		friend constexpr bool operator==(tagged_ptr lhs, tagged_ptr rhs) noexcept
		{
			return lhs.bits_ == rhs.bits_;
		}

		/// \brief	Returns true if two tagged_ptrs are not equal (including their tag bits).
		MUU_NODISCARD
		MUU_ATTR(const)
		friend constexpr bool operator!=(tagged_ptr lhs, tagged_ptr rhs) noexcept
		{
			return lhs.bits_ != rhs.bits_;
		}
	};

	/// \cond

	tagged_ptr(nullptr_t)->tagged_ptr<impl::tptr_nullptr_deduced_tag, 1_sz>;
	template <typename T>
	tagged_ptr(nullptr_t, T) -> tagged_ptr<impl::tptr_nullptr_deduced_tag, 1_sz>;
	template <typename T, typename U>
	tagged_ptr(T*, U) -> tagged_ptr<T>;
	template <typename T>
	tagged_ptr(T*) -> tagged_ptr<T>;

	/// \endcond

	MUU_ABI_VERSION_END;

	namespace impl
	{
		template <typename T>
		struct tagged_pointer_traits_base
		{};

		template <typename T, bool IsVoid>
		struct tagged_pointer_traits
		{};

		template <template <typename, size_t> typename TaggedPointer, typename T, size_t MinAlign>
		struct tagged_pointer_traits_base<TaggedPointer<T, MinAlign>>
		{
			using pointer		  = TaggedPointer<T, MinAlign>;
			using element_type	  = T;
			using difference_type = ptrdiff_t;
			template <typename U>
			using rebind = TaggedPointer<U, MinAlign>;

			MUU_NODISCARD
			MUU_ATTR(pure)
			constexpr static element_type* to_address(const pointer& p) noexcept
			{
				return p.ptr();
			}
		};

		template <template <typename, size_t> typename TaggedPointer, typename T, size_t MinAlign>
		struct tagged_pointer_traits<TaggedPointer<T, MinAlign>, true>
			: tagged_pointer_traits_base<TaggedPointer<T, MinAlign>>
		{};

		template <template <typename, size_t> typename TaggedPointer, typename T, size_t MinAlign>
		struct tagged_pointer_traits<TaggedPointer<T, MinAlign>, false>
			: tagged_pointer_traits_base<TaggedPointer<T, MinAlign>>
		{
			using pointer	   = TaggedPointer<T, MinAlign>;
			using element_type = T;

			MUU_NODISCARD
			constexpr static pointer pointer_to(element_type& r) noexcept
			{
				return pointer{ &r };
			}
		};
	}
}

namespace std
{
	template <typename T, size_t MinAlign>
	struct pointer_traits<muu::tagged_ptr<T, MinAlign>>
		: muu::impl::tagged_pointer_traits<muu::tagged_ptr<T, MinAlign>, std::is_void_v<T>>
	{};
}

MUU_RESET_NDEBUG_OPTIMIZATIONS;
#include "impl/header_end.h"
