// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

/// \file
/// \brief Contains the definition of muu::generic_allocator.

#pragma once
#include "impl/core_utils.h"
#include "impl/header_start.h"

#if MUU_HAS_EXCEPTIONS
	#define MUU_GENERIC_ALLOCATOR_ATTRS                                                                                \
		MUU_NODISCARD                                                                                                  \
		MUU_UNALIASED_ALLOC MUU_ATTR(returns_nonnull)
#else
	#define MUU_GENERIC_ALLOCATOR_ATTRS MUU_NODISCARD
#endif

namespace muu
{
	/// \brief An interface for encapsulating generic allocators.
	/// \ingroup mem
	struct MUU_ABSTRACT_INTERFACE generic_allocator
	{
		/// \brief The default alignment used if alignment is unspecified when requesting allocations.
		static constexpr size_t default_alignment = __STDCPP_DEFAULT_NEW_ALIGNMENT__;

		/// \brief	Requests a memory allocation.
		///
		/// \param 	size	 	The size of the requested allocation.
		/// \param 	alignment	The required alignment. Must be a power of two.
		///
		/// \returns	\conditional_return{When exceptions are enabled} A pointer to the new allocation, or throws std::bad_alloc.
		/// 			<br>
		/// 			\conditional_return{When exceptions are disabled} A pointer to the new allocation, or `nullptr`.
		MUU_GENERIC_ALLOCATOR_ATTRS
		virtual void* allocate(size_t size, size_t alignment) = 0;

		/// \brief	Deallocates a memory allocation previously acquired by #allocate().
		///
		/// \param 	ptr	 		The pointer returned by #allocate().
		/// \param 	size	 	The size of the requested allocation passed to #allocate().
		/// \param 	alignment	The required alignment passed to #allocate().
		MUU_ATTR(nonnull)
		virtual void deallocate(void* ptr, size_t size, size_t alignment = default_alignment) noexcept = 0;

		virtual ~generic_allocator() noexcept = default;

		/// \brief	Requests a memory allocation.
		/// \remark Allocations returned by this overload will have an alignment of #default_alignment.
		///
		/// \param 	size	 	The size of the requested allocation.
		///
		/// \returns	\conditional_return{When exceptions are enabled} A pointer to the new allocation, or throws std::bad_alloc.
		/// 			<br>
		/// 			\conditional_return{When exceptions are disabled} A pointer to the new allocation, or `nullptr`.
		MUU_GENERIC_ALLOCATOR_ATTRS
		MUU_ATTR(assume_aligned(default_alignment))
		void* allocate(size_t size)
		{
			return this->allocate(size, default_alignment);
		}

		/// \brief	Requests a memory allocation.
		///
		/// \tparam 	Alignment	The required alignment. Must be a power of two.
		/// \param 		size	 	The size of the requested allocation.
		///
		/// \returns	\conditional_return{When exceptions are enabled} A pointer to the new allocation, or throws std::bad_alloc.
		/// 			<br>
		/// 			\conditional_return{When exceptions are disabled} A pointer to the new allocation, or `nullptr`.
		template <size_t Alignment>
		MUU_GENERIC_ALLOCATOR_ATTRS
		MUU_ATTR(assume_aligned(Alignment))
		void* allocate(size_t size)
		{
			static_assert(Alignment, "alignment cannot be zero");
			static_assert((Alignment & (Alignment - 1u)) == 0u, "alignment must be a power of two");

			return muu::assume_aligned<Alignment>(this->allocate(size, Alignment));
		}
	};

	namespace impl
	{
		MUU_API
		generic_allocator& get_default_allocator() noexcept;
	}
}

#undef MUU_GENERIC_ALLOCATOR_ATTRS
#include "impl/header_end.h"
