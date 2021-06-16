// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

/// \file
/// \brief Contains the definition of muu::blob.

#pragma once
#include "impl/core_utils.h"
#include "generic_allocator.h"
#include "impl/header_start.h"

namespace muu
{
	MUU_ABI_VERSION_START(0);

	/// \brief Interface for managing chunks of memory.
	/// \ingroup mem
	///
	/// \details A blob is an RAII wrapper around a memory allocation intended to be used anywhere
	/// 		 you might previously have used something like std::vector<std::byte> or std::unique_ptr<std::byte[]>.
	///
	class blob
	{
	  private:
		generic_allocator* allocator_;
		size_t alignment_, size_ = 0;
		void* data_ = nullptr;

	  public:
		/// \brief Creates an empty blob.
		///
		/// \param	allocator 	The #muu::generic_allocator used for allocations.
		///						Leave as `nullptr` to use the default global allocator.
		MUU_NODISCARD_CTOR
		MUU_API
		explicit blob(generic_allocator* allocator = nullptr) noexcept;

		/// \brief Creates a blob of a fixed size and alignment.
		///
		/// \param	size		The size of the blob's data, in bytes.
		/// \param	src	 		The source data to copy, if any.
		/// \param	align		The alignment of the blob's data.
		///						Leave as `0` to use `__STDCPP_DEFAULT_NEW_ALIGNMENT__`.
		/// \param	allocator 	The #muu::generic_allocator used for allocations.
		///						Leave as `nullptr` to use the default global allocator.
		MUU_NODISCARD_CTOR
		MUU_API
		explicit blob(size_t size,
					  const void* src			   = nullptr,
					  size_t align				   = {},
					  generic_allocator* allocator = nullptr);

		/// \brief Copy constructor.
		MUU_NODISCARD_CTOR
		MUU_API
		blob(const blob& other);

		/// \brief Copy constructor.
		///
		/// \param	other		The blob to copy.
		/// \param	align		The alignment of the blob's data.
		///						Leave as `0` to copy the source alignment.
		/// \param	allocator 	The #muu::generic_allocator used for allocations.
		///						Leave as `nullptr` to copy the source allocator.
		MUU_NODISCARD_CTOR
		MUU_API
		blob(const blob& other, size_t align, generic_allocator* allocator = nullptr);

		/// \brief Move constructor.
		MUU_NODISCARD_CTOR
		MUU_API
		blob(blob&& other) noexcept;

		/// \brief Destructor.
		MUU_API
		~blob() noexcept;

		/// Replaces the contents of the blob with the given data.
		///
		/// \param	src	 		The data to copy.
		/// \param	size 		The size of the data.
		/// \param	align		The alignment to use.
		///						Leave as `0` to use `__STDCPP_DEFAULT_NEW_ALIGNMENT__`.
		/// \param	allocator 	The #muu::generic_allocator used for allocations.
		///						Leave as `nullptr` to keep using the current allocator.
		///
		/// \return	A reference to the input blob.
		MUU_API
		blob& assign(size_t size, const void* src, size_t align = {}, generic_allocator* allocator = nullptr);

		/// \brief Replaces the contents of the blob by copying from another.
		///
		/// \remarks Alignment will be made to match the source blob; use assign() if you wish to be explicit
		/// about alignment when copying another blob.
		///
		/// \param	rhs	The blob to copy.
		///
		/// \return	A reference to the LHS blob.
		blob& operator=(const blob& rhs) noexcept
		{
			return assign(rhs.size_, rhs.data_, rhs.alignment_);
		}

		/// \brief Move-assignment operator.
		MUU_API
		blob& operator=(blob&&) noexcept;

		/// \brief Returns the size of the blob's data, in bytes.
		MUU_NODISCARD
		MUU_ATTR(pure)
		size_t size() const noexcept
		{
			return size_;
		}

		/// \brief Resizes the blob, keeping the region of `min(newSize, oldSize)` intact.
		///
		/// \param	size New size.
		///
		/// \return	A reference to the blob.
		MUU_API
		blob& size(size_t size);

		/// \brief Returns the alignment of the blob's data, in bytes.
		MUU_NODISCARD
		MUU_ATTR(pure)
		size_t alignment() const noexcept
		{
			return alignment_;
		}

		/// \brief Returns a pointer to the blob's data.
		MUU_NODISCARD
		MUU_ATTR(pure)
		std::byte* data() noexcept
		{
			return pointer_cast<std::byte*>(data_);
		}

		/// \brief Returns a pointer to the blob's data (const overload).
		MUU_NODISCARD
		MUU_ATTR(pure)
		const std::byte* data() const noexcept
		{
			return pointer_cast<const std::byte*>(data_);
		}

		/// \brief Returns true if the blob contains data.
		MUU_NODISCARD
		MUU_ATTR(pure)
		explicit operator bool() const noexcept
		{
			return data_ != nullptr;
		}
	};

	MUU_ABI_VERSION_END;
}

#include "impl/header_end.h"
