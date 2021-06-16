// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

/// \file
/// \brief Contains the definition of muu::emplacement_array.

#pragma once
#include "impl/core_utils.h"
#include "generic_allocator.h"

MUU_DISABLE_WARNINGS;
#include <new> // placement new
#if !MUU_HAS_EXCEPTIONS
	#include <exception> // std::terminate()
#endif
MUU_ENABLE_WARNINGS;

#include "impl/header_start.h"

namespace muu
{
	MUU_ABI_VERSION_START(0);

	/// \brief	Simple std::vector-like array type for immovable or move-only types.
	///
	/// \tparam	T	Element type stored in the array.
	template <typename T>
	class emplacement_array
	{
		static_assert(!std::is_reference_v<T>, "emplacement_array element type cannot be a reference.");
		static_assert(!std::is_const_v<T> && !std::is_volatile_v<T>,
					  "emplacement_array element type cannot be const- or volatile-qualified");
		static_assert(std::is_nothrow_destructible_v<T>,
					  "emplacement_array element type must be nothrow-destructible.");

	  private:
		///  \cond

		generic_allocator* allocator_;
		size_t count_		= {}, capacity_;
		std::byte* storage_ = nullptr;

		MUU_NODISCARD
		MUU_ATTR(pure)
		MUU_ATTR(returns_nonnull)
		T* ptr(size_t index) noexcept
		{
			return launder(reinterpret_cast<T*>(storage_ + index * sizeof(T)));
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		MUU_ATTR(returns_nonnull)
		const T* ptr(size_t index) const noexcept
		{
			return launder(reinterpret_cast<const T*>(storage_ + index * sizeof(T)));
		}

		void destroy_all_elements() noexcept(std::is_nothrow_destructible_v<T>)
		{
			if constexpr (std::is_trivially_destructible_v<T>)
				count_ = {};
			else
			{
				for (size_t i = count_; i-- > 0u;)
				{
					ptr(i)->~T();
					if constexpr (!std::is_nothrow_destructible_v<T>)
						count_--;
				}
				if constexpr (std::is_nothrow_destructible_v<T>)
					count_ = {};
			}
		}

		void release() noexcept(std::is_nothrow_destructible_v<T>)
		{
			if (storage_)
			{
				destroy_all_elements();
				allocator_->deallocate(storage_, sizeof(T) * capacity_, alignof(T));
				storage_ = nullptr;
			}
		}

		///  \endcond

	  public:
		/// \brief	The array's value type.
		using value_type = T;

		/// \brief	Unsigned index type.
		using size_type = size_t;

		/// \brief	Signed index type.
		using difference_type = ptrdiff_t;

		/// \brief	Reference to the array's value type.
		using reference = value_type&;

		/// \brief	Const reference to the array's value type.
		using const_reference = const value_type&;

		/// \brief	Pointer to the array's value type.
		using pointer = value_type*;

		/// \brief	Const pointer to the array's value type.
		using const_pointer = const value_type*;

		/// \brief	Iterator to a member of the array.
		using iterator = pointer;

		/// \brief	Const iterator to a member of the array.
		using const_iterator = const_pointer;

		/// \brief	Constructor.
		///
		/// \param	capacity	The maximum number of elements the array needs to be able to store.
		/// \param	allocator 	The #muu::generic_allocator used for allocations. Set to `nullptr` to use the default global allocator.
		MUU_NODISCARD_CTOR
		explicit emplacement_array(size_t capacity = 0, generic_allocator* allocator = nullptr)
			: allocator_{ allocator ? allocator : &impl::get_default_allocator() },
			  capacity_{ capacity }
		{
			if (capacity_)
			{
				storage_ = static_cast<std::byte*>(allocator_->allocate(sizeof(T) * capacity_, alignof(T)));
				MUU_ASSERT(storage_ && "allocate() failed!");
#if !MUU_HAS_EXCEPTIONS
				{
					if (!storage_)
						std::terminate();
				}
#endif
			}
		}

		/// \brief	Move constructor.
		MUU_NODISCARD_CTOR
		emplacement_array(emplacement_array&& other) noexcept
			: allocator_{ other.allocator_ },
			  count_{ other.count_ },
			  capacity_{ other.capacity_ },
			  storage_{ other.storage_ }
		{
			other.count_	= 0;
			other.capacity_ = 0;
			other.storage_	= nullptr;
		}

		/// \brief Move-assignment operator.
		emplacement_array& operator=(emplacement_array&& rhs) noexcept
		{
			release();
			allocator_	  = rhs.allocator_;
			count_		  = rhs.count_;
			capacity_	  = rhs.capacity_;
			storage_	  = rhs.storage_;
			rhs.count_	  = 0;
			rhs.capacity_ = 0;
			rhs.storage_  = nullptr;
			return *this;
		}

		/// \brief Destructor.
		~emplacement_array() noexcept
		{
			release();
		}

		MUU_DELETE_COPY(emplacement_array);

		/// \brief	Constructs one new element at the end of the array.
		///
		/// \tparam	Args	Constructor argument types.
		/// \param	args	Arguments to pass to the element's constructor.
		///
		/// \return	A reference to the newly-constructed element.
		template <typename... Args>
		reference emplace_back(Args&&... args) noexcept(std::is_nothrow_constructible_v<T, Args&&...>)
		{
			MUU_ASSERT(count_ < capacity_ && "The emplacement_array is at capacity");

			if constexpr (std::is_nothrow_constructible_v<T, Args&&...>)
			{
				return *(::new (static_cast<void*>(storage_ + (sizeof(T) * count_++)))
							 T{ static_cast<Args&&>(args)... });
			}
			else
			{
				auto& newVal =
					*(::new (static_cast<void*>(storage_ + (sizeof(T) * count_))) T{ static_cast<Args&&>(args)... });
				count_++;
				return newVal;
			}
		}

		/// \brief	Constructs one new element in the array using a construction functor for the emplacement.
		///
		/// \tparam EmplacementFunc		A callable type with the signature `T*(void*)`.
		/// \param func					A callable responsible for performing the placement-new construction.
		///
		/// \return	A reference to the newly-constructed element.
		template <typename EmplacementFunc, typename... ARGS>
		reference emplace_back_with(EmplacementFunc&& func) noexcept(
			std::is_nothrow_invocable_r_v<T&, EmplacementFunc&&, void*>)
		{
			MUU_ASSERT(count_ < capacity_ && "The emplacement_array is at capacity");

			if constexpr (std::is_nothrow_invocable_r_v<T&, EmplacementFunc&&, void*>)
			{
				return *static_cast<EmplacementFunc&&>(func)(static_cast<void*>(storage_ + (sizeof(T) * count_++)));
			}
			else
			{
				auto& newVal =
					*static_cast<EmplacementFunc&&>(func)(static_cast<void*>(storage_ + (sizeof(T) * count_)));
				count_++;
				return newVal;
			}
		}

		/// \brief	Returns a reference to the element at the selected index.
		MUU_NODISCARD
		MUU_ATTR(pure)
		reference operator[](size_t index) noexcept
		{
			return *ptr(index);
		}

		/// \brief	Returns a const reference to the element at the selected index.
		MUU_NODISCARD
		MUU_ATTR(pure)
		const_reference operator[](size_t index) const noexcept
		{
			return *ptr(index);
		}

		/// \brief	The number of elements in the array.
		MUU_NODISCARD
		MUU_ATTR(pure)
		size_type size() const noexcept
		{
			return count_;
		}

		/// \brief	The maximum number of elements that can be stored in the array.
		MUU_NODISCARD
		MUU_ATTR(pure)
		size_type capacity() const noexcept
		{
			return capacity_;
		}

		/// \brief	Returns true if the array is empty.
		MUU_NODISCARD
		MUU_ATTR(pure)
		bool empty() const noexcept
		{
			return count_ == 0u;
		}

		/// \brief	Returns the first element in the array.
		MUU_NODISCARD
		MUU_ATTR(pure)
		reference front() noexcept
		{
			return (*this)[0];
		}

		/// \brief	Returns the first element in the array.
		MUU_NODISCARD
		MUU_ATTR(pure)
		const_reference front() const noexcept
		{
			return (*this)[0];
		}

		/// \brief	Returns the last element in the array.
		MUU_NODISCARD
		MUU_ATTR(pure)
		reference back() noexcept
		{
			return (*this)[count_ - 1_sz];
		}

		/// \brief	Returns the last element in the array.
		MUU_NODISCARD
		MUU_ATTR(pure)
		const_reference back() const noexcept
		{
			return (*this)[count_ - 1_sz];
		}

		/// \brief	Returns a pointer to the first element in the array.
		MUU_NODISCARD
		MUU_ATTR(pure)
		iterator begin() noexcept
		{
			return ptr(0);
		}

		/// \brief	Returns a pointer to one-past-the-last element in the array.
		MUU_NODISCARD
		MUU_ATTR(pure)
		iterator end() noexcept
		{
			return ptr(count_);
		}

		/// \brief	Returns a const pointer to the first element in the array.
		MUU_NODISCARD
		MUU_ATTR(pure)
		const_iterator begin() const noexcept
		{
			return ptr(0);
		}

		/// \brief	Returns a const pointer to one-past-the-last element in the array.
		MUU_NODISCARD
		MUU_ATTR(pure)
		const_iterator end() const noexcept
		{
			return ptr(count_);
		}

		/// \brief	Returns a const pointer to the first element in the array.
		MUU_NODISCARD
		MUU_ATTR(pure)
		const_iterator cbegin() const noexcept
		{
			return ptr(0);
		}

		/// \brief	Returns a const pointer to one-past-the-last element in the array.
		MUU_NODISCARD
		MUU_ATTR(pure)
		const_iterator cend() const noexcept
		{
			return ptr(count_);
		}

		/// \brief	Returns a pointer to the first element in the array.
		MUU_NODISCARD
		MUU_ATTR(pure)
		pointer data() noexcept
		{
			return ptr(0);
		}

		/// \brief	Returns a const pointer to the first element in the array.
		MUU_NODISCARD
		MUU_ATTR(pure)
		const_pointer data() const noexcept
		{
			return ptr(0);
		}

		/// \brief	Clears the array, destroying all currently allocated elements and resetting size to zero.
		void clear() noexcept(std::is_nothrow_destructible_v<T>)
		{
			destroy_all_elements();
		}
	};

	MUU_ABI_VERSION_END;
}

#include "impl/header_end.h"
