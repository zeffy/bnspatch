// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

/// \file
/// \brief  Contains the definition of muu::thread_pool.

#pragma once
#include "core.h"
#include "generic_allocator.h"
#include "string_param.h"

MUU_DISABLE_WARNINGS;
#include <cstring> // memcpy
MUU_ENABLE_WARNINGS;

#include "impl/header_start.h"
MUU_FORCE_NDEBUG_OPTIMIZATIONS;
MUU_PRAGMA_CLANG(diagnostic ignored "-Wignored-attributes")
MUU_PRAGMA_MSVC(warning(disable : 26495)) // core guidelines: uninitialized member

/// \cond
namespace muu::impl
{
	MUU_ABI_VERSION_START(0);

#ifdef __cpp_lib_hardware_interference_size
	inline constexpr size_t thread_pool_task_granularity = max(std::hardware_destructive_interference_size, 64_sz);
#else
	inline constexpr size_t thread_pool_task_granularity = 64;
#endif

	/*
		All of the following is a combination of type-erasure, devirtualization and small function optimization,
		tailored to allow for heap-free moving of a task across a pimpl'd ABI boundary.

		thread_pool_task			captures the callable object and a function for invoking/moving/deleting the task
									(the function is responsible for preserving functionality post type-erasure, and
									is specific to the type-erased thread_pool_task's payload)

		thread_pool_task_action		encodes the arguments passed to a specific invocation of the thread_pool_task's
									invoke/move/delete function

	*/

	struct thread_pool_task;

	struct thread_pool_task_action final
	{
		thread_pool_task& task;

		enum class types : uint8_t
		{
			move,
			invoke,
			destroy
		} type;

		union data_type
		{
			size_t thread_index;
			thread_pool_task* source;
		} data;

		MUU_NODISCARD_CTOR
		thread_pool_task_action(thread_pool_task& task_, thread_pool_task&& source_) noexcept //
			: task{ task_ },
			  type{ types::move }
		{
			data.source = muu::assume_aligned<thread_pool_task_granularity>(&source_);
		}

		MUU_NODISCARD_CTOR
		thread_pool_task_action(thread_pool_task& task_, size_t thread_) noexcept //
			: task{ task_ },
			  type{ types::invoke },
			  data{ thread_ }
		{}

		MUU_NODISCARD_CTOR
		thread_pool_task_action(thread_pool_task& task_) noexcept //
			: task{ task_ },
			  type{ types::destroy }
		{}
	};

	struct alignas(thread_pool_task_granularity) thread_pool_task
	{
		using action_invoker_type = void (*)(thread_pool_task_action&&) noexcept;

		std::byte buffer[thread_pool_task_granularity - sizeof(action_invoker_type)];

		static constexpr size_t buffer_capacity = sizeof(buffer);

		action_invoker_type action_invoker;

		template <typename T>
		MUU_NODISCARD_CTOR
		thread_pool_task(T&& callable_) noexcept;

		MUU_NODISCARD_CTOR
		thread_pool_task(thread_pool_task&& task) noexcept
		{
			task.action_invoker(thread_pool_task_action{ *this, static_cast<thread_pool_task&&>(task) });
		}

		~thread_pool_task() noexcept
		{
			action_invoker(thread_pool_task_action{ *this });
		}

		void operator()(size_t worker_index) noexcept
		{
			action_invoker(thread_pool_task_action{ *this, worker_index });
		}
	};

	static_assert(sizeof(thread_pool_task) == thread_pool_task_granularity);
	static_assert(alignof(thread_pool_task) == thread_pool_task_granularity);
	static_assert(MUU_OFFSETOF(thread_pool_task, buffer) == 0);
	static_assert(std::is_standard_layout_v<thread_pool_task>);

	template <typename T, bool = has_unary_plus_operator<T>>
	inline constexpr bool decays_to_function_pointer_by_unary_plus_ = false;
	template <typename T>
	inline constexpr bool decays_to_function_pointer_by_unary_plus_<T, true> =
		std::is_pointer_v<std::remove_reference_t<decltype(+std::declval<T>())>> //
			&& std::is_function_v<std::remove_pointer_t<std::remove_reference_t<decltype(+std::declval<T>())>>>;

	template <typename T>
	struct thread_pool_task_traits_pointer_to_callable
	{
		using storage_type	= remove_cvref<T>;
		using callable_type = std::remove_pointer_t<storage_type>;

		static_assert(std::is_pointer_v<storage_type>);
		static_assert(
			std::is_function_v<callable_type> || std::is_class_v<callable_type> || std::is_union_v<callable_type>);

		static constexpr bool requires_destruction = false;
		static constexpr bool is_function_pointer  = std::is_function_v<callable_type>;
		static constexpr bool is_referential	   = !is_function_pointer;

		template <typename U>
		MUU_ATTR(returns_nonnull)
		static storage_type select(U&& callable) noexcept
		{
			if constexpr (std::is_function_v<std::remove_reference_t<U>>)
				return callable;
			else if constexpr (decays_to_function_pointer_by_unary_plus_<U&&>)
			{
				using decay_type = std::remove_reference_t<decltype(+std::declval<U&&>())>;
				if constexpr (is_convertible<decay_type, storage_type>)
					return static_cast<storage_type>(+static_cast<U&&>(callable));
				else
					return &callable;
			}
			else
				return &callable;
		}

		template <typename U>
		MUU_ATTR(nonnull)
		static void store(void* buffer, U&& callable) noexcept
		{
			MUU_ASSUME(buffer);

			storage_type ptr = select(static_cast<U&&>(callable));
			std::memcpy(buffer, &ptr, sizeof(storage_type));
		}

		MUU_ATTR(nonnull)
		static void move(void* from, void* to) noexcept
		{
			MUU_ASSUME(from);
			MUU_ASSUME(to);

			std::memcpy(to, from, sizeof(storage_type));
		}

		template <typename... Args>
		static void invoke(storage_type callable, size_t index, Args&&... args) noexcept
		{
			MUU_ASSUME(callable);

			if constexpr (std::is_nothrow_invocable_v<callable_type&, Args&&..., size_t>)
				(*callable)(static_cast<Args&&>(args)..., index);
			else if constexpr (std::is_nothrow_invocable_v<callable_type&, Args&&...>)
			{
				MUU_UNUSED(index);
				(*callable)(static_cast<Args&&>(args)...);
			}
			else if constexpr (std::is_nothrow_invocable_v<callable_type&>)
			{
				MUU_UNUSED(index);
				(MUU_UNUSED(args), ...);
				(*callable)();
			}
			else
				static_assert(always_false<T>, "Evaluated unreachable branch!");
		}

		template <typename... Args>
		static void invoke(void* buffer, size_t index, Args&&... args) noexcept
		{
			MUU_ASSUME(buffer);

			storage_type callable;
			std::memcpy(&callable, buffer, sizeof(storage_type));
			invoke(callable, index, static_cast<Args&&>(args)...);
		}
	};

	template <typename T>
	struct thread_pool_task_traits_stored_callable
	{
		using storage_type	= T;
		using callable_type = T;

		static_assert(std::is_class_v<callable_type> || std::is_union_v<callable_type>);
		static_assert(!std::is_const_v<callable_type> && !std::is_volatile_v<callable_type>);
		static_assert(sizeof(callable_type) <= thread_pool_task::buffer_capacity);
		static_assert(alignof(callable_type) <= thread_pool_task_granularity);

		static constexpr bool requires_destruction = !std::is_trivially_destructible_v<callable_type>;
		static constexpr bool is_function_pointer  = false;
		static constexpr bool is_referential	   = false;

		template <typename U>
		static decltype(auto) select(U&& callable) noexcept
		{
			return static_cast<U&&>(callable);
		}

		template <typename U>
		MUU_ATTR(nonnull)
		static void store(void* buffer, U&& callable) noexcept
		{
			static_assert(std::is_same_v<callable_type, remove_cvref<U>>);
			MUU_ASSUME(buffer);

			if constexpr (std::is_trivially_copyable_v<callable_type>)
				std::memcpy(buffer, &callable, sizeof(callable_type));
			else
			{
				if constexpr (std::is_aggregate_v<callable_type>)
					::new (buffer) callable_type{ static_cast<U&&>(callable) };
				else
					::new (buffer) callable_type(static_cast<U&&>(callable));
			}
		}

		MUU_ATTR(nonnull)
		static void move(void* from, void* to) noexcept
		{
			MUU_ASSUME(from);
			MUU_ASSUME(to);

			if constexpr (std::is_trivially_copyable_v<callable_type>)
				std::memcpy(to, from, sizeof(callable_type));
			else if constexpr (std::is_nothrow_move_constructible_v<callable_type>)
			{
				::new (to) callable_type{ MUU_MOVE(*launder(static_cast<callable_type*>(from))) };
			}
			else if constexpr (std::is_nothrow_default_constructible_v<
								   callable_type> && std::is_nothrow_move_assignable_v<callable_type>)
			{
				auto val = ::new (to) callable_type;
				*val	 = MUU_MOVE(*launder(static_cast<callable_type*>(from)));
			}
			else if constexpr (std::is_nothrow_copy_constructible_v<callable_type>)
			{
				::new (to) callable_type{ *launder(static_cast<callable_type*>(from)) };
			}
			else if constexpr (std::is_nothrow_default_constructible_v<
								   callable_type> && std::is_nothrow_copy_assignable_v<callable_type>)
			{
				auto val = ::new (to) callable_type;
				*val	 = *launder(static_cast<callable_type*>(from));
			}
			else
				static_assert(always_false<T>, "Evaluated unreachable branch!");
		}

		template <typename... Args>
		static void invoke(storage_type& callable, size_t index, Args&&... args) noexcept
		{
			if constexpr (std::is_nothrow_invocable_v<callable_type&, Args&&..., size_t>)
				callable(static_cast<Args&&>(args)..., index);
			else if constexpr (std::is_nothrow_invocable_v<callable_type&, Args&&...>)
			{
				MUU_UNUSED(index);
				callable(static_cast<Args&&>(args)...);
			}
			else if constexpr (std::is_nothrow_invocable_v<callable_type&>)
			{
				MUU_UNUSED(index);
				(MUU_UNUSED(args), ...);
				callable();
			}
			else
				static_assert(always_false<T>, "Evaluated unreachable branch!");
		}

		template <typename... Args>
		static void invoke(void* buffer, size_t index, Args&&... args) noexcept
		{
			MUU_ASSUME(buffer);

			storage_type* callable;
			if constexpr (std::is_trivially_copyable_v<callable_type>)
				callable = static_cast<storage_type*>(buffer);
			else
				callable = launder(static_cast<storage_type*>(buffer));
			MUU_ASSUME(callable != nullptr);

			invoke(*callable, index, static_cast<Args&&>(args)...);
		}

		MUU_LEGACY_REQUIRES(sfinae, bool sfinae = requires_destruction)
		MUU_ATTR(nonnull)
		static void destroy(void* buffer) noexcept MUU_REQUIRES(requires_destruction)
		{
			MUU_ASSUME(buffer);

			launder(static_cast<callable_type*>(buffer))->~callable_type();
		}
	};

	template <typename T>
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr auto thread_pool_task_traits_selector() noexcept
	{
		using bare_type = remove_cvref<T>;

		// function references
		if constexpr (std::is_function_v<bare_type>)
			return thread_pool_task_traits_pointer_to_callable<std::add_pointer_t<bare_type>>{};

		// function pointers
		else if constexpr (std::is_function_v<std::remove_pointer_t<bare_type>>)
			return thread_pool_task_traits_pointer_to_callable<bare_type>{};

		// lambdas that can decay to function pointers
		else if constexpr (std::is_class_v<bare_type>	 //
						   && std::is_empty_v<bare_type> //
						   && decays_to_function_pointer_by_unary_plus_<T>)
		{
			return thread_pool_task_traits_pointer_to_callable<std::remove_reference_t<decltype(+std::declval<T>())>>{};
		}

		// callable objects
		else if constexpr (std::is_class_v<bare_type> || std::is_union_v<bare_type>)
		{
			if constexpr (std::is_rvalue_reference_v<T>)
			{
				constexpr auto size_ok		= sizeof(bare_type) <= thread_pool_task::buffer_capacity;
				constexpr auto alignment_ok = alignof(bare_type) <= thread_pool_task_granularity;
				constexpr auto dtor_ok		= std::is_nothrow_destructible_v<bare_type>;

				static_assert(size_ok, "Rvalue-referenced tasks must be small enough to stored internally.");
				static_assert(alignment_ok,
							  "Rvalue-referenced tasks must have small enough alignment to stored internally.");
				static_assert(dtor_ok, "Rvalue-referenced tasks must be nothrow-destructible.");

				if constexpr (!std::is_trivially_copyable_v<bare_type>) // not memcpy-able
				{
					constexpr auto ctor_ok = std::is_nothrow_constructible_v<bare_type, T>;	 // copy or move constructor
					constexpr auto move_ok = std::is_nothrow_move_constructible_v<bare_type> //
										  || (std::is_nothrow_default_constructible_v<
												  bare_type> && std::is_nothrow_copy_assignable_v<bare_type>);
					constexpr auto copy_ok = std::is_nothrow_copy_constructible_v<bare_type> //
										  || (std::is_nothrow_default_constructible_v<
												  bare_type> && std::is_nothrow_copy_assignable_v<bare_type>);

					static_assert(ctor_ok,
								  "Rvalue-referenced tasks must be trivially-copyable or nothrow-constructible.");
					static_assert(
						move_ok || copy_ok,
						"Rvalue-referenced tasks must be trivially-copyable, nothrow-movable or nothrow-copyable.");
				}

				return thread_pool_task_traits_stored_callable<bare_type>{};
			}
			else
			{
				return thread_pool_task_traits_pointer_to_callable<std::add_pointer_t<std::remove_reference_t<T>>>{};
			}
		}

		// ???
		else
			static_assert(always_false<T>, "Evaluated unreachable branch!");
	}

	template <typename T>
	using thread_pool_task_traits_base = decltype(thread_pool_task_traits_selector<T>());

	template <typename T>
	struct thread_pool_task_traits : thread_pool_task_traits_base<T>
	{};

	template <typename T>
	inline thread_pool_task::thread_pool_task(T&& callable) noexcept
	{
		using traits		= thread_pool_task_traits<T&&>;
		using callable_type = typename traits::callable_type;

		static_assert(std::is_nothrow_invocable_v<callable_type, size_t> || std::is_nothrow_invocable_v<callable_type>);

		// store callable
		traits::store(buffer, static_cast<T&&>(callable));

		// create invoker/mover/deleter
		action_invoker = [](thread_pool_task_action&& action) noexcept
		{
			switch (action.type)
			{
				case thread_pool_task_action::types::move:
				{
					action.task.action_invoker = action.data.source->action_invoker;
					traits::move(action.data.source->buffer, action.task.buffer);
					break;
				}

				case thread_pool_task_action::types::invoke:
				{
					traits::invoke(action.task.buffer, action.data.thread_index);
					break;
				}

				case thread_pool_task_action::types::destroy:
				{
					if constexpr (traits::requires_destruction)
					{
						traits::destroy(action.task.buffer);
						return;
					}
					break;
				}

				default: MUU_UNREACHABLE;
			}
		};
		MUU_ASSERT(action_invoker);
	}

	template <typename T>
	class batch_size_generator final
	{
	  private:
		T remaining;
		T constant;
		T overflow;

	  public:
		batch_size_generator(T job_count, T batch_count) noexcept //
			: remaining{ job_count },
			  constant{ job_count / batch_count },
			  overflow{ job_count % batch_count }
		{}

		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		T operator()() noexcept
		{
			if (!remaining)
				return {};
			T i = constant;
			if (overflow)
			{
				i++;
				overflow--;
			}
			remaining -= i;
			return i;
		}
	};

	MUU_ABI_VERSION_END;
}

#define MUU_MOVE_CHECK MUU_ASSERT(storage_ != nullptr && "The thread_pool has been moved from!")

/// \endcond

namespace muu
{
	MUU_ABI_VERSION_START(0);

	/// \brief A thread pool.
	class thread_pool
	{
	  private:
		void* storage_ = nullptr;

		MUU_NODISCARD
		MUU_API
		size_t lock() noexcept;

		MUU_NODISCARD
		MUU_API
		MUU_ATTR(returns_nonnull)
		MUU_ATTR(assume_aligned(impl::thread_pool_task_granularity))
		void* acquire(size_t) noexcept;

		template <typename T>
		void enqueue(size_t queue_index, T&& task) noexcept
		{
			::new (muu::assume_aligned<impl::thread_pool_task_granularity>(acquire(queue_index)))
				impl::thread_pool_task{ static_cast<T&&>(task) };
		}

		MUU_API
		void unlock(size_t) noexcept;

		template <typename Task>
		class for_each_task final
		{
		  public:
			using traits	   = impl::thread_pool_task_traits<Task>;
			using storage_type = typename traits::storage_type;

		  private:
			storage_type task_;

		  public:
			template <typename Arg>
			void operator()(Arg&& arg, size_t batch_index) noexcept
			{
				traits::invoke(task_, batch_index, static_cast<Arg&&>(arg));
			}

			template <typename Arg>
			void operator()(Arg&& arg) noexcept
			{
				traits::invoke(task_, 0_sz, static_cast<Arg&&>(arg));
			}

			template <typename U>
			MUU_NODISCARD_CTOR
			for_each_task(U&& task) noexcept //
				: task_{ traits::select(static_cast<U&&>(task)) }
			{}
		};

		template <typename OriginalTask, typename Task>
		MUU_NODISCARD
		static auto wrap_for_each_task(Task&& task) noexcept
		{
			static_assert(std::is_reference_v<OriginalTask>);
			static_assert(std::is_same_v<remove_cvref<OriginalTask>, remove_cvref<Task>>);

			if constexpr (std::is_lvalue_reference_v<OriginalTask>)
			{
				static_assert(std::is_same_v<OriginalTask, Task&&>);
				return for_each_task<OriginalTask>{ task };
			}
			else
			{
				if constexpr (std::is_rvalue_reference_v<Task&&>)
					return for_each_task<Task&&>{ static_cast<Task&&>(task) };
				else
					return for_each_task<remove_cvref<Task>&&>{ remove_cvref<Task>{ task } };
			}
		}

	  public:
		/// \brief	Constructs a thread pool.
		///
		/// \param	worker_count		The number of worker threads in the pool. Leave as `0` for 'automatic'.
		/// \param	task_queue_size		Max tasks that can be stored in the internal queue without blocking. Leave as `0` for 'automatic'.
		/// \param	name 				The name of your threadpool (for debugging purposes).
		/// \param	allocator 			The #muu::generic_allocator used for allocations. Leave as `nullptr` to use the default global allocator.
		MUU_NODISCARD_CTOR
		MUU_API
		explicit thread_pool(size_t worker_count		  = 0,
							 size_t task_queue_size		  = 0,
							 string_param name			  = {},
							 generic_allocator* allocator = nullptr);

		/// \brief	Constructs a thread pool.
		///
		/// \param	name 		The name of your thread pool (for debugging purposes).
		/// \param	allocator 	The #muu::generic_allocator used for allocations. Leave as `nullptr` to use the default global allocator.
		MUU_NODISCARD_CTOR
		explicit thread_pool(string_param name, generic_allocator* allocator = nullptr) //
			: thread_pool{ 0, 0, static_cast<string_param&&>(name), allocator }
		{}

		/// \brief	Move constructor.
		MUU_API
		thread_pool(thread_pool&&) noexcept;

		/// \brief	Move-assignment operator.
		MUU_API
		thread_pool& operator=(thread_pool&&) noexcept;

		/// \brief	Destructor.
		/// \warning Any enqueued tasks *currently being executed* are allowed to finish;
		/// 		 attempting to destroy a thread_pool with an enqueued task of indeterminate
		/// 		 length may lead to a deadlock.
		MUU_API
		~thread_pool() noexcept;

		MUU_DELETE_COPY(thread_pool);

		/// \brief	The number of worker threads in the thread pool.
		MUU_NODISCARD
		MUU_API
		MUU_ATTR(pure)
		size_t workers() const noexcept;

		/// \brief	The maximum tasks that may be enqueued without blocking.
		MUU_NODISCARD
		MUU_API
		MUU_ATTR(pure)
		size_t capacity() const noexcept;

		/// \brief	Waits for the thread pool to finish all of its current work.
		///
		/// \warning Do not call this from one of the thread pool's workers.
		MUU_API
		void wait() noexcept;

		/// \brief	Enqueues a task.
		///
		/// \details Tasks must be callables with no parameters, or one parameter to recieve
		/// 		 the index of the worker invoking the task:
		/// \cpp
		/// pool.enqueue([](size_t worker_index) noexcept
		/// {
		///		// worker_index is in the range [0, pool.workers() - 1]
		///	});
		/// pool.enqueue([]() noexcept
		/// {
		///		//...
		///	});
		/// \ecpp
		///
		/// \remarks Tasks must be finite, otherwise the pool will fill and wait() calls will never return.
		/// \remarks Tasks must not throw exceptions.
		///
		/// \warning Do not call this from one of the thread_pool's workers.
		///
		/// \tparam	Task	The type of the task being enqueued.
		/// \param	task  	The task to enqueue.
		///
		/// \returns	A reference to the thread pool.
		template <typename Task>
		thread_pool& enqueue(Task&& task) noexcept
		{
			static_assert(
				std::is_nothrow_invocable_v<Task&&, size_t> //
					|| std::is_nothrow_invocable_v<Task&&>,
				"Tasks passed to thread_pool::enqueue() must be callable as void() noexcept or void(size_t) noexcept");
			MUU_MOVE_CHECK;

			const auto qindex = lock();
			enqueue(qindex, static_cast<Task&&>(task));
			unlock(qindex);
			return *this;
		}

	  private:
		template <typename OriginalTask, bool Indexed, typename Iter, typename Task>
		void enqueue_for_each_batch(Iter batch_start, Iter batch_end, size_t batch_index, Task&& task) noexcept
		{
			if constexpr (Indexed)
				MUU_ASSERT(batch_index < workers());
			else
				MUU_UNUSED(batch_index);

			const auto qindex = lock();

			enqueue(qindex,
					[=, wrapped_task = wrap_for_each_task<OriginalTask>(static_cast<Task&&>(task))]() mutable noexcept
					{
						while (batch_start != batch_end)
						{
							if constexpr (Indexed)
								wrapped_task(*batch_start, batch_index);
							else
								wrapped_task(*batch_start);
							std::advance(batch_start, 1);
						}
					});

			unlock(qindex);
		}

		template <typename Begin, typename Task>
		thread_pool& for_each_impl(Begin begin, size_t job_count, Task&& task) noexcept
		{
			using elem_reference = impl::iter_reference_t<Begin>;
			static_assert(
				std::is_nothrow_invocable_v<Task&&, elem_reference, size_t> //
					|| std::is_nothrow_invocable_v<Task&&, elem_reference>	//
					|| std::is_nothrow_invocable_v<Task&&>,
				"Tasks passed to thread_pool::for_each() must be callable as void() noexcept, void(T) noexcept or "
				"void(T, size_t) noexcept");

			// determine batch count and distribute iterators
			auto batch_generator   = impl::batch_size_generator<size_t>{ job_count, this->workers() };
			size_t next_batch_size = batch_generator();
			auto batch_start	   = begin;
			auto batch_end		   = std::next(begin, static_cast<ptrdiff_t>(next_batch_size));
			auto batch_index	   = 0_sz;

			// dispatch tasks
			static constexpr auto indexed = std::is_nothrow_invocable_v<Task&&, elem_reference, size_t>;
			while (true)
			{
				next_batch_size = batch_generator();
				if (next_batch_size)
				{
					enqueue_for_each_batch<Task&&, indexed>(batch_start, batch_end, batch_index, task);
					batch_start = batch_end;
					std::advance(batch_end, static_cast<ptrdiff_t>(next_batch_size));
				}
				else
				{
					enqueue_for_each_batch<Task&&, indexed>(batch_start,
															batch_end,
															batch_index,
															static_cast<Task&&>(task));
					break;
				}
				batch_index++;
			}
			return *this;
		}

	  public:
		/// \brief	Enqueues a task to execute on every element in a collection.
		///
		/// \details	Tasks must be callables which accept at most two arguments: <br>
		/// 			Argument 0: The current element from the collection <br>
		/// 			Argument 1: The task's batch (in the range `[0, pool.workers() - 1]`) <br>
		/// \cpp
		/// std::array<int, 10> vals;
		/// pool.for_each(vals.begin(), vals.end(), [](int& i, size_t batch_index) noexcept
		/// {
		///		// i is one of the elements of vals
		///		// batch_index is in the range [0, pool.workers() - 1]
		///	});
		/// pool.for_each(vals.begin(), vals.end(), [](int& i) noexcept
		/// {
		///		// i is one of the elements of vals
		///	});
		/// pool.for_range(0, 10, []() noexcept
		/// {
		///		// no args is OK too (though unusual)
		///	});
		/// \ecpp
		///
		/// \remarks Tasks must be finite, otherwise the pool will fill and wait() calls will never return.
		/// \remarks Tasks must not throw exceptions.
		///
		/// \warning Do not call this from one of the thread_pool's workers.
		///
		/// \tparam	Iter 		Collection iterator type.
		/// \tparam	Task		The type of the task being enqueued.
		/// \param	begin		Iterator to the beginning of the collection.
		/// \param	end			Iterator to the end of the collection.
		/// \param	task  		The task to execute for each member of the collection.
		///
		/// \return	A reference to the thread pool.
		template <typename Iter, typename Task>
		thread_pool& for_each(Iter begin, Iter end, Task&& task) noexcept
		{
			MUU_MOVE_CHECK;

			const auto job_count = std::distance(begin, end);
			if (job_count <= 0)
				return *this;

			return for_each_impl(begin, static_cast<size_t>(job_count), static_cast<Task&&>(task));
		}

		/// \brief	Enqueues a task to execute on every element in a collection.
		///
		/// \details	Tasks must be callables which accept at most two arguments: <br>
		/// 			Argument 0: The current element from the collection <br>
		/// 			Argument 1: The task's batch (in the range `[0, pool.workers() - 1]`) <br>
		/// \cpp
		/// std::array<int, 10> vals;
		/// pool.for_each(vals, [](int& i, size_t batch_index) noexcept
		/// {
		///		// i is one of the elements of vals
		///		// batch_index is in the range [0, pool.workers() - 1]
		///	});
		/// pool.for_each(vals, [](int& i) noexcept
		/// {
		///		// i is one of the elements of vals
		///	});
		/// pool.for_range(0, 10, []() noexcept
		/// {
		///		// no args is OK too (though unusual)
		///	});
		/// \ecpp
		///
		/// \remarks Tasks must be finite, otherwise the pool will fill and wait() calls will never return.
		/// \remarks Tasks must not throw exceptions.
		///
		/// \warning Do not call this from one of the thread_pool's workers.
		///
		/// \tparam	T 			Type of the collection.
		/// \tparam	Task		The type of the task being enqueued.
		/// \param	collection	The collection.
		/// \param	task  		The task to execute for each member of the collection.
		///
		/// \return	A reference to the thread pool.
		template <typename T, typename Task>
		thread_pool& for_each(T&& collection, Task&& task) noexcept
		{
			MUU_MOVE_CHECK;

			using std::size;
			const size_t job_count = size(collection);
			if (!job_count)
				return *this;

			using std::begin;
			return for_each_impl(begin(static_cast<T&&>(collection)), job_count, static_cast<Task&&>(task));
		}

	  private:
		template <typename OriginalTask, typename ValueType, bool Indexed, typename T, typename Task>
		void enqueue_for_range_batch(T batch_start, T batch_end, size_t batch_index, Task&& task) noexcept
		{
			if constexpr (Indexed)
				MUU_ASSERT(batch_index < workers());
			else
				MUU_UNUSED(batch_index);

			const auto qindex = lock();

			enqueue(qindex,
					[=, wrapped_task = wrap_for_each_task<OriginalTask>(static_cast<Task&&>(task))]() mutable noexcept
					{
						if (batch_start < batch_end)
						{
							for (; batch_start < batch_end; batch_start++)
							{
								if constexpr (Indexed)
									wrapped_task(static_cast<ValueType>(batch_start), batch_index);
								else
									wrapped_task(static_cast<ValueType>(batch_start));
							}
						}
						else
						{
							for (; batch_start > batch_end; batch_start--)
							{
								if constexpr (Indexed)
									wrapped_task(static_cast<ValueType>(batch_start), batch_index);
								else
									wrapped_task(static_cast<ValueType>(batch_start));
							}
						}
					});

			unlock(qindex);
		}

	  public:
		/// \brief	Enqueues a task to execute once for every value in a range.
		///
		/// \details	Tasks must be callables which accept at most two arguments: <br>
		/// 			Argument 0: The current value from the range <br>
		/// 			Argument 1: The task's batch (in the range `[0, pool.workers() - 1]`) <br>
		/// \cpp
		/// pool.for_range(0, 10, [](int i, size_t batch_index) noexcept
		/// {
		///		// i is in the range [0, 9]
		///		// batch_index is in the range [0, pool.workers() - 1]
		///	});
		/// pool.for_range(0, 10, [](int i) noexcept
		/// {
		///		// i is in the range [0, 9]
		///	});
		/// pool.for_range(0, 10, []() noexcept
		/// {
		///		// no args is OK too
		///	});
		/// \ecpp
		///
		/// \remarks Tasks must be finite, otherwise the pool will fill and Wait() calls will never return.
		/// \remarks Tasks must not throw exceptions.
		///
		/// \warning Do not call this from one of the thread_pool's workers.
		///
		/// \tparam	T 			An integer or enum type.
		/// \tparam	Task		The type of the task being enqueued.
		/// \param	start		The start of the value range (inclusive).
		/// \param	end			The end of the value range (exclusive).
		/// \param	task		The task to enqueue.
		///
		/// \return	A reference to the threadpool.
		template <typename T, typename Task>
		thread_pool& for_range(T start, T end, Task&& task) noexcept
		{
			static_assert(std::is_nothrow_invocable_v<Task&&, T, size_t> //
							  || std::is_nothrow_invocable_v<Task&&, T>	 //
							  || std::is_nothrow_invocable_v<Task&&>,
						  "Tasks passed to thread_pool::for_range() must be callable as void() noexcept, void(T) "
						  "noexcept or void(T, size_t) noexcept");
			MUU_MOVE_CHECK;

			// determine batch count and distribute indices
			using value_type	 = remove_cvref<T>;
			using offset_type	 = largest<remove_enum<value_type>,
										   std::conditional_t<is_signed<remove_enum<value_type>>, signed, unsigned>>;
			using size_type		 = largest<make_unsigned<offset_type>, size_t>;
			const auto job_count = static_cast<size_type>(static_cast<offset_type>(max(unwrap(start), unwrap(end)))
														  - static_cast<offset_type>(min(unwrap(start), unwrap(end))));
			if (!job_count)
				return *this;
			auto batch_generator		 = impl::batch_size_generator<size_type>{ job_count, this->workers() };
			offset_type next_batch_start = unwrap(start);
			size_type next_batch_size	 = batch_generator();
			auto batch_index			 = 0_sz;

			// dispatch tasks
			static constexpr auto indexed = std::is_nothrow_invocable_v<Task&&, T, size_t>;
			while (true)
			{
				const auto batch_start = next_batch_start;
				next_batch_start	   = start < end ? static_cast<offset_type>(batch_start + next_batch_size)
													 : static_cast<offset_type>(batch_start - next_batch_size);
				next_batch_size		   = batch_generator();

				if (next_batch_size)
					enqueue_for_range_batch<Task&&, value_type, indexed>(batch_start,
																		 next_batch_start,
																		 batch_index,
																		 task);
				else
				{
					enqueue_for_range_batch<Task&&, value_type, indexed>(batch_start,
																		 next_batch_start,
																		 batch_index,
																		 static_cast<Task&&>(task));
					break;
				}
				batch_index++;
			}
			return *this;
		}
	};

	MUU_ABI_VERSION_END;
}

#undef MUU_MOVE_CHECK

MUU_RESET_NDEBUG_OPTIMIZATIONS;
#include "impl/header_end.h"
