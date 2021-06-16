// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

#pragma once
#include "../fwd.h"

#if !defined(MUU_TYPE_LIST_PAGE_SIZE) || MUU_TYPE_LIST_PAGE_SIZE <= 0 || MUU_TYPE_LIST_PAGE_SIZE > 64
	#undef MUU_TYPE_LIST_PAGE_SIZE
	#define MUU_TYPE_LIST_PAGE_SIZE 32
#endif
#if MUU_TYPE_LIST_PAGE_SIZE < 8
	#undef MUU_TYPE_LIST_PAGE_SIZE
	#define MUU_TYPE_LIST_PAGE_SIZE 8
#endif

#ifndef MUU_HAS_JUMBO_PAGES
	#define MUU_HAS_JUMBO_PAGES 1
#endif

#if MUU_HAS_BUILTIN(__type_pack_element) || MUU_CLANG >= 6 // older clang implemented __has_builtin poorly
	#define MUU_HAS_TYPE_PACK_ELEMENT 1
#else
	#define MUU_HAS_TYPE_PACK_ELEMENT 0
#endif

#ifndef MUU_HAS_INTEGER_SEQ
	#if defined(__clang__) || defined(_MSC_VER)
		#define MUU_HAS_INTEGER_SEQ 1
	#else
		#define MUU_HAS_INTEGER_SEQ 0
	#endif
#endif
#if !MUU_HAS_INTEGER_SEQ
MUU_DISABLE_WARNINGS;
	#include <utility>
MUU_ENABLE_WARNINGS;
#endif

/// \cond

#define MUU_MAKE_INDEXED_TPARAM(N) MUU_COMMA typename MUU_CONCAT(T, N)
#define MUU_MAKE_INDEXED_TARG(N)   MUU_COMMA MUU_CONCAT(T, N)
#define MUU_0_TO_7				   0, 1, 2, 3, 4, 5, 6, 7
#define MUU_0_TO_15				   MUU_0_TO_7, 8, 9, 10, 11, 12, 13, 14, 15
#define MUU_0_TO_31				   MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
#define MUU_0_TO_47				   MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47
#define MUU_0_TO_63				   MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63

/// \endcond

#include "header_start.h"

namespace muu
{
	/// \addtogroup		meta
	/// @{

	/// \cond

	namespace impl
	{
		inline constexpr size_t type_list_page_size = MUU_TYPE_LIST_PAGE_SIZE;
#if MUU_HAS_JUMBO_PAGES
		inline constexpr size_t type_list_jumbo_page_size = 128;
#else
		inline constexpr size_t type_list_jumbo_page_size = static_cast<size_t>(-1);
#endif

#if MUU_HAS_INTEGER_SEQ
		template <typename T, T... Vals>
		struct integer_sequence
		{};
		template <size_t... Vals>
		using index_sequence = integer_sequence<size_t, Vals...>;
		template <size_t Size>
		using make_index_sequence = __make_integer_seq<integer_sequence, size_t, Size>;
#else
		using std::index_sequence;
		using std::make_index_sequence;
#endif

		enum class type_list_selector_spec : int
		{
			first,
			skip_pages,
			low_index,
			compiler_builtin
		};

		// clang-format off

		// selector
		template <typename List, size_t N, type_list_selector_spec Specialization = (
			MUU_HAS_TYPE_PACK_ELEMENT      ? type_list_selector_spec::compiler_builtin : (
			N == 0                         ? type_list_selector_spec::first : (
			N >= type_list_jumbo_page_size ? type_list_selector_spec::skip_pages : (
			N >= type_list_page_size       ? type_list_selector_spec::skip_pages : (
			                               type_list_selector_spec::low_index
		)))))>
		struct type_list_selector_;

		// clang-format on

#if MUU_HAS_TYPE_PACK_ELEMENT

		// selector - selecting elements using a compiler builtin
		template <typename... T, size_t N>
		struct type_list_selector_<type_list<T...>, N, type_list_selector_spec::compiler_builtin>
		{
			using type = __type_pack_element<N, T...>;
		};

#else

		// selector - first element
		template <typename T0, typename... T, size_t N>
		struct type_list_selector_<type_list<T0, T...>, N, type_list_selector_spec::first>
		{
			using type = T0;
		};

		// selector - skip pages
		template <typename List, size_t N>
		struct type_list_selector_<List, N, type_list_selector_spec::skip_pages>
		{
			// invokes the skip_pages specialization of the slicer
			using type = typename List::template slice<N, 1>::template select<0>;
		};

		// selector - low-index elements
	#if 1
		#define MAKE_SELECTOR_1(N, N0, ...)                                                                            \
			template <typename T##N0 MUU_FOR_EACH(MUU_MAKE_INDEXED_TPARAM, __VA_ARGS__), typename... T>                \
			struct type_list_selector_<type_list<T##N0 MUU_FOR_EACH(MUU_MAKE_INDEXED_TARG, __VA_ARGS__), T...>,        \
									   N,                                                                              \
									   type_list_selector_spec::low_index>                                             \
			{                                                                                                          \
				using type = T##N;                                                                                     \
			}
		#define MAKE_SELECTOR(...) MUU_FOR_EACH_FORCE_UNROLL(MAKE_SELECTOR_1(__VA_ARGS__))

		template <typename T0, typename T1, typename... T>
		struct type_list_selector_<type_list<T0, T1, T...>, 1, type_list_selector_spec::low_index>
		{
			using type = T1;
		};

		MAKE_SELECTOR(2, 0, 1, 2);
		MAKE_SELECTOR(3, 0, 1, 2, 3);
		MAKE_SELECTOR(4, 0, 1, 2, 3, 4);
		MAKE_SELECTOR(5, 0, 1, 2, 3, 4, 5);
		MAKE_SELECTOR(6, 0, 1, 2, 3, 4, 5, 6);
		MAKE_SELECTOR(7, MUU_0_TO_7);
		#if MUU_TYPE_LIST_PAGE_SIZE > 8
		MAKE_SELECTOR(8, MUU_0_TO_7, 8);
		MAKE_SELECTOR(9, MUU_0_TO_7, 8, 9);
		MAKE_SELECTOR(10, MUU_0_TO_7, 8, 9, 10);
		MAKE_SELECTOR(11, MUU_0_TO_7, 8, 9, 10, 11);
		MAKE_SELECTOR(12, MUU_0_TO_7, 8, 9, 10, 11, 12);
		MAKE_SELECTOR(13, MUU_0_TO_7, 8, 9, 10, 11, 12, 13);
		MAKE_SELECTOR(14, MUU_0_TO_7, 8, 9, 10, 11, 12, 13, 14);
		MAKE_SELECTOR(15, MUU_0_TO_15);
		#endif
		#if MUU_TYPE_LIST_PAGE_SIZE > 16
		MAKE_SELECTOR(16, MUU_0_TO_15, 16);
		MAKE_SELECTOR(17, MUU_0_TO_15, 16, 17);
		MAKE_SELECTOR(18, MUU_0_TO_15, 16, 17, 18);
		MAKE_SELECTOR(19, MUU_0_TO_15, 16, 17, 18, 19);
		MAKE_SELECTOR(20, MUU_0_TO_15, 16, 17, 18, 19, 20);
		MAKE_SELECTOR(21, MUU_0_TO_15, 16, 17, 18, 19, 20, 21);
		MAKE_SELECTOR(22, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22);
		MAKE_SELECTOR(23, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23);
		MAKE_SELECTOR(24, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24);
		MAKE_SELECTOR(25, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25);
		MAKE_SELECTOR(26, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26);
		MAKE_SELECTOR(27, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27);
		MAKE_SELECTOR(28, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28);
		MAKE_SELECTOR(29, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29);
		MAKE_SELECTOR(30, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30);
		MAKE_SELECTOR(31, MUU_0_TO_31);
		#endif
		#if MUU_TYPE_LIST_PAGE_SIZE > 32
		MAKE_SELECTOR(32, MUU_0_TO_31, 32);
		MAKE_SELECTOR(33, MUU_0_TO_31, 32, 33);
		MAKE_SELECTOR(34, MUU_0_TO_31, 32, 33, 34);
		MAKE_SELECTOR(35, MUU_0_TO_31, 32, 33, 34, 35);
		MAKE_SELECTOR(36, MUU_0_TO_31, 32, 33, 34, 35, 36);
		MAKE_SELECTOR(37, MUU_0_TO_31, 32, 33, 34, 35, 36, 37);
		MAKE_SELECTOR(38, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38);
		MAKE_SELECTOR(39, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39);
		MAKE_SELECTOR(40, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40);
		MAKE_SELECTOR(41, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41);
		MAKE_SELECTOR(42, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42);
		MAKE_SELECTOR(43, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43);
		MAKE_SELECTOR(44, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44);
		MAKE_SELECTOR(45, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45);
		MAKE_SELECTOR(46, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46);
		MAKE_SELECTOR(47, MUU_0_TO_47);
		#endif
		#if MUU_TYPE_LIST_PAGE_SIZE > 48
		MAKE_SELECTOR(48, MUU_0_TO_47, 48);
		MAKE_SELECTOR(49, MUU_0_TO_47, 48, 49);
		MAKE_SELECTOR(50, MUU_0_TO_47, 48, 49, 50);
		MAKE_SELECTOR(51, MUU_0_TO_47, 48, 49, 50, 51);
		MAKE_SELECTOR(52, MUU_0_TO_47, 48, 49, 50, 51, 52);
		MAKE_SELECTOR(53, MUU_0_TO_47, 48, 49, 50, 51, 52, 53);
		MAKE_SELECTOR(54, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54);
		MAKE_SELECTOR(55, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55);
		MAKE_SELECTOR(56, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56);
		MAKE_SELECTOR(57, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57);
		MAKE_SELECTOR(58, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58);
		MAKE_SELECTOR(59, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59);
		MAKE_SELECTOR(60, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60);
		MAKE_SELECTOR(61, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61);
		MAKE_SELECTOR(62, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62);
		MAKE_SELECTOR(63, MUU_0_TO_63);
		#endif

		#undef MAKE_SELECTOR_1
		#undef MAKE_SELECTOR
	#endif

#endif // !MUU_HAS_TYPE_PACK_ELEMENT

		enum class type_list_slicer_spec : int
		{
			empty,
			first,
			all,
			skip_first_N,
			skip_jumbo_pages,
			skip_pages,
			prefix,
			single_low_index,
			single_compiler_builtin,
			arbitrary_range
		};

		// clang-format off

		// slicer
		template <typename List, size_t Start, size_t Length, type_list_slicer_spec Specialization = (
			!List::length || !Length || Start >= List::length ? type_list_slicer_spec::empty : (
			Length == 1 && MUU_HAS_TYPE_PACK_ELEMENT           ? type_list_slicer_spec::single_compiler_builtin : (
			Start == 0 && Length == 1                         ? type_list_slicer_spec::first : (
			Start == 0 && List::length == Length              ? type_list_slicer_spec::all : (
			Start >= type_list_jumbo_page_size                ? type_list_slicer_spec::skip_jumbo_pages : (
			MUU_HAS_TYPE_PACK_ELEMENT                          ? type_list_slicer_spec::arbitrary_range : (
			Start >= type_list_page_size                      ? type_list_slicer_spec::skip_pages : (
			Length == 1                                       ? type_list_slicer_spec::single_low_index : (
			Start == 0 && Length <= type_list_page_size       ? type_list_slicer_spec::prefix : (
			Start > 0                                         ? type_list_slicer_spec::skip_first_N : (
			                                                    type_list_slicer_spec::arbitrary_range
		)))))))))))>
		struct type_list_slicer_;

		// clang-format on

		// slicer - empty range
		template <typename List, size_t Start, size_t Length>
		struct type_list_slicer_<List, Start, Length, type_list_slicer_spec::empty>
		{
			using type = type_list<>;
		};

		// slicer - arbitrary ranges
		template <typename, size_t, typename>
		struct type_list_index_sequence_slicer_;
		template <typename List, size_t Start, size_t... Seq>
		struct type_list_index_sequence_slicer_<List, Start, index_sequence<Seq...>>
		{
			using type = type_list<typename List::template select<Start + Seq>...>;
		};
		template <typename List, size_t Start, size_t Length>
		struct MUU_EMPTY_BASES type_list_slicer_<List, Start, Length, type_list_slicer_spec::arbitrary_range>
			: type_list_index_sequence_slicer_<List, Start, make_index_sequence<Length>>
		{};

		// slicer - first element
		template <typename T0, typename... T, size_t Start, size_t Length>
		struct type_list_slicer_<type_list<T0, T...>, Start, Length, type_list_slicer_spec::first>
		{
			using type = type_list<T0>;
		};

		// slicer - all (range is entire list)
		template <typename List, size_t Start, size_t Length>
		struct type_list_slicer_<List, Start, Length, type_list_slicer_spec::all>
		{
			using type = List;
		};

		// slicer - skip jumbo pages (multiples of type_list_jumbo_page_size)
#if MUU_HAS_JUMBO_PAGES
		// clang-format off
		template <
			typename T0,   typename T1,   typename T2,   typename T3,   typename T4,   typename T5,   typename T6,   typename T7,
			typename T8,   typename T9,   typename T10,  typename T11,  typename T12,  typename T13,  typename T14,  typename T15,
			typename T16,  typename T17,  typename T18,  typename T19,  typename T20,  typename T21,  typename T22,  typename T23,
			typename T24,  typename T25,  typename T26,  typename T27,  typename T28,  typename T29,  typename T30,  typename T31,
			typename T32,  typename T33,  typename T34,  typename T35,  typename T36,  typename T37,  typename T38,  typename T39,
			typename T40,  typename T41,  typename T42,  typename T43,  typename T44,  typename T45,  typename T46,  typename T47,
			typename T48,  typename T49,  typename T50,  typename T51,  typename T52,  typename T53,  typename T54,  typename T55,
			typename T56,  typename T57,  typename T58,  typename T59,  typename T60,  typename T61,  typename T62,  typename T63,
			typename T64,  typename T65,  typename T66,  typename T67,  typename T68,  typename T69,  typename T70,  typename T71,
			typename T72,  typename T73,  typename T74,  typename T75,  typename T76,  typename T77,  typename T78,  typename T79,
			typename T80,  typename T81,  typename T82,  typename T83,  typename T84,  typename T85,  typename T86,  typename T87,
			typename T88,  typename T89,  typename T90,  typename T91,  typename T92,  typename T93,  typename T94,  typename T95,
			typename T96,  typename T97,  typename T98,  typename T99,  typename T100, typename T101, typename T102, typename T103,
			typename T104, typename T105, typename T106, typename T107, typename T108, typename T109, typename T110, typename T111,
			typename T112, typename T113, typename T114, typename T115, typename T116, typename T117, typename T118, typename T119,
			typename T120, typename T121, typename T122, typename T123, typename T124, typename T125, typename T126, typename T127,
			typename... T, size_t Start, size_t Length
		>
		struct type_list_slicer_<
			type_list<
				T0,   T1,   T2,   T3,   T4,   T5,   T6,   T7,
				T8,   T9,   T10,  T11,  T12,  T13,  T14,  T15,
				T16,  T17,  T18,  T19,  T20,  T21,  T22,  T23,
				T24,  T25,  T26,  T27,  T28,  T29,  T30,  T31,
				T32,  T33,  T34,  T35,  T36,  T37,  T38,  T39,
				T40,  T41,  T42,  T43,  T44,  T45,  T46,  T47,
				T48,  T49,  T50,  T51,  T52,  T53,  T54,  T55,
				T56,  T57,  T58,  T59,  T60,  T61,  T62,  T63,
				T64,  T65,  T66,  T67,  T68,  T69,  T70,  T71,
				T72,  T73,  T74,  T75,  T76,  T77,  T78,  T79,
				T80,  T81,  T82,  T83,  T84,  T85,  T86,  T87,
				T88,  T89,  T90,  T91,  T92,  T93,  T94,  T95,
				T96,  T97,  T98,  T99,  T100, T101, T102, T103,
				T104, T105, T106, T107, T108, T109, T110, T111,
				T112, T113, T114, T115, T116, T117, T118, T119,
				T120, T121, T122, T123, T124, T125, T126, T127,
				T...
			>,
			Start, Length, type_list_slicer_spec::skip_jumbo_pages
		>
		{
			using type = typename type_list<T...>::template slice<Start - type_list_jumbo_page_size, Length>;
		};
		// clang-format on
#endif // MUU_HAS_JUMBO_PAGES

#if MUU_HAS_TYPE_PACK_ELEMENT

		// slicer - selecting arbitrary single element spans using a compiler builtin
		template <typename... T, size_t Start>
		struct type_list_slicer_<type_list<T...>, Start, 1, type_list_slicer_spec::single_compiler_builtin>
		{
			using type = type_list<__type_pack_element<Start, T...>>;
		};

#else

		// slicer - skip pages (multiples of type_list_page_size)
		template <typename List, size_t Start, size_t Length>
		struct type_list_slicer_<List, Start, Length, type_list_slicer_spec::skip_pages>
		{
			// repeatedly invokes the skip_first_N specialization until Start is < type_list_page_size
			using type = typename type_list_slicer_<List,
													type_list_page_size,
													List::length - type_list_page_size,
													type_list_slicer_spec::skip_first_N>::type //
				::template slice<Start - type_list_page_size, Length>;
		};

		// slicer - low-index elements
	#if 1
		#define MAKE_SINGLE_ELEMENT_SLICER_1(N, N0, ...)                                                               \
			template <typename T##N0 MUU_FOR_EACH(MUU_MAKE_INDEXED_TPARAM, __VA_ARGS__), typename... T>                \
			struct type_list_slicer_<type_list<T##N0 MUU_FOR_EACH(MUU_MAKE_INDEXED_TARG, __VA_ARGS__), T...>,          \
									 N,                                                                                \
									 1,                                                                                \
									 type_list_slicer_spec::single_low_index>                                          \
			{                                                                                                          \
				using type = type_list<T##N>;                                                                          \
			}
		#define MAKE_SINGLE_ELEMENT_SLICER(...) MUU_FOR_EACH_FORCE_UNROLL(MAKE_SINGLE_ELEMENT_SLICER_1(__VA_ARGS__))

		template <typename T0, typename T1, typename... T>
		struct type_list_slicer_<type_list<T0, T1, T...>, 1, 1, type_list_slicer_spec::single_low_index>
		{
			using type = type_list<T1>;
		};

		MAKE_SINGLE_ELEMENT_SLICER(2, 0, 1, 2);
		MAKE_SINGLE_ELEMENT_SLICER(3, 0, 1, 2, 3);
		MAKE_SINGLE_ELEMENT_SLICER(4, 0, 1, 2, 3, 4);
		MAKE_SINGLE_ELEMENT_SLICER(5, 0, 1, 2, 3, 4, 5);
		MAKE_SINGLE_ELEMENT_SLICER(6, 0, 1, 2, 3, 4, 5, 6);
		MAKE_SINGLE_ELEMENT_SLICER(7, MUU_0_TO_7);
		#if MUU_TYPE_LIST_PAGE_SIZE > 8
		MAKE_SINGLE_ELEMENT_SLICER(8, MUU_0_TO_7, 8);
		MAKE_SINGLE_ELEMENT_SLICER(9, MUU_0_TO_7, 8, 9);
		MAKE_SINGLE_ELEMENT_SLICER(10, MUU_0_TO_7, 8, 9, 10);
		MAKE_SINGLE_ELEMENT_SLICER(11, MUU_0_TO_7, 8, 9, 10, 11);
		MAKE_SINGLE_ELEMENT_SLICER(12, MUU_0_TO_7, 8, 9, 10, 11, 12);
		MAKE_SINGLE_ELEMENT_SLICER(13, MUU_0_TO_7, 8, 9, 10, 11, 12, 13);
		MAKE_SINGLE_ELEMENT_SLICER(14, MUU_0_TO_7, 8, 9, 10, 11, 12, 13, 14);
		MAKE_SINGLE_ELEMENT_SLICER(15, MUU_0_TO_15);
		#endif
		#if MUU_TYPE_LIST_PAGE_SIZE > 16
		MAKE_SINGLE_ELEMENT_SLICER(16, MUU_0_TO_15, 16);
		MAKE_SINGLE_ELEMENT_SLICER(17, MUU_0_TO_15, 16, 17);
		MAKE_SINGLE_ELEMENT_SLICER(18, MUU_0_TO_15, 16, 17, 18);
		MAKE_SINGLE_ELEMENT_SLICER(19, MUU_0_TO_15, 16, 17, 18, 19);
		MAKE_SINGLE_ELEMENT_SLICER(20, MUU_0_TO_15, 16, 17, 18, 19, 20);
		MAKE_SINGLE_ELEMENT_SLICER(21, MUU_0_TO_15, 16, 17, 18, 19, 20, 21);
		MAKE_SINGLE_ELEMENT_SLICER(22, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22);
		MAKE_SINGLE_ELEMENT_SLICER(23, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23);
		MAKE_SINGLE_ELEMENT_SLICER(24, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24);
		MAKE_SINGLE_ELEMENT_SLICER(25, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25);
		MAKE_SINGLE_ELEMENT_SLICER(26, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26);
		MAKE_SINGLE_ELEMENT_SLICER(27, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27);
		MAKE_SINGLE_ELEMENT_SLICER(28, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28);
		MAKE_SINGLE_ELEMENT_SLICER(29, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29);
		MAKE_SINGLE_ELEMENT_SLICER(30, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30);
		MAKE_SINGLE_ELEMENT_SLICER(31, MUU_0_TO_31);
		#endif
		#if MUU_TYPE_LIST_PAGE_SIZE > 32
		MAKE_SINGLE_ELEMENT_SLICER(32, MUU_0_TO_31, 32);
		MAKE_SINGLE_ELEMENT_SLICER(33, MUU_0_TO_31, 32, 33);
		MAKE_SINGLE_ELEMENT_SLICER(34, MUU_0_TO_31, 32, 33, 34);
		MAKE_SINGLE_ELEMENT_SLICER(35, MUU_0_TO_31, 32, 33, 34, 35);
		MAKE_SINGLE_ELEMENT_SLICER(36, MUU_0_TO_31, 32, 33, 34, 35, 36);
		MAKE_SINGLE_ELEMENT_SLICER(37, MUU_0_TO_31, 32, 33, 34, 35, 36, 37);
		MAKE_SINGLE_ELEMENT_SLICER(38, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38);
		MAKE_SINGLE_ELEMENT_SLICER(39, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39);
		MAKE_SINGLE_ELEMENT_SLICER(40, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40);
		MAKE_SINGLE_ELEMENT_SLICER(41, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41);
		MAKE_SINGLE_ELEMENT_SLICER(42, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42);
		MAKE_SINGLE_ELEMENT_SLICER(43, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43);
		MAKE_SINGLE_ELEMENT_SLICER(44, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44);
		MAKE_SINGLE_ELEMENT_SLICER(45, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45);
		MAKE_SINGLE_ELEMENT_SLICER(46, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46);
		MAKE_SINGLE_ELEMENT_SLICER(47, MUU_0_TO_47);
		#endif
		#if MUU_TYPE_LIST_PAGE_SIZE > 48
		MAKE_SINGLE_ELEMENT_SLICER(48, MUU_0_TO_47, 48);
		MAKE_SINGLE_ELEMENT_SLICER(49, MUU_0_TO_47, 48, 49);
		MAKE_SINGLE_ELEMENT_SLICER(50, MUU_0_TO_47, 48, 49, 50);
		MAKE_SINGLE_ELEMENT_SLICER(51, MUU_0_TO_47, 48, 49, 50, 51);
		MAKE_SINGLE_ELEMENT_SLICER(52, MUU_0_TO_47, 48, 49, 50, 51, 52);
		MAKE_SINGLE_ELEMENT_SLICER(53, MUU_0_TO_47, 48, 49, 50, 51, 52, 53);
		MAKE_SINGLE_ELEMENT_SLICER(54, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54);
		MAKE_SINGLE_ELEMENT_SLICER(55, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55);
		MAKE_SINGLE_ELEMENT_SLICER(56, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56);
		MAKE_SINGLE_ELEMENT_SLICER(57, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57);
		MAKE_SINGLE_ELEMENT_SLICER(58, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58);
		MAKE_SINGLE_ELEMENT_SLICER(59, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59);
		MAKE_SINGLE_ELEMENT_SLICER(60, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60);
		MAKE_SINGLE_ELEMENT_SLICER(61, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61);
		MAKE_SINGLE_ELEMENT_SLICER(62, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62);
		MAKE_SINGLE_ELEMENT_SLICER(63, MUU_0_TO_63);
		#endif

		#undef MAKE_SINGLE_ELEMENT_SLICER_1
		#undef MAKE_SINGLE_ELEMENT_SLICER
	#endif

		// slicer - prefixes
	#if 1
		#define MAKE_PREFIX_SLICER_1(N0, ...)                                                                          \
			template <typename T##N0 MUU_FOR_EACH(MUU_MAKE_INDEXED_TPARAM, __VA_ARGS__), typename... T>                \
			struct type_list_slicer_<type_list<T##N0 MUU_FOR_EACH(MUU_MAKE_INDEXED_TARG, __VA_ARGS__), T...>,          \
									 0,                                                                                \
									 MUU_COUNT_VA_ARGS(__VA_ARGS__) + 1,                                               \
									 type_list_slicer_spec::prefix>                                                    \
			{                                                                                                          \
				using type = type_list<T0 MUU_FOR_EACH(MUU_MAKE_INDEXED_TARG, __VA_ARGS__)>;                           \
			}
		#define MAKE_PREFIX_SLICER(...) MUU_FOR_EACH_FORCE_UNROLL(MAKE_PREFIX_SLICER_1(__VA_ARGS__))

		template <typename T0, typename T1, typename... T>
		struct type_list_slicer_<type_list<T0, T1, T...>, 0, 2, type_list_slicer_spec::prefix>
		{
			using type = type_list<T0, T1>;
		};

		MAKE_PREFIX_SLICER(0, 1, 2);
		MAKE_PREFIX_SLICER(0, 1, 2, 3);
		MAKE_PREFIX_SLICER(0, 1, 2, 3, 4);
		MAKE_PREFIX_SLICER(0, 1, 2, 3, 4, 5);
		MAKE_PREFIX_SLICER(0, 1, 2, 3, 4, 5, 6);
		MAKE_PREFIX_SLICER(MUU_0_TO_7);
		#if MUU_TYPE_LIST_PAGE_SIZE > 8
		MAKE_PREFIX_SLICER(MUU_0_TO_7, 8);
		MAKE_PREFIX_SLICER(MUU_0_TO_7, 8, 9);
		MAKE_PREFIX_SLICER(MUU_0_TO_7, 8, 9, 10);
		MAKE_PREFIX_SLICER(MUU_0_TO_7, 8, 9, 10, 11);
		MAKE_PREFIX_SLICER(MUU_0_TO_7, 8, 9, 10, 11, 12);
		MAKE_PREFIX_SLICER(MUU_0_TO_7, 8, 9, 10, 11, 12, 13);
		MAKE_PREFIX_SLICER(MUU_0_TO_7, 8, 9, 10, 11, 12, 13, 14);
		MAKE_PREFIX_SLICER(MUU_0_TO_15);
		#endif
		#if MUU_TYPE_LIST_PAGE_SIZE > 16
		MAKE_PREFIX_SLICER(MUU_0_TO_15, 16);
		MAKE_PREFIX_SLICER(MUU_0_TO_15, 16, 17);
		MAKE_PREFIX_SLICER(MUU_0_TO_15, 16, 17, 18);
		MAKE_PREFIX_SLICER(MUU_0_TO_15, 16, 17, 18, 19);
		MAKE_PREFIX_SLICER(MUU_0_TO_15, 16, 17, 18, 19, 20);
		MAKE_PREFIX_SLICER(MUU_0_TO_15, 16, 17, 18, 19, 20, 21);
		MAKE_PREFIX_SLICER(MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22);
		MAKE_PREFIX_SLICER(MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23);
		MAKE_PREFIX_SLICER(MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24);
		MAKE_PREFIX_SLICER(MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25);
		MAKE_PREFIX_SLICER(MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26);
		MAKE_PREFIX_SLICER(MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27);
		MAKE_PREFIX_SLICER(MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28);
		MAKE_PREFIX_SLICER(MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29);
		MAKE_PREFIX_SLICER(MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30);
		MAKE_PREFIX_SLICER(MUU_0_TO_31);
		#endif
		#if MUU_TYPE_LIST_PAGE_SIZE > 32
		MAKE_PREFIX_SLICER(MUU_0_TO_31, 32);
		MAKE_PREFIX_SLICER(MUU_0_TO_31, 32, 33);
		MAKE_PREFIX_SLICER(MUU_0_TO_31, 32, 33, 34);
		MAKE_PREFIX_SLICER(MUU_0_TO_31, 32, 33, 34, 35);
		MAKE_PREFIX_SLICER(MUU_0_TO_31, 32, 33, 34, 35, 36);
		MAKE_PREFIX_SLICER(MUU_0_TO_31, 32, 33, 34, 35, 36, 37);
		MAKE_PREFIX_SLICER(MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38);
		MAKE_PREFIX_SLICER(MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39);
		MAKE_PREFIX_SLICER(MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40);
		MAKE_PREFIX_SLICER(MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41);
		MAKE_PREFIX_SLICER(MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42);
		MAKE_PREFIX_SLICER(MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43);
		MAKE_PREFIX_SLICER(MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44);
		MAKE_PREFIX_SLICER(MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45);
		MAKE_PREFIX_SLICER(MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46);
		MAKE_PREFIX_SLICER(MUU_0_TO_47);
		#endif
		#if MUU_TYPE_LIST_PAGE_SIZE > 48
		MAKE_PREFIX_SLICER(MUU_0_TO_47, 48);
		MAKE_PREFIX_SLICER(MUU_0_TO_47, 48, 49);
		MAKE_PREFIX_SLICER(MUU_0_TO_47, 48, 49, 50);
		MAKE_PREFIX_SLICER(MUU_0_TO_47, 48, 49, 50, 51);
		MAKE_PREFIX_SLICER(MUU_0_TO_47, 48, 49, 50, 51, 52);
		MAKE_PREFIX_SLICER(MUU_0_TO_47, 48, 49, 50, 51, 52, 53);
		MAKE_PREFIX_SLICER(MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54);
		MAKE_PREFIX_SLICER(MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55);
		MAKE_PREFIX_SLICER(MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56);
		MAKE_PREFIX_SLICER(MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57);
		MAKE_PREFIX_SLICER(MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58);
		MAKE_PREFIX_SLICER(MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59);
		MAKE_PREFIX_SLICER(MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60);
		MAKE_PREFIX_SLICER(MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61);
		MAKE_PREFIX_SLICER(MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62);
		MAKE_PREFIX_SLICER(MUU_0_TO_63);
		#endif

		#undef MAKE_PREFIX_SLICER_1
		#undef MAKE_PREFIX_SLICER
	#endif

		// slicer - skip first N
	#if 1
		#define MAKE_SKIP_N_SLICER_1(N, N0, N1, ...)                                                                   \
			template <typename T##N0,                                                                                  \
					  typename T##N1 MUU_FOR_EACH(MUU_MAKE_INDEXED_TPARAM, __VA_ARGS__),                               \
					  typename... T,                                                                                   \
					  size_t Length>                                                                                   \
			struct type_list_slicer_<type_list<T##N0, T##N1 MUU_FOR_EACH(MUU_MAKE_INDEXED_TARG, __VA_ARGS__), T...>,   \
									 N,                                                                                \
									 Length,                                                                           \
									 type_list_slicer_spec::skip_first_N>                                              \
			{                                                                                                          \
				using type = typename type_list<T##N, T...>::template slice<0, Length>;                                \
			}
		#define MAKE_SKIP_N_SLICER(...) MUU_FOR_EACH_FORCE_UNROLL(MAKE_SKIP_N_SLICER_1(__VA_ARGS__))

		template <typename T0, typename T1, typename... T, size_t Length>
		struct type_list_slicer_<type_list<T0, T1, T...>, 1, Length, type_list_slicer_spec::skip_first_N>
		{
			using type = typename type_list<T1, T...>::template slice<0, Length>;
		};

		template <typename T0, typename T1, typename T2, typename... T, size_t Length>
		struct type_list_slicer_<type_list<T0, T1, T2, T...>, 2, Length, type_list_slicer_spec::skip_first_N>
		{
			using type = typename type_list<T2, T...>::template slice<0, Length>;
		};

		MAKE_SKIP_N_SLICER(3, 0, 1, 2, 3);
		MAKE_SKIP_N_SLICER(4, 0, 1, 2, 3, 4);
		MAKE_SKIP_N_SLICER(5, 0, 1, 2, 3, 4, 5);
		MAKE_SKIP_N_SLICER(6, 0, 1, 2, 3, 4, 5, 6);
		MAKE_SKIP_N_SLICER(7, MUU_0_TO_7);
		MAKE_SKIP_N_SLICER(8, MUU_0_TO_7, 8);
		#if MUU_TYPE_LIST_PAGE_SIZE > 8
		MAKE_SKIP_N_SLICER(9, MUU_0_TO_7, 8, 9);
		MAKE_SKIP_N_SLICER(10, MUU_0_TO_7, 8, 9, 10);
		MAKE_SKIP_N_SLICER(11, MUU_0_TO_7, 8, 9, 10, 11);
		MAKE_SKIP_N_SLICER(12, MUU_0_TO_7, 8, 9, 10, 11, 12);
		MAKE_SKIP_N_SLICER(13, MUU_0_TO_7, 8, 9, 10, 11, 12, 13);
		MAKE_SKIP_N_SLICER(14, MUU_0_TO_7, 8, 9, 10, 11, 12, 13, 14);
		MAKE_SKIP_N_SLICER(15, MUU_0_TO_15);
		MAKE_SKIP_N_SLICER(16, MUU_0_TO_15, 16);
		#endif
		#if MUU_TYPE_LIST_PAGE_SIZE > 16
		MAKE_SKIP_N_SLICER(17, MUU_0_TO_15, 16, 17);
		MAKE_SKIP_N_SLICER(18, MUU_0_TO_15, 16, 17, 18);
		MAKE_SKIP_N_SLICER(19, MUU_0_TO_15, 16, 17, 18, 19);
		MAKE_SKIP_N_SLICER(20, MUU_0_TO_15, 16, 17, 18, 19, 20);
		MAKE_SKIP_N_SLICER(21, MUU_0_TO_15, 16, 17, 18, 19, 20, 21);
		MAKE_SKIP_N_SLICER(22, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22);
		MAKE_SKIP_N_SLICER(23, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23);
		MAKE_SKIP_N_SLICER(24, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24);
		MAKE_SKIP_N_SLICER(25, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25);
		MAKE_SKIP_N_SLICER(26, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26);
		MAKE_SKIP_N_SLICER(27, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27);
		MAKE_SKIP_N_SLICER(28, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28);
		MAKE_SKIP_N_SLICER(29, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29);
		MAKE_SKIP_N_SLICER(30, MUU_0_TO_15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30);
		MAKE_SKIP_N_SLICER(31, MUU_0_TO_31);
		MAKE_SKIP_N_SLICER(32, MUU_0_TO_31, 32);
		#endif
		#if MUU_TYPE_LIST_PAGE_SIZE > 32
		MAKE_SKIP_N_SLICER(33, MUU_0_TO_31, 32, 33);
		MAKE_SKIP_N_SLICER(34, MUU_0_TO_31, 32, 33, 34);
		MAKE_SKIP_N_SLICER(35, MUU_0_TO_31, 32, 33, 34, 35);
		MAKE_SKIP_N_SLICER(36, MUU_0_TO_31, 32, 33, 34, 35, 36);
		MAKE_SKIP_N_SLICER(37, MUU_0_TO_31, 32, 33, 34, 35, 36, 37);
		MAKE_SKIP_N_SLICER(38, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38);
		MAKE_SKIP_N_SLICER(39, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39);
		MAKE_SKIP_N_SLICER(40, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40);
		MAKE_SKIP_N_SLICER(41, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41);
		MAKE_SKIP_N_SLICER(42, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42);
		MAKE_SKIP_N_SLICER(43, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43);
		MAKE_SKIP_N_SLICER(44, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44);
		MAKE_SKIP_N_SLICER(45, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45);
		MAKE_SKIP_N_SLICER(46, MUU_0_TO_31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46);
		MAKE_SKIP_N_SLICER(47, MUU_0_TO_47);
		MAKE_SKIP_N_SLICER(48, MUU_0_TO_47, 48);
		#endif
		#if MUU_TYPE_LIST_PAGE_SIZE > 48
		MAKE_SKIP_N_SLICER(49, MUU_0_TO_47, 48, 49);
		MAKE_SKIP_N_SLICER(50, MUU_0_TO_47, 48, 49, 50);
		MAKE_SKIP_N_SLICER(51, MUU_0_TO_47, 48, 49, 50, 51);
		MAKE_SKIP_N_SLICER(52, MUU_0_TO_47, 48, 49, 50, 51, 52);
		MAKE_SKIP_N_SLICER(53, MUU_0_TO_47, 48, 49, 50, 51, 52, 53);
		MAKE_SKIP_N_SLICER(54, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54);
		MAKE_SKIP_N_SLICER(55, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55);
		MAKE_SKIP_N_SLICER(56, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56);
		MAKE_SKIP_N_SLICER(57, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57);
		MAKE_SKIP_N_SLICER(58, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58);
		MAKE_SKIP_N_SLICER(59, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59);
		MAKE_SKIP_N_SLICER(60, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60);
		MAKE_SKIP_N_SLICER(61, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61);
		MAKE_SKIP_N_SLICER(62, MUU_0_TO_47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62);
		MAKE_SKIP_N_SLICER(63, MUU_0_TO_63);
		MAKE_SKIP_N_SLICER(64, MUU_0_TO_63, 64);
		#endif

		#undef MAKE_SKIP_N_SLICER_1
		#undef MAKE_SKIP_N_SLICER
	#endif

#endif // !MUU_HAS_TYPE_PACK_ELEMENT

		// clang-format on
	}

	template <>
	struct type_list<>
	{
		static constexpr size_t length = 0;

		// these are clearly nonsense but needed for templates to not cause substitution failure
		template <size_t Index>
		using select = typename impl::type_list_selector_<type_list<>, Index>::type;
		template <size_t Start, size_t Length = (length - Start)>
		using slice = type_list<>;
	};

	template <typename T>
	struct type_list<T>
	{
		static constexpr size_t length = 1;

		using first = T;
		using type	= first;

#if MUU_HAS_TYPE_PACK_ELEMENT
		template <size_t Index>
		using select = __type_pack_element<Index, T>;
#else
		template <size_t Index>
		using select = typename impl::type_list_selector_<type_list<T>, Index>::type;
#endif

		template <size_t Start, size_t Length = (length - Start)>
		using slice = typename impl::type_list_slicer_<type_list<T>, Start, Length>::type;
	};

	template <typename T0, typename... T>
	struct type_list<T0, T...>
	{
		static constexpr size_t length = 1 + sizeof...(T);

		using first = T0;

#if MUU_HAS_TYPE_PACK_ELEMENT
		template <size_t Index>
		using select = __type_pack_element<Index, T0, T...>;
#else
		template <size_t Index>
		using select = typename impl::type_list_selector_<type_list<T0, T...>, Index>::type;
#endif

		template <size_t Start, size_t Length = (length - Start)>
		using slice = typename impl::type_list_slicer_<type_list<T0, T...>, Start, Length>::type;
	};

	/// \endcond

#ifdef DOXYGEN

	/// \brief A 'tag' type for encoding/parameterizing lists of types (without the instantiation heft of std::tuple).
	///
	/// \detail	[set_class m-note m-success] This type is _not_ simply std::tuple without the container functionality!
	///			The underlying template machinery is highly optimized to reduce instantiation burden for even very
	///			massive type lists. Very compiler-friendly.
	///
	/// \tparam T	The list of types represented by the list.
	template <typename... T>
	struct type_list
	{
		/// \brief	The number of types in the list.
		///
		/// \detail \cpp
		/// std::cout << muu::type_list<int, float, char, void>::length << "\n";
		/// \ecpp
		/// \out
		/// 4
		/// \eout
		static constexpr size_t length = sizeof...(T);

		/// \brief The first type in the list.
		///
		/// \detail \cpp
		/// using first_type = muu::type_list<int, float, char, void>::first;
		///
		/// std::cout << "is int:   " << std::is_same_v<first_type, int> << "\n";
		/// std::cout << "is float: " << std::is_same_v<first_type, float> << "\n";
		/// std::cout << "is char:  " << std::is_same_v<first_type, char> << "\n";
		/// std::cout << "is void:  " << std::is_same_v<first_type, void> << "\n";
		/// \ecpp
		/// \out
		/// is int:   true
		/// is float: false
		/// is char:  false
		/// is void:  false
		/// \eout
		using first = POXY_IMPLEMENTATION_DETAIL;

		/// \brief Alias for #first when `length == 1`.
		/// \availability This member is only present when `length == 1`.
		using type = first;

		/// \brief Selects a single type from the list.
		///
		/// \detail \cpp
		/// using selected_type = muu::type_list<int, float, char, void>::select<2>;
		///
		/// std::cout << "is int:   " << std::is_same_v<selected_type, int> << "\n";
		/// std::cout << "is float: " << std::is_same_v<selected_type, float> << "\n";
		/// std::cout << "is char:  " << std::is_same_v<selected_type, char> << "\n";
		/// std::cout << "is void:  " << std::is_same_v<selected_type, void> << "\n";
		/// \ecpp
		/// \out
		/// is int:   false
		/// is float: false
		/// is char:  true
		/// is void:  false
		/// \eout
		template <size_t Index>
		using select = POXY_IMPLEMENTATION_DETAIL;

		/// \brief Selects a slice of types from the list.
		/// \detail \cpp
		/// using types = muu::type_list<int, float, char, void>;
		///
		/// static_assert(std::is_same_v<
		///		types::slice<2, 2>,
		///		muu::type_list<char, void>
		/// >);
		/// \ecpp
		template <size_t Start, size_t Length = (length - Start)>
		using slice = POXY_IMPLEMENTATION_DETAIL;
	};

#endif

	/// \brief A tag type for encoding/parameterizing a single type.
	template <typename T>
	using type_tag = type_list<T>;

	/** @} */ // meta
}

#undef MUU_TYPE_LIST_PAGE_SIZE
#undef MUU_HAS_JUMBO_PAGES
#undef MUU_HAS_TYPE_PACK_ELEMENT
#undef MUU_HAS_INTEGER_SEQ

#undef MUU_MAKE_INDEXED_TPARAM
#undef MUU_MAKE_INDEXED_TARG
#undef MUU_0_TO_7
#undef MUU_0_TO_15
#undef MUU_0_TO_31
#undef MUU_0_TO_47
#undef MUU_0_TO_63

#include "header_end.h"
