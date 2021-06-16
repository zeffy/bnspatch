// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

/// \file
/// \brief  Contains the definition of muu::matrix.

#pragma once
#include "vector.h"
#include "quaternion.h"

MUU_DISABLE_WARNINGS;
#include <tuple>
MUU_ENABLE_WARNINGS;

#include "impl/header_start.h"
MUU_FORCE_NDEBUG_OPTIMIZATIONS;
MUU_DISABLE_SHADOW_WARNINGS;
MUU_DISABLE_SUGGEST_WARNINGS;
MUU_DISABLE_ARITHMETIC_WARNINGS;
MUU_PRAGMA_MSVC(float_control(except, off))
MUU_PRAGMA_MSVC(float_control(precise, off))

//======================================================================================================================
// IMPLEMENTATION DETAILS
#if 1

/// \cond

namespace muu::impl
{
	struct columnwise_init_tag
	{};
	struct columnwise_copy_tag
	{};
	struct row_major_tuple_tag
	{};

	MUU_ABI_VERSION_START(0);

	template <typename Scalar, size_t Rows, size_t Columns>
	struct MUU_TRIVIAL_ABI matrix_
	{
		vector<Scalar, Rows> m[Columns];

		matrix_() noexcept = default;

	  private:
	#if MUU_MSVC

		template <size_t Index>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		static constexpr vector<Scalar, Rows> fill_column_initializer_msvc(Scalar fill) noexcept
		{
			return vector<Scalar, Rows>{ fill };
		}

	#endif

	  public:
	#if MUU_MSVC

		// internal compiler error:
		// https://developercommunity2.visualstudio.com/t/C-Internal-Compiler-Error-in-constexpr/1264044

		template <size_t... ColumnIndices>
		explicit constexpr matrix_(value_fill_tag, std::index_sequence<ColumnIndices...>, Scalar fill) noexcept
			: m{ fill_column_initializer_msvc<ColumnIndices>(fill)... }
		{
			static_assert(sizeof...(ColumnIndices) <= Columns);
		}

	#else

		template <size_t... ColumnIndices>
		explicit constexpr matrix_(value_fill_tag, std::index_sequence<ColumnIndices...>, Scalar fill) noexcept
			: m{ (MUU_UNUSED(ColumnIndices), vector<Scalar, Rows>{ fill })... }
		{
			static_assert(sizeof...(ColumnIndices) <= Columns);
		}

	#endif

		template <typename... T>
		explicit constexpr matrix_(columnwise_init_tag, T... cols) noexcept //
			: m{ cols... }
		{
			static_assert(sizeof...(T) <= Columns);
		}

		template <typename T, size_t... ColumnIndices>
		explicit constexpr matrix_(columnwise_copy_tag, std::index_sequence<ColumnIndices...>, const T& cols) noexcept
			: m{ vector<Scalar, Rows>{ cols[ColumnIndices] }... }
		{
			static_assert(sizeof...(ColumnIndices) <= Columns);
		}

	  private:
		template <size_t Index, typename T>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		static constexpr decltype(auto) get_tuple_value_or_zero(const T& tpl) noexcept
		{
			if constexpr (Index < tuple_size<T>)
			{
				return get_from_tuple_like<Index>(tpl);
			}
			else
			{
				MUU_UNUSED(tpl);
				return Scalar{};
			}
		}

		template <size_t Column, typename T, size_t... RowIndices>
		MUU_NODISCARD
		MUU_ATTR(pure)
		MUU_ATTR(flatten)
		static constexpr vector<Scalar, Rows> column_from_row_major_tuple(const T& tpl,
																		  std::index_sequence<RowIndices...>) noexcept
		{
			static_assert(sizeof...(RowIndices) == Rows);

			return vector<Scalar, Rows>{ static_cast<Scalar>(
				get_tuple_value_or_zero<Column + (Columns * RowIndices)>(tpl))... };
		}

	  public:
		template <typename T, size_t... ColumnIndices>
		explicit constexpr matrix_(const T& tpl, std::index_sequence<ColumnIndices...>) noexcept
			: m{ column_from_row_major_tuple<ColumnIndices>(tpl, std::make_index_sequence<Rows>{})... }
		{
			static_assert(tuple_size<T> <= Rows * Columns);
			static_assert(sizeof...(ColumnIndices) == Columns);
		}

		template <typename T>
		explicit constexpr matrix_(row_major_tuple_tag, const T& tpl) noexcept
			: matrix_{ tpl, std::make_index_sequence<Columns>{} }
		{
			static_assert(tuple_size<T> <= Rows * Columns);
		}

		// row-major scalar constructor optimizations for some common cases

		// 2x2
		MUU_LEGACY_REQUIRES((R == 2 && C == 2), size_t R = Rows, size_t C = Columns)
		constexpr matrix_(Scalar v00, Scalar v01, Scalar v10 = Scalar{}, Scalar v11 = Scalar{}) noexcept
			MUU_REQUIRES(Rows == 2 && Columns == 2)
			: m{ { v00, v10 }, { v01, v11 } }
		{}

		// 3x3
		MUU_LEGACY_REQUIRES((R == 3 && C == 3), size_t R = Rows, size_t C = Columns)
		constexpr matrix_(Scalar v00,
						  Scalar v01,
						  Scalar v02 = Scalar{},
						  Scalar v10 = Scalar{},
						  Scalar v11 = Scalar{},
						  Scalar v12 = Scalar{},
						  Scalar v20 = Scalar{},
						  Scalar v21 = Scalar{},
						  Scalar v22 = Scalar{}) noexcept //
			MUU_REQUIRES(Rows == 3 && Columns == 3)
			: m{ { v00, v10, v20 }, { v01, v11, v21 }, { v02, v12, v22 } }
		{}

		// 3x4
		MUU_LEGACY_REQUIRES((R == 3 && C == 4), size_t R = Rows, size_t C = Columns)
		constexpr matrix_(Scalar v00,
						  Scalar v01,
						  Scalar v02 = Scalar{},
						  Scalar v03 = Scalar{},
						  Scalar v10 = Scalar{},
						  Scalar v11 = Scalar{},
						  Scalar v12 = Scalar{},
						  Scalar v13 = Scalar{},
						  Scalar v20 = Scalar{},
						  Scalar v21 = Scalar{},
						  Scalar v22 = Scalar{},
						  Scalar v23 = Scalar{}) noexcept //
			MUU_REQUIRES(Rows == 3 && Columns == 4)
			: m{ { v00, v10, v20 }, { v01, v11, v21 }, { v02, v12, v22 }, { v03, v13, v23 } }
		{}

		// 4x4
		MUU_LEGACY_REQUIRES((R == 4 && C == 4), size_t R = Rows, size_t C = Columns)
		constexpr matrix_(Scalar v00,
						  Scalar v01,
						  Scalar v02 = Scalar{},
						  Scalar v03 = Scalar{},
						  Scalar v10 = Scalar{},
						  Scalar v11 = Scalar{},
						  Scalar v12 = Scalar{},
						  Scalar v13 = Scalar{},
						  Scalar v20 = Scalar{},
						  Scalar v21 = Scalar{},
						  Scalar v22 = Scalar{},
						  Scalar v23 = Scalar{},
						  Scalar v30 = Scalar{},
						  Scalar v31 = Scalar{},
						  Scalar v32 = Scalar{},
						  Scalar v33 = Scalar{}) noexcept //
			MUU_REQUIRES(Rows == 4 && Columns == 4)
			: m{ { v00, v10, v20, v30 }, { v01, v11, v21, v31 }, { v02, v12, v22, v32 }, { v03, v13, v23, v33 } }
		{}
	};

	MUU_ABI_VERSION_END;

	template <typename Scalar, size_t Rows, size_t Columns>
	inline constexpr bool is_hva<matrix_<Scalar, Rows, Columns>> =
		can_be_hva_of<Scalar, matrix_<Scalar, Rows, Columns>>;

	template <typename Scalar, size_t Rows, size_t Columns>
	inline constexpr bool is_hva<matrix<Scalar, Rows, Columns>> = is_hva<matrix_<Scalar, Rows, Columns>>;

	template <typename Scalar, size_t Rows, size_t Columns>
	struct vectorcall_param_<matrix<Scalar, Rows, Columns>>
	{
		using type = std::conditional_t<pass_vectorcall_by_value<matrix_<Scalar, Rows, Columns>>,
										matrix<Scalar, Rows, Columns>,
										const matrix<Scalar, Rows, Columns>&>;
	};

	template <size_t Rows, size_t Columns>
	inline constexpr bool is_common_matrix = false;
	template <>
	inline constexpr bool is_common_matrix<2, 2> = true;
	template <>
	inline constexpr bool is_common_matrix<3, 3> = true;
	template <>
	inline constexpr bool is_common_matrix<3, 4> = true;
	template <>
	inline constexpr bool is_common_matrix<4, 4> = true;

	#define MAT_GET(r, c) static_cast<type>(m.m[c].template get<r>())

	template <size_t Row0 = 0, size_t Row1 = 1, size_t Col0 = 0, size_t Col1 = 1, typename T>
	MUU_NODISCARD
	MUU_ATTR(pure)
	static constexpr promote_if_small_float<typename T::determinant_type> raw_determinant_2x2(const T& m) noexcept
	{
		MUU_FMA_BLOCK;
		using type = promote_if_small_float<typename T::determinant_type>;

		return MAT_GET(Row0, Col0) * MAT_GET(Row1, Col1) - MAT_GET(Row0, Col1) * MAT_GET(Row1, Col0);
	}

	template <size_t Row0 = 0,
			  size_t Row1 = 1,
			  size_t Row2 = 2,
			  size_t Col0 = 0,
			  size_t Col1 = 1,
			  size_t Col2 = 2,
			  typename T>
	MUU_NODISCARD
	MUU_ATTR(pure)
	static constexpr promote_if_small_float<typename T::determinant_type> raw_determinant_3x3(const T& m) noexcept
	{
		MUU_FMA_BLOCK;
		using type = promote_if_small_float<typename T::determinant_type>;

		return MAT_GET(Row0, Col0) * raw_determinant_2x2<Row1, Row2, Col1, Col2>(m)
			 - MAT_GET(Row0, Col1) * raw_determinant_2x2<Row1, Row2, Col0, Col2>(m)
			 + MAT_GET(Row0, Col2) * raw_determinant_2x2<Row1, Row2, Col0, Col1>(m);
	}

	template <size_t Row0 = 0,
			  size_t Row1 = 1,
			  size_t Row2 = 2,
			  size_t Row3 = 3,
			  size_t Col0 = 0,
			  size_t Col1 = 1,
			  size_t Col2 = 2,
			  size_t Col3 = 3,
			  typename T>
	MUU_NODISCARD
	MUU_ATTR(pure)
	static constexpr promote_if_small_float<typename T::determinant_type> raw_determinant_4x4(const T& m) noexcept
	{
		MUU_FMA_BLOCK;
		using type = promote_if_small_float<typename T::determinant_type>;

		return MAT_GET(Row0, Col0) * raw_determinant_3x3<Row1, Row2, Row3, Col1, Col2, Col3>(m)
			 - MAT_GET(Row0, Col1) * raw_determinant_3x3<Row1, Row2, Row3, Col0, Col2, Col3>(m)
			 + MAT_GET(Row0, Col2) * raw_determinant_3x3<Row1, Row2, Row3, Col0, Col1, Col3>(m)
			 - MAT_GET(Row0, Col3) * raw_determinant_3x3<Row1, Row2, Row3, Col0, Col1, Col2>(m);
	}

	#undef MAT_GET
}

namespace muu
{
	template <typename From, typename Scalar, size_t Rows, size_t Columns>
	inline constexpr bool allow_implicit_bit_cast<From, impl::matrix_<Scalar, Rows, Columns>> =
		allow_implicit_bit_cast<From, matrix<Scalar, Rows, Columns>>;
}

	#define SPECIALIZED_IF(cond) , bool = (cond)

/// \endcond

	#ifndef SPECIALIZED_IF
		#define SPECIALIZED_IF(cond)
	#endif

#endif //===============================================================================================================

//======================================================================================================================
// MATRIX CLASS
#if 1

namespace muu
{
	MUU_ABI_VERSION_START(0);

	/// \brief A matrix.
	/// \ingroup math
	///
	/// \tparam	Scalar      The matrix's scalar component type.
	/// \tparam Rows		The number of rows in the matrix.
	/// \tparam Columns		The number of columns in the matrix.
	template <typename Scalar, size_t Rows, size_t Columns>
	struct MUU_TRIVIAL_ABI matrix //
		MUU_HIDDEN_BASE(impl::matrix_<Scalar, Rows, Columns>)
	{
		static_assert(!std::is_reference_v<Scalar>, "Matrix scalar type cannot be a reference");
		static_assert(!std::is_const_v<Scalar> && !std::is_volatile_v<Scalar>,
					  "Matrix scalar type cannot be const- or volatile-qualified");
		static_assert(std::is_trivially_constructible_v<Scalar>	  //
						  && std::is_trivially_copyable_v<Scalar> //
						  && std::is_trivially_destructible_v<Scalar>,
					  "Matrix scalar type must be trivially constructible, copyable and destructible");
		static_assert(Rows >= 1, "Matrices must have at least one row");
		static_assert(Columns >= 1, "Matrices must have at least one column");

		/// \brief The number of rows in the matrix.
		static constexpr size_t rows = Rows;

		/// \brief The number of columns in the matrix.
		static constexpr size_t columns = Columns;

		/// \brief The type of each scalar component stored in this matrix.
		using scalar_type = Scalar;

		/// \brief The type of one row of this matrix.
		using row_type = vector<scalar_type, columns>;

		/// \brief The type of one column of this matrix.
		using column_type = vector<scalar_type, rows>;

		/// \brief Compile-time constants for this matrix.
		using constants = muu::constants<matrix>;

		/// \brief The scalar type used for determinants. Always signed.
		using determinant_type = std::
			conditional_t<is_integral<scalar_type>, impl::highest_ranked<make_signed<scalar_type>, int>, scalar_type>;

		/// \brief The matrix type returned by inversion operations. Always floating-point.
		using inverse_type = matrix<std::conditional_t<is_integral<scalar_type>, double, scalar_type>, Rows, Columns>;

	  private:
		template <typename S, size_t R, size_t C>
		friend struct matrix;

		using base = impl::matrix_<Scalar, Rows, Columns>;
		static_assert(sizeof(base) == (sizeof(scalar_type) * Rows * Columns), "Matrices should not have padding");

		using intermediate_float = impl::promote_if_small_float<typename inverse_type::scalar_type>;
		static_assert(is_floating_point<typename inverse_type::scalar_type>);
		static_assert(is_floating_point<intermediate_float>);

		using scalar_constants = muu::constants<scalar_type>;

	  public:
	#ifdef DOXYGEN

		/// \brief The values in the matrix (stored column-major).
		column_type m[columns];

	#endif // DOXYGEN

	#if 1 // constructors ---------------------------------------------------------------------------------------------

		/// \brief Default constructor. Values are not initialized.
		matrix() noexcept = default;

		/// \brief Copy constructor.
		MUU_NODISCARD_CTOR
		constexpr matrix(const matrix&) noexcept = default;

		/// \brief Copy-assigment operator.
		constexpr matrix& operator=(const matrix&) noexcept = default;

		/// \brief	Constructs a matrix with all scalar components set to the same value.
		///
		/// \details \cpp
		/// std::cout << matrix<int, 3, 3>{ 1 } << "\n";
		/// \ecpp
		///
		/// \out
		/// {    1,    1,    1,
		///	     1,    1,    1,
		///	     1,    1,    1 }
		/// \eout
		///
		/// \param	fill	The value used to initialize each of the matrix's scalar components.
		MUU_NODISCARD_CTOR
		explicit constexpr matrix(scalar_type fill) noexcept
			: base{ impl::value_fill_tag{}, std::make_index_sequence<Columns>{}, fill }
		{}

		/// \brief	Constructs a matrix from (row-major-ordered) scalars.
		///
		/// \details \cpp
		/// // explicitly-sized matrices:
		/// std::cout << matrix<int, 2, 3>{ 1, 2, 3, 4, 5, 6 } << "\n\n";
		///
		/// // 2x2, 3x3, 3x4 and 4x4 matrices can be deduced automatically from 4, 9 12 and 16 inputs (respectively):
		/// std::cout << matrix{ 1, 2, 3, 4 } << "\n\n";
		/// std::cout << matrix{ 1, 2, 3, 4, 5, 6, 7, 8, 9 } << "\n\n";
		/// std::cout << matrix{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 } << "\n\n";
		/// std::cout << matrix{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 } << "\n\n";
		/// \ecpp
		///
		/// \out
		/// {    1,    2,    3,
		///      4,    5,    6 }
		///
		/// {    1,    2,
		///      3,    4 }
		///
		/// {    1,    2,    3,
		///      4,    5,    6,
		///      7,    8,    9 }
		///
		/// {    1,    2,    3,    4,
		///      5,    6,    7,    8,
		///      9,   10,   11,   12 }
		///
		/// {    1,    2,    3,    4,
		///      5,    6,    7,    8,
		///      9,   10,   11,   12,
		///     13,   14,   15,   16 }
		/// \eout
		///
		/// Any scalar components not covered by the constructor's parameters are initialized to zero.
		///
		/// \tparam T		Types convertible to #scalar_type.
		/// \param	v0		Initial value for the matrix's first scalar component.
		/// \param	v1		Initial value for the matrix's second scalar component.
		/// \param	vals	Initial values for the matrix's remaining scalar components.
		MUU_CONSTRAINED_TEMPLATE((!impl::is_common_matrix<Rows, Columns> //
								  && (Rows * Columns) >= sizeof...(T) + 2
								  && all_convertible_to<scalar_type, scalar_type, T...>),
								 typename... T)
		MUU_NODISCARD_CTOR
		constexpr matrix(scalar_type v0, scalar_type v1, const T&... vals) noexcept
			: base{ impl::row_major_tuple_tag{}, std::tuple<scalar_type, scalar_type, const T&...>{ v0, v1, vals... } }
		{}

		#ifndef DOXYGEN

		// row-major scalar constructor optimizations for some common cases

		// 2x2
		MUU_LEGACY_REQUIRES((R == 2 && C == 2), size_t R = Rows, size_t C = Columns)
		MUU_NODISCARD_CTOR
		constexpr matrix(scalar_type v00,
						 scalar_type v01,
						 scalar_type v10 = scalar_type{},
						 scalar_type v11 = scalar_type{}) noexcept //
			MUU_REQUIRES(Rows == 2 && Columns == 2)
			: base{ v00, v01, v10, v11 }
		{}

		// 3x3
		MUU_LEGACY_REQUIRES((R == 3 && C == 3), size_t R = Rows, size_t C = Columns)
		MUU_NODISCARD_CTOR
		constexpr matrix(scalar_type v00,
						 scalar_type v01,
						 scalar_type v02 = scalar_type{},
						 scalar_type v10 = scalar_type{},
						 scalar_type v11 = scalar_type{},
						 scalar_type v12 = scalar_type{},
						 scalar_type v20 = scalar_type{},
						 scalar_type v21 = scalar_type{},
						 scalar_type v22 = scalar_type{}) noexcept //
			MUU_REQUIRES(Rows == 3 && Columns == 3)
			: base{ v00, v01, v02, v10, v11, v12, v20, v21, v22 }
		{}

		// 3x4
		MUU_LEGACY_REQUIRES((R == 3 && C == 4), size_t R = Rows, size_t C = Columns)
		MUU_NODISCARD_CTOR
		constexpr matrix(scalar_type v00,
						 scalar_type v01,
						 scalar_type v02 = scalar_type{},
						 scalar_type v03 = scalar_type{},
						 scalar_type v10 = scalar_type{},
						 scalar_type v11 = scalar_type{},
						 scalar_type v12 = scalar_type{},
						 scalar_type v13 = scalar_type{},
						 scalar_type v20 = scalar_type{},
						 scalar_type v21 = scalar_type{},
						 scalar_type v22 = scalar_type{},
						 scalar_type v23 = scalar_type{}) noexcept //
			MUU_REQUIRES(Rows == 3 && Columns == 4)
			: base{ v00, v01, v02, v03, v10, v11, v12, v13, v20, v21, v22, v23 }
		{}

		// 4x4
		MUU_LEGACY_REQUIRES((R == 4 && C == 4), size_t R = Rows, size_t C = Columns)
		MUU_NODISCARD_CTOR
		constexpr matrix(scalar_type v00,
						 scalar_type v01,
						 scalar_type v02 = scalar_type{},
						 scalar_type v03 = scalar_type{},
						 scalar_type v10 = scalar_type{},
						 scalar_type v11 = scalar_type{},
						 scalar_type v12 = scalar_type{},
						 scalar_type v13 = scalar_type{},
						 scalar_type v20 = scalar_type{},
						 scalar_type v21 = scalar_type{},
						 scalar_type v22 = scalar_type{},
						 scalar_type v23 = scalar_type{},
						 scalar_type v30 = scalar_type{},
						 scalar_type v31 = scalar_type{},
						 scalar_type v32 = scalar_type{},
						 scalar_type v33 = scalar_type{}) noexcept //
			MUU_REQUIRES(Rows == 4 && Columns == 4)
			: base{ v00, v01, v02, v03, v10, v11, v12, v13, v20, v21, v22, v23, v30, v31, v32, v33 }
		{}

		#endif

		/// \brief Enlarging/truncating/converting constructor.
		/// \details Copies source matrix's scalar components, casting if necessary:
		/// \cpp
		/// matrix<int, 3, 3> m33 = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		/// std::cout << m33 << "\n\n";
		///
		/// matrix<int, 2, 2> m22 = { m33 };
		/// std::cout << m22 << "\n\n";
		///
		/// matrix<int, 4, 4> m44 = { m33 };
		/// std::cout << m44 << "\n\n";
		/// \ecpp
		///
		/// \out
		/// {    1,    2,    3,
		///      4,    5,    6,
		///      7,    8,    9 }
		///
		/// {    1,    2,
		///      4,    5 }
		///
		/// {    1,    2,    3,    0,
		///      4,    5,    6,    0,
		///      7,    8,    9,    0,
		///      0,    0,    0,    0 }
		/// \eout
		///
		/// Any scalar components not covered by the constructor's parameters are initialized to zero.
		///
		/// \tparam	S		Source matrix's #scalar_type.
		/// \tparam	R		Source matrix's row count.
		/// \tparam	C		Source matrix's column count.
		/// \param 	mat		Source matrix.
		template <typename S, size_t R, size_t C>
		MUU_NODISCARD_CTOR
		explicit constexpr matrix(const matrix<S, R, C>& mat) noexcept
			: base{ impl::columnwise_copy_tag{}, std::make_index_sequence<(C < Columns ? C : Columns)>{}, mat.m }
		{}

		/// \brief Constructs a matrix from an implicitly bit-castable type.
		///
		/// \tparam T	A bit-castable type.
		///
		/// \see muu::allow_implicit_bit_cast
		MUU_CONSTRAINED_TEMPLATE((allow_implicit_bit_cast<T, matrix> && !impl::is_matrix_<T>), typename T)
		MUU_NODISCARD_CTOR
		/*implicit*/
		constexpr matrix(const T& blittable) noexcept //
			: base{ muu::bit_cast<base>(blittable) }
		{
			static_assert(sizeof(T) == sizeof(base), "Bit-castable types must be the same size as the matrix");
			static_assert(std::is_trivially_copyable_v<T>, "Bit-castable types must be trivially-copyable");
		}

	  private:
		template <typename... T>
		MUU_NODISCARD_CTOR
		constexpr matrix(impl::columnwise_init_tag, T... cols) noexcept //
			: base{ impl::columnwise_init_tag{}, cols... }
		{}

	  public:
	#endif // constructors

	#if 1 // scalar component accessors -------------------------------------------------------------------------------

	  private:
		template <size_t R, size_t C, typename T>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		MUU_ATTR(flatten)
		static constexpr auto& do_get(T& mat) noexcept
		{
			static_assert(R < Rows, "Row index out of range");
			static_assert(C < Columns, "Column index out of range");

			return mat.m[C].template get<R>();
		}

		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr auto& do_lookup_operator(T& mat, size_t r, size_t c) noexcept
		{
			MUU_ASSUME(r < Rows);
			MUU_ASSUME(c < Columns);

			return mat.m[c][r];
		}

	  public:
		/// \brief Gets a reference to the scalar component at a specific row and column.
		///
		/// \tparam R	The row of the scalar component to retrieve.
		/// \tparam C	The column of the scalar component to retrieve.
		///
		/// \return  A reference to the selected scalar component.
		template <size_t R, size_t C>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		MUU_ATTR(flatten)
		constexpr const scalar_type& get() const noexcept
		{
			return do_get<R, C>(*this);
		}

		/// \brief Gets a reference to the scalar component at a specific row and column.
		///
		/// \tparam R	The row of the scalar component to retrieve.
		/// \tparam C	The column of the scalar component to retrieve.
		///
		/// \return  A reference to the selected scalar component.
		template <size_t R, size_t C>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		MUU_ATTR(flatten)
		constexpr scalar_type& get() noexcept
		{
			return do_get<R, C>(*this);
		}

		/// \brief Gets a reference to the scalar component at a specific row and column.
		///
		/// \param r	The row of the scalar component to retrieve.
		/// \param c	The column of the scalar component to retrieve.
		///
		/// \return  A reference to the selected scalar component.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr const scalar_type& operator()(size_t r, size_t c) const noexcept
		{
			return do_lookup_operator(*this, r, c);
		}

		/// \brief Gets a reference to the scalar component at a specific row and column.
		///
		/// \param r	The row of the scalar component to retrieve.
		/// \param c	The column of the scalar component to retrieve.
		///
		/// \return  A reference to the selected scalar component.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr scalar_type& operator()(size_t r, size_t c) noexcept
		{
			return do_lookup_operator(*this, r, c);
		}

		/// \brief Returns a pointer to the first scalar component in the matrix.
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		MUU_ATTR(flatten)
		constexpr const scalar_type* data() const noexcept
		{
			return &do_get<0, 0>(*this);
		}

		/// \brief Returns a pointer to the first scalar component in the matrix.
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		MUU_ATTR(flatten)
		constexpr scalar_type* data() noexcept
		{
			return &do_get<0, 0>(*this);
		}

	#endif // scalar component accessors

	#if 1 // equality -------------------------------------------------------------------------------------------------

		/// \brief		Returns true if two matrices are exactly equal.
		///
		/// \remarks	This is an exact check;
		///				use #approx_equal() if you want an epsilon-based "near-enough" check.
		MUU_CONSTRAINED_TEMPLATE((!MUU_HAS_VECTORCALL
								  || impl::pass_vectorcall_by_reference<matrix, matrix<T, Rows, Columns>>),
								 typename T)
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr bool operator==(const matrix& lhs, const matrix<T, rows, columns>& rhs) noexcept
		{
			for (size_t i = 0; i < columns; i++)
				if (lhs.m[i] != rhs.m[i])
					return false;
			return true;
		}

		#if MUU_HAS_VECTORCALL

		MUU_CONSTRAINED_TEMPLATE((impl::pass_vectorcall_by_value<matrix, matrix<T, Rows, Columns>>), typename T)
		MUU_NODISCARD
		MUU_ATTR(const)
		friend constexpr bool MUU_VECTORCALL operator==(matrix lhs, matrix<T, rows, columns> rhs) noexcept
		{
			for (size_t i = 0; i < columns; i++)
				if (lhs.m[i] != rhs.m[i])
					return false;
			return true;
		}

		#endif // MUU_HAS_VECTORCALL

		/// \brief	Returns true if two matrices are not exactly equal.
		///
		/// \remarks	This is an exact check;
		///				use #approx_equal() if you want an epsilon-based "near-enough" check.
		MUU_CONSTRAINED_TEMPLATE((!MUU_HAS_VECTORCALL
								  || impl::pass_vectorcall_by_reference<matrix, matrix<T, Rows, Columns>>),
								 typename T)
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr bool operator!=(const matrix& lhs, const matrix<T, rows, columns>& rhs) noexcept
		{
			return !(lhs == rhs);
		}

		#if MUU_HAS_VECTORCALL

		MUU_CONSTRAINED_TEMPLATE((impl::pass_vectorcall_by_value<matrix, matrix<T, Rows, Columns>>), typename T)
		MUU_NODISCARD
		MUU_ATTR(const)
		friend constexpr bool operator!=(matrix lhs, matrix<T, rows, columns> rhs) noexcept
		{
			return !(lhs == rhs);
		}

		#endif // MUU_HAS_VECTORCALL

		/// \brief	Returns true if all the scalar components of a matrix are exactly zero.
		///
		/// \remarks	This is an exact check;
		///				use #approx_zero() if you want an epsilon-based "near-enough" check.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL zero(MUU_VC_PARAM(matrix) m) noexcept
		{
			for (size_t i = 0; i < columns; i++)
				if (!column_type::zero(m.m[i]))
					return false;
			return true;
		}

		/// \brief	Returns true if all the scalar components of the matrix are exactly zero.
		///
		/// \remarks	This is an exact check;
		///				use #approx_zero() if you want an epsilon-based "near-enough" check.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool zero() const noexcept
		{
			return zero(*this);
		}

		/// \brief	Returns true if any of the scalar components of a matrix are infinity or NaN.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL infinity_or_nan(MUU_VC_PARAM(matrix) m) noexcept
		{
			if constexpr (is_floating_point<scalar_type>)
			{
				for (size_t i = 0; i < columns; i++)
					if (column_type::infinity_or_nan(m.m[i]))
						return true;
				return false;
			}
			else
			{
				MUU_UNUSED(m);
				return false;
			}
		}

		/// \brief	Returns true if any of the scalar components of the matrix are infinity or NaN.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool infinity_or_nan() const noexcept
		{
			if constexpr (is_floating_point<scalar_type>)
				return infinity_or_nan(*this);
			else
				return false;
		}

	#endif // equality

	#if 1 // approx_equal ---------------------------------------------------------------------------------------------

		/// \brief	Returns true if two matrices are approximately equal.
		///
		/// \availability	This function is only available when at least one of #scalar_type
		///					and `T` is a floating-point type.
		MUU_CONSTRAINED_TEMPLATE((any_floating_point<Scalar, T> //
								  && (!MUU_HAS_VECTORCALL
									  || impl::pass_vectorcall_by_reference<matrix, matrix<T, Rows, Columns>>)),
								 typename T)
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL approx_equal(
			const matrix& m1,
			const matrix<T, rows, columns>& m2,
			epsilon_type<scalar_type, T> epsilon = default_epsilon<scalar_type, T>) noexcept
		{
			for (size_t i = 0; i < columns; i++)
				if (!column_type::approx_equal(m1.m[i], m2.m[i], epsilon))
					return false;
			return true;
		}

		#if MUU_HAS_VECTORCALL

		MUU_CONSTRAINED_TEMPLATE((any_floating_point<Scalar, T> //
								  && impl::pass_vectorcall_by_value<matrix, matrix<T, Rows, Columns>>),
								 typename T)
		MUU_NODISCARD
		MUU_ATTR(const)
		static constexpr bool MUU_VECTORCALL approx_equal(
			matrix m1,
			matrix<T, rows, columns> m2,
			epsilon_type<scalar_type, T> epsilon = default_epsilon<scalar_type, T>) noexcept
		{
			for (size_t i = 0; i < columns; i++)
				if (!column_type::approx_equal(m1.m[i], m2.m[i], epsilon))
					return false;
			return true;
		}

		#endif // MUU_HAS_VECTORCALL

		/// \brief	Returns true if the matrix is approximately equal to another.
		///
		/// \availability	This function is only available when at least one of #scalar_type
		///					and `T` is a floating-point type.
		MUU_CONSTRAINED_TEMPLATE((any_floating_point<Scalar, T> //
								  && (!MUU_HAS_VECTORCALL
									  || impl::pass_vectorcall_by_reference<matrix<T, Rows, Columns>>)),
								 typename T)
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool MUU_VECTORCALL approx_equal(
			const matrix<T, rows, columns>& m,
			epsilon_type<scalar_type, T> epsilon = default_epsilon<scalar_type, T>) const noexcept
		{
			return approx_equal(*this, m, epsilon);
		}

		#if MUU_HAS_VECTORCALL

		MUU_CONSTRAINED_TEMPLATE((any_floating_point<Scalar, T> //
								  && impl::pass_vectorcall_by_value<matrix<T, Rows, Columns>>),
								 typename T)
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr bool MUU_VECTORCALL approx_equal(
			matrix<T, rows, columns> m,
			epsilon_type<scalar_type, T> epsilon = default_epsilon<scalar_type, T>) const noexcept
		{
			return approx_equal(*this, m, epsilon);
		}

		#endif // MUU_HAS_VECTORCALL

		/// \brief	Returns true if all the scalar components in a matrix are approximately equal to zero.
		///
		/// \availability	This function is only available when #scalar_type is a floating-point type.
		MUU_LEGACY_REQUIRES(is_floating_point<T>, typename T = Scalar)
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL approx_zero(MUU_VC_PARAM(matrix) m,
														 scalar_type epsilon = default_epsilon<scalar_type>) noexcept
			MUU_REQUIRES(is_floating_point<Scalar>)
		{
			for (size_t i = 0; i < columns; i++)
				if (!column_type::approx_zero(m.m[i], epsilon))
					return false;
			return true;
		}

		/// \brief	Returns true if all the scalar components in the matrix are approximately equal to zero.
		///
		/// \availability	This function is only available when #scalar_type is a floating-point type.
		MUU_LEGACY_REQUIRES(is_floating_point<T>, typename T = Scalar)
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool MUU_VECTORCALL approx_zero(scalar_type epsilon = default_epsilon<scalar_type>) const noexcept
			MUU_REQUIRES(is_floating_point<Scalar>)
		{
			return approx_zero(*this, epsilon);
		}

	#endif // approx_equal

	#if 1 // addition -------------------------------------------------------------------------------------------------

		/// \brief Returns the componentwise addition of two matrices.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr matrix MUU_VECTORCALL operator+(MUU_VC_PARAM(matrix) lhs, MUU_VC_PARAM(matrix) rhs) noexcept
		{
			matrix out{ lhs };
			MUU_PRAGMA_MSVC(omp simd)
			for (size_t i = 0; i < columns; i++)
				out.m[i] += rhs.m[i];
			return out;
		}

		/// \brief Componentwise adds another matrix to this one.
		constexpr matrix& MUU_VECTORCALL operator+=(MUU_VC_PARAM(matrix) rhs) noexcept
		{
			MUU_PRAGMA_MSVC(omp simd)
			for (size_t i = 0; i < columns; i++)
				base::m[i] += rhs.m[i];
			return *this;
		}

		/// \brief Returns a componentwise copy of a matrix.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr matrix operator+() const noexcept
		{
			return *this;
		}

	#endif // addition

	#if 1 // subtraction
		  // -------------------------------------------------------------------------------------------------

		/// \brief Returns the componentwise subtraction of two matrices.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr matrix MUU_VECTORCALL operator-(MUU_VC_PARAM(matrix) lhs, MUU_VC_PARAM(matrix) rhs) noexcept
		{
			matrix out{ lhs };
			MUU_PRAGMA_MSVC(omp simd)
			for (size_t i = 0; i < columns; i++)
				out.m[i] -= rhs.m[i];
			return out;
		}

		/// \brief Componentwise subtracts another matrix from this one.
		constexpr matrix& MUU_VECTORCALL operator-=(MUU_VC_PARAM(matrix) rhs) noexcept
		{
			MUU_PRAGMA_MSVC(omp simd)
			for (size_t i = 0; i < columns; i++)
				base::m[i] -= rhs.m[i];
			return *this;
		}

		/// \brief Returns a componentwise negation of a matrix.
		MUU_LEGACY_REQUIRES(is_signed<T>, typename T = Scalar)
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr matrix operator-() const noexcept MUU_REQUIRES(is_signed<Scalar>)
		{
			matrix out{ *this };
			MUU_PRAGMA_MSVC(omp simd)
			for (size_t i = 0; i < columns; i++)
				out.m[i] = -out.m[i];
			return out;
		}

	#endif // subtraction

	#if 1 // multiplication -------------------------------------------------------------------------------------------

		/// \brief Multiplies two matrices.
		///
		/// \tparam C The number of columns in the RHS matrix.
		/// \param lhs  The LHS matrix.
		/// \param rhs  The RHS matrix.
		///
		/// \return  The result of `lhs * rhs`.
		template <size_t C>
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr matrix<scalar_type, rows, C> MUU_VECTORCALL operator*(
			MUU_VC_PARAM(matrix) lhs,
			const matrix<scalar_type, columns, C>& rhs) noexcept
		{
			using result_type = matrix<scalar_type, Rows, C>;
			using type		  = impl::highest_ranked<
				   typename column_type::product_type,
				   std::conditional_t<is_floating_point<scalar_type>, intermediate_float, scalar_type>>;

		#define MULT_DOT(row, col, idx)                                                                                \
			static_cast<type>(lhs.m[idx].template get<row>()) * static_cast<type>(rhs.m[col].template get<idx>())

			// common square cases are manually unrolled
			if constexpr (Rows == 2 && Columns == 2 && C == 2)
			{
				MUU_FMA_BLOCK;

				return result_type{ impl::columnwise_init_tag{},
									column_type{ static_cast<scalar_type>(MULT_DOT(0, 0, 0) + MULT_DOT(0, 0, 1)),
												 static_cast<scalar_type>(MULT_DOT(1, 0, 0) + MULT_DOT(1, 0, 1)) },
									column_type{ static_cast<scalar_type>(MULT_DOT(0, 1, 0) + MULT_DOT(0, 1, 1)),
												 static_cast<scalar_type>(MULT_DOT(1, 1, 0) + MULT_DOT(1, 1, 1)) } };
			}
			else if constexpr (Rows == 3 && Columns == 3 && C == 3)
			{
				MUU_FMA_BLOCK;

				return result_type{
					impl::columnwise_init_tag{},
					column_type{ static_cast<scalar_type>(MULT_DOT(0, 0, 0) + MULT_DOT(0, 0, 1) + MULT_DOT(0, 0, 2)),
								 static_cast<scalar_type>(MULT_DOT(1, 0, 0) + MULT_DOT(1, 0, 1) + MULT_DOT(1, 0, 2)),
								 static_cast<scalar_type>(MULT_DOT(2, 0, 0) + MULT_DOT(2, 0, 1) + MULT_DOT(2, 0, 2)) },
					column_type{ static_cast<scalar_type>(MULT_DOT(0, 1, 0) + MULT_DOT(0, 1, 1) + MULT_DOT(0, 1, 2)),
								 static_cast<scalar_type>(MULT_DOT(1, 1, 0) + MULT_DOT(1, 1, 1) + MULT_DOT(1, 1, 2)),
								 static_cast<scalar_type>(MULT_DOT(2, 1, 0) + MULT_DOT(2, 1, 1) + MULT_DOT(2, 1, 2)) },
					column_type{ static_cast<scalar_type>(MULT_DOT(0, 2, 0) + MULT_DOT(0, 2, 1) + MULT_DOT(0, 2, 2)),
								 static_cast<scalar_type>(MULT_DOT(1, 2, 0) + MULT_DOT(1, 2, 1) + MULT_DOT(1, 2, 2)),
								 static_cast<scalar_type>(MULT_DOT(2, 2, 0) + MULT_DOT(2, 2, 1) + MULT_DOT(2, 2, 2)) }

				};
			}
			else if constexpr (Rows == 4 && Columns == 4 && C == 4)
			{
				MUU_FMA_BLOCK;

				return result_type{ impl::columnwise_init_tag{},
									column_type{ static_cast<scalar_type>(MULT_DOT(0, 0, 0) + MULT_DOT(0, 0, 1)
																		  + MULT_DOT(0, 0, 2) + MULT_DOT(0, 0, 3)),
												 static_cast<scalar_type>(MULT_DOT(1, 0, 0) + MULT_DOT(1, 0, 1)
																		  + MULT_DOT(1, 0, 2) + MULT_DOT(1, 0, 3)),
												 static_cast<scalar_type>(MULT_DOT(2, 0, 0) + MULT_DOT(2, 0, 1)
																		  + MULT_DOT(2, 0, 2) + MULT_DOT(2, 0, 3)),
												 static_cast<scalar_type>(MULT_DOT(3, 0, 0) + MULT_DOT(3, 0, 1)
																		  + MULT_DOT(3, 0, 2) + MULT_DOT(3, 0, 3)) },
									column_type{ static_cast<scalar_type>(MULT_DOT(0, 1, 0) + MULT_DOT(0, 1, 1)
																		  + MULT_DOT(0, 1, 2) + MULT_DOT(0, 1, 3)),
												 static_cast<scalar_type>(MULT_DOT(1, 1, 0) + MULT_DOT(1, 1, 1)
																		  + MULT_DOT(1, 1, 2) + MULT_DOT(1, 1, 3)),
												 static_cast<scalar_type>(MULT_DOT(2, 1, 0) + MULT_DOT(2, 1, 1)
																		  + MULT_DOT(2, 1, 2) + MULT_DOT(2, 1, 3)),
												 static_cast<scalar_type>(MULT_DOT(3, 1, 0) + MULT_DOT(3, 1, 1)
																		  + MULT_DOT(3, 1, 2) + MULT_DOT(3, 1, 3)) },
									column_type{ static_cast<scalar_type>(MULT_DOT(0, 2, 0) + MULT_DOT(0, 2, 1)
																		  + MULT_DOT(0, 2, 2) + MULT_DOT(0, 2, 3)),
												 static_cast<scalar_type>(MULT_DOT(1, 2, 0) + MULT_DOT(1, 2, 1)
																		  + MULT_DOT(1, 2, 2) + MULT_DOT(1, 2, 3)),
												 static_cast<scalar_type>(MULT_DOT(2, 2, 0) + MULT_DOT(2, 2, 1)
																		  + MULT_DOT(2, 2, 2) + MULT_DOT(2, 2, 3)),
												 static_cast<scalar_type>(MULT_DOT(3, 2, 0) + MULT_DOT(3, 2, 1)
																		  + MULT_DOT(3, 2, 2) + MULT_DOT(3, 2, 3)) },
									column_type{ static_cast<scalar_type>(MULT_DOT(0, 3, 0) + MULT_DOT(0, 3, 1)
																		  + MULT_DOT(0, 3, 2) + MULT_DOT(0, 3, 3)),
												 static_cast<scalar_type>(MULT_DOT(1, 3, 0) + MULT_DOT(1, 3, 1)
																		  + MULT_DOT(1, 3, 2) + MULT_DOT(1, 3, 3)),
												 static_cast<scalar_type>(MULT_DOT(2, 3, 0) + MULT_DOT(2, 3, 1)
																		  + MULT_DOT(2, 3, 2) + MULT_DOT(2, 3, 3)),
												 static_cast<scalar_type>(MULT_DOT(3, 3, 0) + MULT_DOT(3, 3, 1)
																		  + MULT_DOT(3, 3, 2) + MULT_DOT(3, 3, 3)) } };
			}
			else
			{
				result_type out;
				for (size_t out_r = 0; out_r < Rows; out_r++)
				{
					for (size_t out_c = 0; out_c < C; out_c++)
					{
						MUU_FMA_BLOCK;

						auto val = static_cast<type>(lhs(out_r, 0)) * static_cast<type>(rhs(0, out_c));

						MUU_PRAGMA_MSVC(omp simd)
						for (size_t r = 1; r < Columns; r++)
							val += static_cast<type>(lhs(out_r, r)) * static_cast<type>(rhs(r, out_c));

						out(out_r, out_c) = static_cast<scalar_type>(val);
					}
				}
				return out;
			}

		#undef MULT_DOT
		}

		/// \brief Multiplies this matrix with another and assigns the result.
		///
		/// \availability	This function is only available when the matrix is square.
		MUU_LEGACY_REQUIRES(R == C, size_t R = Rows, size_t C = Columns)
		constexpr matrix& MUU_VECTORCALL operator*=(MUU_VC_PARAM(matrix) rhs) noexcept MUU_REQUIRES(Rows == Columns)
		{
			return *this = *this * rhs;
		}

		/// \brief Multiplies a matrix and a column vector.
		///
		/// \param lhs  The LHS matrix.
		/// \param rhs  The RHS column vector.
		///
		/// \return  The result of `lhs * rhs`.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr column_type MUU_VECTORCALL operator*(MUU_VC_PARAM(matrix) lhs,
															  MUU_VC_PARAM(vector<scalar_type, columns>) rhs) noexcept
		{
			using type = impl::highest_ranked<
				typename column_type::product_type,
				std::conditional_t<is_floating_point<scalar_type>, intermediate_float, scalar_type>>;

		#define MULT_COL(row, col, vec_elem)                                                                           \
			static_cast<type>(lhs.m[col].template get<row>()) * static_cast<type>(rhs.vec_elem)

			// common square cases are manually unrolled
			if constexpr (Rows == 2 && Columns == 2)
			{
				MUU_FMA_BLOCK;

				return column_type{ static_cast<scalar_type>(MULT_COL(0, 0, x) + MULT_COL(0, 1, y)),
									static_cast<scalar_type>(MULT_COL(1, 0, x) + MULT_COL(1, 1, y)) };
			}
			else if constexpr (Rows == 3 && Columns == 3)
			{
				MUU_FMA_BLOCK;

				return column_type{ static_cast<scalar_type>(MULT_COL(0, 0, x) + MULT_COL(0, 1, y) + MULT_COL(0, 2, z)),
									static_cast<scalar_type>(MULT_COL(1, 0, x) + MULT_COL(1, 1, y) + MULT_COL(1, 2, z)),
									static_cast<scalar_type>(MULT_COL(2, 0, x) + MULT_COL(2, 1, y)
															 + MULT_COL(2, 2, z)) };
			}
			else if constexpr (Rows == 4 && Columns == 4)
			{
				MUU_FMA_BLOCK;

				return column_type{ static_cast<scalar_type>(MULT_COL(0, 0, x) + MULT_COL(0, 1, y) + MULT_COL(0, 2, z)
															 + MULT_COL(0, 3, w)),
									static_cast<scalar_type>(MULT_COL(1, 0, x) + MULT_COL(1, 1, y) + MULT_COL(1, 2, z)
															 + MULT_COL(1, 3, w)),
									static_cast<scalar_type>(MULT_COL(2, 0, x) + MULT_COL(2, 1, y) + MULT_COL(2, 2, z)
															 + MULT_COL(2, 3, w)),
									static_cast<scalar_type>(MULT_COL(3, 0, x) + MULT_COL(3, 1, y) + MULT_COL(3, 2, z)
															 + MULT_COL(3, 3, w)) };
			}
			else
			{
				column_type out;
				for (size_t out_r = 0; out_r < Rows; out_r++)
				{
					MUU_FMA_BLOCK;

					auto val = static_cast<type>(lhs(out_r, 0)) * static_cast<type>(rhs.template get<0>());

					MUU_PRAGMA_MSVC(omp simd)
					for (size_t c = 1; c < Columns; c++)
						val += static_cast<type>(lhs(out_r, c)) * static_cast<type>(rhs[c]);

					out[out_r] = static_cast<scalar_type>(val);
				}
				return out;
			}

		#undef MULT_COL
		}

		/// \brief Multiplies a row vector and a matrix.
		///
		/// \param lhs  The LHS row vector.
		/// \param rhs  The RHS matrix.
		///
		/// \return  The result of `lhs * rhs`.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr row_type MUU_VECTORCALL operator*(MUU_VC_PARAM(vector<scalar_type, rows>) lhs,
														   MUU_VC_PARAM(matrix) rhs) noexcept
		{
			using type = impl::highest_ranked<
				typename column_type::product_type,
				std::conditional_t<is_floating_point<scalar_type>, intermediate_float, scalar_type>>;

		#define MULT_ROW(row, col, vec_elem)                                                                           \
			static_cast<type>(lhs.vec_elem) * static_cast<type>(rhs.template get<row, col>())

			// unroll the common square cases
			if constexpr (Rows == 2 && Columns == 2)
			{
				MUU_FMA_BLOCK;

				return row_type{ static_cast<scalar_type>(MULT_ROW(0, 0, x) + MULT_ROW(1, 0, y)),
								 static_cast<scalar_type>(MULT_ROW(0, 1, x) + MULT_ROW(1, 1, y)) };
			}
			else if constexpr (Rows == 3 && Columns == 3)
			{
				MUU_FMA_BLOCK;

				return row_type{ static_cast<scalar_type>(MULT_ROW(0, 0, x) + MULT_ROW(1, 0, y) + MULT_ROW(2, 0, z)),
								 static_cast<scalar_type>(MULT_ROW(0, 1, x) + MULT_ROW(1, 1, y) + MULT_ROW(2, 1, z)),
								 static_cast<scalar_type>(MULT_ROW(0, 2, x) + MULT_ROW(1, 2, y) + MULT_ROW(2, 2, z)) };
			}
			else if constexpr (Rows == 4 && Columns == 4)
			{
				MUU_FMA_BLOCK;

				return row_type{ static_cast<scalar_type>(MULT_ROW(0, 0, x) + MULT_ROW(1, 0, y) + MULT_ROW(2, 0, z)
														  + MULT_ROW(3, 0, w)),
								 static_cast<scalar_type>(MULT_ROW(0, 1, x) + MULT_ROW(1, 1, y) + MULT_ROW(2, 1, z)
														  + MULT_ROW(3, 1, w)),
								 static_cast<scalar_type>(MULT_ROW(0, 2, x) + MULT_ROW(1, 2, y) + MULT_ROW(2, 2, z)
														  + MULT_ROW(3, 2, w)),
								 static_cast<scalar_type>(MULT_ROW(0, 3, x) + MULT_ROW(1, 3, y) + MULT_ROW(2, 3, z)
														  + MULT_ROW(3, 3, w)) };
			}
			else
			{
				row_type out;
				for (size_t out_col = 0; out_col < Columns; out_col++)
				{
					MUU_FMA_BLOCK;

					auto val = static_cast<type>(lhs.template get<0>()) * static_cast<type>(rhs(0, out_col));

					MUU_PRAGMA_MSVC(omp simd)
					for (size_t r = 1; r < Rows; r++)
						val += static_cast<type>(lhs[r]) * static_cast<type>(rhs(r, out_col));

					out[out_col] = static_cast<scalar_type>(val);
				}
				return out;
			}

		#undef MULT_ROW
		}

		/// \brief Returns the componentwise multiplication of a matrix and a scalar.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr matrix MUU_VECTORCALL operator*(MUU_VC_PARAM(matrix) lhs, scalar_type rhs) noexcept
		{
			matrix out{ lhs };
			out *= rhs;
			return out;
		}

		/// \brief Returns the componentwise multiplication of a matrix and a scalar.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr matrix MUU_VECTORCALL operator*(scalar_type lhs, MUU_VC_PARAM(matrix) rhs) noexcept
		{
			return rhs * lhs;
		}

		/// \brief Componentwise multiplies this matrix by a scalar.
		constexpr matrix& MUU_VECTORCALL operator*=(scalar_type rhs) noexcept
		{
			using type = impl::highest_ranked<
				typename column_type::product_type,
				std::conditional_t<is_floating_point<scalar_type>, intermediate_float, scalar_type>>;

			if constexpr (std::is_same_v<type, scalar_type>)
			{
				for (auto& col : base::m)
					col.raw_multiply_assign_scalar(rhs);
			}
			else
			{
				const auto rhs_ = static_cast<type>(rhs);
				for (auto& col : base::m)
					col.raw_multiply_assign_scalar(rhs_);
			}

			return *this;
		}

	#endif // multiplication

	#if 1 // division -------------------------------------------------------------------------------------------------

		/// \brief Returns the componentwise multiplication of a matrix by a scalar.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr matrix MUU_VECTORCALL operator/(MUU_VC_PARAM(matrix) lhs, scalar_type rhs) noexcept
		{
			matrix out{ lhs };
			out /= rhs;
			return out;
		}

		/// \brief Componentwise multiplies this matrix by a scalar.
		constexpr matrix& MUU_VECTORCALL operator/=(scalar_type rhs) noexcept
		{
			using type = impl::highest_ranked<
				typename column_type::product_type,
				std::conditional_t<is_floating_point<scalar_type>, intermediate_float, scalar_type>>;

			if constexpr (is_floating_point<type>)
			{
				const auto rhs_ = type{ 1 } / static_cast<type>(rhs);
				for (auto& col : base::m)
					col.raw_multiply_assign_scalar(rhs_);
			}
			else if constexpr (std::is_same_v<type, scalar_type>)
			{
				for (auto& col : base::m)
					col.raw_divide_assign_scalar(rhs);
			}
			else
			{
				const auto rhs_ = static_cast<type>(rhs);
				for (auto& col : base::m)
					col.raw_divide_assign_scalar(rhs_);
			}
			return *this;
		}

	#endif // division

	#if 1 // transposition --------------------------------------------------------------------------------------------

		/// \brief	Returns a transposed copy of a matrix.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr matrix<scalar_type, columns, rows> MUU_VECTORCALL transpose(MUU_VC_PARAM(matrix) m) noexcept
		{
			using result_type	= matrix<scalar_type, columns, rows>;
			using result_column = vector<scalar_type, columns>;

		#define MAT_GET(r, c) m.m[c].template get<r>()

			// common square cases are manually unrolled
			if constexpr (Rows == 2 && Columns == 2)
			{
				return result_type{
					impl::columnwise_init_tag{},
					result_column{ MAT_GET(0, 0), MAT_GET(0, 1) },
					result_column{ MAT_GET(1, 0), MAT_GET(1, 1) },
				};
			}
			else if constexpr (Rows == 3 && Columns == 3)
			{
				return result_type{
					impl::columnwise_init_tag{},
					result_column{ MAT_GET(0, 0), MAT_GET(0, 1), MAT_GET(0, 2) },
					result_column{ MAT_GET(1, 0), MAT_GET(1, 1), MAT_GET(1, 2) },
					result_column{ MAT_GET(2, 0), MAT_GET(2, 1), MAT_GET(2, 2) },
				};
			}
			else if constexpr (Rows == 4 && Columns == 4)
			{
				return result_type{
					impl::columnwise_init_tag{},
					result_column{ MAT_GET(0, 0), MAT_GET(0, 1), MAT_GET(0, 2), MAT_GET(0, 3) },
					result_column{ MAT_GET(1, 0), MAT_GET(1, 1), MAT_GET(1, 2), MAT_GET(1, 3) },
					result_column{ MAT_GET(2, 0), MAT_GET(2, 1), MAT_GET(2, 2), MAT_GET(2, 3) },
					result_column{ MAT_GET(3, 0), MAT_GET(3, 1), MAT_GET(3, 2), MAT_GET(3, 3) },
				};
			}
			else
			{
				result_type out;
				for (size_t c = 0; c < Columns; c++)
				{
					auto& col = m.m[c];
					MUU_PRAGMA_MSVC(omp simd)
					for (size_t r = 0; r < Rows; r++)
						out.m[r][c] = col[r];
				}
				return out;
			}

		#undef MAT_GET
		}

		/// \brief	Transposes the matrix (in-place).
		///
		/// \availability	This function is only available when the matrix is square.
		MUU_LEGACY_REQUIRES(R == C, size_t R = Rows, size_t C = Columns)
		constexpr matrix& transpose() noexcept MUU_REQUIRES(Rows == Columns)
		{
			return *this = transpose(*this);
		}

	#endif // transposition

	#if 1 // inverse & determinant ------------------------------------------------------------------------------------

		/// \brief	Calculates the determinant of a matrix.
		///
		/// \availability	This function is only available when the matrix is square
		///					and has at most 4 rows and columns.
		MUU_LEGACY_REQUIRES(R == C && C <= 4, size_t R = Rows, size_t C = Columns)
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr determinant_type MUU_VECTORCALL determinant(MUU_VC_PARAM(matrix) m) noexcept
			MUU_REQUIRES(Rows == Columns && Columns <= 4)
		{
			if constexpr (Columns == 1)
				return static_cast<determinant_type>(m.m[0].x);
			if constexpr (Columns == 2)
				return static_cast<determinant_type>(impl::raw_determinant_2x2(m));
			if constexpr (Columns == 3)
				return static_cast<determinant_type>(impl::raw_determinant_3x3(m));
			if constexpr (Columns == 4)
				return static_cast<determinant_type>(impl::raw_determinant_4x4(m));
		}

		/// \brief	Calculates the determinant of a matrix.
		///
		/// \availability	This function is only available when the matrix is square
		///					and has at most 4 rows and columns.
		MUU_LEGACY_REQUIRES(R == C && C <= 4, size_t R = Rows, size_t C = Columns)
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr determinant_type determinant() noexcept MUU_REQUIRES(Rows == Columns && Columns <= 4)
		{
			return determinant(*this);
		}

		/// \brief	Returns the inverse of a matrix.
		///
		/// \availability	This function is only available when the matrix is square
		///					and has at most 4 rows and columns.
		MUU_LEGACY_REQUIRES(R == C && C <= 4, size_t R = Rows, size_t C = Columns)
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr inverse_type MUU_VECTORCALL invert(MUU_VC_PARAM(matrix) m) noexcept
			MUU_REQUIRES(Rows == Columns && Columns <= 4)
		{
		#define MAT_GET(r, c) static_cast<intermediate_float>(m.m[c].template get<r>())

			using result_scalar = typename inverse_type::scalar_type;
			using result_column = typename inverse_type::column_type;

			if constexpr (Columns == 1)
			{
				return inverse_type{ impl::columnwise_init_tag{},
									 result_column{ static_cast<result_scalar>(
										 intermediate_float{ 1 } / static_cast<intermediate_float>(m.m[0].x)) } };
			}
			if constexpr (Columns == 2)
			{
				MUU_FMA_BLOCK;

				const auto det =
					intermediate_float{ 1 } / static_cast<intermediate_float>(impl::raw_determinant_2x2(m));
				return inverse_type{ impl::columnwise_init_tag{},
									 result_column{ static_cast<result_scalar>(det * MAT_GET(1, 1)),
													static_cast<result_scalar>(det * -MAT_GET(1, 0)) },
									 result_column{ static_cast<result_scalar>(det * -MAT_GET(0, 1)),
													static_cast<result_scalar>(det * MAT_GET(0, 0)) } };
			}
			if constexpr (Columns == 3)
			{
				MUU_FMA_BLOCK;

				const auto det =
					intermediate_float{ 1 } / static_cast<intermediate_float>(impl::raw_determinant_3x3(m));
				return inverse_type{
					impl::columnwise_init_tag{},
					result_column{ static_cast<result_scalar>(
									   det * (MAT_GET(1, 1) * MAT_GET(2, 2) - MAT_GET(1, 2) * MAT_GET(2, 1))),
								   static_cast<result_scalar>(
									   det * -(MAT_GET(1, 0) * MAT_GET(2, 2) - MAT_GET(1, 2) * MAT_GET(2, 0))),
								   static_cast<result_scalar>(
									   det * (MAT_GET(1, 0) * MAT_GET(2, 1) - MAT_GET(1, 1) * MAT_GET(2, 0))) },
					result_column{ static_cast<result_scalar>(
									   det * -(MAT_GET(0, 1) * MAT_GET(2, 2) - MAT_GET(0, 2) * MAT_GET(2, 1))),
								   static_cast<result_scalar>(
									   det * (MAT_GET(0, 0) * MAT_GET(2, 2) - MAT_GET(0, 2) * MAT_GET(2, 0))),
								   static_cast<result_scalar>(
									   det * -(MAT_GET(0, 0) * MAT_GET(2, 1) - MAT_GET(0, 1) * MAT_GET(2, 0))) },
					result_column{ static_cast<result_scalar>(
									   det * (MAT_GET(0, 1) * MAT_GET(1, 2) - MAT_GET(0, 2) * MAT_GET(1, 1))),
								   static_cast<result_scalar>(
									   det * -(MAT_GET(0, 0) * MAT_GET(1, 2) - MAT_GET(0, 2) * MAT_GET(1, 0))),
								   static_cast<result_scalar>(
									   det * (MAT_GET(0, 0) * MAT_GET(1, 1) - MAT_GET(0, 1) * MAT_GET(1, 0))) }
				};
			}
			if constexpr (Columns == 4)
			{
				// generated using https://github.com/willnode/N-Matrix-Programmer

				MUU_FMA_BLOCK;

				const auto A2323 = MAT_GET(2, 2) * MAT_GET(3, 3) - MAT_GET(2, 3) * MAT_GET(3, 2);
				const auto A1323 = MAT_GET(2, 1) * MAT_GET(3, 3) - MAT_GET(2, 3) * MAT_GET(3, 1);
				const auto A1223 = MAT_GET(2, 1) * MAT_GET(3, 2) - MAT_GET(2, 2) * MAT_GET(3, 1);
				const auto A0323 = MAT_GET(2, 0) * MAT_GET(3, 3) - MAT_GET(2, 3) * MAT_GET(3, 0);
				const auto A0223 = MAT_GET(2, 0) * MAT_GET(3, 2) - MAT_GET(2, 2) * MAT_GET(3, 0);
				const auto A0123 = MAT_GET(2, 0) * MAT_GET(3, 1) - MAT_GET(2, 1) * MAT_GET(3, 0);
				const auto A2313 = MAT_GET(1, 2) * MAT_GET(3, 3) - MAT_GET(1, 3) * MAT_GET(3, 2);
				const auto A1313 = MAT_GET(1, 1) * MAT_GET(3, 3) - MAT_GET(1, 3) * MAT_GET(3, 1);
				const auto A1213 = MAT_GET(1, 1) * MAT_GET(3, 2) - MAT_GET(1, 2) * MAT_GET(3, 1);
				const auto A2312 = MAT_GET(1, 2) * MAT_GET(2, 3) - MAT_GET(1, 3) * MAT_GET(2, 2);
				const auto A1312 = MAT_GET(1, 1) * MAT_GET(2, 3) - MAT_GET(1, 3) * MAT_GET(2, 1);
				const auto A1212 = MAT_GET(1, 1) * MAT_GET(2, 2) - MAT_GET(1, 2) * MAT_GET(2, 1);
				const auto A0313 = MAT_GET(1, 0) * MAT_GET(3, 3) - MAT_GET(1, 3) * MAT_GET(3, 0);
				const auto A0213 = MAT_GET(1, 0) * MAT_GET(3, 2) - MAT_GET(1, 2) * MAT_GET(3, 0);
				const auto A0312 = MAT_GET(1, 0) * MAT_GET(2, 3) - MAT_GET(1, 3) * MAT_GET(2, 0);
				const auto A0212 = MAT_GET(1, 0) * MAT_GET(2, 2) - MAT_GET(1, 2) * MAT_GET(2, 0);
				const auto A0113 = MAT_GET(1, 0) * MAT_GET(3, 1) - MAT_GET(1, 1) * MAT_GET(3, 0);
				const auto A0112 = MAT_GET(1, 0) * MAT_GET(2, 1) - MAT_GET(1, 1) * MAT_GET(2, 0);

				const auto det =
					intermediate_float{ 1 }
					/ (MAT_GET(0, 0) * (MAT_GET(1, 1) * A2323 - MAT_GET(1, 2) * A1323 + MAT_GET(1, 3) * A1223)
					   - MAT_GET(0, 1) * (MAT_GET(1, 0) * A2323 - MAT_GET(1, 2) * A0323 + MAT_GET(1, 3) * A0223)
					   + MAT_GET(0, 2) * (MAT_GET(1, 0) * A1323 - MAT_GET(1, 1) * A0323 + MAT_GET(1, 3) * A0123)
					   - MAT_GET(0, 3) * (MAT_GET(1, 0) * A1223 - MAT_GET(1, 1) * A0223 + MAT_GET(1, 2) * A0123));

				return inverse_type{
					impl::columnwise_init_tag{},
					result_column{
						//
						static_cast<result_scalar>(
							det * (MAT_GET(1, 1) * A2323 - MAT_GET(1, 2) * A1323 + MAT_GET(1, 3) * A1223)),
						static_cast<result_scalar>(
							det * -(MAT_GET(1, 0) * A2323 - MAT_GET(1, 2) * A0323 + MAT_GET(1, 3) * A0223)),
						static_cast<result_scalar>(
							det * (MAT_GET(1, 0) * A1323 - MAT_GET(1, 1) * A0323 + MAT_GET(1, 3) * A0123)),
						static_cast<result_scalar>(
							det * -(MAT_GET(1, 0) * A1223 - MAT_GET(1, 1) * A0223 + MAT_GET(1, 2) * A0123)) },
					result_column{ //
								   static_cast<result_scalar>(
									   det * -(MAT_GET(0, 1) * A2323 - MAT_GET(0, 2) * A1323 + MAT_GET(0, 3) * A1223)),
								   static_cast<result_scalar>(
									   det * (MAT_GET(0, 0) * A2323 - MAT_GET(0, 2) * A0323 + MAT_GET(0, 3) * A0223)),
								   static_cast<result_scalar>(
									   det * -(MAT_GET(0, 0) * A1323 - MAT_GET(0, 1) * A0323 + MAT_GET(0, 3) * A0123)),
								   static_cast<result_scalar>(
									   det * (MAT_GET(0, 0) * A1223 - MAT_GET(0, 1) * A0223 + MAT_GET(0, 2) * A0123)) },
					result_column{
						//
						static_cast<result_scalar>(
							det * (MAT_GET(0, 1) * A2313 - MAT_GET(0, 2) * A1313 + MAT_GET(0, 3) * A1213)),
						static_cast<result_scalar>(
							det * -(MAT_GET(0, 0) * A2313 - MAT_GET(0, 2) * A0313 + MAT_GET(0, 3) * A0213)),
						static_cast<result_scalar>(
							det * (MAT_GET(0, 0) * A1313 - MAT_GET(0, 1) * A0313 + MAT_GET(0, 3) * A0113)),
						static_cast<result_scalar>(
							det * -(MAT_GET(0, 0) * A1213 - MAT_GET(0, 1) * A0213 + MAT_GET(0, 2) * A0113)) },
					result_column{ //
								   static_cast<result_scalar>(
									   det * -(MAT_GET(0, 1) * A2312 - MAT_GET(0, 2) * A1312 + MAT_GET(0, 3) * A1212)),
								   static_cast<result_scalar>(
									   det * (MAT_GET(0, 0) * A2312 - MAT_GET(0, 2) * A0312 + MAT_GET(0, 3) * A0212)),
								   static_cast<result_scalar>(
									   det * -(MAT_GET(0, 0) * A1312 - MAT_GET(0, 1) * A0312 + MAT_GET(0, 3) * A0112)),
								   static_cast<result_scalar>(
									   det * (MAT_GET(0, 0) * A1212 - MAT_GET(0, 1) * A0212 + MAT_GET(0, 2) * A0112)) }
				};
			}

		#undef MAT_GET
		}

		/// \brief	Inverts the matrix (in-place).
		///
		/// \availability	This function is only available when the matrix is square,
		///					has at most 4 rows and columns, and has a floating-point #scalar_type.
		MUU_LEGACY_REQUIRES((R == C && C <= 4 && is_floating_point<Scalar>), size_t R = Rows, size_t C = Columns)
		constexpr matrix& invert() noexcept MUU_REQUIRES(Rows == Columns && Columns <= 4 && is_floating_point<Scalar>)
		{
			return *this = invert(*this);
		}

	#endif // inverse & determinant

	#if 1 // orthonormalize -------------------------------------------------------------------------------------------

	  private:
		template <size_t Depth = Rows>
		static constexpr intermediate_float MUU_VECTORCALL column_dot(MUU_VC_PARAM(column_type) c1,
																	  MUU_VC_PARAM(column_type) c2) noexcept
		{
			static_assert(Depth > 0);
			static_assert(Depth <= Rows);

			using type = intermediate_float;

			if constexpr (Depth == Rows)
				return column_type::template raw_dot<type>(c1, c2);
			else
			{
				MUU_FMA_BLOCK;

				// avoid operator[] for vectors <= 4 elems (potentially slower and/or not-constexpr safe)
				type dot = static_cast<type>(c1.template get<0>()) * static_cast<type>(c2.template get<0>());
				if constexpr (Depth > 1)
					dot += static_cast<type>(c1.template get<1>()) * static_cast<type>(c2.template get<1>());
				if constexpr (Depth > 2)
					dot += static_cast<type>(c1.template get<2>()) * static_cast<type>(c2.template get<2>());
				if constexpr (Depth > 3)
					dot += static_cast<type>(c1.template get<3>()) * static_cast<type>(c2.template get<3>());
				if constexpr (Depth > 4)
				{
					MUU_PRAGMA_MSVC(omp simd)
					for (size_t i = 4; i < Depth; i++)
						dot += static_cast<type>(c1[i]) * static_cast<type>(c2[i]);
				}
				return dot;
			}
		}

		template <size_t Depth = Rows>
		static constexpr void column_normalize(column_type& c) noexcept
		{
			static_assert(Depth > 0);
			static_assert(Depth <= Rows);

			if constexpr (Depth == Rows)
				c.normalize();
			else
			{
				MUU_FMA_BLOCK;
				using type = intermediate_float;

				const type inv_len = type{ 1 } / muu::sqrt(column_dot<Depth>(c, c));

				// avoid operator[] for vectors <= 4 elems (potentially slower and/or not-constexpr safe)
				c.template get<0>() = static_cast<scalar_type>(static_cast<type>(c.template get<0>()) * inv_len);
				if constexpr (Depth > 1)
					c.template get<1>() = static_cast<scalar_type>(static_cast<type>(c.template get<1>()) * inv_len);
				if constexpr (Depth > 2)
					c.template get<2>() = static_cast<scalar_type>(static_cast<type>(c.template get<2>()) * inv_len);
				if constexpr (Depth > 3)
					c.template get<3>() = static_cast<scalar_type>(static_cast<type>(c.template get<3>()) * inv_len);
				if constexpr (Depth > 4)
				{
					MUU_PRAGMA_MSVC(omp simd)
					for (size_t i = 4; i < Depth; i++)
						c[i] = static_cast<scalar_type>(static_cast<type>(c[i]) * inv_len);
				}
			}
		}

	  public:
		/// \brief	Orthonormalizes the 3x3 part of a rotation or transformation matrix.
		///
		/// \availability	This function is only available when the matrix has 3 or 4 rows and columns
		/// 				and has a floating-point #scalar_type.
		///
		/// \see [Orthonormal basis](https://en.wikipedia.org/wiki/Orthonormal_basis)
		MUU_LEGACY_REQUIRES((is_floating_point<T> && (Rows == 3 || Rows == 4) && (Columns == 3 || Columns == 4)),
							typename T = Scalar)
		static constexpr matrix MUU_VECTORCALL orthonormalize(MUU_VC_PARAM(matrix) m) noexcept
			MUU_REQUIRES(is_floating_point<Scalar> && (Rows == 3 || Rows == 4) && (Columns == 3 || Columns == 4))
		{
			// 'modified' gram-schmidt:
			// https://fgiesen.wordpress.com/2013/06/02/modified-gram-schmidt-orthogonalization/

			matrix out{ m };

			// x-axis
			column_normalize<3>(out.m[0]);

			constexpr auto subtract_dot_mult = [](auto& out_, auto& c1, auto& c2) noexcept
			{
				MUU_FMA_BLOCK;

				const auto dot = column_dot<3>(c1, c2);
				out_.template get<0>() -= dot * c2.template get<0>();
				out_.template get<1>() -= dot * c2.template get<1>();
				out_.template get<2>() -= dot * c2.template get<2>();
			};

			// y-axis
			subtract_dot_mult(out.m[1], m.m[1], out.m[0]);
			column_normalize<3>(out.m[1]);

			// z-axis
			subtract_dot_mult(out.m[2], m.m[2], out.m[0]);
			subtract_dot_mult(out.m[2], out.m[2], out.m[1]);
			column_normalize<3>(out.m[2]);

			return out;
		}

		/// \brief	Orthonormalizes the 3x3 part of the matrix.
		///
		/// \availability	This function is only available when the matrix has 3 or 4 rows and columns
		/// 				and has a floating-point #scalar_type.
		///
		/// \see [Orthonormal basis](https://en.wikipedia.org/wiki/Orthonormal_basis)
		MUU_LEGACY_REQUIRES_2((is_floating_point<T> && (Rows == 3 || Rows == 4) && (Columns == 3 || Columns == 4)),
							  typename T = Scalar)
		constexpr matrix& orthonormalize() noexcept
			MUU_REQUIRES(is_floating_point<Scalar> && (Rows == 3 || Rows == 4) && (Columns == 3 || Columns == 4))
		{
			return *this = orthonormalize(*this);
		}

	#endif // orthonormalize

	#if 1 // misc -----------------------------------------------------------------------------------------------------

		/// \brief Writes a matrix out to a text stream.
		template <typename Char, typename Traits>
		friend std::basic_ostream<Char, Traits>& operator<<(std::basic_ostream<Char, Traits>& os, const matrix& m)
		{
			impl::print_matrix(os, &m.get<0, 0>(), Rows, Columns);
			return os;
		}

	#endif // misc
	};

	/// \cond

	MUU_CONSTRAINED_TEMPLATE(is_arithmetic<T>, typename T)
	matrix(T)->matrix<std::remove_cv_t<T>, 1, 1>;

	MUU_CONSTRAINED_TEMPLATE((all_arithmetic<T1, T2, T3, T4>), typename T1, typename T2, typename T3, typename T4)
	matrix(T1, T2, T3, T4)->matrix<impl::highest_ranked<T1, T2, T3, T4>, 2, 2>;

	MUU_CONSTRAINED_TEMPLATE((all_arithmetic<T1, T2, T3, T4, T5, T6, T7, T8, T9>),
							 typename T1,
							 typename T2,
							 typename T3,
							 typename T4,
							 typename T5,
							 typename T6,
							 typename T7,
							 typename T8,
							 typename T9)
	matrix(T1, T2, T3, T4, T5, T6, T7, T8, T9)->matrix<impl::highest_ranked<T1, T2, T3, T4, T5, T6, T7, T8, T9>, 3, 3>;

	MUU_CONSTRAINED_TEMPLATE((all_arithmetic<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12>),
							 typename T1,
							 typename T2,
							 typename T3,
							 typename T4,
							 typename T5,
							 typename T6,
							 typename T7,
							 typename T8,
							 typename T9,
							 typename T10,
							 typename T11,
							 typename T12)
	matrix(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12)
		->matrix<impl::highest_ranked<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12>, 3, 4>;

	MUU_CONSTRAINED_TEMPLATE((all_arithmetic<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16>),
							 typename T1,
							 typename T2,
							 typename T3,
							 typename T4,
							 typename T5,
							 typename T6,
							 typename T7,
							 typename T8,
							 typename T9,
							 typename T10,
							 typename T11,
							 typename T12,
							 typename T13,
							 typename T14,
							 typename T15,
							 typename T16)
	matrix(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16)
		->matrix<impl::highest_ranked<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16>, 4, 4>;

	/// \endcond

	MUU_ABI_VERSION_END;
}

#endif //===============================================================================================================

//======================================================================================================================
// CONSTANTS
#if 1

MUU_PUSH_PRECISE_MATH;

namespace muu
{
	namespace impl
	{
		/// \cond

		template <template <typename, size_t, size_t> typename Matrix, typename Scalar, size_t Rows, size_t Columns>
		MUU_NODISCARD
		MUU_CONSTEVAL
		Matrix<Scalar, Rows, Columns> make_identity_matrix() noexcept
		{
			using scalars = constants<Scalar>;
			Matrix<Scalar, Rows, Columns> m{ scalars::zero };
			m.template get<0, 0>() = scalars::one;
			if constexpr (Rows > 1 && Columns > 1)
				m.template get<1, 1>() = scalars::one;
			if constexpr (Rows > 2 && Columns > 2)
				m.template get<2, 2>() = scalars::one;
			if constexpr (Rows > 3 && Columns > 3)
				m.template get<3, 3>() = scalars::one;
			if constexpr (Rows > 4 && Columns > 4)
			{
				for (size_t i = 4; i < muu::min(Rows, Columns); i++)
					m(i, i) = scalars::one;
			}
			return m;
		}

		template <template <typename, size_t, size_t> typename Matrix, typename Scalar, size_t Rows, size_t Columns>
		MUU_NODISCARD
		MUU_CONSTEVAL
		Matrix<Scalar, Rows, Columns> make_rotation_matrix(Scalar xx,
														   Scalar yx,
														   Scalar zx,
														   Scalar xy,
														   Scalar yy,
														   Scalar zy,
														   Scalar xz,
														   Scalar yz,
														   Scalar zz) noexcept
		{
			auto m				   = make_identity_matrix<Matrix, Scalar, Rows, Columns>();
			m.template get<0, 0>() = xx;
			m.template get<1, 0>() = xy;
			m.template get<2, 0>() = xz;
			m.template get<0, 1>() = yx;
			m.template get<1, 1>() = yy;
			m.template get<2, 1>() = yz;
			m.template get<0, 2>() = zx;
			m.template get<1, 2>() = zy;
			m.template get<2, 2>() = zz;
			return m;
		}

		template <typename Scalar, size_t Rows, size_t Columns>
		struct integer_limits<matrix<Scalar, Rows, Columns>>
		{
			using type	  = matrix<Scalar, Rows, Columns>;
			using scalars = integer_limits<Scalar>;

			static constexpr type lowest  = type{ scalars::lowest };
			static constexpr type highest = type{ scalars::highest };
		};

		template <typename Scalar, size_t Rows, size_t Columns>
		struct integer_positive_constants<matrix<Scalar, Rows, Columns>>
		{
			using type	  = matrix<Scalar, Rows, Columns>;
			using scalars = integer_positive_constants<Scalar>;

			static constexpr type zero		  = type{ scalars::zero };
			static constexpr type one		  = type{ scalars::one };
			static constexpr type two		  = type{ scalars::two };
			static constexpr type three		  = type{ scalars::three };
			static constexpr type four		  = type{ scalars::four };
			static constexpr type five		  = type{ scalars::five };
			static constexpr type six		  = type{ scalars::six };
			static constexpr type seven		  = type{ scalars::seven };
			static constexpr type eight		  = type{ scalars::eight };
			static constexpr type nine		  = type{ scalars::nine };
			static constexpr type ten		  = type{ scalars::ten };
			static constexpr type one_hundred = type{ scalars::one_hundred };
		};

		template <typename Scalar, size_t Rows, size_t Columns>
		struct floating_point_traits<matrix<Scalar, Rows, Columns>> : floating_point_traits<Scalar>
		{};

		template <typename Scalar, size_t Rows, size_t Columns>
		struct floating_point_special_constants<matrix<Scalar, Rows, Columns>>
		{
			using type	  = matrix<Scalar, Rows, Columns>;
			using scalars = floating_point_special_constants<Scalar>;

			static constexpr type nan				= type{ scalars::nan };
			static constexpr type signaling_nan		= type{ scalars::signaling_nan };
			static constexpr type infinity			= type{ scalars::infinity };
			static constexpr type negative_infinity = type{ scalars::negative_infinity };
			static constexpr type negative_zero		= type{ scalars::negative_zero };
		};

		template <typename Scalar, size_t Rows, size_t Columns>
		struct floating_point_named_constants<matrix<Scalar, Rows, Columns>>
		{
			using type	  = matrix<Scalar, Rows, Columns>;
			using scalars = floating_point_named_constants<Scalar>;

			static constexpr type one_over_two		   = type{ scalars::one_over_two };
			static constexpr type two_over_three	   = type{ scalars::two_over_three };
			static constexpr type two_over_five		   = type{ scalars::two_over_five };
			static constexpr type sqrt_two			   = type{ scalars::sqrt_two };
			static constexpr type one_over_sqrt_two	   = type{ scalars::one_over_sqrt_two };
			static constexpr type one_over_three	   = type{ scalars::one_over_three };
			static constexpr type three_over_two	   = type{ scalars::three_over_two };
			static constexpr type three_over_four	   = type{ scalars::three_over_four };
			static constexpr type three_over_five	   = type{ scalars::three_over_five };
			static constexpr type sqrt_three		   = type{ scalars::sqrt_three };
			static constexpr type one_over_sqrt_three  = type{ scalars::one_over_sqrt_three };
			static constexpr type pi				   = type{ scalars::pi };
			static constexpr type one_over_pi		   = type{ scalars::one_over_pi };
			static constexpr type pi_over_two		   = type{ scalars::pi_over_two };
			static constexpr type pi_over_three		   = type{ scalars::pi_over_three };
			static constexpr type pi_over_four		   = type{ scalars::pi_over_four };
			static constexpr type pi_over_five		   = type{ scalars::pi_over_five };
			static constexpr type pi_over_six		   = type{ scalars::pi_over_six };
			static constexpr type pi_over_seven		   = type{ scalars::pi_over_seven };
			static constexpr type pi_over_eight		   = type{ scalars::pi_over_eight };
			static constexpr type sqrt_pi			   = type{ scalars::sqrt_pi };
			static constexpr type one_over_sqrt_pi	   = type{ scalars::one_over_sqrt_pi };
			static constexpr type two_pi			   = type{ scalars::two_pi };
			static constexpr type sqrt_two_pi		   = type{ scalars::sqrt_two_pi };
			static constexpr type one_over_sqrt_two_pi = type{ scalars::one_over_sqrt_two_pi };
			static constexpr type one_over_three_pi	   = type{ scalars::one_over_three_pi };
			static constexpr type three_pi_over_two	   = type{ scalars::three_pi_over_two };
			static constexpr type three_pi_over_four   = type{ scalars::three_pi_over_four };
			static constexpr type three_pi_over_five   = type{ scalars::three_pi_over_five };
			static constexpr type e					   = type{ scalars::e };
			static constexpr type one_over_e		   = type{ scalars::one_over_e };
			static constexpr type e_over_two		   = type{ scalars::e_over_two };
			static constexpr type e_over_three		   = type{ scalars::e_over_three };
			static constexpr type e_over_four		   = type{ scalars::e_over_four };
			static constexpr type e_over_five		   = type{ scalars::e_over_five };
			static constexpr type e_over_six		   = type{ scalars::e_over_six };
			static constexpr type sqrt_e			   = type{ scalars::sqrt_e };
			static constexpr type one_over_sqrt_e	   = type{ scalars::one_over_sqrt_e };
			static constexpr type phi				   = type{ scalars::phi };
			static constexpr type one_over_phi		   = type{ scalars::one_over_phi };
			static constexpr type phi_over_two		   = type{ scalars::phi_over_two };
			static constexpr type phi_over_three	   = type{ scalars::phi_over_three };
			static constexpr type phi_over_four		   = type{ scalars::phi_over_four };
			static constexpr type phi_over_five		   = type{ scalars::phi_over_five };
			static constexpr type phi_over_six		   = type{ scalars::phi_over_six };
			static constexpr type sqrt_phi			   = type{ scalars::sqrt_phi };
			static constexpr type one_over_sqrt_phi	   = type{ scalars::one_over_sqrt_phi };
			static constexpr type degrees_to_radians   = type{ scalars::degrees_to_radians };
			static constexpr type radians_to_degrees   = type{ scalars::radians_to_degrees };
		};

		template <typename Scalar,
				  size_t Rows,
				  size_t Columns,
				  int = (is_floating_point<Scalar> ? 2 : (is_signed<Scalar> ? 1 : 0))>
		struct matrix_constants_base : unsigned_integral_constants<matrix<Scalar, Rows, Columns>>
		{};
		template <typename Scalar, size_t Rows, size_t Columns>
		struct matrix_constants_base<Scalar, Rows, Columns, 1>
			: signed_integral_constants<matrix<Scalar, Rows, Columns>>
		{};
		template <typename Scalar, size_t Rows, size_t Columns>
		struct matrix_constants_base<Scalar, Rows, Columns, 2> : floating_point_constants<matrix<Scalar, Rows, Columns>>
		{};

		/// \endcond

		template <typename Scalar,
				  size_t Rows,
				  size_t Columns SPECIALIZED_IF(Rows >= 3 && Rows <= 4 && Columns >= 3 && Columns <= 4
												&& is_signed<Scalar>)>
		struct rotation_matrix_constants
		{
			using scalars = muu::constants<Scalar>;

			/// \name Rotations
			/// @{

			/// \brief A matrix encoding a rotation 90 degrees to the right.
			static constexpr matrix<Scalar, Rows, Columns> right =
				make_rotation_matrix<matrix, Scalar, Rows, Columns>(scalars::zero,
																	scalars::zero,
																	-scalars::one,
																	scalars::zero,
																	scalars::one,
																	scalars::zero,
																	scalars::one,
																	scalars::zero,
																	scalars::zero);

			/// \brief A matrix encoding a rotation 90 degrees upward.
			static constexpr matrix<Scalar, Rows, Columns> up =
				make_rotation_matrix<matrix, Scalar, Rows, Columns>(scalars::one,
																	scalars::zero,
																	scalars::zero,
																	scalars::zero,
																	scalars::zero,
																	-scalars::one,
																	scalars::zero,
																	scalars::one,
																	scalars::zero);

			/// \brief A matrix encoding a rotation 180 degrees backward.
			static constexpr matrix<Scalar, Rows, Columns> backward =
				make_rotation_matrix<matrix, Scalar, Rows, Columns>(-scalars::one,
																	scalars::zero,
																	scalars::zero,
																	scalars::zero,
																	scalars::one,
																	scalars::zero,
																	scalars::zero,
																	scalars::zero,
																	-scalars::one);

			/// \brief A matrix encoding a rotation 90 degrees to the left.
			static constexpr matrix<Scalar, Rows, Columns> left =
				make_rotation_matrix<matrix, Scalar, Rows, Columns>(scalars::zero,
																	scalars::zero,
																	scalars::one,
																	scalars::zero,
																	scalars::one,
																	scalars::zero,
																	-scalars::one,
																	scalars::zero,
																	scalars::zero);

			/// \brief A matrix encoding a rotation 90 degrees downward.
			static constexpr matrix<Scalar, Rows, Columns> down =
				make_rotation_matrix<matrix, Scalar, Rows, Columns>(scalars::one,
																	scalars::zero,
																	scalars::zero,
																	scalars::zero,
																	scalars::zero,
																	scalars::one,
																	scalars::zero,
																	-scalars::one,
																	scalars::zero);

			/// @}
		};

		/// \cond

		template <typename Scalar, size_t Rows, size_t Columns>
		struct rotation_matrix_constants<Scalar, Rows, Columns, false>
		{};

		/// \endcond
	}

	#ifdef DOXYGEN
		#define MATRIX_CONSTANTS_BASES                                                                                 \
			impl::rotation_matrix_constants<Scalar, Rows, Columns>,                                                    \
				impl::integer_limits<matrix<Scalar, Rows, Columns>>,                                                   \
				impl::integer_positive_constants<matrix<Scalar, Rows, Columns>>,                                       \
				impl::floating_point_traits<matrix<Scalar, Rows, Columns>>,                                            \
				impl::floating_point_special_constants<matrix<Scalar, Rows, Columns>>,                                 \
				impl::floating_point_named_constants<matrix<Scalar, Rows, Columns>>
	#else
		#define MATRIX_CONSTANTS_BASES                                                                                 \
			impl::rotation_matrix_constants<Scalar, Rows, Columns>, impl::matrix_constants_base<Scalar, Rows, Columns>
	#endif

	/// \brief		Matrix constants.
	///
	/// \ingroup	constants
	/// \see		muu::matrix
	template <typename Scalar, size_t Rows, size_t Columns>
	struct constants<matrix<Scalar, Rows, Columns>> : MATRIX_CONSTANTS_BASES
	{
		/// \brief The identity matrix.
		static constexpr matrix<Scalar, Rows, Columns> identity =
			impl::make_identity_matrix<matrix, Scalar, Rows, Columns>();
	};

	#undef MATRIX_CONSTANTS_BASES
}

MUU_POP_PRECISE_MATH;

#endif //===============================================================================================================

//======================================================================================================================
// FREE FUNCTIONS
#if 1

namespace muu
{
	/// \ingroup	infinity_or_nan
	/// \relatesalso	muu::matrix
	///
	/// \brief	Returns true if any of the scalar components of a matrix are infinity or NaN.
	template <typename S, size_t R, size_t C>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr bool infinity_or_nan(const matrix<S, R, C>& m) noexcept
	{
		if constexpr (is_floating_point<S>)
			return matrix<S, R, C>::infinity_or_nan(m);
		else
		{
			MUU_UNUSED(m);
			return false;
		}
	}

	/// \brief		Returns true if two matrices are approximately equal.
	///
	/// \ingroup	approx_equal
	/// \relatesalso	muu::matrix
	///
	/// \availability	This function is only available when at least one of `S` and `T` is a floating-point type.
	MUU_CONSTRAINED_TEMPLATE((any_floating_point<S, T>), typename S, typename T, size_t R, size_t C)
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr bool MUU_VECTORCALL approx_equal(const matrix<S, R, C>& m1,
											   const matrix<T, R, C>& m2,
											   epsilon_type<S, T> epsilon = default_epsilon<S, T>) noexcept
	{
		return matrix<S, R, C>::approx_equal(m1, m2, epsilon);
	}

	/// \brief		Returns true if all the scalar components of a matrix are approximately equal to zero.
	///
	/// \ingroup	approx_zero
	/// \relatesalso	muu::matrix
	///
	/// \availability	This function is only available when `S` is a floating-point type.
	MUU_CONSTRAINED_TEMPLATE(is_floating_point<S>, typename S, size_t R, size_t C)
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr bool MUU_VECTORCALL approx_zero(const matrix<S, R, C>& m, S epsilon = default_epsilon<S>) noexcept
	{
		return matrix<S, R, C>::approx_zero(m, epsilon);
	}

	/// \brief	Returns a transposed copy of a matrix.
	///
	/// \relatesalso	muu::matrix
	template <typename S, size_t R, size_t C>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr matrix<S, C, R> transpose(const matrix<S, R, C>& m) noexcept
	{
		return matrix<S, R, C>::transpose(m);
	}

	/// \brief	Calculates the determinant of a matrix.
	///
	/// \relatesalso	muu::matrix
	///
	/// \availability	This function is only available for square matrices with at most 4 rows and columns.
	MUU_CONSTRAINED_TEMPLATE(
		(R == C && R <= 4),
		typename S,
		size_t R,
		size_t C //
			MUU_HIDDEN_PARAM(typename determinant_type = typename matrix<S, R, C>::determinant_type))
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr determinant_type determinant(const matrix<S, R, C>& m) noexcept
	{
		return matrix<S, R, C>::determinant(m);
	}

	/// \brief	Returns the inverse of a matrix.
	///
	/// \relatesalso	muu::matrix
	///
	/// \availability	This function is only available for square matrices with at most 4 rows and columns.
	MUU_CONSTRAINED_TEMPLATE((R == C && R <= 4),
							 typename S,
							 size_t R,
							 size_t C //
								 MUU_HIDDEN_PARAM(typename inverse_type = typename matrix<S, R, C>::inverse_type))
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr inverse_type invert(const matrix<S, R, C>& m) noexcept
	{
		return matrix<S, R, C>::invert(m);
	}

	/// \brief	Returns a copy of a matrix with the 3x3 part orthonormalized.
	///
	/// \relatesalso	muu::matrix
	///
	/// \availability	This function is only available for matrices with 3 or 4 rows and columns
	/// 				and a floating-point scalar_type.
	///
	/// \see [Orthonormal basis](https://en.wikipedia.org/wiki/Orthonormal_basis)
	MUU_CONSTRAINED_TEMPLATE(is_floating_point<S>, typename S, size_t R, size_t C)
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr matrix<S, R, C> orthonormalize(const matrix<S, R, C>& m) noexcept
	{
		return matrix<S, R, C>::orthonormalize(m);
	}
}

#endif //===============================================================================================================

#undef SPECIALIZED_IF

MUU_RESET_NDEBUG_OPTIMIZATIONS;
#include "impl/header_end.h"
