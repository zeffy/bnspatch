// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

/// \file
/// \brief  Contains the definition of muu::plane.

#pragma once
#include "impl/geometry_common.h"
#include "impl/header_start.h"
MUU_DISABLE_SHADOW_WARNINGS;
MUU_PRAGMA_MSVC(float_control(except, off))
MUU_PRAGMA_MSVC(float_control(precise, off))

//======================================================================================================================
// PLANE CLASS
#if 1

namespace muu
{
	MUU_ABI_VERSION_START(0);

	/// \brief A plane.
	/// \ingroup math
	///
	/// \tparam	Scalar      The plane's scalar component type. Must be a floating-point type.
	///
	/// \see [Plane](https://en.wikipedia.org/wiki/Plane_%28geometry%29)
	template <typename Scalar>
	struct MUU_TRIVIAL_ABI plane //
		MUU_HIDDEN_BASE(impl::plane_<Scalar>)
	{
		static_assert(!std::is_reference_v<Scalar>, "Plane scalar type cannot be a reference");
		static_assert(!std::is_const_v<Scalar> && !std::is_volatile_v<Scalar>,
					  "Plane scalar type cannot be const- or volatile-qualified");
		static_assert(std::is_trivially_constructible_v<
						  Scalar> && std::is_trivially_copyable_v<Scalar> && std::is_trivially_destructible_v<Scalar>,
					  "Plane scalar type must be trivially constructible, copyable and destructible");
		static_assert(is_signed<Scalar>, "Plane scalar type must be signed");
		static_assert(is_floating_point<Scalar>, "Plane scalar type must be a floating-point type");

		/// \brief The plane's scalar type.
		using scalar_type = Scalar;

		/// \brief The three-dimensional #muu::vector with the same #scalar_type as the plane.
		using vector_type = vector<scalar_type, 3>;

		/// \brief Compile-time plane constants.
		using constants = muu::constants<plane>;

	  private:
		using base = impl::plane_<Scalar>;
		static_assert(sizeof(base) == (sizeof(scalar_type) * 4), "Planes should not have padding");

		using planes			 = impl::planes_common<Scalar>;
		using triangles			 = impl::triangles_common<Scalar>;
		using collision			 = impl::collision_common<Scalar>;
		using intermediate_float = impl::promote_if_small_float<scalar_type>;
		static_assert(is_floating_point<intermediate_float>);

		using scalar_constants = muu::constants<scalar_type>;

	  public:
	#ifdef DOXYGEN

		/// \brief	The plane's normal direction.
		vector_type n;

		/// \brief	The `d` term of the plane equation.
		scalar_type d;

	#endif // DOXYGEN

	#if 1 // constructors ----------------------------------------------------------------------------------------------

		/// \brief Default constructor. Values are not initialized.
		plane() noexcept = default;

		/// \brief Copy constructor.
		MUU_NODISCARD_CTOR
		constexpr plane(const plane&) noexcept = default;

		/// \brief Copy-assigment operator.
		constexpr plane& operator=(const plane&) noexcept = default;

		/// \brief	Constructs a plane from `n` and `d` terms.
		MUU_NODISCARD_CTOR
		constexpr plane(const vector_type& n, scalar_type d) noexcept //
			: base{ n, d }
		{}

		/// \brief	Constructs a plane from a position and normal direction.
		MUU_NODISCARD_CTOR
		constexpr plane(const vector_type& position, const vector_type& direction) noexcept //
			: base{ direction, -vector_type::dot(position, direction) }
		{}

		/// \brief	Constructs a plane from three points.
		MUU_NODISCARD_CTOR
		constexpr plane(const vector_type& p1, const vector_type& p2, const vector_type& p3) noexcept //
			: plane{ p1, triangles::normal(p1, p2, p3) }
		{}

		/// \brief	Constructs a plane from a triangle.
		MUU_NODISCARD_CTOR
		explicit constexpr plane(MUU_GEOM_PARAM(triangle) tri) noexcept //
			: plane{ tri.points[0], triangles::normal(tri) }
		{}

		/// \brief	Converting constructor.
		template <typename S>
		MUU_NODISCARD_CTOR
		explicit constexpr plane(const plane<S>& p) noexcept //
			: base{ vector_type{ p.n }, static_cast<scalar_type>(p.d) }
		{}

		/// \brief Constructs a plane from an implicitly bit-castable type.
		///
		/// \tparam T	A bit-castable type.
		///
		/// \see muu::allow_implicit_bit_cast
		MUU_CONSTRAINED_TEMPLATE((allow_implicit_bit_cast<T, plane>), typename T)
		MUU_NODISCARD_CTOR
		/*implicit*/
		constexpr plane(const T& blittable) noexcept //
			: base{ muu::bit_cast<base>(blittable) }
		{
			static_assert(sizeof(T) == sizeof(base), "Bit-castable types must be the same size as the plane");
			static_assert(std::is_trivially_copyable_v<T>, "Bit-castable types must be trivially-copyable");
		}

	#endif // constructors

	#if 1 // equality --------------------------------------------------------------------------------------------------
		/// \name Equality
		/// @{

		/// \brief		Returns true if two planes are exactly equal.
		///
		/// \remarks	This is an exact check;
		///				use #approx_equal() if you want an epsilon-based "near-enough" check.
		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr bool MUU_VECTORCALL operator==(MUU_VC_PARAM(plane) lhs, const plane<T>& rhs) noexcept
		{
			return lhs.n == rhs.n && lhs.d == rhs.d;
		}

		/// \brief	Returns true if two planes are not exactly equal.
		///
		/// \remarks	This is an exact check;
		///				use #approx_equal() if you want an epsilon-based "near-enough" check.
		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr bool MUU_VECTORCALL operator!=(MUU_VC_PARAM(plane) lhs, const plane<T>& rhs) noexcept
		{
			return !(lhs == rhs);
		}

		/// \brief	Returns true if all the scalar components of a plane are exactly zero.
		///
		/// \remarks	This is an exact check;
		///				use #approx_zero() if you want an epsilon-based "near-enough" check.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL zero(MUU_VC_PARAM(plane) p) noexcept
		{
			return vector_type::zero(p.n) && p.d == scalar_constants::zero;
		}

		/// \brief	Returns true if all the scalar components of the plane are exactly zero.
		///
		/// \remarks	This is an exact check;
		///				use #approx_equal() if you want an epsilon-based "near-enough" check.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool zero() const noexcept
		{
			return zero(*this);
		}

		/// \brief	Returns true if any of the scalar components of a plane are infinity or NaN.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL infinity_or_nan(MUU_VC_PARAM(plane) p) noexcept
		{
			return vector_type::infinity_or_nan(p.n) || muu::infinity_or_nan(p.d);
		}

		/// \brief	Returns true if any of the scalar components of the plane are infinity or NaN.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool infinity_or_nan() const noexcept
		{
			return infinity_or_nan(*this);
		}

	#endif // equality

	#if 1 // approx_equal ----------------------------------------------------------------------------------------------

		/// \brief	Returns true if two planes are approximately equal.
		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL approx_equal(
			MUU_VC_PARAM(plane) p1,
			const plane<T>& p2,
			epsilon_type<scalar_type, T> epsilon = default_epsilon<scalar_type, T>) noexcept
		{
			return vector_type::approx_equal(p1.n, p2.n, epsilon) && muu::approx_equal(p1.d, p2.d, epsilon);
		}

		/// \brief	Returns true if the plane is approximately equal to another.
		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool MUU_VECTORCALL approx_equal(
			const plane<T>& p,
			epsilon_type<scalar_type, T> epsilon = default_epsilon<scalar_type, T>) const noexcept
		{
			return approx_equal(*this, p, epsilon);
		}

		/// \brief	Returns true if all the scalar components in a plane are approximately equal to zero.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL approx_zero(MUU_VC_PARAM(plane) p,
														 scalar_type epsilon = default_epsilon<scalar_type>) noexcept
		{
			return vector_type::approx_zero(p.n, epsilon) && muu::approx_zero(p.d, epsilon);
		}

		/// \brief	Returns true if all the scalar components in the plane are approximately equal to zero.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool MUU_VECTORCALL approx_zero(scalar_type epsilon = default_epsilon<scalar_type>) const noexcept
		{
			return approx_zero(*this, epsilon);
		}

		/// \brief	Returns true if a plane has approximately zero volume.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL approx_empty(MUU_VC_PARAM(plane) p,
														  scalar_type epsilon = default_epsilon<scalar_type>) noexcept
		{
			return vector_type::approx_zero(p.extents, epsilon);
		}

		/// \brief	Returns true if the plane has approximately zero volume.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool MUU_VECTORCALL approx_empty(scalar_type epsilon = default_epsilon<scalar_type>) const noexcept
		{
			return vector_type::approx_zero(base::extents, epsilon);
		}

			/// @}
	#endif // approx_equal

	#if 1 // normalization --------------------------------------------------------------------------------------------
		/// \name Normalization
		/// @{

		/// \brief		Normalizes a plane.
		///
		/// \param p	The plane to normalize.
		///
		/// \return		A normalized copy of the input plane.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr plane MUU_VECTORCALL normalize(MUU_VC_PARAM(plane) p) noexcept
		{
			const intermediate_float inv_length = intermediate_float{ 1 } / vector_type::raw_length(p.n);
			return plane{ vector_type::raw_multiply_scalar(p.n, inv_length),
						  static_cast<scalar_type>(p.d * inv_length) };
		}

		/// \brief		Normalizes the plane (in-place).
		///
		/// \return		A reference to the plane.
		constexpr plane& normalize() noexcept
		{
			return *this = normalize(*this);
		}

		/// \brief Returns true if a plane is normalized.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL normalized(MUU_VC_PARAM(plane) p) noexcept
		{
			return vector_type::normalized(p.n);
		}

		/// \brief Returns true if the plane is normalized.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool normalized() const noexcept
		{
			return vector_type::normalized(base::n);
		}

			/// @}
	#endif // normalization

	#if 1 // distance and projection -----------------------------------------------------------------------------------
		/// \name Distance and projection
		/// @{

		/// \brief	Returns the signed distance of a point from a plane.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr scalar_type MUU_VECTORCALL signed_distance(MUU_VC_PARAM(plane) p,
																	MUU_VC_PARAM(vector_type) point) noexcept
		{
			return planes::signed_distance(p.n, p.d, point);
		}

		/// \brief	Returns the signed distance of a point from the plane.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr scalar_type MUU_VECTORCALL signed_distance(MUU_VC_PARAM(vector_type) point) const noexcept
		{
			return planes::signed_distance(base::n, base::d, point);
		}

		/// \brief	Returns the unsigned distance of a point from a plane.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr scalar_type MUU_VECTORCALL distance(MUU_VC_PARAM(plane) p,
															 MUU_VC_PARAM(vector_type) point) noexcept
		{
			return planes::unsigned_distance(p.n, p.d, point);
		}

		/// \brief	Returns the unsigned distance of a point from the plane.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr scalar_type MUU_VECTORCALL distance(MUU_VC_PARAM(vector_type) point) const noexcept
		{
			return planes::unsigned_distance(base::n, base::d, point);
		}

		/// \brief	Returns the projection of a point onto a plane.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector_type MUU_VECTORCALL project(MUU_VC_PARAM(plane) p,
															MUU_VC_PARAM(vector_type) point) noexcept
		{
			return planes::project(p.n, p.d, point);
		}

		/// \brief	Returns the projection of a point onto the plane.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr vector_type MUU_VECTORCALL project(MUU_VC_PARAM(vector_type) point) const noexcept
		{
			return planes::project(base::n, base::d, point);
		}

			/// @}
	#endif // distances and projection

	#if 1 // intersection and containment ------------------------------------------------------------------------------
		/// \name Intersection and containment
		/// @{

		/// \brief	Returns true if a plane contains a point.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL contains(MUU_VC_PARAM(plane) p, MUU_VC_PARAM(vector_type) point) noexcept
		{
			return collision::plane_contains_point(p.n, p.d, point);
		}

		/// \brief	Returns true if the plane contains a point.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool MUU_VECTORCALL contains(MUU_VC_PARAM(vector_type) point) const noexcept
		{
			return collision::plane_contains_point(base::n, base::d, point);
		}

		/// \brief	Returns true if a plane intersects a bounding box.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL intersects(MUU_VC_PARAM(plane) p, MUU_GEOM_PARAM(bounding_box) bb) noexcept
		{
			return collision::aabb_intersects_plane(bb.center, bb.extents, p.n, p.d);
		}

		/// \brief	Returns true if the plane intersects a bounding box.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool MUU_VECTORCALL intersects(MUU_GEOM_PARAM(bounding_box) bb) const noexcept
		{
			return collision::aabb_intersects_plane(bb.center, bb.extents, base::n, base::d);
		}

			/// @}
	#endif // intersection and containment

	#if 1 // misc ------------------------------------------------------------------------------------------------------

		/// \brief Writes a plane out to a text stream.
		template <typename Char, typename Traits>
		friend std::basic_ostream<Char, Traits>& operator<<(std::basic_ostream<Char, Traits>& os, const plane& p)
		{
			impl::print_compound_vector(os, &p.n.x, 3_sz, true, &p.d, 1_sz, false);
			return os;
		}

	#endif // misc
	};

	/// \cond

	MUU_CONSTRAINED_TEMPLATE((all_arithmetic<N, D>), typename N, typename D)
	plane(vector<N, 3>, D)->plane<impl::highest_ranked<N, D>>;

	template <typename P, typename N>
	plane(vector<P, 3>, vector<N, 3>) -> plane<impl::highest_ranked<P, N>>;

	template <typename T, typename U, typename V>
	plane(vector<T, 3>, vector<U, 3>, vector<V, 3>) -> plane<impl::highest_ranked<T, U, V>>;

	template <typename T>
	plane(const triangle<T>&) -> plane<T>;

	/// \endcond

	MUU_ABI_VERSION_END;
}

namespace std
{
	/// \brief Specialization of std::tuple_size for muu::plane.
	template <typename Scalar>
	struct tuple_size<muu::plane<Scalar>>
	{
		static constexpr size_t value = 2;
	};

	/// \brief Specialization of std::tuple_element for muu::plane.
	template <size_t I, typename Scalar>
	struct tuple_element<I, muu::plane<Scalar>>
	{
		static_assert(I < 2);
		using type = std::conditional_t<I == 0, muu::vector<Scalar, 3>, Scalar>;
	};
}

#endif //===============================================================================================================

//======================================================================================================================
// CONSTANTS
#if 1

MUU_PUSH_PRECISE_MATH;

namespace muu
{
	/// \ingroup	constants
	/// \see		muu::plane
	///
	/// \brief		Plane constants.
	template <typename Scalar>
	struct constants<plane<Scalar>>
	{
		using scalars = constants<Scalar>;
		using vectors = constants<vector<Scalar, 3>>;

		/// \brief A plane with all members initialized to zero.
		static constexpr plane<Scalar> zero = { vectors::zero, scalars::zero };

		/// \brief The XY plane.
		static constexpr plane<Scalar> xy = { vectors::z_axis, scalars::zero };

		/// \brief The XZ plane.
		static constexpr plane<Scalar> xz = { vectors::y_axis, scalars::zero };

		/// \brief The YZ plane.
		static constexpr plane<Scalar> yz = { vectors::x_axis, scalars::zero };
	};
}

MUU_POP_PRECISE_MATH;

#endif //===============================================================================================================

//======================================================================================================================
// FREE FUNCTIONS
#if 1

namespace muu
{
	/// \ingroup		infinity_or_nan
	/// \relatesalso	muu::plane
	///
	/// \brief	Returns true if any of the scalar components of a plane are infinity or NaN.
	template <typename S>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr bool infinity_or_nan(const plane<S>& p) noexcept
	{
		return plane<S>::infinity_or_nan(p);
	}

	/// \ingroup		approx_equal
	/// \relatesalso	muu::plane
	///
	/// \brief		Returns true if two planes are approximately equal.
	template <typename S, typename T>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr bool MUU_VECTORCALL approx_equal(const plane<S>& p1,
											   const plane<T>& p2,
											   epsilon_type<S, T> epsilon = default_epsilon<S, T>) noexcept
	{
		return plane<S>::approx_equal(p1, p2, epsilon);
	}

	/// \ingroup		approx_zero
	/// \relatesalso	muu::plane
	///
	/// \brief		Returns true if all the scalar components of a plane are approximately equal to zero.
	template <typename S>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr bool MUU_VECTORCALL approx_zero(const plane<S>& p, S epsilon = default_epsilon<S>) noexcept
	{
		return plane<S>::approx_zero(p, epsilon);
	}

	/// \ingroup	normalized
	/// \relatesalso	muu::plane
	///
	/// \brief Returns true if a plane is normalized.
	template <typename S>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr bool normalized(const plane<S>& p) noexcept
	{
		return plane<S>::normalized(p);
	}
}

#endif //===============================================================================================================

#include "impl/header_end.h"
