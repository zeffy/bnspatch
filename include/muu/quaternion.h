// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

/// \file
/// \brief  Contains the definition of muu::quaternion.

#pragma once
#include "vector.h"

MUU_DISABLE_WARNINGS;
#include <iosfwd>
MUU_ENABLE_WARNINGS;

#include "impl/header_start.h"
MUU_FORCE_NDEBUG_OPTIMIZATIONS;
MUU_DISABLE_SHADOW_WARNINGS;
MUU_DISABLE_ARITHMETIC_WARNINGS;
MUU_PRAGMA_MSVC(float_control(except, off))
MUU_PRAGMA_MSVC(float_control(precise, off))

//======================================================================================================================
// IMPLEMENTATION DETAILS
#if 1

/// \cond

namespace muu::impl
{
	MUU_ABI_VERSION_START(0);

	template <typename Scalar>
	struct MUU_TRIVIAL_ABI quaternion_
	{
		Scalar s;
		vector<Scalar, 3> v;
	};

	MUU_ABI_VERSION_END;

	template <typename Scalar>
	inline constexpr bool is_hva<quaternion_<Scalar>> = can_be_hva_of<Scalar, quaternion_<Scalar>>;

	template <typename Scalar>
	inline constexpr bool is_hva<quaternion<Scalar>> = is_hva<quaternion_<Scalar>>;

	template <typename Scalar>
	struct vectorcall_param_<quaternion<Scalar>>
	{
		using type = std::
			conditional_t<pass_vectorcall_by_value<quaternion_<Scalar>>, quaternion<Scalar>, const quaternion<Scalar>&>;
	};
}

namespace muu
{
	template <typename From, typename Scalar>
	inline constexpr bool allow_implicit_bit_cast<From, impl::quaternion_<Scalar>> =
		allow_implicit_bit_cast<From, quaternion<Scalar>>;
}

/// \endcond

#endif //===============================================================================================================

//======================================================================================================================
// HELPER CLASSES
#if 1
namespace muu
{
	MUU_ABI_VERSION_START(0);

	/// \brief	An axis-angle rotation.
	/// \ingroup math
	///
	/// \tparam	Scalar	The scalar component type of the data members.
	///
	/// \see		muu::quaternion
	template <typename Scalar>
	struct MUU_TRIVIAL_ABI axis_angle_rotation
	{
		static_assert(!std::is_reference_v<Scalar>, "Axis-angle rotation scalar type cannot be a reference");
		static_assert(!std::is_const_v<Scalar> && !std::is_volatile_v<Scalar>,
					  "Axis-angle rotation scalar type cannot be const- or volatile-qualified");

		/// \brief The scalar type of the axis and angle.
		using scalar_type = Scalar;

		/// \brief	The axis being rotated around.
		vector<scalar_type, 3> axis;

		/// \brief	The angle of rotation (in radians).
		scalar_type angle;

		/// \brief Writes an axis-angle rotation out to a text stream.
		template <typename Char, typename Traits>
		friend std::basic_ostream<Char, Traits>& operator<<(std::basic_ostream<Char, Traits>& os,
															const axis_angle_rotation& rot)
		{
			impl::print_compound_vector(os, &rot.axis.x, 3_sz, true, &rot.angle, 1_sz, false);
			return os;
		}
	};

	/// \cond

	template <typename Axis, typename Angle>
	axis_angle_rotation(vector<Axis, 3>, Angle)
		-> axis_angle_rotation<impl::std_math_common_type<impl::highest_ranked<Axis, Angle>>>;

	template <typename Axis, typename Angle>
	axis_angle_rotation(std::initializer_list<Axis>, Angle)
		-> axis_angle_rotation<impl::std_math_common_type<impl::highest_ranked<Axis, Angle>>>;

	/// \endcond

	/// \brief	A set of euler angles used for rotation.
	/// \ingroup math
	///
	/// \details This type models a specific form of Euler angles relating to the Aircraft Principal Axes,
	/// 		and observes the following conventions:
	/// 		<table>
	/// 		<tr><td><strong><em>Yaw</em></strong></td>
	/// 		<td><ul>
	/// 		<li>Applied <em>first</em>
	/// 		<li>Corresponds to a rotation around the local up axis
	/// 		<li>A positive yaw means "turn the nose of the aircraft to the right"
	/// 		</ul></td></tr>
	/// 		<tr><td><strong><em>Pitch</em></strong></td>
	/// 		<td><ul>
	/// 		<li>Applied <em>second</em>
	/// 		<li>Corresponds to a rotation around the local right axis
	/// 		<li>A positive pitch means "point the nose of the aircraft up toward the sky".
	/// 		</ul></td></tr>
	/// 		<tr><td><strong><em>Roll</em></strong></td>
	/// 		<td><ul>
	/// 		<li>Applied <em>third</em>
	/// 		<li>Corresponds to a rotation around the local forward axis
	/// 		<li>A positive roll means "tilt the right wing of the aircraft toward the ground".
	/// 		</ul></td></tr>
	/// 		</table>
	///
	/// 		The angles are always in radians.
	///
	/// \tparam	Scalar	The scalar component type of the data members.
	///
	/// \see
	/// 	 - muu::quaternion
	/// 	 - [Euler Angles](https://en.wikipedia.org/wiki/Euler_angles)
	/// 	 - [Aircraft Principal Axes](https://en.wikipedia.org/wiki/Aircraft_principal_axes)
	/// 	 - [Euler Angles (math)](https://www.euclideanspace.com/maths/geometry/rotations/euler/index.htm)
	template <typename Scalar>
	struct MUU_TRIVIAL_ABI euler_rotation
	{
		static_assert(!std::is_reference_v<Scalar>, "Euler rotation scalar type cannot be a reference");
		static_assert(!std::is_const_v<Scalar> && !std::is_volatile_v<Scalar>,
					  "Euler rotation scalar type cannot be const- or volatile-qualified");

		/// \brief The scalar type of the rotation's angles.
		using scalar_type = Scalar;

		/// \brief The rotation around the local up axis (in radians).
		/// \remark A positive yaw means "turn the nose of the aircraft to the right".
		scalar_type yaw;

		/// \brief The rotation around the local right axis (in radians).
		/// \remark A positive pitch means "point the nose of the aircraft up toward the sky".
		scalar_type pitch;

		/// \brief The rotation around the local forward axis (in radians).
		/// \remark A positive roll means "tilt the aircraft so the right wing points toward the ground".
		scalar_type roll;

		/// \brief	Scales an euler rotation.
		MUU_NODISCARD
		MUU_ATTR(const)
		friend constexpr euler_rotation MUU_VECTORCALL operator*(const euler_rotation& lhs, scalar_type rhs) noexcept
		{
			return euler_rotation{ lhs.yaw * rhs, lhs.pitch * rhs, lhs.roll * rhs };
		}

		/// \brief	Scales an euler rotation.
		MUU_NODISCARD
		MUU_ATTR(const)
		friend constexpr euler_rotation MUU_VECTORCALL operator*(scalar_type lhs, const euler_rotation& rhs) noexcept
		{
			return rhs * lhs;
		}

		/// \brief	Scales an euler rotation.
		constexpr euler_rotation& MUU_VECTORCALL operator*=(scalar_type rhs) noexcept
		{
			return *this = *this * rhs;
		}

		/// \brief Writes a euler rotation out to a text stream.
		template <typename Char, typename Traits>
		friend std::basic_ostream<Char, Traits>& operator<<(std::basic_ostream<Char, Traits>& os,
															const euler_rotation& rot)
		{
			static_assert(sizeof(euler_rotation) == sizeof(scalar_type) * 3);
			impl::print_vector(os, &rot.yaw, 3u);
			return os;
		}
	};

	/// \cond

	template <typename Yaw, typename Pitch, typename Roll>
	euler_rotation(Yaw, Pitch, Roll)
		-> euler_rotation<impl::std_math_common_type<impl::highest_ranked<Yaw, Pitch, Roll>>>;

	/// \endcond

	MUU_ABI_VERSION_END;

	/// \cond
	namespace impl
	{
		template <typename Scalar>
		inline constexpr bool is_hva<axis_angle_rotation<Scalar>> = can_be_hva_of<Scalar, axis_angle_rotation<Scalar>>;

		template <typename Scalar>
		inline constexpr bool is_hva<euler_rotation<Scalar>> = can_be_hva_of<Scalar, euler_rotation<Scalar>>;
	}
	/// \endcond
}
#endif //===============================================================================================================

//======================================================================================================================
// QUATERNION CLASS
#if 1

namespace muu
{
	MUU_ABI_VERSION_START(0);

	/// \brief A quaternion.
	/// \ingroup math
	///
	/// \tparam	Scalar      The quaternion's scalar component type. Must be a floating-point type.
	///
	/// \see
	/// 	 - muu::vector
	/// 	 - muu::axis_angle_rotation
	/// 	 - muu::euler_rotation
	template <typename Scalar>
	struct MUU_TRIVIAL_ABI quaternion //
		MUU_HIDDEN_BASE(impl::quaternion_<Scalar>)
	{
		static_assert(!std::is_reference_v<Scalar>, "Quaternion scalar type cannot be a reference");
		static_assert(!std::is_const_v<Scalar> && !std::is_volatile_v<Scalar>,
					  "Quaternion scalar type cannot be const- or volatile-qualified");
		static_assert(std::is_trivially_constructible_v<Scalar>	  //
						  && std::is_trivially_copyable_v<Scalar> //
						  && std::is_trivially_destructible_v<Scalar>,
					  "Quaternion scalar type must be trivially constructible, copyable and destructible");
		static_assert(is_floating_point<Scalar>, "Quaternion scalar type must be a floating-point type");

		/// \brief The type of each scalar component stored in this quaternion.
		using scalar_type = Scalar;

		/// \brief The three-dimensional #muu::vector with the same #scalar_type as this quaternion.
		using vector_type = vector<scalar_type, 3>;

		/// \brief The #muu::axis_angle_rotation with the same #scalar_type as this quaternion.
		using axis_angle_type = axis_angle_rotation<scalar_type>;

		/// \brief The #muu::euler_rotation with the same #scalar_type as this quaternion.
		using euler_type = euler_rotation<scalar_type>;

		/// \brief Compile-time constants for this quaternion.
		using constants = muu::constants<quaternion>;

	  private:
		using base = impl::quaternion_<Scalar>;
		static_assert(sizeof(base) == (sizeof(scalar_type) * 4), "Quaternions should not have padding");

		using intermediate_float = impl::promote_if_small_float<scalar_type>;
		static_assert(is_floating_point<intermediate_float>);

		using scalar_constants = muu::constants<scalar_type>;

	  public:
	#ifdef DOXYGEN

		/// \brief The quaternion's scalar (real) part.
		scalar_type s;
		/// \brief The quaternion's vector (imaginary) part.
		vector_type v;

	#endif // DOXYGEN

	#if 1 // constructors ---------------------------------------------------------------------------------------------

		/// \brief Default constructor. Values are not initialized.
		quaternion() noexcept = default;

		/// \brief Copy constructor.
		MUU_NODISCARD_CTOR
		constexpr quaternion(const quaternion&) noexcept = default;

		/// \brief Copy-assigment operator.
		constexpr quaternion& operator=(const quaternion&) noexcept = default;

		/// \brief	Constructs a quaternion from raw scalar values.
		///
		/// \param	s	Initial value for the scalar (real) part.
		/// \param	vx	Initial value for the vector (imaginary) part's X component.
		/// \param	vy	Initial value for the vector (imaginary) part's Y component.
		/// \param	vz	Initial value for the vector (imaginary) part's Z component.
		MUU_NODISCARD_CTOR
		constexpr quaternion(scalar_type s, scalar_type vx, scalar_type vy, scalar_type vz) noexcept
			: base{ s, vector_type{ vx, vy, vz } }
		{}

		/// \brief	Constructs a quaternion from a scalar and a vector.
		///
		/// \param	s	Initial value for the scalar (real) part.
		/// \param	v	Initial value for the vector (imaginary) part.
		MUU_NODISCARD_CTOR
		constexpr quaternion(scalar_type s, const vector_type& v) noexcept //
			: base{ s, v }
		{}

		/// \brief Converting constructor.
		template <typename T>
		MUU_NODISCARD_CTOR
		explicit constexpr quaternion(const quaternion<T>& quat) noexcept
			: base{ static_cast<scalar_type>(quat.s), vector_type{ quat.v } }
		{}

		/// \brief	Constructs a quaternion from an axis-angle rotation.
		MUU_NODISCARD_CTOR
		explicit constexpr quaternion(const axis_angle_type& aa) noexcept //
			: quaternion{ from_axis_angle(aa) }
		{}

		/// \brief	Constructs a quaternion from a set of euler angles.
		MUU_NODISCARD_CTOR
		explicit constexpr quaternion(const euler_type& euler) noexcept //
			: quaternion{ from_euler(euler) }
		{}

		/// \brief Constructs a quaternion from an implicitly bit-castable type.
		///
		/// \tparam T	A bit-castable type.
		///
		/// \see muu::allow_implicit_bit_cast
		MUU_CONSTRAINED_TEMPLATE((allow_implicit_bit_cast<T, quaternion> && !impl::is_quaternion_<T>), typename T)
		MUU_NODISCARD_CTOR
		/*implicit*/
		constexpr quaternion(const T& blittable) noexcept //
			: base{ muu::bit_cast<base>(blittable) }
		{
			static_assert(sizeof(T) == sizeof(base), "Bit-castable types must be the same size as the quaternion");
			static_assert(std::is_trivially_copyable_v<T>, "Bit-castable types must be trivially-copyable");
		}

	#endif // constructors

	#if 1 // value accessors ------------------------------------------------------------------------------------------

	  private:
		template <size_t Index, typename T>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		static constexpr auto& do_get(T& quat) noexcept
		{
			static_assert(Index < 2, "Element index out of range");

			if constexpr (Index == 0)
				return quat.s;
			if constexpr (Index == 1)
				return quat.v;
		}

	  public:
		/// \brief Gets a reference to the value at a specific index.
		///
		/// \tparam Index  The index of the value to retrieve, where s == 0, v == 1.
		///
		/// \return  A reference to the selected value.
		template <size_t Index>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		MUU_ATTR(flatten)
		constexpr const auto& get() const noexcept
		{
			return do_get<Index>(*this);
		}

		/// \brief Gets a reference to the value at a specific index.
		///
		/// \tparam Index  The index of the value to retrieve, where s == 0, v == 1.
		///
		/// \return  A reference to the selected value.
		template <size_t Index>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		MUU_ATTR(flatten)
		constexpr auto& get() noexcept
		{
			return do_get<Index>(*this);
		}

		/// \brief Returns a pointer to the first scalar component in the quaternion.
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		MUU_ATTR(flatten)
		constexpr const scalar_type* data() const noexcept
		{
			return &do_get<0>(*this);
		}

		/// \brief Returns a pointer to the first scalar component in the quaternion.
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		MUU_ATTR(flatten)
		constexpr scalar_type* data() noexcept
		{
			return &do_get<0>(*this);
		}

	#endif // value accessors

	#if 1 // equality -------------------------------------------------------------------------------------------------

		/// \brief		Returns true if two quaternions are exactly equal.
		///
		/// \remarks	This is an exact check;
		///				use #approx_equal() if you want an epsilon-based "near-enough" check.
		MUU_CONSTRAINED_TEMPLATE((!MUU_HAS_VECTORCALL || impl::pass_vectorcall_by_reference<quaternion, quaternion<T>>),
								 typename T)
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr bool operator==(const quaternion& lhs, const quaternion<T>& rhs) noexcept
		{
			if constexpr (std::is_same_v<scalar_type, T>)
			{
				return lhs.s == rhs.s && lhs.v == rhs.v;
			}
			else
			{
				using type = impl::equality_check_type<scalar_type, T>;

				if (static_cast<type>(lhs.s) != static_cast<type>(rhs.s))
					return false;
				return lhs.v == rhs.v;
			}
		}

		#if MUU_HAS_VECTORCALL

		MUU_CONSTRAINED_TEMPLATE((impl::pass_vectorcall_by_value<quaternion, quaternion<T>>), typename T)
		MUU_NODISCARD
		MUU_ATTR(const)
		friend constexpr bool MUU_VECTORCALL operator==(quaternion lhs, quaternion<T> rhs) noexcept
		{
			if constexpr (std::is_same_v<scalar_type, T>)
			{
				return lhs.s == rhs.s && lhs.v == rhs.v;
			}
			else
			{
				using type = impl::equality_check_type<scalar_type, T>;

				if (static_cast<type>(lhs.s) != static_cast<type>(rhs.s))
					return false;
				return lhs.v == rhs.v;
			}
		}

		#endif // MUU_HAS_VECTORCALL

		/// \brief	Returns true if two quaternions are not exactly equal.
		///
		/// \remarks	This is an exact check;
		///				use #approx_equal() if you want an epsilon-based "near-enough" check.
		MUU_CONSTRAINED_TEMPLATE((!MUU_HAS_VECTORCALL || impl::pass_vectorcall_by_reference<quaternion, quaternion<T>>),
								 typename T)
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr bool operator!=(const quaternion& lhs, const quaternion<T>& rhs) noexcept
		{
			return !(lhs == rhs);
		}

		#if MUU_HAS_VECTORCALL

		MUU_CONSTRAINED_TEMPLATE((impl::pass_vectorcall_by_value<quaternion, quaternion<T>>), typename T)
		MUU_NODISCARD
		MUU_ATTR(const)
		friend constexpr bool MUU_VECTORCALL operator!=(quaternion lhs, quaternion<T> rhs) noexcept
		{
			return !(lhs == rhs);
		}

		#endif // MUU_HAS_VECTORCALL

		/// \brief	Returns true if all the scalar components of a quaternion are exactly zero.
		///
		/// \remarks	This is an exact check;
		///				use #approx_zero() if you want an epsilon-based "near-enough" check.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL zero(MUU_VC_PARAM(quaternion) q) noexcept
		{
			return q.s == scalar_constants::zero && vector_type::zero(q.v);
		}

		/// \brief	Returns true if all the scalar components of the quaternion are exactly zero.
		///
		/// \remarks	This is an exact check;
		///				use #approx_zero() if you want an epsilon-based "near-enough" check.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool zero() const noexcept
		{
			return zero(*this);
		}

		/// \brief	Returns true if any of the scalar components of a quaternion are infinity or NaN.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL infinity_or_nan(MUU_VC_PARAM(quaternion) q) noexcept
		{
			return muu::infinity_or_nan(q.s) || vector_type::infinity_or_nan(q.v);
		}

		/// \brief	Returns true if any of the scalar components of the quaternion are infinity or NaN.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool infinity_or_nan() const noexcept
		{
			return infinity_or_nan(*this);
		}

	#endif // equality

	#if 1 // approx_equal ---------------------------------------------------------------------------------------------

		/// \brief	Returns true if two quaternions are approximately equal.
		MUU_CONSTRAINED_TEMPLATE((!MUU_HAS_VECTORCALL || impl::pass_vectorcall_by_reference<quaternion, quaternion<T>>),
								 typename T)
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL approx_equal(
			const quaternion& q1,
			const quaternion<T>& q2,
			epsilon_type<scalar_type, T> epsilon = default_epsilon<scalar_type, T>) noexcept
		{
			if constexpr (std::is_same_v<scalar_type, T>)
			{
				return muu::approx_equal(q1.s, q2.s, epsilon) && vector_type::approx_equal(q1.v, q2.v, epsilon);
			}
			else
			{
				using type = impl::equality_check_type<scalar_type, T>;

				return muu::approx_equal(static_cast<type>(q1.s), static_cast<type>(q2.s), static_cast<type>(epsilon))
					&& vector_type::approx_equal(q1.v, q2.v, epsilon);
			}
		}

		#if MUU_HAS_VECTORCALL

		MUU_CONSTRAINED_TEMPLATE_2((impl::pass_vectorcall_by_value<quaternion, quaternion<T>>), typename T)
		MUU_NODISCARD
		MUU_ATTR(const)
		static constexpr bool MUU_VECTORCALL approx_equal(
			quaternion q1,
			quaternion<T> q2,
			epsilon_type<scalar_type, T> epsilon = default_epsilon<scalar_type, T>) noexcept
		{
			if constexpr (std::is_same_v<scalar_type, T>)
			{
				return muu::approx_equal(q1.s, q2.s, epsilon) && vector_type::approx_equal(q1.v, q2.v, epsilon);
			}
			else
			{
				using type = impl::equality_check_type<scalar_type, T>;

				return muu::approx_equal(static_cast<type>(q1.s), static_cast<type>(q2.s), static_cast<type>(epsilon))
					&& vector_type::approx_equal(q1.v, q2.v, epsilon);
			}
		}

		#endif // MUU_HAS_VECTORCALL

		/// \brief	Returns true if the quaternion is approximately equal to another.
		MUU_CONSTRAINED_TEMPLATE((!MUU_HAS_VECTORCALL || impl::pass_vectorcall_by_reference<quaternion<T>>), typename T)
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool MUU_VECTORCALL approx_equal(
			const quaternion<T>& q,
			epsilon_type<scalar_type, T> epsilon = default_epsilon<scalar_type, T>) const noexcept
		{
			return approx_equal(*this, q, epsilon);
		}

		#if MUU_HAS_VECTORCALL

		MUU_CONSTRAINED_TEMPLATE(impl::pass_vectorcall_by_value<quaternion<T>>, typename T)
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool MUU_VECTORCALL approx_equal(
			quaternion<T> q,
			epsilon_type<scalar_type, T> epsilon = default_epsilon<scalar_type, T>) const noexcept
		{
			return approx_equal(*this, q, epsilon);
		}

		#endif // MUU_HAS_VECTORCALL

		/// \brief	Returns true if all the scalar components in a quaternion are approximately equal to zero.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL approx_zero(MUU_VC_PARAM(quaternion) q,
														 scalar_type epsilon = default_epsilon<scalar_type>) noexcept
		{
			return muu::approx_zero(q.s, epsilon) && vector_type::approx_zero(q.v, epsilon);
		}

		/// \brief	Returns true if all the scalar components in the quaternion are approximately equal to zero.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool MUU_VECTORCALL approx_zero(scalar_type epsilon = default_epsilon<scalar_type>) const noexcept
		{
			return approx_zero(*this, epsilon);
		}

	#endif // approx_equal

	#if 1 // dot product ----------------------------------------------------------------------------------------------

	  private:
		template <typename T = intermediate_float>
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr T MUU_VECTORCALL raw_dot(MUU_VC_PARAM(quaternion) q1, MUU_VC_PARAM(quaternion) q2) noexcept
		{
			MUU_FMA_BLOCK;

			static_assert(std::is_same_v<impl::highest_ranked<T, intermediate_float>, T>); // non-truncating

			return static_cast<T>(q1.s) * static_cast<T>(q2.s) + vector_type::template raw_dot<T>(q1.v, q2.v);
		}

	  public:
		/// \brief	Returns the dot product of two quaternions.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr scalar_type MUU_VECTORCALL dot(MUU_VC_PARAM(quaternion) q1,
														MUU_VC_PARAM(quaternion) q2) noexcept
		{
			return static_cast<scalar_type>(raw_dot(q1, q2));
		}

		/// \brief	Returns the dot product of this and another quaternion.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr scalar_type MUU_VECTORCALL dot(MUU_VC_PARAM(quaternion) q) const noexcept
		{
			return dot(*this, q);
		}

	#endif // dot product

	#if 1 // normalization --------------------------------------------------------------------------------------------

		/// \brief		Normalizes a quaternion.
		///
		/// \param q	The quaternion to normalize.
		///
		/// \return		A normalized copy of the input quaternion.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr quaternion MUU_VECTORCALL normalize(MUU_VC_PARAM(quaternion) q) noexcept
		{
			const intermediate_float inv_length = intermediate_float{ 1 } / muu::sqrt(raw_dot(q, q));
			return quaternion{ static_cast<scalar_type>(q.s * inv_length),
							   vector_type::raw_multiply_scalar(q.v, inv_length) };
		}

		/// \brief		Normalizes the quaternion (in-place).
		///
		/// \return		A reference to the quaternion.
		constexpr quaternion& normalize() noexcept
		{
			return *this = normalize(*this);
		}

		/// \brief Returns true if a quaternion is normalized (i.e. has a length of 1).
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL normalized(MUU_VC_PARAM(quaternion) q) noexcept
		{
			constexpr auto epsilon = intermediate_float{ 1 }
								   / (100ull * (sizeof(scalar_type) >= sizeof(float) ? 10000ull : 1ull)
									  * (sizeof(scalar_type) >= sizeof(double) ? 10000ull : 1ull));

			return muu::approx_equal(raw_dot(q, q), intermediate_float{ 1 }, epsilon);
		}

		/// \brief Returns true if the quaternion is normalized (i.e. has a length of 1).
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool normalized() const noexcept
		{
			return normalized(*this);
		}

		[[deprecated]] MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL unit_length(MUU_VC_PARAM(quaternion) q) noexcept
		{
			return normalized(q);
		}

		[[deprecated]] MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr bool unit_length() const noexcept
		{
			return normalized(*this);
		}

	#endif // normalization

	#if 1 // conjugate ------------------------------------------------------------------------------------------------

		/// \brief		Returns the conjugate of a quaternion.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr quaternion MUU_VECTORCALL conjugate(MUU_VC_PARAM(quaternion) q) noexcept
		{
			return { q.s, -q.v };
		}

		/// \brief		Returns the conjugate of the quaternion.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr quaternion conjugate() const noexcept
		{
			return { base::s, -base::v };
		}

	#endif // conjugate

	#if 1 // axis-angle conversions -----------------------------------------------------------------------------------

		/// \brief Creates a quaternion from an axis-angle rotation.
		///
		/// \param axis		Axis to rotate around. Must be unit-length.
		/// \param angle	Angle to rotate by (in radians).
		///
		/// \return A quaternion encoding the given axis-angle rotation.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr quaternion MUU_VECTORCALL from_axis_angle(MUU_VC_PARAM(vector_type) axis,
																   scalar_type angle) noexcept
		{
			if constexpr (impl::is_small_float_<scalar_type>)
			{
				const auto angle_ =
					static_cast<intermediate_float>(angle) * muu::constants<intermediate_float>::one_over_two;
				return quaternion{
					static_cast<scalar_type>(muu::cos(angle_)),				 // scalar
					vector_type::raw_multiply_scalar(axis, muu::sin(angle_)) // vector
				};
			}
			else
			{
				angle *= scalar_constants::one_over_two;
				return quaternion{
					muu::cos(angle),	   // scalar
					muu::sin(angle) * axis // vector
				};
			}
		}

		/// \brief Creates a quaternion from an axis-angle rotation.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr quaternion MUU_VECTORCALL from_axis_angle(MUU_VC_PARAM(axis_angle_type) aa) noexcept
		{
			return from_axis_angle(aa.axis, aa.angle);
		}

	  private:
		template <typename T = intermediate_float>
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr axis_angle_rotation<T> MUU_VECTORCALL raw_to_axis_angle(MUU_VC_PARAM(quaternion) q,
																				 bool shortest_path = true) noexcept
		{
			using type			  = impl::highest_ranked<intermediate_float, T>;
			const auto len		  = vector_type::template raw_length<type>(q.v);
			const auto correction = shortest_path && q.s < scalar_constants::zero ? type{ -1 } : type{ 1 };

			if MUU_UNLIKELY(len == type{})
			{
				// This happens at angle = 0 and 360. All axes are correct, so any will do.
				return {
					muu::vector<T, 3>::constants::x_axis,
					static_cast<T>(type{ 2 } * muu::atan2(len, static_cast<type>(q.s) * correction)),
				};
			}
			else
			{
				return {
					muu::vector<T, 3>{
						static_cast<T>((static_cast<type>(q.v.x) * correction) / len),
						static_cast<T>((static_cast<type>(q.v.y) * correction) / len),
						static_cast<T>((static_cast<type>(q.v.z) * correction) / len),
					},
					static_cast<T>(type{ 2 } * muu::atan2(len, static_cast<type>(q.s) * correction)),
				};
			}
		}

	  public:
		/// \brief	Extracts an axis-angle rotation from a quaternion.
		///
		/// \param	quat			The quaternion to convert. Must be unit-length.
		/// \param	shortest_path	Should the returned values be derived from the shortest path?
		/// 						`true` is more intuitive but means that the returned values may not convert back
		/// 						to the original quaternion if used with #from_axis_angle().
		///
		/// \returns	An axis-angle rotation representing the rotation stored in the given quaternion.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr axis_angle_type MUU_VECTORCALL to_axis_angle(MUU_VC_PARAM(quaternion) quat,
																	  bool shortest_path = true) noexcept
		{
			return raw_to_axis_angle<scalar_type>(quat, shortest_path);
		}

		/// \brief	Extracts an axis-angle rotation from this quaternion.
		///
		/// \param	shortest_path	Should the returned values be derived from the shortest path?
		/// 						`true` is more intuitive but means that the returned values may not convert back
		/// 						to the original quaternion if used with #from_axis_angle().
		///
		/// \returns	An axis-angle rotation representing the rotation stored in the quaternion.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr axis_angle_type to_axis_angle(bool shortest_path = true) const noexcept
		{
			return raw_to_axis_angle<scalar_type>(*this, shortest_path);
		}

	#endif // axis-angle conversions

	#if 1 // euler conversions ----------------------------------------------------------------------------------------

		/// \brief Creates a quaternion from a set of euler angles.
		///
		/// \param yaw		The rotation around the local up axis (in radians).
		/// \param pitch	The rotation around the local right axis (in radians).
		/// \param roll		The rotation around the local forward axis (in radians).
		///
		/// \return A quaternion encoding the given axis-angle rotation.
		MUU_NODISCARD
		MUU_ATTR(const)
		static constexpr quaternion MUU_VECTORCALL from_euler(scalar_type yaw,
															  scalar_type pitch,
															  scalar_type roll) noexcept
		{
			MUU_FMA_BLOCK;
			using type = intermediate_float;

			// ensure rotation signs correspond with the aircraft principal axes:
			//	yaw - positive turns toward the right (nose turns east)
			//	pitch - positive pitches upward (nose points up away from ground)
			//	roll - positive rolls to the right (right wing tilts down)
			//	(see https://en.wikipedia.org/wiki/Flight_dynamics_(fixed-wing_aircraft)
			//
			yaw	 = -yaw;
			roll = -roll;

			const type c1 = muu::cos(static_cast<type>(pitch) * muu::constants<type>::one_over_two);
			const type s1 = muu::sin(static_cast<type>(pitch) * muu::constants<type>::one_over_two);
			const type c2 = muu::cos(static_cast<type>(yaw) * muu::constants<type>::one_over_two);
			const type s2 = muu::sin(static_cast<type>(yaw) * muu::constants<type>::one_over_two);
			const type c3 = muu::cos(static_cast<type>(roll) * muu::constants<type>::one_over_two);
			const type s3 = muu::sin(static_cast<type>(roll) * muu::constants<type>::one_over_two);

			return {
				static_cast<scalar_type>(c1 * c2 * c3 - s1 * s2 * s3), // scalar (w)
				static_cast<scalar_type>(s1 * c2 * c3 - c1 * s2 * s3), // vector (x)
				static_cast<scalar_type>(c1 * s2 * c3 + s1 * c2 * s3), // vector (y)
				static_cast<scalar_type>(c1 * c2 * s3 + s1 * s2 * c3)  // vector (z)
			};
		}

		/// \brief Creates a quaternion from an axis-angle rotation.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr quaternion MUU_VECTORCALL from_euler(MUU_VC_PARAM(euler_type) euler) noexcept
		{
			return from_euler(euler.yaw, euler.pitch, euler.roll);
		}

		/// \brief	Extracts a set of euler angles from a quaternion.
		///
		/// \param	q	The quaternion to convert.
		///
		/// \returns	A set of euler angles representing the rotation stored in the given quaternion.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr euler_type MUU_VECTORCALL to_euler(MUU_VC_PARAM(quaternion) q) noexcept
		{
			MUU_FMA_BLOCK;
			using type = intermediate_float;

			const type sqw	= static_cast<type>(q.s) * q.s;
			const type sqx	= static_cast<type>(q.v.x) * q.v.x;
			const type sqy	= static_cast<type>(q.v.y) * q.v.y;
			const type sqz	= static_cast<type>(q.v.z) * q.v.z;
			const type test = static_cast<type>(q.v.y) * q.v.z + static_cast<type>(q.s) * q.v.x;
			const type correction =
				static_cast<type>(sqx) + static_cast<type>(sqy) + static_cast<type>(sqz) + static_cast<type>(sqw);

			// https://www.euclideanspace.com/maths/geometry/rotations/conversions/quaternionToEuler/index.htm
			// (note that they pitch around Z, not X; pitch and roll are swapped here)

			constexpr type threshold = static_cast<type>(0.49995);

			// singularity at north pole
			if MUU_UNLIKELY(test > threshold * correction)
			{
				MUU_FMA_BLOCK;
				return { static_cast<scalar_type>(type{ -2 } * muu::atan2(q.v.z, q.s)),
						 static_cast<scalar_type>(muu::constants<type>::pi_over_two),
						 scalar_constants::zero };
			}

			// singularity at south pole
			else if MUU_UNLIKELY(test < -threshold * correction)
			{
				MUU_FMA_BLOCK;
				return { static_cast<scalar_type>(type{ 2 } * muu::atan2(q.v.z, q.s)),
						 static_cast<scalar_type>(-muu::constants<type>::pi_over_two),
						 scalar_constants::zero };
			}

			else
			{
				MUU_FMA_BLOCK;
				// note the sign of yaw and roll are flipped;
				// see from_euler() for an explanation

				return { static_cast<scalar_type>(
							 -muu::atan2(type{ -2 } * (q.v.x * q.v.z - q.s * q.v.y), sqw - sqx - sqy + sqz)),
						 static_cast<scalar_type>(muu::asin(type{ 2 } * test / correction)),
						 static_cast<scalar_type>(
							 -muu::atan2(type{ -2 } * (q.v.x * q.v.y - q.s * q.v.z), sqw - sqx + sqy - sqz)) };
			}
		}

		/// \brief	Extracts a set of euler angles from this quaternion.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr euler_type to_euler() const noexcept
		{
			return to_euler(*this);
		}

	#endif // euler conversions

	#if 1 // multiplication -------------------------------------------------------------------------------------------

	  private:
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr quaternion MUU_VECTORCALL multiply(MUU_VC_PARAM(quaternion) lhs,
															MUU_VC_PARAM(quaternion) rhs) noexcept
		{
			using type = intermediate_float;

			if constexpr (all_same<scalar_type, type>)
			{
				MUU_FMA_BLOCK;
				return { lhs.s * rhs.s - vector_type::template raw_dot<type>(lhs.v, rhs.v),
						 lhs.s * rhs.v + rhs.s * lhs.v + impl::raw_cross<vector<type, 3>>(lhs.v, rhs.v) };
			}
			else
			{
				MUU_FMA_BLOCK;
				return { static_cast<scalar_type>(static_cast<type>(lhs.s) * rhs.s
												  - vector_type::template raw_dot<type>(lhs.v, rhs.v)),

						 vector_type{ static_cast<type>(lhs.s) * static_cast<vector<type, 3>>(rhs.v)
									  + static_cast<type>(rhs.s) * static_cast<vector<type, 3>>(lhs.v)
									  + impl::raw_cross<vector<type, 3>>(lhs.v, rhs.v) } };
			}
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector_type MUU_VECTORCALL rotate_vector(MUU_VC_PARAM(quaternion) lhs,
																  MUU_VC_PARAM(vector_type) rhs) noexcept
		{
			MUU_FMA_BLOCK;
			using type = intermediate_float;

			auto t		 = type{ 2 } * impl::raw_cross<vector<type, 3>>(lhs.v, rhs);
			const auto u = impl::raw_cross<vector<type, 3>>(lhs.v, t);
			t *= static_cast<type>(lhs.s);
			return { static_cast<scalar_type>(rhs.x + t.x + u.x),
					 static_cast<scalar_type>(rhs.y + t.y + u.y),
					 static_cast<scalar_type>(rhs.z + t.z + u.z) };
		}

	  public:
		/// \brief Multiplies two quaternions.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr quaternion MUU_VECTORCALL operator*(MUU_VC_PARAM(quaternion) lhs,
															 MUU_VC_PARAM(quaternion) rhs) noexcept
		{
			return multiply(lhs, rhs);
		}

		/// \brief Multiplies this quaternion with another.
		constexpr quaternion& MUU_VECTORCALL operator*=(MUU_VC_PARAM(quaternion) rhs) noexcept
		{
			return *this = multiply(*this, rhs);
		}

		/// \brief Rotates a three-dimensional vector by the rotation encoded in a quaternion.
		MUU_NODISCARD
		friend constexpr vector_type MUU_VECTORCALL operator*(MUU_VC_PARAM(quaternion) lhs,
															  MUU_VC_PARAM(vector_type) rhs) noexcept
		{
			return rotate_vector(lhs, rhs);
		}

		/// \brief Rotates a three-dimensional vector by the rotation encoded in a quaternion.
		MUU_NODISCARD
		friend constexpr vector_type MUU_VECTORCALL operator*(MUU_VC_PARAM(vector_type) lhs,
															  MUU_VC_PARAM(quaternion) rhs) noexcept
		{
			return rotate_vector(rhs, lhs);
		}

		/// \brief Scales the shortest-path rotation equivalent of a quaternion by a scalar.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr quaternion MUU_VECTORCALL operator*(MUU_VC_PARAM(quaternion) lhs, scalar_type rhs) noexcept
		{
			MUU_FMA_BLOCK;

			auto aa = raw_to_axis_angle<intermediate_float>(lhs);
			aa.angle *= rhs * muu::constants<intermediate_float>::one_over_two;
			aa.axis.normalize(); // todo: unnecessary?
			return { static_cast<scalar_type>(muu::cos(aa.angle)),
					 static_cast<vector_type>(muu::sin(aa.angle) * aa.axis) };
		}

		/// \brief Scales the shortest-path rotation equivalent of a quaternion by a scalar.
		MUU_NODISCARD
		friend constexpr quaternion MUU_VECTORCALL operator*(scalar_type lhs, MUU_VC_PARAM(quaternion) rhs) noexcept
		{
			return rhs * lhs;
		}

		/// \brief Scales the shortest-path rotation equivalent of this quaternion by a scalar (in-place).
		constexpr quaternion& MUU_VECTORCALL operator*=(scalar_type rhs) noexcept
		{
			return *this = (*this * rhs);
		}

	#endif // multiplication

	#if 1 // misc -----------------------------------------------------------------------------------------------------

		/// \brief Writes a quaternion out to a text stream.
		template <typename Char, typename Traits>
		friend std::basic_ostream<Char, Traits>& operator<<(std::basic_ostream<Char, Traits>& os, const quaternion& q)
		{
			impl::print_compound_vector(os, &q.s, 1_sz, false, &q.v.x, 3_sz, true);
			return os;
		}

		/// \brief	Performs a spherical-linear interpolation between two quaternion orientations.
		///
		/// \param	start	The start orientation.
		/// \param	finish	The finish orientation.
		/// \param	alpha 	The blend factor.
		///
		/// \returns	A quaternion orientation derived from a spherical-linear interpolation between `start` and
		/// `finish`.
		///
		/// \see [Slerp](https://en.wikipedia.org/wiki/Slerp)
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr quaternion MUU_VECTORCALL slerp(MUU_VC_PARAM(quaternion) start,
														 MUU_VC_PARAM(quaternion) finish,
														 scalar_type alpha) noexcept
		{
			MUU_FMA_BLOCK;

			using type = intermediate_float;
			auto dot   = raw_dot<type>(start, finish);

			// map from { s, v } and { -s, -v } (they represent the same rotation)
			auto correction = type{ 1 };
			if (dot < type{})
			{
				correction = type{ -1 };
				dot		   = -dot;
			}

			// they're extremely close, do a normal lerp
			if (dot >= static_cast<type>(0.9995))
			{
				MUU_FMA_BLOCK;
				const auto inv_alpha = type{ 1 } - static_cast<type>(alpha);

				return normalize(quaternion{
					static_cast<scalar_type>(start.s * inv_alpha + finish.s * static_cast<type>(alpha) * correction),
					vector_type::raw_multiply_scalar(start.v, inv_alpha)
						+ vector_type::raw_multiply_scalar(finish.v, static_cast<type>(alpha) * correction) });
			}

			const auto theta_0		 = muu::acos(dot);
			const auto theta		 = theta_0 * static_cast<type>(alpha);
			const auto sin_theta_div = muu::sin(theta) / muu::sin(theta_0);
			const auto s0			 = muu::cos(theta) - dot * sin_theta_div;
			const auto s1			 = sin_theta_div;
			return { static_cast<scalar_type>(start.s * s0 + finish.s * s1 * correction),
					 vector_type::raw_multiply_scalar(start.v, s0)
						 + vector_type::raw_multiply_scalar(finish.v, static_cast<type>(s1) * correction) };
		}

		/// \brief	Performs a spherical-linear interpolation on this quaternion (in-place).
		///
		/// \param	target	The 'target' orientation.
		/// \param	alpha 	The blend factor.
		///
		/// \return	A reference to the quaternion.
		///
		/// \see [Slerp](https://en.wikipedia.org/wiki/Slerp)
		constexpr quaternion& MUU_VECTORCALL slerp(MUU_VC_PARAM(quaternion) target, scalar_type alpha) noexcept
		{
			return *this = slerp(*this, target, alpha);
		}

	#endif // misc
	};

	/// \cond

	template <typename S, typename X, typename Y, typename Z>
	quaternion(S, X, Y, Z) -> quaternion<impl::std_math_common_type<impl::highest_ranked<S, X, Y, Z>>>;

	template <typename S>
	quaternion(S, S, S, S) -> quaternion<impl::std_math_common_type<S>>;

	template <typename R, typename I>
	quaternion(R, vector<I, 3>) -> quaternion<impl::std_math_common_type<impl::highest_ranked<R, I>>>;

	template <typename S>
	quaternion(const axis_angle_rotation<S>&) -> quaternion<S>;

	template <typename S>
	quaternion(const euler_rotation<S>&) -> quaternion<S>;

	/// \endcond

	MUU_ABI_VERSION_END;
}

namespace std
{
	/// \brief Specialization of std::tuple_size for muu::quaternion.
	template <typename Scalar>
	struct tuple_size<muu::quaternion<Scalar>>
	{
		static constexpr size_t value = 2;
	};

	/// \brief Specialization of std::tuple_element for muu::quaternion.
	template <size_t I, typename Scalar>
	struct tuple_element<I, muu::quaternion<Scalar>>
	{
		static_assert(I < 2);
		using type = std::conditional_t<I == 1, muu::vector<Scalar, 3>, Scalar>;
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
	/// \see		muu::quaternion
	///
	/// \brief		Quaternion constants.
	template <typename Scalar>
	struct constants<quaternion<Scalar>>
	{
		using scalars = constants<Scalar>;
		using vectors = constants<vector<Scalar, 3>>;

		/// \brief A quaternion with all members initialized to zero.
		static constexpr quaternion<Scalar> zero{ scalars::zero, vectors::zero };

		/// \brief The identity quaternion.
		static constexpr quaternion<Scalar> identity{ scalars::one, vectors::zero };
	};
}

MUU_POP_PRECISE_MATH;

#endif //===============================================================================================================

//======================================================================================================================
// FREE FUNCTIONS
#if 1

namespace muu
{
	/// \ingroup	infinity_or_nan
	/// \relatesalso	muu::quaternion
	///
	/// \brief	Returns true if any of the scalar components of a quaternion are infinity or NaN.
	template <typename S>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr bool infinity_or_nan(const quaternion<S>& q) noexcept
	{
		return quaternion<S>::infinity_or_nan(q);
	}

	/// \ingroup	approx_equal
	/// \relatesalso	muu::quaternion
	///
	/// \brief		Returns true if two quaternions are approximately equal.
	template <typename S, typename T>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr bool MUU_VECTORCALL approx_equal(const quaternion<S>& q1,
											   const quaternion<T>& q2,
											   epsilon_type<S, T> epsilon = default_epsilon<S, T>) noexcept
	{
		return quaternion<S>::approx_equal(q1, q2, epsilon);
	}

	/// \ingroup	approx_zero
	/// \relatesalso	muu::quaternion
	///
	/// \brief		Returns true if all the scalar components of a quaternion are approximately equal to zero.
	template <typename S>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr bool MUU_VECTORCALL approx_zero(const quaternion<S>& q, S epsilon = default_epsilon<S>) noexcept
	{
		return quaternion<S>::approx_zero(q, epsilon);
	}

	/// \ingroup	normalized
	/// \relatesalso	muu::quaternion
	///
	/// \brief Returns true if a quaternion is normalized (i.e. has a length of 1).
	template <typename S>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr bool normalized(const quaternion<S>& q) noexcept
	{
		return quaternion<S>::normalized(q);
	}

	template <typename S>
	MUU_NODISCARD
	[[deprecated]] MUU_ATTR(pure)
	constexpr bool unit_length(const quaternion<S>& q) noexcept
	{
		return quaternion<S>::normalized(q);
	}

	/// \relatesalso muu::quaternion
	///
	/// \brief	Returns the dot product of two quaternions.
	template <typename S>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr S dot(const quaternion<S>& q1, const quaternion<S>& q2) noexcept
	{
		return quaternion<S>::dot(q1, q2);
	}

	/// \relatesalso muu::quaternion
	///
	/// \brief	Normalizes a quaternion.
	///
	/// \param q	The quaternion to normalize.
	///
	/// \return		A normalized copy of the input quaternion.
	template <typename S>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr quaternion<S> normalize(const quaternion<S>& q) noexcept
	{
		return quaternion<S>::normalize(q);
	}

	/// \relatesalso	muu::quaternion
	///
	/// \brief	Performs a spherical-linear interpolation between two quaternions.
	template <typename S>
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr quaternion<S> MUU_VECTORCALL slerp(const quaternion<S>& start,
												 const quaternion<S>& finish,
												 S alpha) noexcept
	{
		return quaternion<S>::slerp(start, finish, alpha);
	}
}

#endif //===============================================================================================================

MUU_RESET_NDEBUG_OPTIMIZATIONS;
#include "impl/header_end.h"
