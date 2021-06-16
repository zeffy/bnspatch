// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

#pragma once
#include "../vector.h"
#include "../matrix.h"
#include "header_start.h"

namespace muu
{
	/// \brief Corner masks/indices for three-dimensional bounding-boxes.
	/// \ingroup math
	///
	/// \see
	/// 	- muu::bounding_box
	/// 	- muu::oriented_bounding_box
	enum class box_corners : uint8_t
	{
		min = 0,		///< The 'min' corner (negative offset on all axes).
		x	= 1,		///< The corner with a positive offset on the X axis, negative on Y and Z.
		y	= 2,		///< The corner with a positive offset on the Y axis, negative on X and Z.
		xy	= x | y,	///< The corner with a positive offset on the X and Y axes, negative on Z.
		z	= 4,		///< The corner with a positive offset on the Z axis, negative on X and Y.
		xz	= x | z,	///< The corner with a positive offset on the X and Z axes, negative on Y.
		yz	= y | z,	///< The corner with a positive offset on the Y and Z axes, negative on X.
		max = x | y | z ///< The 'max' corner (positive offset on all axes).
	};
	MUU_MAKE_FLAGS(box_corners);
}

/// \cond

MUU_PUSH_WARNINGS;
MUU_DISABLE_SPAM_WARNINGS;
MUU_FORCE_NDEBUG_OPTIMIZATIONS;
MUU_PRAGMA_MSVC(inline_recursion(on))
MUU_PRAGMA_MSVC(float_control(push))
MUU_PRAGMA_MSVC(float_control(except, off))
MUU_PRAGMA_MSVC(float_control(precise, off))

namespace muu::impl
{
	MUU_ABI_VERSION_START(0);

	template <typename Scalar>
	struct MUU_TRIVIAL_ABI plane_
	{
		vector<Scalar, 3> n;
		Scalar d;
	};

	template <typename Scalar>
	struct MUU_TRIVIAL_ABI triangle_
	{
		vector<Scalar, 3> points[3];
	};

	template <typename Scalar>
	struct MUU_TRIVIAL_ABI bounding_sphere_
	{
		vector<Scalar, 3> center;
		Scalar radius;
	};

	template <typename Scalar>
	struct MUU_TRIVIAL_ABI bounding_box_
	{
		vector<Scalar, 3> center;
		vector<Scalar, 3> extents;
	};

	template <typename Scalar>
	struct MUU_TRIVIAL_ABI oriented_bounding_box_
	{
		vector<Scalar, 3> center;
		vector<Scalar, 3> extents;
		matrix<Scalar, 3, 3> axes;
	};

	MUU_ABI_VERSION_END;

	template <typename Scalar>
	inline constexpr bool is_hva<plane_<Scalar>> = can_be_hva_of<Scalar, plane_<Scalar>>;

	template <typename Scalar>
	inline constexpr bool is_hva<plane<Scalar>> = is_hva<plane_<Scalar>>;

	template <typename Scalar>
	struct vectorcall_param_<plane<Scalar>>
	{
		using type = std::conditional_t<pass_vectorcall_by_value<plane_<Scalar>>, plane<Scalar>, const plane<Scalar>&>;
	};

	template <typename Scalar>
	inline constexpr bool is_hva<triangle_<Scalar>> = can_be_hva_of<Scalar, triangle_<Scalar>>;

	template <typename Scalar>
	inline constexpr bool is_hva<triangle<Scalar>> = is_hva<triangle_<Scalar>>;

	template <typename Scalar>
	struct vectorcall_param_<triangle<Scalar>>
	{
		using type =
			std::conditional_t<pass_vectorcall_by_value<triangle_<Scalar>>, triangle<Scalar>, const triangle<Scalar>&>;
	};

	template <typename Scalar>
	inline constexpr bool is_hva<bounding_sphere_<Scalar>> = can_be_hva_of<Scalar, bounding_sphere_<Scalar>>;

	template <typename Scalar>
	inline constexpr bool is_hva<bounding_sphere<Scalar>> = is_hva<bounding_sphere_<Scalar>>;

	template <typename Scalar>
	struct vectorcall_param_<bounding_sphere<Scalar>>
	{
		using type = std::conditional_t<pass_vectorcall_by_value<bounding_sphere_<Scalar>>,
										bounding_sphere<Scalar>,
										const bounding_sphere<Scalar>&>;
	};

	template <typename Scalar>
	inline constexpr bool is_hva<bounding_box_<Scalar>> = can_be_hva_of<Scalar, bounding_box_<Scalar>>;

	template <typename Scalar>
	inline constexpr bool is_hva<bounding_box<Scalar>> = is_hva<bounding_box_<Scalar>>;

	template <typename Scalar>
	struct vectorcall_param_<bounding_box<Scalar>>
	{
		using type = std::conditional_t<pass_vectorcall_by_value<bounding_box_<Scalar>>,
										bounding_box<Scalar>,
										const bounding_box<Scalar>&>;
	};

	template <typename Scalar>
	inline constexpr bool is_hva<oriented_bounding_box_<Scalar>> =
		can_be_hva_of<Scalar, oriented_bounding_box_<Scalar>>;

	template <typename Scalar>
	inline constexpr bool is_hva<oriented_bounding_box<Scalar>> = is_hva<oriented_bounding_box_<Scalar>>;

	template <typename Scalar>
	struct vectorcall_param_<oriented_bounding_box<Scalar>>
	{
		using type = std::conditional_t<pass_vectorcall_by_value<oriented_bounding_box_<Scalar>>,
										oriented_bounding_box<Scalar>,
										const oriented_bounding_box<Scalar>&>;
	};

	template <typename Scalar>
	struct boxes_common
	{
		using scalar_type  = Scalar;
		using vector_type  = vector<scalar_type, 3>;
		using vector_param = vectorcall_param<vector_type>;

		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		static constexpr scalar_type MUU_VECTORCALL width(vector_param extents) noexcept
		{
			return extents.x * scalar_type{ 2 };
		}

		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		static constexpr scalar_type MUU_VECTORCALL height(vector_param extents) noexcept
		{
			return extents.y * scalar_type{ 2 };
		}

		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		static constexpr scalar_type MUU_VECTORCALL depth(vector_param extents) noexcept
		{
			return extents.z * scalar_type{ 2 };
		}

		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		static constexpr scalar_type MUU_VECTORCALL diagonal(vector_param extents) noexcept
		{
			return vector_type::length(extents) * scalar_type{ 2 };
		}

		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		static constexpr const scalar_type& shortest_extent(const vector_type& extents) noexcept
		{
			return min(extents.x, min(extents.y, extents.z));
		}

		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		static constexpr const scalar_type& longest_extent(const vector_type& extents) noexcept
		{
			return max(extents.x, max(extents.y, extents.z));
		}

		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		static constexpr scalar_type& shortest_extent(vector_type& extents) noexcept
		{
			return min(extents.x, min(extents.y, extents.z));
		}

		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		static constexpr scalar_type& longest_extent(vector_type& extents) noexcept
		{
			return max(extents.x, max(extents.y, extents.z));
		}

		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		static constexpr scalar_type shortest_side(const vector_type& extents) noexcept
		{
			return shortest_extent(extents) * scalar_type{ 2 };
		}

		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		static constexpr scalar_type longest_side(const vector_type& extents) noexcept
		{
			return longest_extent(extents) * scalar_type{ 2 };
		}

		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		MUU_ATTR(flatten)
		static constexpr scalar_type MUU_VECTORCALL volume(vector_param extents) noexcept
		{
			return extents.x * extents.y * extents.z * scalar_type{ 8 };
		}

		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		MUU_ATTR(flatten)
		static constexpr scalar_type MUU_VECTORCALL mass(vector_param extents, scalar_type density) noexcept
		{
			return density * volume(extents);
		}

		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		MUU_ATTR(flatten)
		static constexpr scalar_type MUU_VECTORCALL density(vector_param extents, scalar_type mass) noexcept
		{
			return mass / volume(extents);
		}

		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL degenerate(vector_param extents) noexcept
		{
			return extents.x <= scalar_type{} || extents.y <= scalar_type{} || extents.z <= scalar_type{};
		}

		template <box_corners Corner>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		static constexpr vector_type MUU_VECTORCALL corner_offset(vector_param extents) noexcept
		{
			static_assert(Corner <= box_corners::max);

			if constexpr (Corner == box_corners::min)
				return -extents;
			if constexpr (Corner == box_corners::x)
				return vector_type{ extents.x, -extents.y, -extents.z };
			if constexpr (Corner == box_corners::y)
				return vector_type{ -extents.x, extents.y, -extents.z };
			if constexpr (Corner == box_corners::z)
				return vector_type{ -extents.x, -extents.y, extents.z };
			if constexpr (Corner == box_corners::xy)
				return vector_type{ extents.x, extents.y, -extents.z };
			if constexpr (Corner == box_corners::xz)
				return vector_type{ extents.x, -extents.y, extents.z };
			if constexpr (Corner == box_corners::yz)
				return vector_type{ -extents.x, extents.y, extents.z };
			if constexpr (Corner == box_corners::max)
				return extents;
		}

		MUU_NODISCARD
		MUU_ATTR_NDEBUG(pure)
		static constexpr vector_type MUU_VECTORCALL corner_offset(vector_param extents, box_corners which) noexcept
		{
			MUU_CONSTEXPR_SAFE_ASSERT(which <= box_corners::max && "'which' cannot exceed box_corners::max");
			MUU_ASSUME(which <= box_corners::max);

			switch (which)
			{
				case box_corners::min: return corner_offset<box_corners::min>(extents);
				case box_corners::x: return corner_offset<box_corners::x>(extents);
				case box_corners::y: return corner_offset<box_corners::y>(extents);
				case box_corners::xy: return corner_offset<box_corners::xy>(extents);
				case box_corners::z: return corner_offset<box_corners::z>(extents);
				case box_corners::xz: return corner_offset<box_corners::xz>(extents);
				case box_corners::yz: return corner_offset<box_corners::yz>(extents);
				case box_corners::max: return corner_offset<box_corners::max>(extents);
				default: MUU_UNREACHABLE;
			}
			MUU_UNREACHABLE;
		}

		template <box_corners Corner>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(pure)
		static constexpr vector_type MUU_VECTORCALL corner(vector_param center, vector_param extents) noexcept
		{
			return center + corner_offset<Corner>(extents);
		}

		template <box_corners Corner>
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector_type MUU_VECTORCALL corner(vector_param center,
														   vector_param extents,
														   const matrix<scalar_type, 3, 3>& axes) noexcept
		{
			const auto offset = corner_offset<Corner>(extents);
			return center + offset.x * axes.m[0] + offset.y * axes.m[1] + offset.z * axes.m[2];
		}

		MUU_NODISCARD
		MUU_ATTR_NDEBUG(pure)
		static constexpr vector_type MUU_VECTORCALL corner(vector_param center,
														   vector_param extents,
														   box_corners which) noexcept
		{
			return center + corner_offset(extents, which);
		}

		MUU_NODISCARD
		MUU_ATTR_NDEBUG(pure)
		static constexpr vector_type MUU_VECTORCALL corner(vector_param center,
														   vector_param extents,
														   const matrix<scalar_type, 3, 3>& axes,
														   box_corners which) noexcept
		{
			const auto offset = corner_offset(extents, which);
			return center + offset.x * axes.m[0] + offset.y * axes.m[1] + offset.z * axes.m[2];
		}
	};

	template <typename Scalar>
	struct planes_common
	{
		using scalar_type  = Scalar;
		using vector_type  = vector<scalar_type, 3>;
		using vector_param = vectorcall_param<vector_type>;

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr scalar_type MUU_VECTORCALL signed_distance(vector_param normal,
																	scalar_type d,
																	vector_param point) noexcept
		{
			return vector_type::dot(normal, point) + d;
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr scalar_type MUU_VECTORCALL unsigned_distance(vector_param normal,
																	  scalar_type d,
																	  vector_param point) noexcept
		{
			return muu::abs(signed_distance(normal, d, point));
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector_type MUU_VECTORCALL project_with_signed_distance(vector_param normal,
																				 vector_param point,
																				 scalar_type signed_dist) noexcept
		{
			MUU_FMA_BLOCK;

			return point - normal * signed_dist;
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector_type MUU_VECTORCALL project(vector_param normal,
															scalar_type d,
															vector_param point) noexcept
		{
			return project_with_signed_distance(normal, point, signed_distance(normal, d, point));
		}
	};

	template <typename Scalar>
	struct triangles_common
	{
		using scalar_type	 = Scalar;
		using vector_type	 = vector<scalar_type, 3>;
		using vector_param	 = vectorcall_param<vector_type>;
		using triangle_param = vectorcall_param<triangle_<scalar_type>>;

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector_type MUU_VECTORCALL normal(vector_param p0, vector_param p1, vector_param p2) noexcept
		{
			return vector_type::normalize(vector_type::cross(p1 - p0, p2 - p0));
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector_type MUU_VECTORCALL normal(triangle_param tri) noexcept
		{
			return vector_type::normalize(
				vector_type::cross(tri.points[1] - tri.points[0], tri.points[2] - tri.points[0]));
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector_type MUU_VECTORCALL center(vector_param p0, vector_param p1, vector_param p2) noexcept
		{
			MUU_FMA_BLOCK;

			return (p0 + p1 + p2) / scalar_type{ 3 };
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector_type MUU_VECTORCALL center(triangle_param tri) noexcept
		{
			MUU_FMA_BLOCK;

			return (tri.points[0] + tri.points[1] + tri.points[2]) / scalar_type{ 3 };
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr scalar_type MUU_VECTORCALL perimeter(vector_param p0,
															  vector_param p1,
															  vector_param p2) noexcept
		{
			return vector_param::distance(p0, p1) //
				 + vector_param::distance(p1, p2) //
				 + vector_param::distance(p2, p0);
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr scalar_type MUU_VECTORCALL perimeter(triangle_param tri) noexcept
		{
			return vector_param::distance(tri.points[0], tri.points[1]) //
				 + vector_param::distance(tri.points[1], tri.points[2]) //
				 + vector_param::distance(tri.points[2], tri.points[0]);
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr scalar_type MUU_VECTORCALL area(vector_param p0, vector_param p1, vector_param p2) noexcept
		{
			MUU_FMA_BLOCK;

			const auto a = vector_param::distance(p0, p1);
			const auto b = vector_param::distance(p1, p2);
			const auto c = vector_param::distance(p2, p0);
			const auto s = (a + b + c) / scalar_type{ 2 };
			return muu::sqrt(s * (s - a) * (s - b) * (s - c)); // heron's formula
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr scalar_type MUU_VECTORCALL area(triangle_param tri) noexcept
		{
			return area(tri.points[0], tri.points[1], tri.points[2]);
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector_type MUU_VECTORCALL barycentric(vector_param p0,
																vector_param p1,
																vector_param p2,
																vector_param point) noexcept
		{
			MUU_FMA_BLOCK;

			const auto v0	 = p1 - p0;
			const auto v1	 = p2 - p0;
			const auto d00	 = vector_type::dot(v0, v0);
			const auto d01	 = vector_type::dot(v0, v1);
			const auto d11	 = vector_type::dot(v1, v1);
			const auto denom = scalar_type{ 1 } / (d00 * d11 - d01 * d01);

			const auto v2  = point - p0;
			const auto d20 = vector_type::dot(v2, v0);
			const auto d21 = vector_type::dot(v2, v1);

			vector_type out{ scalar_type{ 1 }, //
							 (d11 * d20 - d01 * d21) * denom,
							 (d00 * d21 - d01 * d20) * denom };
			out.x -= out.y + out.z;
			return out;
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr vector_type MUU_VECTORCALL barycentric(triangle_param tri, vector_param point) noexcept
		{
			return barycentric(tri.points[0], tri.points[1], tri.points[2], point);
		}

		struct MUU_TRIVIAL_ABI memoized_barycentric
		{
			vector_type p;
			vector_type v0;
			vector_type v1;
			scalar_type d00;
			scalar_type d01;
			scalar_type d11;
			scalar_type denom;

			MUU_NODISCARD_CTOR
			constexpr memoized_barycentric(const vector_type& p0, const vector_type& p1, const vector_type& p2) noexcept
				: p{ p0 },
				  v0{ p1 - p0 },
				  v1{ p2 - p0 },
				  d00{ vector_type::dot(v0, v0) },
				  d01{ vector_type::dot(v0, v1) },
				  d11{ vector_type::dot(v1, v1) },
				  denom{ scalar_type{ 1 } / (d00 * d11 - d01 * d01) }
			{}

			MUU_NODISCARD_CTOR
			constexpr memoized_barycentric(const triangle_param& tri) noexcept
				: memoized_barycentric{ tri.points[0], tri.points[1], tri.points[2] }
			{}

			MUU_NODISCARD
			MUU_ATTR(pure)
			constexpr vector_type MUU_VECTORCALL operator()(vector_param point) const noexcept
			{
				MUU_FMA_BLOCK;

				const auto v2  = point - p;
				const auto d20 = vector_type::dot(v2, v0);
				const auto d21 = vector_type::dot(v2, v1);

				vector_type out{ scalar_type{ 1 }, //
								 (d11 * d20 - d01 * d21) * denom,
								 (d00 * d21 - d01 * d20) * denom };
				out.x -= out.y + out.z;
				return out;
			}
		};
	};

	template <typename Scalar>
	struct collision_common
	{
		using scalar_type = Scalar;
		using vector_type = vector<scalar_type, 3>;

		using vector_param	 = vectorcall_param<vector_type>;
		using triangle_param = vectorcall_param<triangle_<scalar_type>>;

		using planes	= planes_common<Scalar>;
		using boxes		= boxes_common<Scalar>;
		using triangles = triangles_common<Scalar>;

		struct sat_tester
		{
			scalar_type min = constants<scalar_type>::highest;
			scalar_type max = constants<scalar_type>::lowest;

			constexpr void MUU_VECTORCALL operator()(vector_param axis, vector_param point) noexcept
			{
				const auto proj = vector_type::dot(axis, point);
				min				= muu::min(proj, min);
				max				= muu::max(proj, max);
			}

			template <size_t N>
			constexpr void MUU_VECTORCALL operator()(vector_param axis, const vector_type (&points)[N]) noexcept
			{
				for (const auto p : points)
					(*this)(axis, p);
			}

			MUU_NODISCARD
			MUU_ATTR(pure)
			constexpr bool MUU_VECTORCALL operator()(scalar_type threshold) noexcept
			{
				return max >= threshold && min <= threshold;
			}

			MUU_NODISCARD
			MUU_ATTR(pure)
			constexpr bool MUU_VECTORCALL operator()(scalar_type min_threshold, scalar_type max_threshold) noexcept
			{
				return max >= min_threshold && min <= max_threshold;
			}

			MUU_NODISCARD
			MUU_ATTR(pure)
			constexpr bool MUU_VECTORCALL operator()(const sat_tester& other) noexcept
			{
				return max >= other.min && min <= other.max;
			}
		};

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL plane_contains_point(vector_param normal,
																  scalar_type d,
																  vector_param point) noexcept
		{
			return muu::approx_zero(planes::signed_distance(normal, d, point));
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL plane_intersects_plane(vector_param normal1, vector_param normal2) noexcept
		{
			return muu::approx_zero(vector_type::length_squared(vector_type::cross(normal1, normal2)));
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL plane_intersects_line_segment(vector_param normal,
																		   scalar_type d,
																		   vector_param start,
																		   vector_param end) noexcept
		{
			return planes::signed_distance(normal, d, start) * planes::signed_distance(normal, d, end) >= scalar_type{};
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL aabb_contains_point(vector_param center,
																 vector_param extents,
																 vector_param point) noexcept
		{
			const auto adj = vector_type::abs(point - center);
			return adj.x <= extents.x //
				&& adj.y <= extents.y //
				&& adj.z <= extents.z;
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL aabb_intersects_aabb_minmax(vector_param min1,
																		 vector_param max1,
																		 vector_param min2,
																		 vector_param max2) noexcept
		{
			return max1.x >= min2.x //
				&& min1.x <= max2.x //
				&& max1.y >= min2.y //
				&& min1.y <= max2.y //
				&& max1.z >= min2.z //
				&& min1.z <= max2.z;
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL aabb_intersects_aabb(vector_param center1,
																  vector_param extents1,
																  vector_param center2,
																  vector_param extents2) noexcept
		{
			return aabb_intersects_aabb_minmax(center1 - extents1,
											   center1 + extents1,
											   center2 - extents2,
											   center2 + extents2);
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL aabb_intersects_sphere_minmax(vector_param min,
																		   vector_param max,
																		   vector_param sphere_center,
																		   scalar_type sphere_radius) noexcept
		{
			return vector_type::distance_squared(vector_type::clamp(sphere_center, min, max), sphere_center)
				<= sphere_radius;
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL aabb_intersects_sphere(vector_param center,
																	vector_param extents,
																	vector_param sphere_center,
																	scalar_type sphere_radius) noexcept
		{
			return aabb_intersects_sphere_minmax(center - extents, //
												 center + extents, //
												 sphere_center,	   //
												 sphere_radius);
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL aabb_intersects_line_segment(vector_param center,
																		  vector_param extents,
																		  vector_param start,
																		  vector_param end) noexcept
		{
			MUU_FMA_BLOCK;

			const auto mid_delta = (end - start) / scalar_type{ 2 };
			const auto mid_point = start + mid_delta - center;
			const auto abs_delta = vector_type::abs(mid_delta);

			if (muu::abs(mid_point.x) > extents.x + abs_delta.x	   //
				|| muu::abs(mid_point.y) > extents.y + abs_delta.y //
				|| muu::abs(mid_point.z) > extents.z + abs_delta.z)
				return false;

			if (muu::abs(mid_delta.y * mid_point.z - mid_delta.z * mid_point.y)
					> extents.y * abs_delta.z + extents.z * abs_delta.y
				|| muu::abs(mid_delta.z * mid_point.x - mid_delta.x * mid_point.z)
					   > extents.z * abs_delta.x + extents.x * abs_delta.z
				|| muu::abs(mid_delta.x * mid_point.y - mid_delta.y * mid_point.x)
					   > extents.x * abs_delta.y + extents.y * abs_delta.x)
				return false;

			return true;
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL aabb_intersects_plane(vector_param center,
																   vector_param extents,
																   vector_param normal,
																   scalar_type d) noexcept
		{
			return planes::unsigned_distance(normal, d, center) <= vector_type::dot(extents, vector_type::abs(normal));
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL aabb_intersects_triangle(vector_param center,
																	  vector_param extents,
																	  vector_param p0,
																	  vector_param p1,
																	  vector_param p2) noexcept
		{
			MUU_FMA_BLOCK;

			// this is the Akenine-Moller algorithm:
			// https://fileadmin.cs.lth.se/cs/Personal/Tomas_Akenine-Moller/pubs/tribox.pdf

			// test box normals against triangle
			const auto aabb_min					= center - extents;
			const auto aabb_max					= center + extents;
			constexpr vector_type box_normals[] = { vector_type::constants::x_axis,
													vector_type::constants::y_axis,
													vector_type::constants::z_axis };
			for (size_t i = 0; i < 3_sz; i++)
			{
				sat_tester sat;
				sat(box_normals[i], p0);
				sat(box_normals[i], p1);
				sat(box_normals[i], p2);
				if (!sat(aabb_min[i], aabb_max[i]))
					return false;
			}

			// test triangle normal against box
			const vector_type box_verts[] = { aabb_min,
											  boxes::template corner<box_corners::x>(center, extents),
											  boxes::template corner<box_corners::xy>(center, extents),
											  boxes::template corner<box_corners::xz>(center, extents),
											  boxes::template corner<box_corners::y>(center, extents),
											  boxes::template corner<box_corners::yz>(center, extents),
											  boxes::template corner<box_corners::z>(center, extents),
											  aabb_max };
			{
				const auto axis = triangles::normal(p0, p1, p2);
				sat_tester sat;
				sat(axis, box_verts);
				if (!sat(vector_type::dot(axis, p0)))
					return false;
			}

			// test edge cross products
			const vector_type tri_edges[] = { p1 - p0, p2 - p1, p0 - p2 };
			for (size_t i = 0; i < 3_sz; i++)
			{
				for (size_t j = 0; j < 3_sz; j++)
				{
					const auto axis = vector_type::cross(tri_edges[i], box_normals[j]);

					sat_tester box_sat;
					box_sat(axis, box_verts);

					sat_tester tri_sat;
					tri_sat(axis, p0);
					tri_sat(axis, p1);
					tri_sat(axis, p2);

					if (!box_sat(tri_sat))
						return false;
				}
			}

			return true;
#if 0				   

			const typename triangles::memoized_barycentric bary_terms{ p0, p1, p2 };
			const auto box_diagonal_test = [&](const auto& corner1, const auto& corner2) noexcept
			{
				MUU_FMA_BLOCK;

				scalar_type ray_len{};
				const auto ray_dir = vector_type::direction(corner1, corner2, ray_len);
				if (vector_type::dot(plane_normal, ray_dir) == scalar_type{})
					return false;

				const auto hit_dist =
					(-plane_d - vector_type::dot(plane_normal, corner1)) / vector_type::dot(plane_normal, ray_dir);
				if (hit_dist < scalar_type{} || hit_dist > ray_len)
					return false;

				const auto bary = bary_terms(corner1 + ray_dir * hit_dist);
				return bary.x >= scalar_type{} && bary.y >= scalar_type{} && bary.z >= scalar_type{};
			};
			return box_diagonal_test(aabb_min, aabb_max)
				|| box_diagonal_test(boxes::template corner<box_corners::x>(center, extents),
									 boxes::template corner<box_corners::yz>(center, extents))
				|| box_diagonal_test(boxes::template corner<box_corners::xz>(center, extents),
									 boxes::template corner<box_corners::y>(center, extents))
				|| box_diagonal_test(boxes::template corner<box_corners::z>(center, extents),
									 boxes::template corner<box_corners::xy>(center, extents));
#endif
		}

		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr bool MUU_VECTORCALL aabb_intersects_triangle(vector_param center,
																	  vector_param extents,
																	  triangle_param tri) noexcept
		{
			return aabb_intersects_triangle(center, extents, tri.points[0], tri.points[1], tri.points[2]);
		}
	};
}

namespace muu
{
	template <typename From, typename Scalar>
	inline constexpr bool allow_implicit_bit_cast<From, impl::plane_<Scalar>> =
		allow_implicit_bit_cast<From, plane<Scalar>>;

	template <typename From, typename Scalar>
	inline constexpr bool allow_implicit_bit_cast<From, impl::triangle_<Scalar>> =
		allow_implicit_bit_cast<From, triangle<Scalar>>;

	template <typename From, typename Scalar>
	inline constexpr bool allow_implicit_bit_cast<From, impl::bounding_sphere_<Scalar>> =
		allow_implicit_bit_cast<From, bounding_sphere<Scalar>>;

	template <typename From, typename Scalar>
	inline constexpr bool allow_implicit_bit_cast<From, impl::bounding_box_<Scalar>> =
		allow_implicit_bit_cast<From, bounding_box<Scalar>>;

	template <typename From, typename Scalar>
	inline constexpr bool allow_implicit_bit_cast<From, impl::oriented_bounding_box_<Scalar>> =
		allow_implicit_bit_cast<From, oriented_bounding_box<Scalar>>;
}

MUU_PRAGMA_MSVC(float_control(pop))
MUU_PRAGMA_MSVC(inline_recursion(off))
MUU_RESET_NDEBUG_OPTIMIZATIONS;
MUU_POP_WARNINGS; // MUU_DISABLE_SPAM_WARNINGS

#if !MUU_INTELLISENSE
	#define MUU_GEOM_PARAM(name) ::muu::impl::vectorcall_param<::muu::impl::MUU_CONCAT(name, _) < scalar_type> >
#endif

/// \endcond

#ifndef MUU_GEOM_PARAM
	#define MUU_GEOM_PARAM(name) const name<scalar_type>&
#endif

#include "header_end.h"
