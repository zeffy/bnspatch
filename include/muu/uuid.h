// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

/// \file
/// \brief  Contains the definition of muu::uuid.

#pragma once
#include "hashing.h"

MUU_DISABLE_WARNINGS;
#include <optional>
#include <iosfwd>
#include <typeindex> // std::hash on-the-cheap
MUU_ENABLE_WARNINGS;

#include "impl/header_start.h"
MUU_DISABLE_SWITCH_WARNINGS;

/// \cond
namespace muu::impl
{
	using uuid_raw_bytes = std::byte[16];

	struct uuid_bytes final
	{
		uuid_raw_bytes value;
	};
	static_assert(sizeof(uuid_bytes) == 16);

	namespace MUU_ENDIANNESS_NAMESPACE
	{
		MUU_ABI_VERSION_START(0);

		template <unsigned>
		struct uuid_slicer;

		template <>
		struct uuid_slicer<2>
		{
			MUU_NODISCARD
			MUU_ATTR(pure)
			static constexpr uint16_t slice(const uuid_raw_bytes& byte_arr, unsigned first) noexcept
			{
				MUU_ASSUME((first + 2u) <= 16u);
				if constexpr (build::is_little_endian)
					return pack(byte_arr[first], byte_arr[first + 1u]);
				else
					return pack(byte_arr[first + 1u], byte_arr[first]);
			}
		};

		template <>
		struct uuid_slicer<4>
		{
			MUU_NODISCARD
			MUU_ATTR(pure)
			static constexpr uint32_t slice(const uuid_raw_bytes& byte_arr, unsigned first) noexcept
			{
				MUU_ASSUME((first + 4u) <= 16u);
				if constexpr (build::is_little_endian)
					return pack(byte_arr[first], byte_arr[first + 1u], byte_arr[first + 2u], byte_arr[first + 3u]);
				else
					return pack(byte_arr[first + 3u], byte_arr[first + 2u], byte_arr[first + 1u], byte_arr[first]);
			}
		};

		template <>
		struct uuid_slicer<8>
		{
			MUU_NODISCARD
			MUU_ATTR(pure)
			static constexpr uint64_t slice(const uuid_raw_bytes& byte_arr, unsigned first) noexcept
			{
				MUU_ASSUME((first + 8u) <= 16u);
				if constexpr (build::is_little_endian)
					return pack(byte_arr[first],
								byte_arr[first + 1u],
								byte_arr[first + 2u],
								byte_arr[first + 3u],
								byte_arr[first + 4u],
								byte_arr[first + 5u],
								byte_arr[first + 6u],
								byte_arr[first + 7u]);
				else
					return pack(byte_arr[first + 7u],
								byte_arr[first + 6u],
								byte_arr[first + 5u],
								byte_arr[first + 4u],
								byte_arr[first + 3u],
								byte_arr[first + 2u],
								byte_arr[first + 1u],
								byte_arr[first]);
			}
		};

		MUU_ABI_VERSION_END;
	} // be/le

	template <unsigned N>
	MUU_ATTR(pure)
	MUU_ATTR(flatten)
	constexpr auto uuid_slice(const uuid_raw_bytes& byte_arr, unsigned first) noexcept
	{
		using slicer = MUU_ENDIANNESS_NAMESPACE::uuid_slicer<N>;
		return slicer::slice(byte_arr, first);
	}

	MUU_API
	void print_to_stream(std::ostream& stream, const uuid&);

	MUU_API
	void print_to_stream(std::wostream& stream, const uuid&);
}
/// \endcond

namespace muu
{
	/// \brief	A UUID variant as per RFC 4122.
	///
	/// \see
	/// 	 - muu::uuid
	/// 	 - RFC 4122: https://tools.ietf.org/html/rfc4122
	enum class uuid_variant : uint8_t
	{
		none,				///< No variant specified.
		standard,			///< The 'standard' variant outlaid in RFC 4122.
		reserved_ncs,		///< Reserved for backward compatibility.
		reserved_microsoft, ///< Reserved for backward compatibility.
		reserved_future,	///< Reserved for backward compatibility.
	};

	/// \brief	A UUID version as per RFC 4122.
	///
	/// \see
	/// 	 - muu::uuid
	/// 	 - RFC 4122: https://tools.ietf.org/html/rfc4122
	enum class uuid_version : uint8_t
	{
		none,			 ///< No version specified.
		time,			 ///< Version 1: Time-based UUID.
		dce,			 ///< Version 2: DCE Security version, with embedded POSIX UIDs.
		name_md5,		 ///< Version 3: Name-based UUID generated using MD5 hashing.
		random,			 ///< Version 4: Randomly-generated UUID.
		name_sha1,		 ///< Version 5: Name-based UUID generated using SHA-1 hashing.
		unknown = 0b1111 ///< Unknown or non-standard version.
	};

	MUU_ABI_VERSION_START(0);

	/// \brief A 128-bit universally-unique identifier (UUID).
	/// \ingroup core
	///
	/// \see RFC 4122: https://tools.ietf.org/html/rfc4122
	struct uuid
	{
		/// \brief	Static constants for this type.
		using constants = muu::constants<uuid>;

		/// \brief The raw bytes in the UUID.
		///
		/// \details The byte layout of the UUID is always the same regardless of the target platform:
		/// <br>
		/// <br>`[ 0]`&nbsp;&nbsp; time_low - most significant byte
		/// <br>`[ 1]`&nbsp;&nbsp; ...
		/// <br>`[ 2]`&nbsp;&nbsp; ...
		/// <br>`[ 3]`&nbsp;&nbsp; time_low - least significant byte
		/// <br>`[ 4]`&nbsp;&nbsp; time_mid - most significante byte
		/// <br>`[ 5]`&nbsp;&nbsp; time_mid - least significante byte
		/// <br>`[ 6]`&nbsp;&nbsp; time_high_and_version - most significante byte
		/// <br>`[ 7]`&nbsp;&nbsp; time_high_and_version - least significante byte
		/// <br>`[ 8]`&nbsp;&nbsp; clock_seq_high_and_reserved
		/// <br>`[ 9]`&nbsp;&nbsp; clock_seq_low
		/// <br>`[10]`&nbsp;&nbsp; node - most significant byte
		/// <br>`[11]`&nbsp;&nbsp; ...
		/// <br>`[12]`&nbsp;&nbsp; ...
		/// <br>`[13]`&nbsp;&nbsp; ...
		/// <br>`[14]`&nbsp;&nbsp; ...
		/// <br>`[15]`&nbsp;&nbsp; node - least significant byte
		/// <br><br>Relevant excerpt from the UUID RFC:
		/// \out
		/// In the absence of explicit application or presentation protocol
		/// specification to the contrary, a UUID is encoded as a 128-bit object,
		/// as follows:
		///
		/// The fields are encoded as 16 octets, with the sizes and order of the
		/// fields defined above, and with each field encoded with the Most
		/// Significant Byte first (known as network byte order).  Note that the
		/// field names, particularly for multiplexed fields, follow historical
		/// practice.
		///
		/// 0                   1                   2                   3
		///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		/// |                          time_low                             |
		/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		/// |       time_mid                |      time_high_and_version    |
		/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		/// |clk_seq_hi_res |  clk_seq_low  |         node (0-1)            |
		/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		/// |                         node (2-5)                            |
		/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		/// \eout
		impl::uuid_bytes bytes;

		/// \brief Creates a new UUID using the platform's UUID generator.
		MUU_API
		static uuid generate() noexcept;

		/// \brief Default constructor. Leaves the UUID uninitialized.
		uuid() noexcept = default;

		/// \brief	Creates a UUID from it's raw integral components, as per RFC 4122.
		///
		/// \param	time_low						The 'time-low' field.
		/// \param	time_mid						The 'time-middle' field.
		/// \param	time_high_and_version			The 'time-high-and-version' field.
		/// \param	clock_seq_high_and_reserved		The 'clock-seq-high-and-reserved' field.
		/// \param	clock_seq_low					The 'clock-seq-low' field.
		/// \param	node							The 'node' field. The highest 2 bytes are ignored
		/// 										(the 'node' field of a UUID is a 48-bit unsigned int).
		MUU_NODISCARD_CTOR
		constexpr uuid(uint32_t time_low,
					   uint16_t time_mid,
					   uint16_t time_high_and_version,
					   uint8_t clock_seq_high_and_reserved,
					   uint8_t clock_seq_low,
					   uint64_t node) noexcept
			: bytes{ { std::byte{ byte_select < build::is_little_endian ? 3 : 0 > (time_low) },
					   std::byte{ byte_select < build::is_little_endian ? 2 : 1 > (time_low) },
					   std::byte{ byte_select < build::is_little_endian ? 1 : 2 > (time_low) },
					   std::byte{ byte_select < build::is_little_endian ? 0 : 3 > (time_low) },
					   std::byte{ byte_select < build::is_little_endian ? 1 : 0 > (time_mid) },
					   std::byte{ byte_select < build::is_little_endian ? 0 : 1 > (time_mid) },
					   std::byte{ byte_select < build::is_little_endian ? 1 : 0 > (time_high_and_version) },
					   std::byte{ byte_select < build::is_little_endian ? 0 : 1 > (time_high_and_version) },
					   std::byte{ clock_seq_high_and_reserved },
					   std::byte{ clock_seq_low },
					   std::byte{ byte_select < build::is_little_endian ? 5 : 2 > (node) },
					   std::byte{ byte_select < build::is_little_endian ? 4 : 3 > (node) },
					   std::byte{ byte_select < build::is_little_endian ? 3 : 4 > (node) },
					   std::byte{ byte_select < build::is_little_endian ? 2 : 5 > (node) },
					   std::byte{ byte_select < build::is_little_endian ? 1 : 6 > (node) },
					   std::byte{ byte_select < build::is_little_endian ? 0 : 7 > (node) } } }
		{}

		/// \brief	Creats a UUID from it's raw integral components, as per RFC 4122.
		///
		/// \param	time_low				The 'time-low' field.
		/// \param	time_mid				The 'time-middle' field.
		/// \param	time_high_and_version	The 'time-high-and-version' field.
		/// \param	clock_seq				The 'clock-seq-high-and-reserved' (MSB) and 'clock-seq-low' (LSB) fields.
		/// \param	node					The 'node' field. The highest 2 bytes are ignored
		/// 								(the 'node' field of a UUID is a 48-bit unsigned int).
		MUU_NODISCARD_CTOR
		constexpr uuid(uint32_t time_low,
					   uint16_t time_mid,
					   uint16_t time_high_and_version,
					   uint16_t clock_seq,
					   uint64_t node) noexcept
			: bytes{ { std::byte{ byte_select < build::is_little_endian ? 3 : 0 > (time_low) },
					   std::byte{ byte_select < build::is_little_endian ? 2 : 1 > (time_low) },
					   std::byte{ byte_select < build::is_little_endian ? 1 : 2 > (time_low) },
					   std::byte{ byte_select < build::is_little_endian ? 0 : 3 > (time_low) },
					   std::byte{ byte_select < build::is_little_endian ? 1 : 0 > (time_mid) },
					   std::byte{ byte_select < build::is_little_endian ? 0 : 1 > (time_mid) },
					   std::byte{ byte_select < build::is_little_endian ? 1 : 0 > (time_high_and_version) },
					   std::byte{ byte_select < build::is_little_endian ? 0 : 1 > (time_high_and_version) },
					   std::byte{ byte_select < build::is_little_endian ? 1 : 0 > (clock_seq) },
					   std::byte{ byte_select < build::is_little_endian ? 0 : 1 > (clock_seq) },
					   std::byte{ byte_select < build::is_little_endian ? 5 : 2 > (node) },
					   std::byte{ byte_select < build::is_little_endian ? 4 : 3 > (node) },
					   std::byte{ byte_select < build::is_little_endian ? 3 : 4 > (node) },
					   std::byte{ byte_select < build::is_little_endian ? 2 : 5 > (node) },
					   std::byte{ byte_select < build::is_little_endian ? 1 : 6 > (node) },
					   std::byte{ byte_select < build::is_little_endian ? 0 : 7 > (node) } } }
		{}

		/// \brief	Explicitly constructs a null UUID.
		MUU_NODISCARD_CTOR
		constexpr uuid(std::nullptr_t) noexcept : bytes{}
		{}

#if MUU_HAS_INT128

	#if MUU_LITTLE_ENDIAN

		/// \brief	Constructs a UUID directly from a 128-bit integer.
		///
		/// \param 	val	The value to convert into a UUID.
		MUU_NODISCARD_CTOR
		constexpr uuid(uint128_t val) noexcept : bytes{ muu::bit_cast<decltype(bytes)>(byte_reverse(val)) }
		{}

	#else // ^^^ MUU_LITTLE_ENDIAN / MUU_BIG_ENDIAN vvv

		MUU_NODISCARD_CTOR
		constexpr uuid(uint128_t val) noexcept : bytes{ muu::bit_cast<decltype(bytes)>(val) }
		{}

	#endif // MUU_BIG_ENDIAN

#endif // MUU_HAS_INT128

		/// \brief	Constructs a version-5 named UUID by hashing some binary data.
		///
		/// \details UUIDs generated by this constructor are deterministic;
		/// 		 the same namespace and name will always produce the same UUID.
		///
		/// \param 	name_space		The 'name space' the ID will belong to.
		/// \param 	name_data		The 'name' data to hash.
		/// \param 	name_size	  	Size of the name data in bytes.
		///
		/// \see RFC 4122 Section 4.3: https://tools.ietf.org/html/rfc4122#section-4.3
		MUU_NODISCARD_CTOR
		MUU_API
		uuid(const uuid& name_space, const void* name_data, size_t name_size) noexcept;

		/// \brief	Constructs a version-5 named UUID by hashing a string.
		///
		/// \details UUIDs generated by this constructor are deterministic;
		/// 		 the same namespace and name will always produce the same UUID.
		///
		/// \param	name_space	The 'namespace' for the id.
		/// \param	name  		The 'name' of the ID.
		///
		/// \see RFC 4122 Section 4.3: https://tools.ietf.org/html/rfc4122#section-4.3
		MUU_NODISCARD_CTOR
		uuid(const uuid& name_space, std::string_view name) noexcept : uuid{ name_space, name.data(), name.length() }
		{}

#ifdef __cpp_lib_char8_t

		/// \brief	Constructs a version-5 named UUID by hashing a string.
		///
		/// \details UUIDs generated by this constructor are deterministic;
		/// 		 the same namespace and name will always produce the same UUID.
		///
		/// \param	name_space	The 'namespace' for the id.
		/// \param	name  		The 'name' of the ID.
		///
		/// \see RFC 4122 Section 4.3: https://tools.ietf.org/html/rfc4122#section-4.3
		MUU_NODISCARD_CTOR
		uuid(const uuid& name_space, std::u8string_view name) noexcept : uuid{ name_space, name.data(), name.length() }
		{}

#endif

		/// \brief	Returns the UUID's variant.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr uuid_variant variant() const noexcept
		{
			const auto v = static_cast<unsigned>(unwrap((bytes.value[8] & std::byte{ 0b11100000_u8 }) >> 5));
			MUU_ASSUME(v <= 0b111u);

			if (!v)
				return uuid_variant::none;
			else if MUU_UNLIKELY(v <= 0b011u) // 0 x x
				return uuid_variant::reserved_ncs;
			else
			{
				// any possible variant in this branch has the high bit set, i.e. 0b1XX

				if MUU_LIKELY((v | 0b101u) == 0b101u) // 1 0 x
					return uuid_variant::standard;
				else if (v == 0b110) // 1 1 0
					return uuid_variant::reserved_microsoft;
				else // 1 1 1
					return uuid_variant::reserved_future;
			}
		}

		/// \brief	Returns the UUID's version.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr uuid_version version() const noexcept
		{
			const auto v = static_cast<unsigned>(unwrap((bytes.value[6] & std::byte{ 0b11110000_u8 }) >> 4));
			MUU_ASSUME(v <= 0b1111u);

			return v > 5u ? uuid_version::unknown : static_cast<uuid_version>(v);
		}

		/// \brief	Returns the value of the 'time-low' field.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr uint32_t time_low() const noexcept
		{
			return impl::uuid_slice<4>(bytes.value, 0);
		}

		/// \brief	Returns the value of the 'time-mid' field.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr uint16_t time_mid() const noexcept
		{
			return impl::uuid_slice<2>(bytes.value, 4);
		}

		/// \brief	Returns the value of the 'time-high-and-version' field.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr uint16_t time_high_and_version() const noexcept
		{
			return impl::uuid_slice<2>(bytes.value, 6);
		}

		/// \brief	Returns the value of the 'clock-seq-high-and-reserved' field.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr uint8_t clock_seq_high_and_reserved() const noexcept
		{
			return unwrap(bytes.value[8]);
		}

		/// \brief	Returns the value of the 'clock-seq-low' field.
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr uint8_t clock_seq_low() const noexcept
		{
			return unwrap(bytes.value[9]);
		}

		/// \brief	Returns the value of the 'node' field.
		///
		/// \remarks The two most significant bytes of the return value will always be zero
		/// 		 (the 'node' field of a UUID is a 48-bit unsigned int).
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr uint64_t node() const noexcept
		{
			return impl::uuid_slice<8>(bytes.value, 8) & 0x0000FFFFFFFFFFFF_u64;
		}

#if MUU_HAS_INT128

		/// \brief	Converts a UUID directly into a 128-bit integer.
		MUU_NODISCARD
		MUU_ATTR(pure)
		explicit constexpr operator uint128_t() const noexcept
		{
			if constexpr (build::supports_constexpr_bit_cast)
			{
				if constexpr (build::is_little_endian)
					return byte_reverse(muu::bit_cast<uint128_t>(bytes));
				else
					return muu::bit_cast<uint128_t>(bytes);
			}
			else
			{
				if constexpr (build::is_little_endian)
					return pack(bytes.value[0],
								bytes.value[1],
								bytes.value[2],
								bytes.value[3],
								bytes.value[4],
								bytes.value[5],
								bytes.value[6],
								bytes.value[7],
								bytes.value[8],
								bytes.value[9],
								bytes.value[10],
								bytes.value[11],
								bytes.value[12],
								bytes.value[13],
								bytes.value[14],
								bytes.value[15]);
				else
					return pack(bytes.value[15],
								bytes.value[14],
								bytes.value[13],
								bytes.value[12],
								bytes.value[11],
								bytes.value[10],
								bytes.value[9],
								bytes.value[8],
								bytes.value[7],
								bytes.value[6],
								bytes.value[5],
								bytes.value[4],
								bytes.value[3],
								bytes.value[2],
								bytes.value[1],
								bytes.value[0]);
			}
		}

#endif

		/// \brief	Returns true if this UUID has non-zero value.
		MUU_NODISCARD
		MUU_ATTR(pure)
		explicit constexpr operator bool() const noexcept
		{
#if MUU_HAS_INT128
			if constexpr (build::supports_constexpr_bit_cast)
				return muu::bit_cast<uint128_t>(bytes) != uint128_t{};
			else
#endif
			{
				for (size_t i = 0; i < 16_sz; i++)
					if (bytes.value[i] != std::byte{})
						return true;
				return false;
			}
		}

		/// \brief	Returns true if two UUIDs are equal.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr bool operator==(const uuid& lhs, const uuid& rhs) noexcept
		{
#if !MUU_ICC
			if (&lhs == &rhs)
				return true;
#endif

#if MUU_HAS_INT128
			if constexpr (build::supports_constexpr_bit_cast)
				return muu::bit_cast<uint128_t>(lhs) == muu::bit_cast<uint128_t>(rhs);
			else
#endif
			{
				for (size_t i = 0; i < 16_sz; i++)
				{
					if (lhs.bytes.value[i] != rhs.bytes.value[i])
						return false;
				}
				return true;
			}
		}

		/// \brief	Returns true if two UUIDs are not equal.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr bool operator!=(const uuid& lhs, const uuid& rhs) noexcept
		{
			return !(lhs == rhs);
		}

		/// \brief	Returns the lexicographical ordering of two UUID's.
		MUU_NODISCARD
		MUU_ATTR(pure)
		static constexpr int32_t compare(const uuid& lhs, const uuid& rhs) noexcept
		{
#if !MUU_ICC
			if (&lhs == &rhs)
				return 0;
#endif

#if MUU_HAS_INT128
			{
				const auto l = static_cast<uint128_t>(lhs);
				const auto r = static_cast<uint128_t>(rhs);
				if (l != r)
					return l < r ? -1 : 1;
			}
#else
			{
				for (size_t i = 0; i < 16_sz; i++)
				{
					if (lhs.bytes.value[i] != rhs.bytes.value[i])
						return lhs.bytes.value[i] < rhs.bytes.value[i] ? -1 : 1;
				}
			}
#endif

			return 0;
		}

		/// \brief	Returns true if the LHS UUID is ordered lower than the RHS UUID.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr bool operator<(const uuid& lhs, const uuid& rhs) noexcept
		{
			return compare(lhs, rhs) < 0;
		}

		/// \brief	Returns true if the LHS UUID is ordered lower than or equal to the RHS UUID.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr bool operator<=(const uuid& lhs, const uuid& rhs) noexcept
		{
			return compare(lhs, rhs) <= 0;
		}

		/// \brief	Returns true if the LHS UUID is ordered higher than the RHS UUID.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr bool operator>(const uuid& lhs, const uuid& rhs) noexcept
		{
			return compare(lhs, rhs) > 0;
		}

		/// \brief	Returns true if the LHS UUID is ordered higher than or equal to the RHS UUID.
		MUU_NODISCARD
		MUU_ATTR(pure)
		friend constexpr bool operator>=(const uuid& lhs, const uuid& rhs) noexcept
		{
			return compare(lhs, rhs) >= 0;
		}

	  private:
		template <typename T>
		MUU_NODISCARD
		static constexpr std::optional<uuid> parse_impl(std::basic_string_view<T> str) noexcept;

	  public:
		/// \brief	Attempts to parse a UUID from a UTF-8 string.
		MUU_NODISCARD
		static constexpr std::optional<uuid> parse(std::string_view str) noexcept;

#ifdef __cpp_lib_char8_t

		/// \brief	Attempts to parse a UUID from a UTF-8 string.
		MUU_NODISCARD
		static constexpr std::optional<uuid> parse(std::u8string_view str) noexcept;

#endif

		/// \brief	Attempts to parse a UUID from a UTF-16 string.
		MUU_NODISCARD
		static constexpr std::optional<uuid> parse(std::u16string_view str) noexcept;

		/// \brief	Attempts to parse a UUID from a UTF-32 string.
		MUU_NODISCARD
		static constexpr std::optional<uuid> parse(std::u32string_view str) noexcept;

		/// \brief	Attempts to parse a UUID from a wide string.
		MUU_NODISCARD
		static constexpr std::optional<uuid> parse(std::wstring_view str) noexcept;

		/// \brief	Writes a UUID to a text stream.
		template <typename Char, typename Traits>
		friend std::basic_ostream<Char, Traits>& operator<<(std::basic_ostream<Char, Traits>& lhs, const uuid& rhs)
		{
			impl::print_to_stream(lhs, rhs);
			return lhs;
		}
	};

	MUU_ABI_VERSION_END;

	/// \brief	UUID constants.
	///
	/// \ingroup		constants
	template <>
	struct constants<uuid>
	{
		/// \brief	The nil UUID (all bytes are zero).
		static constexpr uuid nil = uuid{ nullptr };

		/// \name Namespaces
		/// @{

		/// \brief	The UUID namespace for domain names (6BA7B810-9DAD-11D1-80B4-00C04FD430C8).
		static constexpr uuid namespace_dns =
			uuid{ 0x6BA7B810u, 0x9DAD_u16, 0x11D1_u16, 0x80B4_u16, 0x00C04FD430C8_u64 };

		/// \brief	The UUID namespace for URLs (6BA7B811-9DAD-11D1-80B4-00C04FD430C8).
		static constexpr uuid namespace_url =
			uuid{ 0x6BA7B811u, 0x9DAD_u16, 0x11D1_u16, 0x80B4_u16, 0x00C04FD430C8_u64 };

		/// \brief	The UUID namespace for ISO OIDs (6BA7B812-9DAD-11D1-80B4-00C04FD430C8).
		static constexpr uuid namespace_oid =
			uuid{ 0x6BA7B812u, 0x9DAD_u16, 0x11D1_u16, 0x80B4_u16, 0x00C04FD430C8_u64 };

		/// \brief	The UUID namespace for X.500 DNs (6BA7B814-9DAD-11D1-80B4-00C04FD430C8).
		static constexpr uuid namespace_x500 =
			uuid{ 0x6BA7B814u, 0x9DAD_u16, 0x11D1_u16, 0x80B4_u16, 0x00C04FD430C8_u64 };

		/// @}
	};

	namespace impl
	{
		MUU_ABI_VERSION_START(0);

		struct uuid_parser
		{
			uuid value{ nullptr };
			bool bracketed = false;
			unsigned digits{};
			unsigned rsh = 4;
			enum states
			{
				s_initial,
				s_parsing,
				s_finished,
				s_error
			} state{};

			constexpr uuid_parser() noexcept = default;

			MUU_NODISCARD
			explicit constexpr operator bool() noexcept
			{
				return !bracketed && state == s_finished;
			}

			constexpr bool operator()(char32_t c) noexcept
			{
				if (!muu::is_ascii_code_point(c))
				{
					state = s_error;
					return false;
				}

				switch (state)
				{
					// haven't seen any hex characters yet, might see whitespace and/or a left brace
					case s_initial:
						if (c == U'{')
						{
							if (bracketed)
								state = s_error;
							bracketed = true;
							break;
						}
						else if (muu::is_ascii_whitespace(c))
							break;
						else if (muu::is_hexadecimal_digit(c))
							state = s_parsing;
						else
						{
							state = s_error;
							break;
						}

						[[fallthrough]];

					// consuming hex digits, optional whitespace/hyphens between octets
					case s_parsing:
						if (muu::is_hexadecimal_digit(c))
						{
							value.bytes.value[digits / 2u] |= static_cast<std::byte>(hex_to_dec(c) << rsh);
							if (++digits == 32)
								state = s_finished;
							rsh = ((digits + 1u) % 2u) * 4u;
						}
						else if (muu::is_ascii_hyphen(c) || muu::is_ascii_whitespace(c))
						{
							if (digits % 2u == 1u)
								state = s_error;
						}
						else
							state = s_error;
						break;

					// consumed all digits, closing out with trailing whitespace and maybe a bracket
					case s_finished:
						if (c == U'}')
						{
							if (bracketed)
								bracketed = false;
							else
								state = s_error;
						}
						else if (muu::is_ascii_whitespace(c))
							break;
						else
							state = s_error;
						break;
				}
				return state != s_error;
			}
		};

		MUU_ABI_VERSION_END;
	}

	/// \cond

	template <typename T>
	MUU_ATTR(pure)
	constexpr std::optional<uuid> uuid::parse_impl(std::basic_string_view<T> str) noexcept
	{
		if (str.length() < 32) // uuid with no braces or hyphens
			return {};

		impl::uuid_parser parser;
		impl::utf_decode(str, parser);
		if (parser)
			return parser.value;
		return {};
	}

	MUU_ATTR(pure)
	constexpr std::optional<uuid> uuid::parse(std::string_view str) noexcept
	{
		return parse_impl(str);
	}
#ifdef __cpp_lib_char8_t
	MUU_ATTR(pure)
	constexpr std::optional<uuid> uuid::parse(std::u8string_view str) noexcept
	{
		return parse_impl(str);
	}
#endif
	MUU_ATTR(pure)
	constexpr std::optional<uuid> uuid::parse(std::u16string_view str) noexcept
	{
		return parse_impl(str);
	}
	MUU_ATTR(pure)
	constexpr std::optional<uuid> uuid::parse(std::u32string_view str) noexcept
	{
		return parse_impl(str);
	}
	MUU_ATTR(pure)
	constexpr std::optional<uuid> uuid::parse(std::wstring_view str) noexcept
	{
		return parse_impl(str);
	}

	/// \endcond

	inline namespace literals
	{
		MUU_ABI_VERSION_START(0);

		/// \brief	Constructs a uuid from a string literal using uuid::parse.
		/// \detail \cpp
		/// const uuid id = "{06B35EFD-A532-4410-ADD1-C8C536C31A84}"_uuid;
		/// \ecpp
		///
		/// \relatesalso muu::uuid
		MUU_NODISCARD
		MUU_ATTR(pure)
		MUU_CONSTEVAL
		uuid operator"" _uuid(const char* str, size_t len) noexcept
		{
			auto id = uuid::parse(std::string_view{ str, len });
			return id ? *id : uuid{};
		}

		MUU_ABI_VERSION_END;
	}
}

namespace std
{
	/// \brief	Specialization of std::hash for muu::uuid.
	/// \ingroup hashing
	template <>
	struct hash<muu::uuid>
	{
		MUU_NODISCARD
		MUU_ATTR(pure)
		constexpr size_t operator()(const muu::uuid& id) const noexcept
		{
			using namespace muu;

#define get_slice(idx) impl::uuid_slice<sizeof(size_t)>(id.bytes.value, sizeof(size_t) * idx)

			hash_combiner<> hasher{ get_slice(0) };
			if constexpr (sizeof(size_t) < 16)
				hasher(get_slice(1));
			if constexpr (sizeof(size_t) < 8)
			{
				hasher(get_slice(2));
				hasher(get_slice(3));
			}
			if constexpr (sizeof(size_t) < 4)
			{
				hasher(get_slice(4));
				hasher(get_slice(5));
				hasher(get_slice(6));
				hasher(get_slice(7));
			}
			return hasher.value();

#undef get_slice
		}
	};
}

#include "impl/header_end.h"
