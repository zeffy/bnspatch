// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

/// \file
/// \brief Contains the definitions of functions and types related to the generation of hashes.

#pragma once
#include "strings.h"

MUU_DISABLE_WARNINGS;
#include <iosfwd>
MUU_ENABLE_WARNINGS;

#include "impl/header_start.h"
MUU_FORCE_NDEBUG_OPTIMIZATIONS;

namespace muu
{
	/// \addtogroup		hashing
	/// @{

	/// \cond
	namespace impl
	{
		MUU_ABI_VERSION_START(0);

		// these constants are based on the 'golden ratio', as seen in boost::hash_combine
		// and about a million other places. It probably *should* be something better, but I'm no hashing expert.
		// see:
		// https://stackoverflow.com/questions/35985960/c-why-is-boosthash-combine-the-best-way-to-combine-hash-values/50978188#50978188

		template <size_t Bits>
		struct hash_combiner_traits
		{
			static_assert(
				always_false<hash_combiner_traits<Bits>>,
				"Hash combining with hashes of given number of bits is not implemented on the target platform");
		};

		template <>
		struct hash_combiner_traits<16>
		{
			static constexpr uint16_t offset = 0x9E37_u16;
			static constexpr int left_shift	 = 3;
			static constexpr int right_shift = 1;
		};

		template <>
		struct hash_combiner_traits<32>
		{
			static constexpr uint32_t offset = 0x9E3779B9_u32;
			static constexpr int left_shift	 = 6;
			static constexpr int right_shift = 2;
		};

		template <>
		struct hash_combiner_traits<64>
		{
			static constexpr uint64_t offset = 0x9E3779B97F4A7C15_u64;
			static constexpr int left_shift	 = 12;
			static constexpr int right_shift = 4;
		};

#if MUU_HAS_INT128

		template <>
		struct hash_combiner_traits<128>
		{
			static constexpr uint128_t offset = pack(0x9E3779B97F4A7C15_u64, 0xF39CC0605D396154_u64);
			static constexpr int left_shift	  = 24;
			static constexpr int right_shift  = 8;
		};

#endif

		MUU_ABI_VERSION_END;
	}
	/// \endcond

	MUU_ABI_VERSION_START(0);

	/// \brief	A hash combiner for integral hashes.
	///
	/// \tparam	Bits	The hash size, in bits.
	template <size_t Bits = (sizeof(size_t) * CHAR_BIT)>
	class MUU_TRIVIAL_ABI hash_combiner
	{
	  public:
		using hash_type = unsigned_integer<Bits>;

	  private:
		hash_type value_;

	  public:
		constexpr hash_combiner(hash_type seed_hash) noexcept : value_{ seed_hash }
		{}

		constexpr hash_combiner& operator()(hash_type new_hash) noexcept
		{
			using traits = impl::hash_combiner_traits<Bits>;
			value_ ^= (new_hash + traits::offset + (value_ << traits::left_shift) + (value_ >> traits::right_shift));
			return *this;
		}

		MUU_NODISCARD
		constexpr hash_type value() const noexcept
		{
			return value_;
		}
	};

	MUU_ABI_VERSION_END;

	/// \cond
	namespace impl
	{
		template <size_t Bits>
		struct fnv1a_traits
		{
			static_assert(
				always_false<std::integral_constant<size_t, Bits>>,
				"FNV-1a hashing with integers of given number of bits is not implemented on the target platform");
		};

		template <>
		struct fnv1a_traits<32>
		{
			static constexpr uint32_t prime		   = 0x01000193_u32;
			static constexpr uint32_t offset_basis = 0x811C9DC5_u32;
		};

		template <>
		struct fnv1a_traits<64>
		{
			static constexpr uint64_t prime		   = 0x00000100000001B3_u64;
			static constexpr uint64_t offset_basis = 0xCBF29CE484222325_u64;
		};

#if MUU_HAS_INT128

		template <>
		struct fnv1a_traits<128>
		{
			static constexpr uint128_t prime		= pack(0x0000000001000000_u64, 0x000000000000013B_u64);
			static constexpr uint128_t offset_basis = pack(0x6C62272E07BB0142_u64, 0x62B821756295C58D_u64);
		};

#endif

		template <typename T>
		constexpr void add_to_hasher_as_utf8(T& hasher, char32_t cp) noexcept
		{
			if (!cp)
				hasher(uint8_t{});
			else
			{
				const auto utf8 = utf8_code_point<char>{ cp };
				hasher(utf8.view());
			}
		}

		template <typename T, typename U>
		constexpr void add_to_hasher_as_utf8(T& hasher, std::basic_string_view<U> str) noexcept
		{
			utf_decode(str, [&](char32_t cp) noexcept { add_to_hasher_as_utf8(hasher, cp); });
		}
	}
	/// \endcond

	MUU_ABI_VERSION_START(0);

	/// \brief	FNV-1a hasher.
	///
	/// \tparam	Bits	The hash size, in bits.
	///
	/// \see [Fowler-Noll-Vo hash function](https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function)
	template <size_t Bits = (sizeof(size_t) * CHAR_BIT)>
	class MUU_TRIVIAL_ABI fnv1a
	{
	  public:
		using hash_type = unsigned_integer<Bits>;

	  private:
		hash_type value_ = impl::fnv1a_traits<Bits>::offset_basis;

		template <typename Char>
		constexpr fnv1a& hash_string_view(std::basic_string_view<Char> str) noexcept
		{
			if constexpr (sizeof(Char) == 1)
			{
				for (auto c : str)
					(*this)(static_cast<uint8_t>(c));
			}
			else
			{
				impl::add_to_hasher_as_utf8(*this, str);
			}
			return *this;
		}

	  public:
		/// \brief	Constructs a new FNV-1a hasher.
		constexpr fnv1a() noexcept = default;

		/// \brief	Appends a single byte to the hash function's input.
		constexpr fnv1a& operator()(uint8_t byte) noexcept
		{
			value_ ^= static_cast<hash_type>(byte);
			value_ *= impl::fnv1a_traits<Bits>::prime;
			return *this;
		}

		/// \brief	Appends a single byte to the hash function's input.
		constexpr fnv1a& operator()(std::byte byte) noexcept
		{
			return (*this)(static_cast<uint8_t>(byte));
		}

		/// \brief	Appends a sequence of raw data to the hash function's input.
		fnv1a& operator()(const void* data, size_t size) noexcept
		{
			const auto end = pointer_cast<const uint8_t*>(data) + size;
			for (auto ptr = pointer_cast<const uint8_t*>(data); ptr != end; ptr++)
				(*this)(*ptr);
			return *this;
		}

		/// \brief	Appends a string to the hash function's input.
		constexpr fnv1a& operator()(std::string_view str) noexcept
		{
			return hash_string_view(str);
		}

		/// \brief	Appends a wide string to the hash function's input.
		constexpr fnv1a& operator()(std::wstring_view str) noexcept
		{
			return hash_string_view(str);
		}

		/// \brief	Appends a UTF-32 string to the hash function's input.
		constexpr fnv1a& operator()(std::u32string_view str) noexcept
		{
			return hash_string_view(str);
		}

		/// \brief	Appends a UTF-16 string to the hash function's input.
		constexpr fnv1a& operator()(std::u16string_view str) noexcept
		{
			return hash_string_view(str);
		}

#ifdef __cpp_lib_char8_t

		/// \brief	Appends a UTF-8 string to the hash function's input.
		constexpr fnv1a& operator()(std::u8string_view str) noexcept
		{
			return hash_string_view(str);
		}

#endif // __cpp_lib_char8_t

		/// \brief	Returns the calculated hash value.
		MUU_NODISCARD
		constexpr hash_type value() const noexcept
		{
			return value_;
		}

		/// \brief	Writes an FNV-1a hash to a text stream.
		template <typename Char, typename Traits>
		friend std::basic_ostream<Char, Traits>& operator<<(std::basic_ostream<Char, Traits>& lhs, const fnv1a& rhs)
		{
			for (unsigned i = sizeof(value_); i-- > 0u;)
				lhs << impl::byte_to_hex(byte_select(rhs.value_, i));
			return lhs;
		}
	};

	/// \brief	SHA-1 hasher.
	///
	/// \details \cpp
	/// sha1 hasher;
	/// hasher("The quick brown fox jumps over the lazy dog"sv);
	/// hasher.finish();
	/// std::cout << hasher << std::endl;
	/// \ecpp
	///
	/// \out
	/// 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
	/// \eout
	///
	/// \see [SHA-1](https://en.wikipedia.org/wiki/SHA-1)
	class sha1 final
	{
	  public:
		struct hash_bytes
		{
			std::byte value[20];
		};
		using hash_type = hash_bytes;

	  private:
		struct digest_bytes
		{
			uint32_t value[5];
		};

		union state_t
		{
			digest_bytes digest;
			hash_bytes hash;
		} state;
		uint32_t processed_blocks{};
		uint8_t current_block_length{};
		uint8_t current_block[64];
		bool finished_ = false;

		void add(uint8_t) noexcept;
		void add(const uint8_t*, size_t) noexcept;

		template <typename Char>
		sha1& hash_string_view(std::basic_string_view<Char> str) noexcept
		{
			if constexpr (sizeof(Char) == 1)
			{
				return (*this)(str.data(), str.size());
			}
			else
			{
				impl::add_to_hasher_as_utf8(*this, str);
				return *this;
			}
		}

	  public:
		/// \brief	Constructs a new SHA-1 hasher.
		MUU_API
		sha1() noexcept;

		/// \brief	Appends a single byte to the hash function's input.
		MUU_API
		sha1& operator()(uint8_t byte) noexcept;

		/// \brief	Appends a single byte to the hash function's input.
		sha1& operator()(std::byte byte) noexcept
		{
			return (*this)(unwrap(byte));
		}

		/// \brief	Appends a sequence of raw data to the hash function's input.
		MUU_API
		sha1& operator()(const void* data, size_t size) noexcept;

		/// \brief	Appends a string to the hash function's input.
		sha1& operator()(std::string_view str) noexcept
		{
			return hash_string_view(str);
		}

		/// \brief	Appends a wide string to the hash function's input.
		sha1& operator()(std::wstring_view str) noexcept
		{
			return hash_string_view(str);
		}

		/// \brief	Appends a UTF-32 string to the hash function's input.
		sha1& operator()(std::u32string_view str) noexcept
		{
			return hash_string_view(str);
		}

		/// \brief	Appends a UTF-16 string to the hash function's input.
		sha1& operator()(std::u16string_view str) noexcept
		{
			return hash_string_view(str);
		}

#ifdef __cpp_lib_char8_t

		/// \brief	Appends a UTF-8 string to the hash function's input.
		sha1& operator()(std::u8string_view str) noexcept
		{
			return hash_string_view(str);
		}

#endif // __cpp_lib_char8_t

		/// \brief	Finishes calculating the hash.
		/// \details Appending to the hash function's input has no effect after finish() is called.
		MUU_API
		sha1& finish() noexcept;

		/// \brief	Returns the calculated hash value.
		///
		/// \warning Calling this before finish() has been called is undefined behaviour.
		MUU_NODISCARD
		MUU_ATTR(pure)
		const hash_type& value() const noexcept
		{
			return state.hash;
		}

		/// \brief	Writes an SHA-1 hash to a text stream.
		///
		///	\warning Calling this before finish() has been called is undefined behaviour.
		template <typename Char, typename Traits>
		friend std::basic_ostream<Char, Traits>& operator<<(std::basic_ostream<Char, Traits>& lhs, const sha1& rhs)
		{
			for (auto byte : rhs.value().value)
				lhs << impl::byte_to_hex(unwrap(byte));
			return lhs;
		}
	};

	MUU_ABI_VERSION_END;

	/// @}
}

MUU_RESET_NDEBUG_OPTIMIZATIONS;
#include "impl/header_end.h"
