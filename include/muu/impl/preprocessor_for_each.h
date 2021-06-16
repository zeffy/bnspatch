// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

#pragma once

#define MUU_FOR_EACH_FORCE_UNROLL(x) x // without this msvc treats forwarded __VA_ARGS__ as a single token

#define MUU_FOR_EACH_IMPL_0(fn, x)		  fn(x)
#define MUU_FOR_EACH_IMPL_1(fn, x, ...)	  fn(x) MUU_FOR_EACH_IMPL_0(fn, __VA_ARGS__)
#define MUU_FOR_EACH_IMPL_2(fn, x, ...)	  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_1(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_3(fn, x, ...)	  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_2(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_4(fn, x, ...)	  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_3(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_5(fn, x, ...)	  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_4(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_6(fn, x, ...)	  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_5(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_7(fn, x, ...)	  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_6(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_8(fn, x, ...)	  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_7(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_9(fn, x, ...)	  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_8(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_10(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_9(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_11(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_10(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_12(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_11(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_13(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_12(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_14(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_13(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_15(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_14(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_16(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_15(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_17(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_16(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_18(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_17(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_19(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_18(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_20(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_19(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_21(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_20(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_22(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_21(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_23(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_22(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_24(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_23(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_25(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_24(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_26(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_25(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_27(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_26(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_28(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_27(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_29(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_28(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_30(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_29(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_31(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_30(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_32(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_31(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_33(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_32(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_34(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_33(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_35(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_34(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_36(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_35(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_37(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_36(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_38(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_37(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_39(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_38(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_40(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_39(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_41(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_40(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_42(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_41(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_43(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_42(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_44(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_43(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_45(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_44(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_46(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_45(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_47(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_46(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_48(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_47(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_49(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_48(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_50(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_49(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_51(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_50(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_52(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_51(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_53(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_52(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_54(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_53(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_55(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_54(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_56(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_55(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_57(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_56(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_58(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_57(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_59(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_58(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_60(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_59(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_61(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_60(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_62(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_61(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_63(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_62(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_64(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_63(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_65(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_64(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_66(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_65(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_67(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_66(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_68(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_67(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_69(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_68(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_70(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_69(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_71(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_70(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_72(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_71(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_73(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_72(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_74(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_73(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_75(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_74(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_76(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_75(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_77(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_76(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_78(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_77(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_79(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_78(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_80(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_79(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_81(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_80(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_82(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_81(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_83(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_82(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_84(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_83(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_85(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_84(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_86(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_85(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_87(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_86(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_88(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_87(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_89(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_88(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_90(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_89(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_91(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_90(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_92(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_91(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_93(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_92(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_94(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_93(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_95(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_94(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_96(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_95(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_97(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_96(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_98(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_97(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_99(fn, x, ...)  fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_98(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_100(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_99(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_101(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_100(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_102(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_101(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_103(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_102(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_104(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_103(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_105(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_104(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_106(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_105(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_107(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_106(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_108(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_107(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_109(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_108(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_110(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_109(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_111(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_110(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_112(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_111(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_113(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_112(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_114(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_113(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_115(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_114(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_116(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_115(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_117(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_116(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_118(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_117(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_119(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_118(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_120(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_119(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_121(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_120(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_122(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_121(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_123(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_122(fn, __VA_ARGS__))
#define MUU_FOR_EACH_IMPL_124(fn, x, ...) fn(x) MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_123(fn, __VA_ARGS__))

#define MUU_FOR_EACH_IMPL_SELECT(_0,                                                                                   \
								 _1,                                                                                   \
								 _2,                                                                                   \
								 _3,                                                                                   \
								 _4,                                                                                   \
								 _5,                                                                                   \
								 _6,                                                                                   \
								 _7,                                                                                   \
								 _8,                                                                                   \
								 _9,                                                                                   \
								 _10,                                                                                  \
								 _11,                                                                                  \
								 _12,                                                                                  \
								 _13,                                                                                  \
								 _14,                                                                                  \
								 _15,                                                                                  \
								 _16,                                                                                  \
								 _17,                                                                                  \
								 _18,                                                                                  \
								 _19,                                                                                  \
								 _20,                                                                                  \
								 _21,                                                                                  \
								 _22,                                                                                  \
								 _23,                                                                                  \
								 _24,                                                                                  \
								 _25,                                                                                  \
								 _26,                                                                                  \
								 _27,                                                                                  \
								 _28,                                                                                  \
								 _29,                                                                                  \
								 _30,                                                                                  \
								 _31,                                                                                  \
								 _32,                                                                                  \
								 _33,                                                                                  \
								 _34,                                                                                  \
								 _35,                                                                                  \
								 _36,                                                                                  \
								 _37,                                                                                  \
								 _38,                                                                                  \
								 _39,                                                                                  \
								 _40,                                                                                  \
								 _41,                                                                                  \
								 _42,                                                                                  \
								 _43,                                                                                  \
								 _44,                                                                                  \
								 _45,                                                                                  \
								 _46,                                                                                  \
								 _47,                                                                                  \
								 _48,                                                                                  \
								 _49,                                                                                  \
								 _50,                                                                                  \
								 _51,                                                                                  \
								 _52,                                                                                  \
								 _53,                                                                                  \
								 _54,                                                                                  \
								 _55,                                                                                  \
								 _56,                                                                                  \
								 _57,                                                                                  \
								 _58,                                                                                  \
								 _59,                                                                                  \
								 _60,                                                                                  \
								 _61,                                                                                  \
								 _62,                                                                                  \
								 _63,                                                                                  \
								 _64,                                                                                  \
								 _65,                                                                                  \
								 _66,                                                                                  \
								 _67,                                                                                  \
								 _68,                                                                                  \
								 _69,                                                                                  \
								 _70,                                                                                  \
								 _71,                                                                                  \
								 _72,                                                                                  \
								 _73,                                                                                  \
								 _74,                                                                                  \
								 _75,                                                                                  \
								 _76,                                                                                  \
								 _77,                                                                                  \
								 _78,                                                                                  \
								 _79,                                                                                  \
								 _80,                                                                                  \
								 _81,                                                                                  \
								 _82,                                                                                  \
								 _83,                                                                                  \
								 _84,                                                                                  \
								 _85,                                                                                  \
								 _86,                                                                                  \
								 _87,                                                                                  \
								 _88,                                                                                  \
								 _89,                                                                                  \
								 _90,                                                                                  \
								 _91,                                                                                  \
								 _92,                                                                                  \
								 _93,                                                                                  \
								 _94,                                                                                  \
								 _95,                                                                                  \
								 _96,                                                                                  \
								 _97,                                                                                  \
								 _98,                                                                                  \
								 _99,                                                                                  \
								 _100,                                                                                 \
								 _101,                                                                                 \
								 _102,                                                                                 \
								 _103,                                                                                 \
								 _104,                                                                                 \
								 _105,                                                                                 \
								 _106,                                                                                 \
								 _107,                                                                                 \
								 _108,                                                                                 \
								 _109,                                                                                 \
								 _110,                                                                                 \
								 _111,                                                                                 \
								 _112,                                                                                 \
								 _113,                                                                                 \
								 _114,                                                                                 \
								 _115,                                                                                 \
								 _116,                                                                                 \
								 _117,                                                                                 \
								 _118,                                                                                 \
								 _119,                                                                                 \
								 _120,                                                                                 \
								 _121,                                                                                 \
								 _122,                                                                                 \
								 _123,                                                                                 \
								 _124,                                                                                 \
								 fn,                                                                                   \
								 ...)                                                                                  \
	fn

#define MUU_FOR_EACH(fn, ...)                                                                                          \
	MUU_FOR_EACH_FORCE_UNROLL(MUU_FOR_EACH_IMPL_SELECT(__VA_ARGS__,                                                    \
													   MUU_FOR_EACH_IMPL_124,                                          \
													   MUU_FOR_EACH_IMPL_123,                                          \
													   MUU_FOR_EACH_IMPL_122,                                          \
													   MUU_FOR_EACH_IMPL_121,                                          \
													   MUU_FOR_EACH_IMPL_120,                                          \
													   MUU_FOR_EACH_IMPL_119,                                          \
													   MUU_FOR_EACH_IMPL_118,                                          \
													   MUU_FOR_EACH_IMPL_117,                                          \
													   MUU_FOR_EACH_IMPL_116,                                          \
													   MUU_FOR_EACH_IMPL_115,                                          \
													   MUU_FOR_EACH_IMPL_114,                                          \
													   MUU_FOR_EACH_IMPL_113,                                          \
													   MUU_FOR_EACH_IMPL_112,                                          \
													   MUU_FOR_EACH_IMPL_111,                                          \
													   MUU_FOR_EACH_IMPL_110,                                          \
													   MUU_FOR_EACH_IMPL_109,                                          \
													   MUU_FOR_EACH_IMPL_108,                                          \
													   MUU_FOR_EACH_IMPL_107,                                          \
													   MUU_FOR_EACH_IMPL_106,                                          \
													   MUU_FOR_EACH_IMPL_105,                                          \
													   MUU_FOR_EACH_IMPL_104,                                          \
													   MUU_FOR_EACH_IMPL_103,                                          \
													   MUU_FOR_EACH_IMPL_102,                                          \
													   MUU_FOR_EACH_IMPL_101,                                          \
													   MUU_FOR_EACH_IMPL_100,                                          \
													   MUU_FOR_EACH_IMPL_99,                                           \
													   MUU_FOR_EACH_IMPL_98,                                           \
													   MUU_FOR_EACH_IMPL_97,                                           \
													   MUU_FOR_EACH_IMPL_96,                                           \
													   MUU_FOR_EACH_IMPL_95,                                           \
													   MUU_FOR_EACH_IMPL_94,                                           \
													   MUU_FOR_EACH_IMPL_93,                                           \
													   MUU_FOR_EACH_IMPL_92,                                           \
													   MUU_FOR_EACH_IMPL_91,                                           \
													   MUU_FOR_EACH_IMPL_90,                                           \
													   MUU_FOR_EACH_IMPL_89,                                           \
													   MUU_FOR_EACH_IMPL_88,                                           \
													   MUU_FOR_EACH_IMPL_87,                                           \
													   MUU_FOR_EACH_IMPL_86,                                           \
													   MUU_FOR_EACH_IMPL_85,                                           \
													   MUU_FOR_EACH_IMPL_84,                                           \
													   MUU_FOR_EACH_IMPL_83,                                           \
													   MUU_FOR_EACH_IMPL_82,                                           \
													   MUU_FOR_EACH_IMPL_81,                                           \
													   MUU_FOR_EACH_IMPL_80,                                           \
													   MUU_FOR_EACH_IMPL_79,                                           \
													   MUU_FOR_EACH_IMPL_78,                                           \
													   MUU_FOR_EACH_IMPL_77,                                           \
													   MUU_FOR_EACH_IMPL_76,                                           \
													   MUU_FOR_EACH_IMPL_75,                                           \
													   MUU_FOR_EACH_IMPL_74,                                           \
													   MUU_FOR_EACH_IMPL_73,                                           \
													   MUU_FOR_EACH_IMPL_72,                                           \
													   MUU_FOR_EACH_IMPL_71,                                           \
													   MUU_FOR_EACH_IMPL_70,                                           \
													   MUU_FOR_EACH_IMPL_69,                                           \
													   MUU_FOR_EACH_IMPL_68,                                           \
													   MUU_FOR_EACH_IMPL_67,                                           \
													   MUU_FOR_EACH_IMPL_66,                                           \
													   MUU_FOR_EACH_IMPL_65,                                           \
													   MUU_FOR_EACH_IMPL_64,                                           \
													   MUU_FOR_EACH_IMPL_63,                                           \
													   MUU_FOR_EACH_IMPL_62,                                           \
													   MUU_FOR_EACH_IMPL_61,                                           \
													   MUU_FOR_EACH_IMPL_60,                                           \
													   MUU_FOR_EACH_IMPL_59,                                           \
													   MUU_FOR_EACH_IMPL_58,                                           \
													   MUU_FOR_EACH_IMPL_57,                                           \
													   MUU_FOR_EACH_IMPL_56,                                           \
													   MUU_FOR_EACH_IMPL_55,                                           \
													   MUU_FOR_EACH_IMPL_54,                                           \
													   MUU_FOR_EACH_IMPL_53,                                           \
													   MUU_FOR_EACH_IMPL_52,                                           \
													   MUU_FOR_EACH_IMPL_51,                                           \
													   MUU_FOR_EACH_IMPL_50,                                           \
													   MUU_FOR_EACH_IMPL_49,                                           \
													   MUU_FOR_EACH_IMPL_48,                                           \
													   MUU_FOR_EACH_IMPL_47,                                           \
													   MUU_FOR_EACH_IMPL_46,                                           \
													   MUU_FOR_EACH_IMPL_45,                                           \
													   MUU_FOR_EACH_IMPL_44,                                           \
													   MUU_FOR_EACH_IMPL_43,                                           \
													   MUU_FOR_EACH_IMPL_42,                                           \
													   MUU_FOR_EACH_IMPL_41,                                           \
													   MUU_FOR_EACH_IMPL_40,                                           \
													   MUU_FOR_EACH_IMPL_39,                                           \
													   MUU_FOR_EACH_IMPL_38,                                           \
													   MUU_FOR_EACH_IMPL_37,                                           \
													   MUU_FOR_EACH_IMPL_36,                                           \
													   MUU_FOR_EACH_IMPL_35,                                           \
													   MUU_FOR_EACH_IMPL_34,                                           \
													   MUU_FOR_EACH_IMPL_33,                                           \
													   MUU_FOR_EACH_IMPL_32,                                           \
													   MUU_FOR_EACH_IMPL_31,                                           \
													   MUU_FOR_EACH_IMPL_30,                                           \
													   MUU_FOR_EACH_IMPL_29,                                           \
													   MUU_FOR_EACH_IMPL_28,                                           \
													   MUU_FOR_EACH_IMPL_27,                                           \
													   MUU_FOR_EACH_IMPL_26,                                           \
													   MUU_FOR_EACH_IMPL_25,                                           \
													   MUU_FOR_EACH_IMPL_24,                                           \
													   MUU_FOR_EACH_IMPL_23,                                           \
													   MUU_FOR_EACH_IMPL_22,                                           \
													   MUU_FOR_EACH_IMPL_21,                                           \
													   MUU_FOR_EACH_IMPL_20,                                           \
													   MUU_FOR_EACH_IMPL_19,                                           \
													   MUU_FOR_EACH_IMPL_18,                                           \
													   MUU_FOR_EACH_IMPL_17,                                           \
													   MUU_FOR_EACH_IMPL_16,                                           \
													   MUU_FOR_EACH_IMPL_15,                                           \
													   MUU_FOR_EACH_IMPL_14,                                           \
													   MUU_FOR_EACH_IMPL_13,                                           \
													   MUU_FOR_EACH_IMPL_12,                                           \
													   MUU_FOR_EACH_IMPL_11,                                           \
													   MUU_FOR_EACH_IMPL_10,                                           \
													   MUU_FOR_EACH_IMPL_9,                                            \
													   MUU_FOR_EACH_IMPL_8,                                            \
													   MUU_FOR_EACH_IMPL_7,                                            \
													   MUU_FOR_EACH_IMPL_6,                                            \
													   MUU_FOR_EACH_IMPL_5,                                            \
													   MUU_FOR_EACH_IMPL_4,                                            \
													   MUU_FOR_EACH_IMPL_3,                                            \
													   MUU_FOR_EACH_IMPL_2,                                            \
													   MUU_FOR_EACH_IMPL_1,                                            \
													   MUU_FOR_EACH_IMPL_0)(fn, __VA_ARGS__))

#define MUU_COUNT_VA_ARGS_IMPL(_1_,                                                                                    \
							   _2_,                                                                                    \
							   _3_,                                                                                    \
							   _4_,                                                                                    \
							   _5_,                                                                                    \
							   _6_,                                                                                    \
							   _7_,                                                                                    \
							   _8_,                                                                                    \
							   _9_,                                                                                    \
							   _10_,                                                                                   \
							   _11_,                                                                                   \
							   _12_,                                                                                   \
							   _13_,                                                                                   \
							   _14_,                                                                                   \
							   _15_,                                                                                   \
							   _16_,                                                                                   \
							   _17_,                                                                                   \
							   _18_,                                                                                   \
							   _19_,                                                                                   \
							   _20_,                                                                                   \
							   _21_,                                                                                   \
							   _22_,                                                                                   \
							   _23_,                                                                                   \
							   _24_,                                                                                   \
							   _25_,                                                                                   \
							   _26_,                                                                                   \
							   _27_,                                                                                   \
							   _28_,                                                                                   \
							   _29_,                                                                                   \
							   _30_,                                                                                   \
							   _31_,                                                                                   \
							   _32_,                                                                                   \
							   _33_,                                                                                   \
							   _34_,                                                                                   \
							   _35_,                                                                                   \
							   _36_,                                                                                   \
							   _37_,                                                                                   \
							   _38_,                                                                                   \
							   _39_,                                                                                   \
							   _40_,                                                                                   \
							   _41_,                                                                                   \
							   _42_,                                                                                   \
							   _43_,                                                                                   \
							   _44_,                                                                                   \
							   _45_,                                                                                   \
							   _46_,                                                                                   \
							   _47_,                                                                                   \
							   _48_,                                                                                   \
							   _49_,                                                                                   \
							   _50_,                                                                                   \
							   _51_,                                                                                   \
							   _52_,                                                                                   \
							   _53_,                                                                                   \
							   _54_,                                                                                   \
							   _55_,                                                                                   \
							   _56_,                                                                                   \
							   _57_,                                                                                   \
							   _58_,                                                                                   \
							   _59_,                                                                                   \
							   _60_,                                                                                   \
							   _61_,                                                                                   \
							   _62_,                                                                                   \
							   _63_,                                                                                   \
							   _64_,                                                                                   \
							   _65_,                                                                                   \
							   _66_,                                                                                   \
							   _67_,                                                                                   \
							   _68_,                                                                                   \
							   _69_,                                                                                   \
							   _70_,                                                                                   \
							   _71_,                                                                                   \
							   _72_,                                                                                   \
							   _73_,                                                                                   \
							   _74_,                                                                                   \
							   _75_,                                                                                   \
							   _76_,                                                                                   \
							   _77_,                                                                                   \
							   _78_,                                                                                   \
							   _79_,                                                                                   \
							   _80_,                                                                                   \
							   _81_,                                                                                   \
							   _82_,                                                                                   \
							   _83_,                                                                                   \
							   _84_,                                                                                   \
							   _85_,                                                                                   \
							   _86_,                                                                                   \
							   _87_,                                                                                   \
							   _88_,                                                                                   \
							   _89_,                                                                                   \
							   _90_,                                                                                   \
							   _91_,                                                                                   \
							   _92_,                                                                                   \
							   _93_,                                                                                   \
							   _94_,                                                                                   \
							   _95_,                                                                                   \
							   _96_,                                                                                   \
							   _97_,                                                                                   \
							   _98_,                                                                                   \
							   _99_,                                                                                   \
							   _100_,                                                                                  \
							   _101_,                                                                                  \
							   _102_,                                                                                  \
							   _103_,                                                                                  \
							   _104_,                                                                                  \
							   _105_,                                                                                  \
							   _106_,                                                                                  \
							   _107_,                                                                                  \
							   _108_,                                                                                  \
							   _109_,                                                                                  \
							   _110_,                                                                                  \
							   _111_,                                                                                  \
							   _112_,                                                                                  \
							   _113_,                                                                                  \
							   _114_,                                                                                  \
							   _115_,                                                                                  \
							   _116_,                                                                                  \
							   _117_,                                                                                  \
							   _118_,                                                                                  \
							   _119_,                                                                                  \
							   _120_,                                                                                  \
							   _121_,                                                                                  \
							   _122_,                                                                                  \
							   _123_,                                                                                  \
							   _124_,                                                                                  \
							   count,                                                                                  \
							   ...)                                                                                    \
	count

#define MUU_COUNT_VA_ARGS_IMPL_EXPANDER(args) MUU_COUNT_VA_ARGS_IMPL args

#define MUU_COUNT_VA_ARGS(...)                                                                                         \
	MUU_COUNT_VA_ARGS_IMPL_EXPANDER((__VA_ARGS__,                                                                      \
									 124,                                                                              \
									 123,                                                                              \
									 122,                                                                              \
									 121,                                                                              \
									 120,                                                                              \
									 119,                                                                              \
									 118,                                                                              \
									 117,                                                                              \
									 116,                                                                              \
									 115,                                                                              \
									 114,                                                                              \
									 113,                                                                              \
									 112,                                                                              \
									 111,                                                                              \
									 110,                                                                              \
									 109,                                                                              \
									 108,                                                                              \
									 107,                                                                              \
									 106,                                                                              \
									 105,                                                                              \
									 104,                                                                              \
									 103,                                                                              \
									 102,                                                                              \
									 101,                                                                              \
									 100,                                                                              \
									 99,                                                                               \
									 98,                                                                               \
									 97,                                                                               \
									 96,                                                                               \
									 95,                                                                               \
									 94,                                                                               \
									 93,                                                                               \
									 92,                                                                               \
									 91,                                                                               \
									 90,                                                                               \
									 89,                                                                               \
									 88,                                                                               \
									 87,                                                                               \
									 86,                                                                               \
									 85,                                                                               \
									 84,                                                                               \
									 83,                                                                               \
									 82,                                                                               \
									 81,                                                                               \
									 80,                                                                               \
									 79,                                                                               \
									 78,                                                                               \
									 77,                                                                               \
									 76,                                                                               \
									 75,                                                                               \
									 74,                                                                               \
									 73,                                                                               \
									 72,                                                                               \
									 71,                                                                               \
									 70,                                                                               \
									 69,                                                                               \
									 68,                                                                               \
									 67,                                                                               \
									 66,                                                                               \
									 65,                                                                               \
									 64,                                                                               \
									 63,                                                                               \
									 62,                                                                               \
									 61,                                                                               \
									 60,                                                                               \
									 59,                                                                               \
									 58,                                                                               \
									 57,                                                                               \
									 56,                                                                               \
									 55,                                                                               \
									 54,                                                                               \
									 53,                                                                               \
									 52,                                                                               \
									 51,                                                                               \
									 50,                                                                               \
									 49,                                                                               \
									 48,                                                                               \
									 47,                                                                               \
									 46,                                                                               \
									 45,                                                                               \
									 44,                                                                               \
									 43,                                                                               \
									 42,                                                                               \
									 41,                                                                               \
									 40,                                                                               \
									 39,                                                                               \
									 38,                                                                               \
									 37,                                                                               \
									 36,                                                                               \
									 35,                                                                               \
									 34,                                                                               \
									 33,                                                                               \
									 32,                                                                               \
									 31,                                                                               \
									 30,                                                                               \
									 29,                                                                               \
									 28,                                                                               \
									 27,                                                                               \
									 26,                                                                               \
									 25,                                                                               \
									 24,                                                                               \
									 23,                                                                               \
									 22,                                                                               \
									 21,                                                                               \
									 20,                                                                               \
									 19,                                                                               \
									 18,                                                                               \
									 17,                                                                               \
									 16,                                                                               \
									 15,                                                                               \
									 14,                                                                               \
									 13,                                                                               \
									 12,                                                                               \
									 11,                                                                               \
									 10,                                                                               \
									 9,                                                                                \
									 8,                                                                                \
									 7,                                                                                \
									 6,                                                                                \
									 5,                                                                                \
									 4,                                                                                \
									 3,                                                                                \
									 2,                                                                                \
									 1,                                                                                \
									 0))
