#include "../preprocessor.h"

MUU_PUSH_WARNINGS;
MUU_DISABLE_SPAM_WARNINGS;

#if MUU_MSVC || MUU_ICC_CL
	#pragma inline_recursion(on)
	#pragma float_control(push)
	#pragma push_macro("min")
	#pragma push_macro("max")
	#undef min
	#undef max
#endif

MUU_PRAGMA_GCC(push_options)

MUU_PRAGMA_CLANG_GE(13, float_control(push))
