#include "../preprocessor.h"

MUU_PRAGMA_CLANG_GE(13, float_control(pop))

MUU_PRAGMA_GCC(pop_options)

#if MUU_MSVC || MUU_ICC_CL
	#pragma pop_macro("min")
	#pragma pop_macro("max")
	#pragma float_control(pop)
	#pragma inline_recursion(off)
#endif

MUU_POP_WARNINGS;
