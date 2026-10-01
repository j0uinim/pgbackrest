/***********************************************************************************************************************************
Harness for Testing Filters
***********************************************************************************************************************************/
#include <build.h>

#include "common/debug.h"
#include "common/error/error.h"
#include "common/io/filter/filter.h"
#include "common/type/buffer.h"

#include "harness/debug.h"
#include "harness/filter.h"

/**********************************************************************************************************************************/
void
hrnFilterProcessTo(
    IoFilter *const filter, const Buffer *const input, const size_t inputChunk, const size_t outputChunk, Buffer *const result)
{
    FUNCTION_HARNESS_BEGIN();
        FUNCTION_HARNESS_PARAM(IO_FILTER, filter);
        FUNCTION_HARNESS_PARAM(BUFFER, input);
        FUNCTION_HARNESS_PARAM(SIZE, inputChunk);
        FUNCTION_HARNESS_PARAM(SIZE, outputChunk);
        FUNCTION_HARNESS_PARAM(BUFFER, result);
    FUNCTION_HARNESS_END();

    Buffer *const output = bufNew(outputChunk);

    for (size_t inputOffset = 0; inputOffset < bufUsed(input); inputOffset += inputChunk)
    {
        const size_t size = bufUsed(input) - inputOffset < inputChunk ? bufUsed(input) - inputOffset : inputChunk;
        const Buffer *const chunk = BUF(bufPtrConst(input) + inputOffset, size);

        do
        {
            bufUsedZero(output);

            TRY_BEGIN()
            {
                ioFilterProcessInOut(filter, chunk, output);
            }
            FINALLY()
            {
                bufCat(result, output);
            }
            TRY_END();
        }
        while (ioFilterInputSame(filter));
    }

    do
    {
        bufUsedZero(output);

        TRY_BEGIN()
        {
            ioFilterProcessInOut(filter, NULL, output);
        }
        FINALLY()
        {
            bufCat(result, output);
        }
        TRY_END();
    }
    while (!ioFilterDone(filter));

    FUNCTION_HARNESS_RETURN_VOID();
}

/**********************************************************************************************************************************/
Buffer *
hrnFilterProcess(IoFilter *const filter, const Buffer *const input, const size_t inputChunk, const size_t outputChunk)
{
    FUNCTION_HARNESS_BEGIN();
        FUNCTION_HARNESS_PARAM(IO_FILTER, filter);
        FUNCTION_HARNESS_PARAM(BUFFER, input);
        FUNCTION_HARNESS_PARAM(SIZE, inputChunk);
        FUNCTION_HARNESS_PARAM(SIZE, outputChunk);
    FUNCTION_HARNESS_END();

    Buffer *const result = bufNew(0);

    hrnFilterProcessTo(filter, input, inputChunk, outputChunk, result);

    FUNCTION_HARNESS_RETURN(BUFFER, result);
}
