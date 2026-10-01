/***********************************************************************************************************************************
Harness for Testing Filters
***********************************************************************************************************************************/
#ifndef TEST_HARNESS_FILTER_H
#define TEST_HARNESS_FILTER_H

#include "common/io/filter/filter.h"

/***********************************************************************************************************************************
Functions
***********************************************************************************************************************************/
// Process a whole buffer with a filter, giving it input and taking output in chunks of the sizes given, so that a stream is split
// across calls in many ways. The output is added to the result as it is released, and also when a call fails after releasing some,
// so the result has all that was released before an error.
void hrnFilterProcessTo(IoFilter *filter, const Buffer *input, size_t inputChunk, size_t outputChunk, Buffer *result);

// Same, returning the output
Buffer *hrnFilterProcess(IoFilter *filter, const Buffer *input, size_t inputChunk, size_t outputChunk);

#endif
