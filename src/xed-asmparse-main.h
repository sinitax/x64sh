#include "xed-encode.h"

#ifndef XED_ASMPARSE_H
#define XED_ASMPARSE_H
#include "xed-asmparse.h"
#endif

void xed_asmparse_setup(void);
xed_uint_t xed_asmparse_encode(xed_enc_line_parsed_t *v,
	xed_uint8_t *buf, xed_uint_t size);
