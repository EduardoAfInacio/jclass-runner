#ifndef PRINT_H
#define PRINT_H

#include "leitor.h"

void print_prompt(ClassFile* cf);

void print_string_pool(ConstantPool* cp, int pos_pool);

void print_methods(ClassFile* cf);

void print_code(ClassFile* cf, CodeAttribute* cd_atrb);

void print_exc(ClassFile* cf, ExceptionAttribute* exc_atrb);

void print_access_flags(uint16_t access_flags);

#endif