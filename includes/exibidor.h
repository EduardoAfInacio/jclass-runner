#ifndef PRINT_H
#define PRINT_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "leitor.h"

void print_prompt(ClassFile* cf);

void print_string_pool(cp_info* cp, int pos_pool);

void print_methods(ClassFile* cf);

void print_code(ClassFile* cf, code_attribute* cd_atrb);

void print_exc(ClassFile* cf, exceptions_attribute* exc_atrb);

void print_access_flags(uint16_t access_flags);

#endif