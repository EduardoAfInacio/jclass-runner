#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include "leitor.h"

typedef struct {
    int32_t mais_significativo;
    int32_t menos_significativo;
} Wide;

Wide divide_64(int64_t valor);
int32_t float_to_int(float valor);
int64_t double_to_int(double valor);
int32_t get_utf(ConstantPool* cp, int32_t pos_pool);
int16_t concat16(int8_t byte1, int8_t byte2);
int64_t concat64(int32_t int1, int32_t int2);
char* read_string_cp(ConstantPool *constant_pool, uint16_t indice);
int32_t get_numero_parametros(ClassFile *classe, Method *metodo);

#endif