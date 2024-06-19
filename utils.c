#include "includes/utils.h"

#include <string.h>
#include <stdlib.h>

Wide divide_64(int64_t valor)
{
    Wide retorno = {.mais_significativo = (valor >> 32), .menos_significativo = (valor & 0xffffffff)};
    return retorno;
}

int32_t float_to_int(float valor)
{
    int32_t retorno;
    memcpy(&retorno, &valor, sizeof(int32_t));
    return retorno;
}

int64_t double_to_int(double valor)
{
    int64_t retorno;
    memcpy(&retorno, &valor, sizeof(int64_t));
    return retorno;
}

int32_t get_utf(ConstantPool *cp, int32_t pos_pool)
{
    uint8_t tag = cp[pos_pool].tag;

    if (tag == CONSTANT_Utf8)
    {
        return pos_pool;
    }

    switch (tag)
    {
    case CONSTANT_Class:
        return get_utf(cp, cp[pos_pool].info.Class.name_index - 1);
    case CONSTANT_String:
        return get_utf(cp, cp[pos_pool].info.String.string_index - 1);
    case CONSTANT_Integer:
        return get_utf(cp, cp[pos_pool].info.String.string_index - 1);
    case CONSTANT_Float:
        return get_utf(cp, cp[pos_pool].info.String.string_index - 1);
    }
}

int16_t concat16(int8_t byte1, int8_t byte2)
{
    int16_t aux = byte1;
    return (aux << 8) | byte2;
}

int64_t concat64(int32_t int1, int32_t int2)
{
    int64_t aux = int1;
    return (aux << 32) | int2;
}

char *read_string_cp(ConstantPool *constant_pool, uint16_t indice)
{
    uint16_t length = constant_pool[indice - 1].info.Utf8.length;
    char *retorno = malloc(length + 1);

    for (uint16_t i = 0; i < length; i++)
    {
        retorno[i] = (char)(constant_pool[indice - 1]).info.Utf8.bytes[i];
    }

    retorno[length] = '\0';

    return retorno;
}

int32_t get_numero_parametros(ClassFile *classe, Method *metodo)
{
    int32_t parametros = 0;
    uint16_t length = classe->constant_pool[(metodo->descriptor_index - 1)].info.Utf8.length;
    uint8_t *bytes = classe->constant_pool[(metodo->descriptor_index - 1)].info.Utf8.bytes;

    for (int16_t i = 0; i < length; i++)
    {
        if (bytes[i] == ')')
            break;

        switch (bytes[i])
        {
        case 'L':
            while (bytes[i] != ';')
            {
                i++;
            }

            parametros++;
            break;

        case 'D':
        case 'J':
            parametros += 2;
            break;

        case 'Z':
        case 'S':
        case 'F':
        case 'I':
        case 'C':
        case 'B':
            parametros++;
        }
    }

    return parametros;
}