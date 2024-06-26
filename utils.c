/**
 * @file utils.c
 * @brief Contém utilitários e funções auxiliares para a manipulação de dados e operações comuns
 * na JVM, incluindo conversões de tipos, concatenação de valores e leitura de dados do pool de constantes.
 */

#include "includes/utils.h"

#include <string.h>
#include <stdlib.h>

/**
 * @brief Divide um inteiro de 64 bits em duas partes, mais significativa e menos significativa.
 * 
 * @param valor O valor de 64 bits a ser dividido.
 * @return Wide Estrutura contendo as partes mais e menos significativas do valor.
 */
Wide divide_64(int64_t valor)
{
    Wide retorno = {.mais_significativo = (valor >> 32), .menos_significativo = (valor & 0xffffffff)};
    return retorno;
}

/**
 * @brief Converte um valor float para um inteiro de 32 bits.
 * 
 * @param valor O valor float a ser convertido.
 * @return int32_t O valor convertido em inteiro de 32 bits.
 */
int32_t float_to_int(float valor)
{
    int32_t retorno;
    memcpy(&retorno, &valor, sizeof(int32_t));
    return retorno;
}

/**
 * @brief Converte um valor double para um inteiro de 64 bits.
 * 
 * @param valor O valor double a ser convertido.
 * @return int64_t O valor convertido em inteiro de 64 bits.
 */
int64_t double_to_int(double valor)
{
    int64_t retorno;
    memcpy(&retorno, &valor, sizeof(int64_t));
    return retorno;
}

/**
 * @brief Concatena dois bytes para formar um inteiro de 16 bits.
 * 
 * @param byte1 O primeiro byte.
 * @param byte2 O segundo byte.
 * @return uint16_t O inteiro de 16 bits resultante.
 */
uint16_t concat16(uint8_t byte1, uint8_t byte2)
{
    uint16_t aux = byte1;
    return (aux << 8) | byte2;
}

/**
 * @brief Concatena dois inteiros de 32 bits para formar um inteiro de 64 bits.
 * 
 * @param int1 O primeiro inteiro de 32 bits.
 * @param int2 O segundo inteiro de 32 bits.
 * @return uint64_t O inteiro de 64 bits resultante.
 */
uint64_t concat64(uint32_t int1, uint32_t int2)
{
    uint64_t aux = int1;
    return (aux << 32) | int2;
}

/**
 * @brief Lê uma string do pool de constantes pelo índice especificado.
 * 
 * @param constant_pool O pool de constantes da classe.
 * @param indice O índice da string no pool de constantes.
 * @return char* A string lida do pool de constantes.
 */
char *read_string_cp(ConstantPool *constant_pool, uint16_t indice)
{
    uint16_t length = constant_pool[indice - 1].info.Utf8.length;
    char *retorno = calloc(length + 1, sizeof(char));

    for (uint16_t i = 0; i < length; i++)
    {
        retorno[i] = (char)(constant_pool[indice - 1]).info.Utf8.bytes[i];
    }

    retorno[length] = '\0';

    return retorno;
}

/**
 * @brief Calcula o número de parâmetros de um método com base em seu descritor.
 * 
 * Analisa o descritor do método para determinar quantos parâmetros ele possui.
 * Considera os diferentes tipos de parâmetros e trata corretamente os tipos que ocupam
 * dois espaços na pilha (como long e double).
 *
 * @param classe Ponteiro para a classe contendo o método.
 * @param metodo Ponteiro para o método cujos parâmetros serão contados.
 * @return int32_t O número total de parâmetros do método.
 */
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

/**
 * @brief Lê o nome da classe de um objeto ClassFile.
 * 
 * Acessa o pool de constantes da classe para encontrar o nome da classe, usando o índice
 * armazenado no campo this_class do objeto ClassFile.
 *
 * @param classe Ponteiro para o objeto ClassFile do qual o nome da classe será lido.
 * @return char* String contendo o nome da classe.
 */
char* read_nome_classe(ClassFile *classe)
{
    uint16_t indice_classe = classe->this_class;
    uint16_t indice_nome_classe = classe->constant_pool[indice_classe - 1].info.Class.name_index;
    return read_string_cp(classe->constant_pool, indice_nome_classe); 
}

/**
 * @brief Lê o nome da superclasse de um objeto ClassFile.
 * 
 * Acessa o pool de constantes para encontrar o nome da superclasse, usando o índice
 * armazenado no campo super_class do objeto ClassFile. Retorna NULL se a classe não
 * tiver uma superclasse definida (o que geralmente ocorre apenas para java/lang/Object).
 *
 * @param classe Ponteiro para o objeto ClassFile do qual a superclasse será lida.
 * @return char* String contendo o nome da superclasse, ou NULL se não houver superclasse.
 */
char* read_super_classe(ClassFile *classe)
{
    uint16_t indice_super_classe = classe->super_class;

    if (!indice_super_classe)
    {
        return NULL;
    }

    uint16_t indice_nome_super_classe = classe->constant_pool[indice_super_classe - 1].info.Class.name_index;
    return read_string_cp(classe->constant_pool, indice_nome_super_classe); 
}