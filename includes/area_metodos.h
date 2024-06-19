#ifndef AREA_METODOS_H
#define AREA_METODOS_H

#include "leitor.h"
#include <stdint.h>

typedef struct
{
    ClassFile **classes;
    uint32_t length;
} ListaClasse;

typedef struct
{
    char *nome;
    int32_t valor1;
    int32_t valor2;
} Campo;

typedef struct Objeto
{
    ClassFile *classe;
    struct Objeto *super_classe;
    Campo *campos;
    uint32_t campos_length;
} Objeto;

typedef struct
{
    int32_t *array;
    uint32_t length;
    char *tipo;
} Array;

typedef struct
{
    Array *arrays;
    uint32_t length;
} ListaArray;

extern ListaClasse lista_classes;
extern ListaArray lista_arrays;

void inicializa_lista_classes();
void inicializa_lista_arrays();
Campo *campo_por_nome(Objeto *objeto, char *nome);
Objeto *cria_objeto(ClassFile *classe);
int32_t *cria_array(uint32_t length, uint32_t bytes, char *tipo);

#endif