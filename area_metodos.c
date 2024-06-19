#include "includes/area_metodos.h"
#include <stdlib.h>
#include <string.h>
#include "includes/utils.h"

ListaArray lista_arrays;
ListaClasse lista_classes;

void inicializa_lista_classes()
{
    lista_classes.classes = (ClassFile **)calloc(1, sizeof(ClassFile *));
    lista_classes.classes[0] = class_reader("classpath/java/lang/Object.class");
    lista_classes.length = 1;
}

void inicializa_lista_arrays() 
{
    lista_arrays.arrays = NULL;
    lista_arrays.length = 0;
}

Campo *campo_por_nome(Objeto *objeto, char *nome)
{
    for (uint32_t i = 0; i < objeto->campos_length; i++)
    {
        if (strcmp(nome, objeto->campos[i].nome) == 0)
        {
            return &(objeto->campos[i]);
        }
    }

    return NULL;
}

Objeto *cria_objeto(ClassFile *classe)
{
    Objeto *objeto;
    objeto = calloc(1, sizeof(Objeto));
    objeto->classe = classe;

    objeto->campos = calloc(sizeof(Campo), classe->fields_count);

    for (int i = 0; i < classe->fields_count; i++)
    {
        objeto->campos[i].nome = read_string_cp(classe->constant_pool, classe->fields[i].name_index);
        objeto->campos[i].valor1 = 0;
        objeto->campos[i].valor2 = 0;
    }

    return objeto;
}

int32_t* cria_array(uint32_t length, uint32_t bytes, char *tipo)
{
    int32_t* array = calloc(length, bytes);

	lista_arrays.arrays = realloc(lista_arrays.arrays, sizeof(Array) * (lista_arrays.length + 1));
    lista_arrays.length++;
    lista_arrays.arrays[lista_arrays.length - 1].array = array;
    lista_arrays.arrays[lista_arrays.length - 1].length = length;
    lista_arrays.arrays[lista_arrays.length - 1].tipo = tipo;

    return array;
}