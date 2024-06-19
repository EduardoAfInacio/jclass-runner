#include "includes/carregador.h"
#include <stdlib.h>
#include <string.h>
#include "includes/utils.h"

ClassFile *carrega_classe(char *classe)
{
    for (uint32_t i = 0; i < lista_classes.length; i++)
    {
        if (strcmp(classe, read_string_cp(lista_classes.classes[i]->constant_pool, lista_classes.classes[i]->this_class)))
        {
            return lista_classes.classes[i];
        }
    }

    ClassFile *class_file = class_reader(classe);
    lista_classes.classes = realloc(lista_classes.classes, sizeof(ClassFile *) * lista_classes.length + 1);
    lista_classes.classes[lista_classes.length] = class_file;
    lista_classes.length++;

    return class_file;
}

Method *busca_metodo(ClassFile *classe, char *nome, char *descritor)
{
    for (int i = 0; i < classe->methods_count; i++)
    {
        char *nome_temp = read_string_cp(classe->constant_pool, classe->methods[i].name_index - 1);
        char *descritor_temp = read_string_cp(classe->constant_pool, classe->methods[i].descriptor_index - 1);

        if ((strcmp(nome, nome_temp) == 0) && (strcmp(descritor, descritor_temp) == 0))
        {
            return (classe->methods + i);
        }
    }
}