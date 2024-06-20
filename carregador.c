#include "includes/carregador.h"
#include <stdlib.h>
#include <string.h>
#include "includes/utils.h"
#include "includes/frame.h"

ClassFile *carrega_classe(char *classe)
{
    for (uint32_t i = 0; i < lista_classes.length; i++)
    {
        char *nome_classe_carregada = read_nome_classe(lista_classes.classes[i]);

        if (!strcmp(classe, nome_classe_carregada))
        {
            return lista_classes.classes[i];
        }
    }

    char *caminho = calloc(16 + strlen(classe), sizeof(char));
    strcpy(caminho, "classpath/");
    strcat(caminho, classe);
    strcat(caminho, ".class");

    ClassFile *class_file = class_reader(caminho);

    if (!class_file)
    {
        printf("ERRO: classe %s nao encontrada\n", classe);
        exit(1);
    }

    Method *clinit = busca_metodo(class_file, "<clinit>", "()V");

    if (clinit)
    {
        push_frame(class_file->constant_pool, clinit);
        executa_frame_atual();
    }

    lista_classes.classes = realloc(lista_classes.classes, sizeof(ClassFile *) * lista_classes.length + 1);
    lista_classes.classes[lista_classes.length] = class_file;
    lista_classes.length++;

    return class_file;
}

ClassFile *carrega_classe_fora_classpath(char *classe)
{
    ClassFile *class_file = class_reader(classe);

    if (!class_file)
    {
        exit(1);
    }

    for (uint32_t i = 0; i < lista_classes.length; i++)
    {
        char *nome_classe = read_nome_classe(class_file);
        char *nome_classe_carregada = read_nome_classe(lista_classes.classes[i]);

        if (!strcmp(nome_classe, nome_classe_carregada))
        {
            return lista_classes.classes[i];
        }
    }

    Method *clinit = busca_metodo(class_file, "<clinit>", "()V");

    if (clinit)
    {
        push_frame(class_file->constant_pool, clinit);
        executa_frame_atual();
    }

    lista_classes.classes = realloc(lista_classes.classes, sizeof(ClassFile *) * lista_classes.length + 1);
    lista_classes.classes[lista_classes.length] = class_file;
    lista_classes.length++;

    return class_file;
}

Method *busca_metodo(ClassFile *classe, char *nome, char *descritor)
{
    for (int i = 0; i < classe->methods_count; i++)
    {
        char *nome_temp = read_string_cp(classe->constant_pool, classe->methods[i].name_index);
        char *descritor_temp = read_string_cp(classe->constant_pool, classe->methods[i].descriptor_index);

        if (!strcmp(nome, nome_temp) && !strcmp(descritor, descritor_temp))
        {
            return (classe->methods + i);
        }
    }

    return NULL;
}