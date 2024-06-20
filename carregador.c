#include "includes/carregador.h"
#include <stdlib.h>
#include <string.h>
#include "includes/utils.h"
#include "includes/frame.h"

ClassFile *carrega_classe(char *nome_classe)
{
    ClassFile *classe = busca_classe(nome_classe);

    if (classe)
    {
        return classe;
    }

    char *caminho = calloc(16 + strlen(nome_classe), sizeof(char));
    strcpy(caminho, "classpath/");
    strcat(caminho, nome_classe);
    strcat(caminho, ".class");

    classe = class_reader(caminho);

    if (!classe)
    {
        printf("ERRO: classe %s nao encontrada\n", nome_classe);
        exit(1);
    }

    Method *clinit = busca_metodo(classe, "<clinit>", "()V");

    if (clinit)
    {
        push_frame(classe->constant_pool, clinit);
        executa_frame_atual();
    }

    lista_classes.classes = realloc(lista_classes.classes, sizeof(ClassFile *) * lista_classes.length + 1);
    lista_classes.classes[lista_classes.length] = classe;
    lista_classes.length++;

    return classe;
}

ClassFile *carrega_classe_fora_classpath(char *caminho_classe)
{
    ClassFile *classe = class_reader(caminho_classe);

    if (!classe)
    {
        printf("ERRO: classe %s nao encontrada\n", caminho_classe);
        exit(1);
    }

    char *nome_classe = read_nome_classe(classe);

    if(busca_classe(nome_classe))
    {
        return classe;
    }

    Method *clinit = busca_metodo(classe, "<clinit>", "()V");

    if (clinit)
    {
        push_frame(classe->constant_pool, clinit);
        executa_frame_atual();
    }

    lista_classes.classes = realloc(lista_classes.classes, sizeof(ClassFile *) * lista_classes.length + 1);
    lista_classes.classes[lista_classes.length] = classe;
    lista_classes.length++;

    return classe;
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

ClassFile *busca_classe(char *nome_classe)
{
    for (uint32_t i = 0; i < lista_classes.length; i++)
    {
        char* nome_classe_temp = read_nome_classe(lista_classes.classes[i]);
        if (!strcmp(nome_classe, nome_classe_temp))
        {
            return lista_classes.classes[i];
        }
    }

    return NULL;
}