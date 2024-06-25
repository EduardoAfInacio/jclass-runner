#include "includes/carregador.h"
#include <stdlib.h>
#include <string.h>
#include "includes/utils.h"
#include "includes/frame.h"

char *classpath;
bool carregado = false;

void inicializa_carregador(char *cp)
{
    classpath = cp;
}

ClassFile *carrega_classe(char *nome_classe)
{
    ClassFile *classe = busca_classe(nome_classe);

    if (classe)
    {
        return classe;
    }

    char *caminho = calloc(strlen(classpath) + strlen(nome_classe) + 7, sizeof(char));
    strcpy(caminho, nome_classe);
    strcat(caminho, ".class");

    classe = class_reader(caminho);

    if (!classe)
    {
        strcpy(caminho, classpath);
        strcat(caminho, "/");
        strcat(caminho, nome_classe);
        strcat(caminho, ".class");

        classe = class_reader(caminho);

        if (!classe)
        {
            printf("ERRO: classe %s nao encontrada\n", nome_classe);
            exit(1);
        }
    }

    if (classe->super_class)
    {
        char *super_classe = read_super_classe(classe);
        if (strcmp(super_classe, "java/lang/Object"))
        {
            carrega_classe(super_classe);
        }
    }

    MethodRef *clinit_ref = busca_metodo(classe, "<clinit>", "()V");

    if (clinit_ref && clinit_ref->classe == classe)
    {
        push_frame(classe->constant_pool, clinit_ref->metodo);

        if (carregado)
        {
            executa_frame_atual();
        }

        free(clinit_ref);
    }

    lista_classes.classes = realloc(lista_classes.classes, sizeof(ClassFile *) * lista_classes.length + 1);
    lista_classes.classes[lista_classes.length] = classe;
    lista_classes.length++;

    free(caminho);
    return classe;
}

ClassFile *carrega_classe_inicial(char *caminho_classe)
{
    ClassFile *classe = class_reader(caminho_classe);

    if (!classe)
    {
        printf("ERRO: classe %s nao encontrada\n", caminho_classe);
        exit(1);
    }

    char *nome_classe = read_nome_classe(classe);

    return carrega_classe(nome_classe);
}

MethodRef *busca_metodo(ClassFile *classe, char *nome, char *descritor)
{
    for (int i = 0; i < classe->methods_count; i++)
    {
        char *nome_temp = read_string_cp(classe->constant_pool, classe->methods[i].name_index);
        char *descritor_temp = read_string_cp(classe->constant_pool, classe->methods[i].descriptor_index);

        if (!strcmp(nome, nome_temp) && !strcmp(descritor, descritor_temp))
        {
            MethodRef *metodo_ref = calloc(1, sizeof(MethodRef));
            metodo_ref->metodo = classe->methods + i;
            metodo_ref->classe = classe;
            free(nome_temp);
            free(descritor_temp);
            return metodo_ref;
        }

        free(nome_temp);
        free(descritor_temp);
    }

    ClassFile *super_classe = busca_super_classe(classe);

    if (!super_classe)
    {
        return NULL;
    }

    return busca_metodo(super_classe, nome, descritor);
}

ClassFile *busca_classe(char *nome_classe)
{
    for (uint32_t i = 0; i < lista_classes.length; i++)
    {
        char *nome_classe_temp = read_nome_classe(lista_classes.classes[i]);
        if (!strcmp(nome_classe, nome_classe_temp))
        {
            return lista_classes.classes[i];
        }
    }

    return NULL;
}

ClassFile *busca_super_classe(ClassFile *classe)
{
    char *nome_super_classe = read_super_classe(classe);

    if (!nome_super_classe)
    {
        return NULL;
    }

    return busca_classe(nome_super_classe);
}