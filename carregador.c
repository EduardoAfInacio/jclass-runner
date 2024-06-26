/**
 * @file carregador.c
 * @brief Responsável pelo carregamento, ligação e inicialização de classes Java na JVM. Este arquivo
 * contém funções para carregar classes a partir de seus nomes, resolver referências do constant pool,
 * e preparar a classe para execução, invocando métodos <clinit> conforme necessário para inicialização estática.
 */

#include "includes/carregador.h"
#include <stdlib.h>
#include <string.h>
#include "includes/utils.h"
#include "includes/frame.h"

char *classpath;
bool carregado = false;

/**
 * @brief Inicializa o carregador de classes configurando o caminho base para a busca de arquivos de classe.
 * 
 * @param cp Caminho base usado para carregar os arquivos de classe.
 */
void inicializa_carregador(char *cp)
{
    classpath = cp;
}

/**
 * @brief Carrega uma classe pelo nome, buscando primeiro na memória e, se necessário, no sistema de arquivos.
 * 
 * @param nome_classe O nome da classe a ser carregada.
 * @return ClassFile* Um ponteiro para a estrutura ClassFile carregada, ou NULL se a classe não for encontrada.
 */
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

    classe->campos = calloc(classe->fields_count, sizeof(Campo));
    classe->campos_length = 0;

    for (uint16_t i = 0; i < classe->fields_count; i++)
    {
        classe->campos[i].nome = read_string_cp(classe->constant_pool, classe->fields[i].name_index);
        classe->campos[i].valor1 = 0;
        classe->campos[i].valor2 = 0;
        classe->campos_length++;
    }

    lista_classes.classes = realloc(lista_classes.classes, sizeof(ClassFile *) * lista_classes.length + 1);
    lista_classes.classes[lista_classes.length] = classe;
    lista_classes.length++;

    free(caminho);
    return classe;
}

/**
 * @brief Busca um método em uma classe pelo nome e descritor, procurando recursivamente na hierarquia de superclasses se necessário.
 * 
 * @param classe Classe na qual o método será buscado.
 * @param nome Nome do método a ser buscado.
 * @param descritor Descritor do método a ser buscado.
 * @return MethodRef* Um ponteiro para o método encontrado, ou NULL se o método não for encontrado.
 */
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

/**
 * @brief Busca uma classe previamente carregada pelo nome.
 * 
 * @param nome_classe Nome da classe a ser buscada na lista de classes carregadas.
 * @return ClassFile* Um ponteiro para a classe encontrada, ou NULL se a classe não for encontrada.
 */
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

/**
 * @brief Busca a superclasse de uma classe dada.
 * 
 * @param classe Classe da qual a superclasse será buscada.
 * @return ClassFile* Um ponteiro para a superclasse encontrada, ou NULL se não houver superclasse.
 */
ClassFile *busca_super_classe(ClassFile *classe)
{
    char *nome_super_classe = read_super_classe(classe);

    if (!nome_super_classe)
    {
        return NULL;
    }

    return busca_classe(nome_super_classe);
}