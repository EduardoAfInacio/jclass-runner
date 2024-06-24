/**
 * @file area_metodos.c
 * @brief Gerencia a área de métodos na memória, onde as definições de classes são armazenadas e
 * gerenciadas. Este componente é crucial para a execução da JVM, mantendo o controle sobre as classes
 * carregadas, suas instâncias, e a execução de métodos associados.
 */

#include "includes/area_metodos.h"
#include <stdlib.h>
#include <string.h>
#include "includes/utils.h"
#include "includes/carregador.h"

ListaArray lista_arrays;
ListaClasse lista_classes;

/**
 * @brief Inicializa a lista de classes carregando a classe base 'java/lang/Object' como primeira classe.
 */
void inicializa_lista_classes()
{
    lista_classes.classes = (ClassFile **)calloc(1, sizeof(ClassFile *));
    lista_classes.classes[0] = carrega_classe("java/lang/Object");
    lista_classes.length = 1;
}


/**
 * @brief Inicializa a lista de arrays dinâmicos usados no sistema, preparando para alocações futuras.
 */
void inicializa_lista_arrays() 
{
    lista_arrays.arrays = NULL;
    lista_arrays.length = 0;
}

/**
 * @brief Busca um campo por nome em um objeto específico.
 * 
 * @param objeto Objeto no qual os campos serão buscados.
 * @param nome Nome do campo a ser buscado.
 * @return Campo* Retorna um ponteiro para o campo se encontrado, ou NULL caso contrário.
 */
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

/**
 * @brief Cria uma nova instância de objeto de uma classe especificada.
 * 
 * @param classe Classe do objeto a ser instanciado.
 * @return Objeto* Retorna um ponteiro para o novo objeto instanciado.
 */
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

/**
 * @brief Cria um novo array de um tipo especificado com um tamanho definido.
 * 
 * @param length Número de elementos do array.
 * @param bytes Tamanho em bytes de cada elemento do array.
 * @param tipo Descrição do tipo de dados contidos no array.
 * @return int32_t* Retorna um ponteiro para o novo array criado.
 */
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