/**
 * @file main.c
 * @brief Ponto de entrada principal para o executor de classes Java. Este arquivo
 * contém a função main que inicializa os sistemas necessários e começa a execução
 * de um arquivo de classe Java especificado como entrada. Ele lida com a análise de
 * argumentos da linha de comando, configuração de classpath, e invocação do método main
 * da classe especificada.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "includes/frame.h"
#include "includes/carregador.h"
#include "includes/instrucao.h"
#include "includes/area_metodos.h"

/**
 * @brief Função principal que executa a simulação de uma JVM.
 * 
 * @param argc Número de argumentos de linha de comando.
 * @param args Vetor de strings contendo os argumentos.
 * @return int Retorna 0 em caso de sucesso, ou 1 se houver um erro.
 */
int main(int argc, char *args[])
{

  char *cp; // Classpath para carregar as classes
  char *caminho_classe; // Caminho da classe principal a ser executada

  switch (argc) // Processa os argumentos de linha de comando
  {
  case 2: // Argumento único esperado para o caminho da classe
    caminho_classe = args[1];
    cp = "classpath";
    break;

  case 4: // Argumentos adicionais para especificar o classpath
    if (!strcmp(args[2], "-cp"))
    {
      caminho_classe = args[1];
      cp = args[3];
      break;
    }

  default: // Formato de comando incorreto
    printf("Por favor, execute o programa no formato:\n./jclass-runner <caminho/arquivo.class> [-cp <classpath>]\n");
    return 1;
  }

  for(int i = 0; i < strlen(caminho_classe); i++)
  {
    if (caminho_classe[i] == '.')
    {
      caminho_classe[i] = '/';
    }
  }

  // inicializações
  inicializa_carregador(cp);
  inicializa_instrucoes();
  inicializa_pilha_frames();
  inicializa_lista_classes();
  inicializa_lista_arrays();

  // Carrega a classe inicial e busca o método main
  ClassFile *classe = carrega_classe(caminho_classe);
  MethodRef *metodo_ref = busca_metodo(classe, "main", "([Ljava/lang/String;)V");
  if (!metodo_ref)
  {
    printf("ERRO: declare o método \"public static void main(String[] args)\" em uma das classes.\n");
    return 1;
  }

  carregado = true;

  // Executa todos os frames na pilha até que estejam completos
  for (uint32_t i = 0; i < pilha_frame->length; i++)
  {
    executa_frame_atual();
  }

  push_frame(metodo_ref->classe->constant_pool, metodo_ref->metodo);

  executa_frame_atual();

  free(metodo_ref);
  return 0;
}
