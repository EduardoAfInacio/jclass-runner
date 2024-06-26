#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "includes/frame.h"
#include "includes/carregador.h"
#include "includes/instrucao.h"
#include "includes/area_metodos.h"

int main(int argc, char *args[])
{

  char *cp;
  char *caminho_classe;

  switch (argc)
  {
  case 2:
    caminho_classe = args[1];
    cp = "classpath";
    break;

  case 4:
    if (!strcmp(args[2], "-cp"))
    {
      caminho_classe = args[1];
      cp = args[3];
      break;
    }

  default:
    printf("Por favor, execute o programa no formato:\n./jclass-runner <caminho/arquivo.class> [-cp <classpath>]\n");
    return 1;
  }

  // inicializações
  inicializa_carregador(cp);
  inicializa_instrucoes();
  inicializa_pilha_frames();
  inicializa_lista_classes();
  inicializa_lista_arrays();

  ClassFile *classe = carrega_classe(caminho_classe);
  MethodRef *metodo_ref = busca_metodo(classe, "main", "([Ljava/lang/String;)V");
  if (!metodo_ref)
  {
    printf("ERRO: declare o método \"public static void main(String[] args)\" em uma das classes.\n");
    return 1;
  }

  carregado = true;

  for (uint32_t i = 0; i < pilha_frame->length; i++)
  {
    executa_frame_atual();
  }

  push_frame(metodo_ref->classe->constant_pool, metodo_ref->metodo);

  executa_frame_atual();

  free(metodo_ref);
  return 0;
}
