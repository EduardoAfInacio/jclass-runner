#include <stdio.h>
#include <string.h>

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

  carrega_classe_inicial(caminho_classe);
}
