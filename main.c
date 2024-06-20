#include <stdio.h>

#include "includes/frame.h"
#include "includes/carregador.h"
#include "includes/instrucao.h"
#include "includes/area_metodos.h"

int main(int argc, char *args[]) {
  
  if (argc < 2) {
    printf("Por favor, forneça o arquivo .class a ser executado.\n");
    return 0;
  }

  // inicializações
  inicializa_instrucoes();
  inicializa_pilha_frames();
  inicializa_lista_classes();
  inicializa_lista_arrays();

  carrega_classe_fora_classpath(args[1]);
}
