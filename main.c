#include <stdio.h>

#include "includes/frame.h"
#include "includes/carregador.h"
#include "includes/instrucao.h"

int main(int argc, char *args[]) {
  
  if (argc < 2) {
    printf("Por favor, forneça o arquivo .class a ser executado.\n");
    return 0;
  }

  // inicializações
  inicializa_instrucoes();
  inicializa_pilha_frames();
  inicializa_lista_classes();

  
}
