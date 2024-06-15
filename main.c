#include <stdio.h>

#include "includes/exibidor.h"
#include "includes/leitor.h"
#include "includes/carregador.h"
#include "includes/frame.h"
#include "includes/instrucao.h"
#include "includes/utils.h"
#include <string.h>
#include <stdlib.h>

int main(int argc, char *args[]) {
  
  if (argc < 2) {
    printf("Por favor, forneça o arquivo .class a ser executado.\n");
    return 0;
  }

  // inicializações
  inicializa_instrucoes();
  inicializa_pilha_frames();

  carrega_object();
}
