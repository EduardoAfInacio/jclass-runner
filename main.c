#include <stdio.h>

#include "includes/exibidor.h"
#include "includes/leitor.h"
#include "includes/carregador.h"

int main(int argc, char *args[]) {
  
  if (argc < 2) {
    printf("Por favor, forneça o arquivo .class a ser executado.\n");
    return 0;
  }

  carrega_object();

  print_prompt(classes.content[0]);

  return 0;
}
