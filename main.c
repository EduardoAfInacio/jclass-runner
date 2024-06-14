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

  add_frame(classes.content[0], 10);

  Frame* frame_atual = get_frame_atual();

  double double1 = 30000000.50344;
  double double2 = 2.0;
  int64_t long1;
  int64_t long2;

  memcpy(&long1, &double1, sizeof(int64_t));
  memcpy(&long2, &double2, sizeof(int64_t));

  Wide wide1 = divide_64(long1);
  Wide wide2 = divide_64(long2);

  frame_atual->fields[0] = wide1.mais_significativo;
  frame_atual->fields[1] = wide1.menos_significativo;
  frame_atual->fields[2] = wide2.mais_significativo;
  frame_atual->fields[3] = wide2.menos_significativo;
  lload_0();
  // lload_2();
  d2i();

  int32_t temp2 = pop_pilha_operandos();
  // int32_t temp1 = pop_pilha_operandos();
  // int64_t temp = concat64(temp1, temp2);

  // double resultado;

  // memcpy(&resultado, &temp, sizeof(int64_t));

  printf("%d\n", temp2);

  return 0;
}
