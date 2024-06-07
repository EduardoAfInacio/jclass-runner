#ifndef DECODER_H
#define DECODER_H

#include <string.h>

/* Maxsize para o nome das instruções */
#define INSTRUCTION_NAME 30

/* Estrutura para decodificar um opcode para o nome correspondente da instrução
 * e a quantidade de bytes que a instrução consome */
typedef struct decoder {
  char instruction[INSTRUCTION_NAME];  // Nome - instrução
  int bytes;                           // Quant de bytes
} decoder;

/*
 * Função que inicializa um array de estruturas decodificador.
 * Cada elemento do array é configurado com o nome da instrução correspondente e
 * o número de bytes que a instrução consome.
 */
void start_decoder(decoder dec[]);

#endif
