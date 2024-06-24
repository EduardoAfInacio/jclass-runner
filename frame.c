/**
 * @file frame.c
 * @brief Gerencia frames de execução para métodos de classes Java. Cada frame contém o estado
 * de execução de um método, incluindo seu contador de programa (PC), operandos, variáveis locais,
 * e uma referência ao pool de constantes. Este arquivo oferece funcionalidades para manipular a pilha
 * de frames durante a execução dos métodos.
 */

#include "includes/frame.h"

#include <stdlib.h>

PilhaFrame *pilha_frame;

/**
 * @brief Inicializa a pilha de frames da JVM.
 * Aloca memória para a pilha e define seus valores iniciais.
 */
void inicializa_pilha_frames()
{
    pilha_frame = calloc(1, sizeof(pilha_frame));
    pilha_frame->frames = NULL;
    pilha_frame->length = 0;
}

/**
 * @brief Empilha um novo frame na pilha de frames.
 * 
 * @param constant_pool O pool de constantes utilizado pelo método.
 * @param metodo O método que será executado no frame empilhado.
 */
void push_frame(ConstantPool *constant_pool, Method *metodo)
{
    CodeAttribute *code = metodo->code_attribute;

    pilha_frame->frames = realloc(pilha_frame->frames, (pilha_frame->length + 1) * sizeof(Frame));
    pilha_frame->frames[pilha_frame->length].pc = 0;
    pilha_frame->frames[pilha_frame->length].constant_pool = constant_pool;
    pilha_frame->frames[pilha_frame->length].max_stack = code->max_stack;
    pilha_frame->frames[pilha_frame->length].max_locals = code->max_locals;
    pilha_frame->frames[pilha_frame->length].code_length = code->code_length;
    pilha_frame->frames[pilha_frame->length].code = code->code;
    pilha_frame->frames[pilha_frame->length].fields = calloc(pilha_frame->frames[pilha_frame->length].max_locals, sizeof(int32_t));
    pilha_frame->frames[pilha_frame->length].operandos = calloc(pilha_frame->frames[pilha_frame->length].max_stack, sizeof(int32_t));
    pilha_frame->frames[pilha_frame->length].operandos_length = 0;

    pilha_frame->length++;
}


/**
 * @brief Desempilha o frame atual da pilha de frames.
 * Libera a memória alocada para os campos locais e operandos do frame.
 */
void pop_frame()
{
    Frame *frame_atual = get_frame_atual();
    free(frame_atual->fields);
    free(frame_atual->operandos);
    pilha_frame->frames = realloc(pilha_frame->frames, pilha_frame->length * sizeof(Frame));
    pilha_frame->length--;
}

/**
 * @brief Retorna o frame atual no topo da pilha de frames.
 * 
 * @return Frame* O frame atual.
 */
Frame *get_frame_atual()
{
    if (!pilha_frame->length)
    {
        printf("ERRO: Pilha de frames vazia!");
        exit(0);
    }

    return &(pilha_frame->frames[pilha_frame->length - 1]);
}

/**
 * @brief Executa o frame atual até que o PC (program counter) alcance o final do código.
 * Executa cada instrução conforme definido pelo PC até que o frame seja completamente executado.
 */
void executa_frame_atual()
{
    Frame *frame_atual;
    do
    {
        frame_atual = get_frame_atual();

        // printf("--------------------------\n");
        // printf("PC: %d\n", frame_atual->pc);
        // printf("Instrucao: %s\n", instrucoes[frame_atual->code[frame_atual->pc]].nome);
        // printf("--------------------------\n\n");

        instrucoes[frame_atual->code[frame_atual->pc]].exec();
    } while (frame_atual->pc < frame_atual->code_length);

    pop_frame();
}

/**
 * @brief Empilha um valor de retorno no frame anterior ao atual.
 * 
 * @param retorno O valor a ser retornado.
 */
void push_retorno(int32_t retorno)
{
    Frame *proximo_frame = &(pilha_frame->frames[pilha_frame->length - 2]);

    if (proximo_frame->operandos_length >= proximo_frame->max_stack)
    {
        printf("ERRO: Pilha de operandos excedida!\n");
        exit(0);
    }

    proximo_frame->operandos[proximo_frame->operandos_length] = retorno;
    proximo_frame->operandos_length++;
}

/**
 * @brief Empilha um operando no stack do frame atual.
 * 
 * @param valor O valor do operando a ser empilhado.
 */
void push_operando(int32_t valor)
{
    Frame *frame_atual = get_frame_atual();

    if (frame_atual->operandos_length >= frame_atual->max_stack)
    {
        printf("ERRO: Pilha de operandos excedida!\n");
        exit(0);
    }

    frame_atual->operandos[frame_atual->operandos_length] = valor;
    frame_atual->operandos_length++;
}

/**
 * @brief Desempilha um operando do stack do frame atual.
 * 
 * @return int32_t O valor do operando desempilhado.
 */
int32_t pop_operando()
{
    Frame *frame_atual = get_frame_atual();

    if (frame_atual->operandos_length == 0)
    {
        printf("ERRO: Pilha de operandos vazia\n");
        exit(1);
    }

    frame_atual->operandos_length--;

    return frame_atual->operandos[frame_atual->operandos_length];
}

/**
 * @brief Atualiza o PC (program counter) do frame atual para apontar para a próxima instrução.
 * Incrementa o PC com base no número de bytes da instrução atual.
 */
void atualiza_pc()
{
    Frame *frame_atual = get_frame_atual();
    frame_atual->pc += instrucoes[frame_atual->code[frame_atual->pc]].bytes + 1;
}
