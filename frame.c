#include "includes/frame.h"

#include <stdlib.h>

PilhaFrame *pilha_frame;

void inicializa_pilha_frames()
{
    pilha_frame = calloc(1, sizeof(pilha_frame));
    pilha_frame->frames = NULL;
    pilha_frame->length = 0;
}

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

void pop_frame()
{
    Frame *frame_atual = get_frame_atual();
    free(frame_atual->fields);
    free(frame_atual->operandos);
    pilha_frame->frames = realloc(pilha_frame->frames, pilha_frame->length * sizeof(Frame));
    pilha_frame->length--;
}

Frame *get_frame_atual()
{
    if (!pilha_frame->length)
    {
        printf("ERRO: Pilha de frames vazia!");
        exit(0);
    }

    return &(pilha_frame->frames[pilha_frame->length - 1]);
}

void executa_frame_atual()
{
    Frame *frame_atual;
    do
    {
        frame_atual = get_frame_atual();

        printf("--------------------------\n");
        printf("PC: %d\n", frame_atual->pc);
        printf("Instrucao: %s\n", instrucoes[frame_atual->code[frame_atual->pc]].nome);
        printf("--------------------------\n\n");

        instrucoes[frame_atual->code[frame_atual->pc]].exec();
    } while (frame_atual->pc < frame_atual->code_length);

    pop_frame();
}

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

void atualiza_pc()
{
    Frame *frame_atual = get_frame_atual();
    frame_atual->pc += instrucoes[frame_atual->code[frame_atual->pc]].bytes + 1;
}
