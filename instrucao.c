/**
 * @file instrucao.c
 * @brief Define e implementa o conjunto de instruções da JVM. Este arquivo contém a implementação
 * de todas as instruções do bytecode Java que podem ser executadas pela JVM, manipulando o estado
 * da máquina virtual conforme necessário para cada tipo de instrução.
 */

#include "includes/instrucao.h"
#include "includes/frame.h"
#include "includes/utils.h"
#include "includes/area_metodos.h"
#include "includes/carregador.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdbool.h>

char *string_buffer = NULL;
Instrucao instrucoes[NUM_INSTRUCOES];
bool wide_instruction = false;

/**
 * @brief Inicializa o vetor de instruções que a JVM irá utilizar para executar bytecodes.
 * Cada posição do vetor contém o nome da instrução, o ponteiro para a função que executa a instrução,
 * e o número de bytes adicionais que a instrução usa.
 */
void inicializa_instrucoes()
{
    instrucoes[0].nome = "nop";
    instrucoes[0].exec = &nop;
    instrucoes[0].bytes = 0;

    instrucoes[1].nome = "aconst_null";
    instrucoes[1].exec = &aconst_null;
    instrucoes[1].bytes = 0;

    instrucoes[2].nome = "iconst_m1";
    instrucoes[2].exec = &iconst_m1;
    instrucoes[2].bytes = 0;

    instrucoes[3].nome = "iconst_0";
    instrucoes[3].exec = &iconst_0;
    instrucoes[3].bytes = 0;

    instrucoes[4].nome = "iconst_1";
    instrucoes[4].exec = &iconst_1;
    instrucoes[4].bytes = 0;

    instrucoes[5].nome = "iconst_2";
    instrucoes[5].exec = &iconst_2;
    instrucoes[5].bytes = 0;

    instrucoes[6].nome = "iconst_3";
    instrucoes[6].exec = &iconst_3;
    instrucoes[6].bytes = 0;

    instrucoes[7].nome = "iconst_4";
    instrucoes[7].exec = &iconst_4;
    instrucoes[7].bytes = 0;

    instrucoes[8].nome = "iconst_5";
    instrucoes[8].exec = &iconst_5;
    instrucoes[8].bytes = 0;

    instrucoes[9].nome = "lconst_0";
    instrucoes[9].exec = &lconst_0;
    instrucoes[9].bytes = 0;

    instrucoes[10].nome = "lconst_1";
    instrucoes[10].exec = &lconst_1;
    instrucoes[10].bytes = 0;

    instrucoes[11].nome = "fconst_0";
    instrucoes[11].exec = &fconst_0;
    instrucoes[11].bytes = 0;

    instrucoes[12].nome = "fconst_1";
    instrucoes[12].exec = &fconst_1;
    instrucoes[12].bytes = 0;

    instrucoes[13].nome = "fconst_2";
    instrucoes[13].exec = &fconst_2;
    instrucoes[13].bytes = 0;

    instrucoes[14].nome = "dconst_0";
    instrucoes[14].exec = &dconst_0;
    instrucoes[14].bytes = 0;

    instrucoes[15].nome = "dconst_1";
    instrucoes[15].exec = &dconst_1;
    instrucoes[15].bytes = 0;

    instrucoes[16].nome = "bipush";
    instrucoes[16].exec = &bipush;
    instrucoes[16].bytes = 1;

    instrucoes[17].nome = "sipush";
    instrucoes[17].exec = &sipush;
    instrucoes[17].bytes = 2;

    instrucoes[18].nome = "ldc";
    instrucoes[18].exec = &ldc;
    instrucoes[18].bytes = 1;

    instrucoes[19].nome = "ldc_w";
    instrucoes[19].exec = &ldc_w;
    instrucoes[19].bytes = 2;

    instrucoes[20].nome = "ldc2_w";
    instrucoes[20].exec = &ldc2_w;
    instrucoes[20].bytes = 2;

    instrucoes[21].nome = "iload";
    instrucoes[21].exec = &iload;
    instrucoes[21].bytes = 1;

    instrucoes[22].nome = "lload";
    instrucoes[22].exec = &lload;
    instrucoes[22].bytes = 1;

    instrucoes[23].nome = "fload";
    instrucoes[23].exec = &fload;
    instrucoes[23].bytes = 1;

    instrucoes[24].nome = "dload";
    instrucoes[24].exec = &dload;
    instrucoes[24].bytes = 1;

    instrucoes[25].nome = "aload";
    instrucoes[25].exec = &aload;
    instrucoes[25].bytes = 1;

    instrucoes[26].nome = "iload_0";
    instrucoes[26].exec = &iload_0;
    instrucoes[26].bytes = 0;

    instrucoes[27].nome = "iload_1";
    instrucoes[27].exec = &iload_1;
    instrucoes[27].bytes = 0;

    instrucoes[28].nome = "iload_2";
    instrucoes[28].exec = &iload_2;
    instrucoes[28].bytes = 0;

    instrucoes[29].nome = "iload_3";
    instrucoes[29].exec = &iload_3;
    instrucoes[29].bytes = 0;

    instrucoes[30].nome = "lload_0";
    instrucoes[30].exec = &lload_0;
    instrucoes[30].bytes = 0;

    instrucoes[31].nome = "lload_1";
    instrucoes[31].exec = &lload_1;
    instrucoes[31].bytes = 0;

    instrucoes[32].nome = "lload_2";
    instrucoes[32].exec = &lload_2;
    instrucoes[32].bytes = 0;

    instrucoes[33].nome = "lload_3";
    instrucoes[33].exec = &lload_3;
    instrucoes[33].bytes = 0;

    instrucoes[34].nome = "fload_0";
    instrucoes[34].exec = &fload_0;
    instrucoes[34].bytes = 0;

    instrucoes[35].nome = "fload_1";
    instrucoes[35].exec = &fload_1;
    instrucoes[35].bytes = 0;

    instrucoes[36].nome = "fload_2";
    instrucoes[36].exec = &fload_2;
    instrucoes[36].bytes = 0;

    instrucoes[37].nome = "fload_3";
    instrucoes[37].exec = &fload_3;
    instrucoes[37].bytes = 0;

    instrucoes[38].nome = "dload_0";
    instrucoes[38].exec = &dload_0;
    instrucoes[38].bytes = 0;

    instrucoes[39].nome = "dload_1";
    instrucoes[39].exec = &dload_1;
    instrucoes[39].bytes = 0;

    instrucoes[40].nome = "dload_2";
    instrucoes[40].exec = &dload_2;
    instrucoes[40].bytes = 0;

    instrucoes[41].nome = "dload_3";
    instrucoes[41].exec = &dload_3;
    instrucoes[41].bytes = 0;

    instrucoes[42].nome = "aload_0";
    instrucoes[42].exec = &aload_0;
    instrucoes[42].bytes = 0;

    instrucoes[43].nome = "aload_1";
    instrucoes[43].exec = &aload_1;
    instrucoes[43].bytes = 0;

    instrucoes[44].nome = "aload_2";
    instrucoes[44].exec = &aload_2;
    instrucoes[44].bytes = 0;

    instrucoes[45].nome = "aload_3";
    instrucoes[45].exec = &aload_3;
    instrucoes[45].bytes = 0;

    instrucoes[46].nome = "iaload";
    instrucoes[46].exec = &iaload;
    instrucoes[46].bytes = 0;

    instrucoes[47].nome = "laload";
    instrucoes[47].exec = &laload;
    instrucoes[47].bytes = 0;

    instrucoes[48].nome = "faload";
    instrucoes[48].exec = &faload;
    instrucoes[48].bytes = 0;

    instrucoes[49].nome = "daload";
    instrucoes[49].exec = &daload;
    instrucoes[49].bytes = 0;

    instrucoes[50].nome = "aaload";
    instrucoes[50].exec = &aaload;
    instrucoes[50].bytes = 0;

    instrucoes[51].nome = "baload";
    instrucoes[51].exec = &baload;
    instrucoes[51].bytes = 0;

    instrucoes[52].nome = "caload";
    instrucoes[52].exec = &caload;
    instrucoes[52].bytes = 0;

    instrucoes[53].nome = "saload";
    instrucoes[53].exec = &saload;
    instrucoes[53].bytes = 0;

    instrucoes[54].nome = "istore";
    instrucoes[54].exec = &istore;
    instrucoes[54].bytes = 1;

    instrucoes[55].nome = "lstore";
    instrucoes[55].exec = &lstore;
    instrucoes[55].bytes = 1;

    instrucoes[56].nome = "fstore";
    instrucoes[56].exec = &fstore;
    instrucoes[56].bytes = 1;

    instrucoes[57].nome = "dstore";
    instrucoes[57].exec = &dstore;
    instrucoes[57].bytes = 1;

    instrucoes[58].nome = "astore";
    instrucoes[58].exec = &astore;
    instrucoes[58].bytes = 1;

    instrucoes[59].nome = "istore_0";
    instrucoes[59].exec = &istore_0;
    instrucoes[59].bytes = 0;

    instrucoes[60].nome = "istore_1";
    instrucoes[60].exec = &istore_1;
    instrucoes[60].bytes = 0;

    instrucoes[61].nome = "istore_2";
    instrucoes[61].exec = &istore_2;
    instrucoes[61].bytes = 0;

    instrucoes[62].nome = "istore_3";
    instrucoes[62].exec = &istore_3;
    instrucoes[62].bytes = 0;

    instrucoes[63].nome = "lstore_0";
    instrucoes[63].exec = &lstore_0;
    instrucoes[63].bytes = 0;

    instrucoes[64].nome = "lstore_1";
    instrucoes[64].exec = &lstore_1;
    instrucoes[64].bytes = 0;

    instrucoes[65].nome = "lstore_2";
    instrucoes[65].exec = &lstore_2;
    instrucoes[65].bytes = 0;

    instrucoes[66].nome = "lstore_3";
    instrucoes[66].exec = &lstore_3;
    instrucoes[66].bytes = 0;

    instrucoes[67].nome = "fstore_0";
    instrucoes[67].exec = &fstore_0;
    instrucoes[67].bytes = 0;

    instrucoes[68].nome = "fstore_1";
    instrucoes[68].exec = &fstore_1;
    instrucoes[68].bytes = 0;

    instrucoes[69].nome = "fstore_2";
    instrucoes[69].exec = &fstore_2;
    instrucoes[69].bytes = 0;

    instrucoes[70].nome = "fstore_3";
    instrucoes[70].exec = &fstore_3;
    instrucoes[70].bytes = 0;

    instrucoes[71].nome = "dstore_0";
    instrucoes[71].exec = &dstore_0;
    instrucoes[71].bytes = 0;

    instrucoes[72].nome = "dstore_1";
    instrucoes[72].exec = &dstore_1;
    instrucoes[72].bytes = 0;

    instrucoes[73].nome = "dstore_2";
    instrucoes[73].exec = &dstore_2;
    instrucoes[73].bytes = 0;

    instrucoes[74].nome = "dstore_3";
    instrucoes[74].exec = &dstore_3;
    instrucoes[74].bytes = 0;

    instrucoes[75].nome = "astore_0";
    instrucoes[75].exec = &astore_0;
    instrucoes[75].bytes = 0;

    instrucoes[76].nome = "astore_1";
    instrucoes[76].exec = &astore_1;
    instrucoes[76].bytes = 0;

    instrucoes[77].nome = "astore_2";
    instrucoes[77].exec = &astore_2;
    instrucoes[77].bytes = 0;

    instrucoes[78].nome = "astore_3";
    instrucoes[78].exec = &astore_3;
    instrucoes[78].bytes = 0;

    instrucoes[79].nome = "iastore";
    instrucoes[79].exec = &iastore;
    instrucoes[79].bytes = 0;

    instrucoes[80].nome = "lastore";
    instrucoes[80].exec = &lastore;
    instrucoes[80].bytes = 0;

    instrucoes[81].nome = "fastore";
    instrucoes[81].exec = &fastore;
    instrucoes[81].bytes = 0;

    instrucoes[82].nome = "dastore";
    instrucoes[82].exec = &dastore;
    instrucoes[82].bytes = 0;

    instrucoes[83].nome = "aastore";
    instrucoes[83].exec = &aastore;
    instrucoes[83].bytes = 0;

    instrucoes[84].nome = "bastore";
    instrucoes[84].exec = &bastore;
    instrucoes[84].bytes = 0;

    instrucoes[85].nome = "castore";
    instrucoes[85].exec = &castore;
    instrucoes[85].bytes = 0;

    instrucoes[86].nome = "sastore";
    instrucoes[86].exec = &sastore;
    instrucoes[86].bytes = 0;

    instrucoes[87].nome = "pop";
    instrucoes[87].exec = &pop;
    instrucoes[87].bytes = 0;

    instrucoes[88].nome = "pop2";
    instrucoes[88].exec = &pop2;
    instrucoes[88].bytes = 0;

    instrucoes[89].nome = "dup";
    instrucoes[89].exec = &dup;
    instrucoes[89].bytes = 0;

    instrucoes[90].nome = "dup_x1";
    instrucoes[90].exec = &dup_x1;
    instrucoes[90].bytes = 0;

    instrucoes[91].nome = "dup_x2";
    instrucoes[91].exec = &dup_x2;
    instrucoes[91].bytes = 0;

    instrucoes[92].nome = "dup2";
    instrucoes[92].exec = &dup2;
    instrucoes[92].bytes = 0;

    instrucoes[93].nome = "dup2_x1";
    instrucoes[93].exec = &dup2_x1;
    instrucoes[93].bytes = 0;

    instrucoes[94].nome = "dup2_x2";
    instrucoes[94].exec = &dup2_x2;
    instrucoes[94].bytes = 0;

    instrucoes[95].nome = "swap";
    instrucoes[95].exec = &swap;
    instrucoes[95].bytes = 0;

    instrucoes[96].nome = "iadd";
    instrucoes[96].exec = &iadd;
    instrucoes[96].bytes = 0;

    instrucoes[97].nome = "ladd";
    instrucoes[97].exec = &ladd;
    instrucoes[97].bytes = 0;

    instrucoes[98].nome = "fadd";
    instrucoes[98].exec = &fadd;
    instrucoes[98].bytes = 0;

    instrucoes[99].nome = "dadd";
    instrucoes[99].exec = &dadd;
    instrucoes[99].bytes = 0;

    instrucoes[100].nome = "isub";
    instrucoes[100].exec = &isub;
    instrucoes[100].bytes = 0;

    instrucoes[101].nome = "lsub";
    instrucoes[101].exec = &lsub;
    instrucoes[101].bytes = 0;

    instrucoes[102].nome = "fsub";
    instrucoes[102].exec = &fsub;
    instrucoes[102].bytes = 0;

    instrucoes[103].nome = "dsub";
    instrucoes[103].exec = &dsub;
    instrucoes[103].bytes = 0;

    instrucoes[104].nome = "imul";
    instrucoes[104].exec = &imul;
    instrucoes[104].bytes = 0;

    instrucoes[105].nome = "lmul";
    instrucoes[105].exec = &lmul;
    instrucoes[105].bytes = 0;

    instrucoes[106].nome = "fmul";
    instrucoes[106].exec = &fmul;
    instrucoes[106].bytes = 0;

    instrucoes[107].nome = "dmul";
    instrucoes[107].exec = &dmul;
    instrucoes[107].bytes = 0;

    instrucoes[108].nome = "idiv";
    instrucoes[108].exec = &idiv;
    instrucoes[108].bytes = 0;

    instrucoes[109].nome = "ldiv";
    instrucoes[109].exec = &jvm_ldiv;
    instrucoes[109].bytes = 0;

    instrucoes[110].nome = "fdiv";
    instrucoes[110].exec = &fdiv;
    instrucoes[110].bytes = 0;

    instrucoes[111].nome = "ddiv";
    instrucoes[111].exec = &ddiv;
    instrucoes[111].bytes = 0;

    instrucoes[112].nome = "irem";
    instrucoes[112].exec = &irem;
    instrucoes[112].bytes = 0;

    instrucoes[113].nome = "lrem";
    instrucoes[113].exec = &lrem;
    instrucoes[113].bytes = 0;

    instrucoes[114].nome = "frem";
    instrucoes[114].exec = &frem;
    instrucoes[114].bytes = 0;

    instrucoes[115].nome = "drem";
    instrucoes[115].exec = &jvm_drem;
    instrucoes[115].bytes = 0;

    instrucoes[116].nome = "ineg";
    instrucoes[116].exec = &ineg;
    instrucoes[116].bytes = 0;

    instrucoes[117].nome = "lneg";
    instrucoes[117].exec = &lneg;
    instrucoes[117].bytes = 0;

    instrucoes[118].nome = "fneg";
    instrucoes[118].exec = &fneg;
    instrucoes[118].bytes = 0;

    instrucoes[119].nome = "dneg";
    instrucoes[119].exec = &dneg;
    instrucoes[119].bytes = 0;

    instrucoes[120].nome = "ishl";
    instrucoes[120].exec = &ishl;
    instrucoes[120].bytes = 0;

    instrucoes[121].nome = "lshl";
    instrucoes[121].exec = &lshl;
    instrucoes[121].bytes = 0;

    instrucoes[122].nome = "ishr";
    instrucoes[122].exec = &ishr;
    instrucoes[122].bytes = 0;

    instrucoes[123].nome = "lshr";
    instrucoes[123].exec = &lshr;
    instrucoes[123].bytes = 0;

    instrucoes[124].nome = "iushr";
    instrucoes[124].exec = &iushr;
    instrucoes[124].bytes = 0;

    instrucoes[125].nome = "lushr";
    instrucoes[125].exec = &lushr;
    instrucoes[125].bytes = 0;

    instrucoes[126].nome = "iand";
    instrucoes[126].exec = &iand;
    instrucoes[126].bytes = 0;

    instrucoes[127].nome = "land";
    instrucoes[127].exec = &land;
    instrucoes[127].bytes = 0;

    instrucoes[128].nome = "ior";
    instrucoes[128].exec = &ior;
    instrucoes[128].bytes = 0;

    instrucoes[129].nome = "lor";
    instrucoes[129].exec = &lor;
    instrucoes[129].bytes = 0;

    instrucoes[130].nome = "ixor";
    instrucoes[130].exec = &ixor;
    instrucoes[130].bytes = 0;

    instrucoes[131].nome = "lxor";
    instrucoes[131].exec = &lxor;
    instrucoes[131].bytes = 0;

    instrucoes[132].nome = "iinc";
    instrucoes[132].exec = &iinc;
    instrucoes[132].bytes = 2;

    instrucoes[133].nome = "i2l";
    instrucoes[133].exec = &i2l;
    instrucoes[133].bytes = 0;

    instrucoes[134].nome = "i2f";
    instrucoes[134].exec = &i2f;
    instrucoes[134].bytes = 0;

    instrucoes[135].nome = "i2d";
    instrucoes[135].exec = &i2d;
    instrucoes[135].bytes = 0;

    instrucoes[136].nome = "l2i";
    instrucoes[136].exec = &l2i;
    instrucoes[136].bytes = 0;

    instrucoes[137].nome = "l2f";
    instrucoes[137].exec = &l2f;
    instrucoes[137].bytes = 0;

    instrucoes[138].nome = "l2d";
    instrucoes[138].exec = &l2d;
    instrucoes[138].bytes = 0;

    instrucoes[139].nome = "f2i";
    instrucoes[139].exec = &f2i;
    instrucoes[139].bytes = 0;

    instrucoes[140].nome = "f2l";
    instrucoes[140].exec = &f2l;
    instrucoes[140].bytes = 0;

    instrucoes[141].nome = "f2d";
    instrucoes[141].exec = &f2d;
    instrucoes[141].bytes = 0;

    instrucoes[142].nome = "d2i";
    instrucoes[142].exec = &d2i;
    instrucoes[142].bytes = 0;

    instrucoes[143].nome = "d2l";
    instrucoes[143].exec = &d2l;
    instrucoes[143].bytes = 0;

    instrucoes[144].nome = "d2f";
    instrucoes[144].exec = &d2f;
    instrucoes[144].bytes = 0;

    instrucoes[145].nome = "i2b";
    instrucoes[145].exec = &i2b;
    instrucoes[145].bytes = 0;

    instrucoes[146].nome = "i2c";
    instrucoes[146].exec = &i2c;
    instrucoes[146].bytes = 0;

    instrucoes[147].nome = "i2s";
    instrucoes[147].exec = &i2s;
    instrucoes[147].bytes = 0;

    instrucoes[148].nome = "lcmp";
    instrucoes[148].exec = &lcmp;
    instrucoes[148].bytes = 0;

    instrucoes[149].nome = "fcmpl";
    instrucoes[149].exec = &fcmpl;
    instrucoes[149].bytes = 0;

    instrucoes[150].nome = "fcmpg";
    instrucoes[150].exec = &fcmpg;
    instrucoes[150].bytes = 0;

    instrucoes[151].nome = "dcmpl";
    instrucoes[151].exec = &dcmpl;
    instrucoes[151].bytes = 0;

    instrucoes[152].nome = "dcmpg";
    instrucoes[152].exec = &dcmpg;
    instrucoes[152].bytes = 0;

    instrucoes[153].nome = "ifeq";
    instrucoes[153].exec = &ifeq;
    instrucoes[153].bytes = 2;

    instrucoes[154].nome = "ifne";
    instrucoes[154].exec = &ifne;
    instrucoes[154].bytes = 2;

    instrucoes[155].nome = "iflt";
    instrucoes[155].exec = &iflt;
    instrucoes[155].bytes = 2;

    instrucoes[156].nome = "ifge";
    instrucoes[156].exec = &ifge;
    instrucoes[156].bytes = 2;

    instrucoes[157].nome = "ifgt";
    instrucoes[157].exec = &ifgt;
    instrucoes[157].bytes = 2;

    instrucoes[158].nome = "ifle";
    instrucoes[158].exec = &ifle;
    instrucoes[158].bytes = 2;

    instrucoes[159].nome = "if_icmpeq";
    instrucoes[159].exec = &if_icmpeq;
    instrucoes[159].bytes = 2;

    instrucoes[160].nome = "if_icmpne";
    instrucoes[160].exec = &if_icmpne;
    instrucoes[160].bytes = 2;

    instrucoes[161].nome = "if_icmplt";
    instrucoes[161].exec = &if_icmplt;
    instrucoes[161].bytes = 2;

    instrucoes[162].nome = "if_icmpge";
    instrucoes[162].exec = &if_icmpge;
    instrucoes[162].bytes = 2;

    instrucoes[163].nome = "if_icmpgt";
    instrucoes[163].exec = &if_icmpgt;
    instrucoes[163].bytes = 2;

    instrucoes[164].nome = "if_icmple";
    instrucoes[164].exec = &if_icmple;
    instrucoes[164].bytes = 2;

    instrucoes[165].nome = "if_acmpeq";
    instrucoes[165].exec = &if_acmpeq;
    instrucoes[165].bytes = 2;

    instrucoes[166].nome = "if_acmpne";
    instrucoes[166].exec = &if_acmpne;
    instrucoes[166].bytes = 2;

    instrucoes[167].nome = "goto";
    instrucoes[167].exec = &jvm_goto;
    instrucoes[167].bytes = 2;

    instrucoes[168].nome = "jsr";
    instrucoes[168].exec = &jsr;
    instrucoes[168].bytes = 2;

    instrucoes[169].nome = "ret";
    instrucoes[169].exec = &ret;
    instrucoes[169].bytes = 1;

    instrucoes[170].nome = "tableswitch";
    instrucoes[170].exec = &tableswitch;

    instrucoes[170].bytes = 14;

    instrucoes[171].nome = "lookupswitch";
    instrucoes[171].exec = &lookupswitch;

    instrucoes[171].bytes = 10;

    instrucoes[172].nome = "ireturn";
    instrucoes[172].exec = &ireturn;
    instrucoes[172].bytes = 0;

    instrucoes[173].nome = "lreturn";
    instrucoes[173].exec = &lreturn;
    instrucoes[173].bytes = 0;

    instrucoes[174].nome = "freturn";
    instrucoes[174].exec = &freturn;
    instrucoes[174].bytes = 0;

    instrucoes[175].nome = "dreturn";
    instrucoes[175].exec = &dreturn;
    instrucoes[176].bytes = 0;

    instrucoes[176].nome = "areturn";
    instrucoes[176].exec = &areturn;
    instrucoes[176].bytes = 0;

    instrucoes[177].nome = "return";
    instrucoes[177].exec = &jvm_return;
    instrucoes[177].bytes = 0;

    instrucoes[178].nome = "getstatic";
    instrucoes[178].exec = &getstatic;
    instrucoes[178].bytes = 2;

    instrucoes[179].nome = "putstatic";
    instrucoes[179].exec = &putstatic;
    instrucoes[179].bytes = 2;

    instrucoes[180].nome = "getfield";
    instrucoes[180].exec = &getfield;
    instrucoes[180].bytes = 2;

    instrucoes[181].nome = "putfield";
    instrucoes[181].exec = &putfield;
    instrucoes[181].bytes = 2;

    instrucoes[182].nome = "invokevirtual";
    instrucoes[182].exec = &invokevirtual;
    instrucoes[182].bytes = 2;

    instrucoes[183].nome = "invokespecial";
    instrucoes[183].exec = &invokespecial;
    instrucoes[183].bytes = 2;

    instrucoes[184].nome = "invokestatic";
    instrucoes[184].exec = &invokestatic;
    instrucoes[184].bytes = 2;

    instrucoes[185].nome = "invokeinterface";
    instrucoes[185].exec = &invokeinterface;
    instrucoes[185].bytes = 4;

    instrucoes[187].nome = "new";
    instrucoes[187].exec = &jvm_new;
    instrucoes[187].bytes = 2;

    instrucoes[188].nome = "newarray";
    instrucoes[188].exec = &newarray;
    instrucoes[188].bytes = 1;

    instrucoes[189].nome = "anewarray";
    instrucoes[189].exec = &anewarray;
    instrucoes[189].bytes = 2;

    instrucoes[190].nome = "arraylength";
    instrucoes[190].exec = &arraylength;
    instrucoes[190].bytes = 0;

    instrucoes[191].nome = "athrow";
    instrucoes[191].exec = &athrow;
    instrucoes[191].bytes = 0;

    instrucoes[192].nome = "checkcast";
    instrucoes[192].exec = &checkcast;
    instrucoes[192].bytes = 2;

    instrucoes[193].nome = "instanceof";
    instrucoes[193].exec = & instanceof ;
    instrucoes[193].bytes = 2;

    instrucoes[194].nome = "monitorenter";
    instrucoes[194].exec = &monitorenter;
    instrucoes[194].bytes = 0;

    instrucoes[195].nome = "monitorexit";
    instrucoes[195].exec = &monitorexit;
    instrucoes[195].bytes = 0;

    instrucoes[196].nome = "wide";
    instrucoes[196].exec = &wide;
    instrucoes[196].bytes = 3;

    instrucoes[197].nome = "multianewarray";
    instrucoes[197].exec = &multianewarray;
    instrucoes[197].bytes = 3;

    instrucoes[198].nome = "ifnull";
    instrucoes[198].exec = &ifnull;
    instrucoes[198].bytes = 2;

    instrucoes[199].nome = "ifnonnull";
    instrucoes[199].exec = &ifnonnull;
    instrucoes[199].bytes = 2;

    instrucoes[200].nome = "goto_w";
    instrucoes[200].exec = &goto_w;
    instrucoes[200].bytes = 4;

    instrucoes[201].nome = "jsr_w";
    instrucoes[201].exec = &jsr_w;
    instrucoes[201].bytes = 4;
}

/**
 * @brief Função que simula a execução do bytecode 'nop' na JVM.
 * Essencialmente não realiza operação alguma e é usada para avançar o contador de programa.
 */
void nop()
{
    atualiza_pc();
}

/**
 * @brief Empilha um valor nulo (null) na pilha de operandos do frame atual.
 */
void aconst_null()
{
    push_operando(0);
    atualiza_pc();
}

/**
 * @brief Empilha constantes inteiras de -1 a 5 na pilha de operandos do frame atual.
 */
void iconst_m1()
{
    push_operando(-1);
    atualiza_pc();
}

void iconst_0()
{
    push_operando(0);
    atualiza_pc();
}

void iconst_1()
{
    push_operando(1);
    atualiza_pc();
}

void iconst_2()
{
    push_operando(2);
    atualiza_pc();
}

void iconst_3()
{
    push_operando(3);
    atualiza_pc();
}

void iconst_4()
{
    push_operando(4);
    atualiza_pc();
}

void iconst_5()
{
    push_operando(5);
    atualiza_pc();
}

/**
 * @brief Empilha constantes longas 0 e 1 na pilha de operandos do frame atual.
 */
void lconst_0()
{
    Wide wide = divide_64(0);
    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);
    atualiza_pc();
}

void lconst_1()
{
    Wide wide = divide_64(1);
    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);
    atualiza_pc();
}

/**
 * @brief Empilha constantes de ponto flutuante 0.0, 1.0 e 2.0 na pilha de operandos do frame atual.
 */
void fconst_0()
{
    push_operando(float_to_int(0.0));
    atualiza_pc();
}

void fconst_1()
{
    push_operando(float_to_int(1.0));
    atualiza_pc();
}

void fconst_2()
{
    push_operando(float_to_int(2.0));
    atualiza_pc();
}

/**
 * @brief Empilha constantes double 0.0 e 1.0 na pilha de operandos do frame atual.
 */
void dconst_0()
{
    Wide wide = divide_64(double_to_int(0.0));
    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);
    atualiza_pc();
}

void dconst_1()
{
    Wide wide = divide_64(double_to_int(1.0));
    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);
    atualiza_pc();
}

/**
 * @brief Função que simula a instrução 'bipush' da JVM.
 * Empilha um byte imediato como um inteiro na pilha de operandos do frame atual.
 */
void bipush()
{
    Frame *frame_atual = get_frame_atual();
    int8_t argumento = frame_atual->code[frame_atual->pc + 1];

    push_operando(argumento);

    atualiza_pc();
}

/**
 * @brief Função que simula a instrução 'sipush' da JVM.
 * Empilha um short imediato como um inteiro na pilha de operandos do frame atual.
 */
void sipush()
{
    Frame *frame_atual = get_frame_atual();
    int8_t byte1 = frame_atual->code[(frame_atual->pc + 1)];
    int8_t byte2 = frame_atual->code[(frame_atual->pc + 2)];
    int16_t si = concat16(byte1, byte2);

    push_operando(si);
    atualiza_pc();
}

/**
 * @brief Função que simula a instrução 'ldc' da JVM para carregar constantes de um índice no pool de constantes.
 */
void ldc()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t indice = frame_atual->code[frame_atual->pc + 1];
    uint8_t tag = frame_atual->constant_pool[indice - 1].tag;

    switch (tag)
    {
    case CONSTANT_Float:
        push_operando(frame_atual->constant_pool[indice - 1].info.Float.bytes);
        break;

    case CONSTANT_Integer:
        push_operando(frame_atual->constant_pool[indice - 1].info.Integer.bytes);
        break;

    case CONSTANT_String:
        push_operando((intptr_t)read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[indice - 1].info.String.string_index));
        break;

    default:
        printf("ERRO: ldc não implementada para tag %d\n", tag);
        exit(1);
        break;
    }

    atualiza_pc();
}

/**
 * @brief Função que simula a instrução 'ldc_w' da JVM, similar ao 'ldc' mas com um índice wide (mais amplo).
 */
void ldc_w()
{
    Frame *frame_atual = get_frame_atual();
    uint16_t indice = concat16(frame_atual->code[frame_atual->pc + 1], frame_atual->code[frame_atual->pc + 2]);
    uint8_t tag = (frame_atual->constant_pool[indice - 1]).tag;

    switch (tag)
    {
    case CONSTANT_Float:
        push_operando(frame_atual->constant_pool[indice - 1].info.Float.bytes);
        break;

    case CONSTANT_Integer:
        push_operando(frame_atual->constant_pool[indice - 1].info.Integer.bytes);
        break;

    case CONSTANT_String:
        push_operando((intptr_t)read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[indice - 1].info.String.string_index));
        break;

    default:
        printf("ERRO: ldc_w não implementada para tag %d\n", tag);
        exit(1);
        break;
    }

    atualiza_pc();
}


/**
 * @brief Função que simula a instrução 'ldc2_w' da JVM para carregar constantes longas e double do pool de constantes.
 */
void ldc2_w()
{
    Frame *frame_atual = get_frame_atual();

    uint16_t indice = concat16(frame_atual->code[frame_atual->pc + 1], frame_atual->code[frame_atual->pc + 2]);
    uint8_t tag = (frame_atual->constant_pool[indice - 1]).tag;
    uint32_t mais_significativos;
    uint32_t menos_significativos;

    switch (tag)
    {
    case CONSTANT_Long:
        mais_significativos = frame_atual->constant_pool[indice - 1].info.Long.high_bytes;
        menos_significativos = frame_atual->constant_pool[indice - 1].info.Long.low_bytes;
        push_operando(mais_significativos);
        push_operando(menos_significativos);
        break;

    case CONSTANT_Double:
        mais_significativos = frame_atual->constant_pool[indice - 1].info.Double.high_bytes;
        menos_significativos = frame_atual->constant_pool[indice - 1].info.Double.low_bytes;
        push_operando(mais_significativos);
        push_operando(menos_significativos);
        break;

    default:
        printf("ERRO: ldc2_w não implementada para tag %d\n", tag);
        exit(1);
        break;
    }

    atualiza_pc();
}

/**
 * @brief Carrega um inteiro de uma variável local especificada e empilha na pilha de operandos do frame atual.
 * Funções similares são definidas para tipos long, float, double e referência.
 */
void iload()
{
    Frame *frame_atual = get_frame_atual();
    if (wide_instruction)
    {
        uint8_t byte1 = frame_atual->code[frame_atual->pc + 2];
        uint8_t byte2 = frame_atual->code[frame_atual->pc + 3];
        uint16_t indice = concat16(byte1, byte2);
        push_operando(frame_atual->fields[indice]);
        frame_atual->pc += 4;
    }
    else
    {
        uint8_t indice = frame_atual->code[frame_atual->pc + 1];
        push_operando(frame_atual->fields[indice]);
        atualiza_pc();
    }
}

void lload()
{
    Frame *frame_atual = get_frame_atual();
    if (wide_instruction)
    {
        uint8_t byte1 = frame_atual->code[frame_atual->pc + 2];
        uint8_t byte2 = frame_atual->code[frame_atual->pc + 3];
        uint16_t indice = concat16(byte1, byte2);
        int32_t menos_significativos = frame_atual->fields[indice];
        int32_t mais_significativos = frame_atual->fields[indice + 1];

        push_operando(mais_significativos);
        push_operando(menos_significativos);
        frame_atual->pc += 4;
    }
    else
    {
        uint8_t indice = frame_atual->code[frame_atual->pc + 1];
        int32_t menos_significativos = frame_atual->fields[indice];
        int32_t mais_significativos = frame_atual->fields[indice + 1];

        push_operando(mais_significativos);
        push_operando(menos_significativos);

        atualiza_pc();
    }
}

void fload()
{
    Frame *frame_atual = get_frame_atual();
    if (wide_instruction)
    {
        uint8_t byte1 = frame_atual->code[frame_atual->pc + 2];
        uint8_t byte2 = frame_atual->code[frame_atual->pc + 3];
        uint16_t indice = concat16(byte1, byte2);
        push_operando(frame_atual->fields[indice]);
        frame_atual->pc += 4;
    }
    else
    {
        uint8_t indice = frame_atual->code[frame_atual->pc + 1];
        push_operando(frame_atual->fields[indice]);
        atualiza_pc();
    }
}

void dload()
{
    Frame *frame_atual = get_frame_atual();
    if (wide_instruction)
    {
        uint8_t byte1 = frame_atual->code[frame_atual->pc + 2];
        uint8_t byte2 = frame_atual->code[frame_atual->pc + 3];
        uint16_t indice = concat16(byte1, byte2);
        int32_t menos_significativos = frame_atual->fields[indice];
        int32_t mais_significativos = frame_atual->fields[indice + 1];

        push_operando(mais_significativos);
        push_operando(menos_significativos);
        frame_atual->pc += 4;
    }
    else
    {
        uint8_t indice = frame_atual->code[frame_atual->pc + 1];
        int32_t menos_significativos = frame_atual->fields[indice];
        int32_t mais_significativos = frame_atual->fields[indice + 1];

        push_operando(mais_significativos);
        push_operando(menos_significativos);

        atualiza_pc();
    }
}

void aload()
{
    Frame *frame_atual = get_frame_atual();
    if (wide_instruction)
    {
        uint8_t byte1 = frame_atual->code[frame_atual->pc + 2];
        uint8_t byte2 = frame_atual->code[frame_atual->pc + 3];
        uint16_t indice = concat16(byte1, byte2);
        push_operando(frame_atual->fields[indice]);
        frame_atual->pc += 4;
    }
    else
    {
        uint8_t indice = frame_atual->code[frame_atual->pc + 1];
        push_operando(frame_atual->fields[indice]);
        atualiza_pc();
    }
}

/**
 * @brief Armazena um inteiro da pilha de operandos em uma variável local especificada.
 * Funções similares são definidas para tipos long, float, double e referência.
 */
void iload_0()
{
    push_operando(get_frame_atual()->fields[0]);
    atualiza_pc();
}

void iload_1()
{
    push_operando(get_frame_atual()->fields[1]);
    atualiza_pc();
}

void iload_2()
{

    push_operando(get_frame_atual()->fields[2]);
    atualiza_pc();
}

void iload_3()
{

    push_operando(get_frame_atual()->fields[3]);
    atualiza_pc();
}

void lload_0()
{
    Frame *frame_atual = get_frame_atual();
    int32_t menos_significativos = frame_atual->fields[0];
    int32_t mais_significativos = frame_atual->fields[1];

    push_operando(mais_significativos);
    push_operando(menos_significativos);

    atualiza_pc();
}

void lload_1()
{
    Frame *frame_atual = get_frame_atual();
    int32_t menos_significativos = frame_atual->fields[1];
    int32_t mais_significativos = frame_atual->fields[2];

    push_operando(mais_significativos);
    push_operando(menos_significativos);

    atualiza_pc();
}

void lload_2()
{
    Frame *frame_atual = get_frame_atual();
    int32_t menos_significativos = frame_atual->fields[2];
    int32_t mais_significativos = frame_atual->fields[3];

    push_operando(mais_significativos);
    push_operando(menos_significativos);

    atualiza_pc();
}

void lload_3()
{
    Frame *frame_atual = get_frame_atual();
    int32_t menos_significativos = frame_atual->fields[3];
    int32_t mais_significativos = frame_atual->fields[4];

    push_operando(mais_significativos);
    push_operando(menos_significativos);

    atualiza_pc();
}

void fload_0()
{
    push_operando(get_frame_atual()->fields[0]);
    atualiza_pc();
}

void fload_1()
{

    push_operando(get_frame_atual()->fields[1]);
    atualiza_pc();
}

void fload_2()
{

    push_operando(get_frame_atual()->fields[2]);
    atualiza_pc();
}

void fload_3()
{

    push_operando(get_frame_atual()->fields[3]);
    atualiza_pc();
}

void dload_0()
{

    Frame *frame_atual = get_frame_atual();
    int32_t menos_significativos = frame_atual->fields[0];
    int32_t mais_significativos = frame_atual->fields[1];

    push_operando(mais_significativos);
    push_operando(menos_significativos);

    atualiza_pc();
}

void dload_1()
{
    Frame *frame_atual = get_frame_atual();
    int32_t menos_significativos = frame_atual->fields[1];
    int32_t mais_significativos = frame_atual->fields[2];

    push_operando(mais_significativos);
    push_operando(menos_significativos);

    atualiza_pc();
}

void dload_2()
{
    Frame *frame_atual = get_frame_atual();
    int32_t menos_significativos = frame_atual->fields[2];
    int32_t mais_significativos = frame_atual->fields[3];

    push_operando(mais_significativos);
    push_operando(menos_significativos);

    atualiza_pc();
}

void dload_3()
{
    Frame *frame_atual = get_frame_atual();
    int32_t menos_significativos = frame_atual->fields[3];
    int32_t mais_significativos = frame_atual->fields[4];

    push_operando(mais_significativos);
    push_operando(menos_significativos);

    atualiza_pc();
}

void aload_0()
{

    push_operando(get_frame_atual()->fields[0]);
    atualiza_pc();
}

void aload_1()
{
    push_operando(get_frame_atual()->fields[1]);
    atualiza_pc();
}

void aload_2()
{
    push_operando(get_frame_atual()->fields[2]);
    atualiza_pc();
}

void aload_3()
{
    push_operando(get_frame_atual()->fields[3]);
    atualiza_pc();
}

/**
 * @brief Carrega um inteiro de um array referenciado pelo índice na pilha de operandos.
 */
void iaload()
{
    int32_t indice = pop_operando();
    int32_t *referencia = (int32_t *)(intptr_t)pop_operando();

    push_operando(referencia[indice]);
    atualiza_pc();
}

/**
 * @brief Carrega um long de um array referenciado pelo índice na pilha de operandos, envolvendo duas posições do array.
 */
void laload()
{
    int32_t indice = pop_operando() * 2;
    int32_t *referencia = (int32_t *)(intptr_t)pop_operando();

    push_operando(referencia[indice + 1]);
    push_operando(referencia[indice]);
    atualiza_pc();
}

/**
 * @brief Carrega um float de um array referenciado pelo índice na pilha de operandos.
 */
void faload()
{
    int32_t indice = pop_operando();
    int32_t *referencia = (int32_t *)(intptr_t)pop_operando();

    push_operando(referencia[indice]);
    atualiza_pc();
}

/**
 * @brief Carrega um double de um array referenciado pelo índice na pilha de operandos, envolvendo duas posições do array.
 */
void daload()
{
    int32_t indice = pop_operando() * 2;
    int32_t *referencia = (int32_t *)(intptr_t)pop_operando();

    push_operando(referencia[indice + 1]);
    push_operando(referencia[indice]);
    atualiza_pc();
}

/**
 * @brief Carrega uma referência de um array referenciado pelo índice na pilha de operandos.
 */
void aaload()
{

    int32_t indice = pop_operando();
    int32_t *referencia = (int32_t *)(intptr_t)pop_operando();

    push_operando(referencia[indice]);
    atualiza_pc();
}

/**
 * @brief Carrega um byte de um array de bytes referenciado pelo índice na pilha de operandos e o expande para o tipo inteiro.
 */
void baload()
{
    int32_t indice = pop_operando();
    int8_t *referencia = (int8_t *)(intptr_t)pop_operando();

    push_operando(referencia[indice]);
    atualiza_pc();
}

/**
 * @brief Carrega um char de um array de chars referenciado pelo índice na pilha de operandos e o expande para o tipo inteiro.
 */
void caload()
{
    int32_t indice = pop_operando();
    int16_t *referencia = (int16_t *)(intptr_t)pop_operando();

    push_operando(referencia[indice]);
    atualiza_pc();
}

/**
 * @brief Carrega um short de um array de shorts referenciado pelo índice na pilha de operandos e o expande para o tipo inteiro.
 */
void saload()
{

    int32_t indice = pop_operando();
    int16_t *referencia = (int16_t *)(intptr_t)pop_operando();

    push_operando(referencia[indice]);
    atualiza_pc();
}

/**
 * @brief Armazena um inteiro da pilha de operandos em uma variável local especificada.
 */
void istore()
{
    Frame *frame_atual = get_frame_atual();
    if (wide_instruction)
    {
        uint8_t byte1 = frame_atual->code[frame_atual->pc + 2];
        uint8_t byte2 = frame_atual->code[frame_atual->pc + 3];
        uint16_t indice = concat16(byte1, byte2);
        frame_atual->fields[indice] = pop_operando();
        frame_atual->pc += 4;
    }
    else
    {
        uint8_t indice = frame_atual->code[frame_atual->pc + 1];
        frame_atual->fields[indice] = pop_operando();
        atualiza_pc();
    }
}

/**
 * @brief Armazena um long da pilha de operandos em duas posições consecutivas de variáveis locais, começando pela especificada.
 */
void lstore()
{
    Frame *frame_atual = get_frame_atual();
    if (wide_instruction)
    {
        uint8_t byte1 = frame_atual->code[frame_atual->pc + 2];
        uint8_t byte2 = frame_atual->code[frame_atual->pc + 3];
        uint16_t indice = concat16(byte1, byte2);
        int32_t menos_significativos = pop_operando();
        int32_t mais_significativos = pop_operando();

        frame_atual->fields[indice] = menos_significativos;
        frame_atual->fields[indice + 1] = mais_significativos;
        frame_atual->pc += 4;
    }
    else
    {
        Frame *frame_atual = get_frame_atual();
        uint8_t indice = frame_atual->code[frame_atual->pc + 1];
        int32_t menos_significativos = pop_operando();
        int32_t mais_significativos = pop_operando();

        frame_atual->fields[indice] = menos_significativos;
        frame_atual->fields[indice + 1] = mais_significativos;

        atualiza_pc();
    }
}

/**
 * @brief Armazena um float da pilha de operandos em uma variável local especificada.
 */
void fstore()
{
    Frame *frame_atual = get_frame_atual();
    if (wide_instruction)
    {
        uint8_t byte1 = frame_atual->code[frame_atual->pc + 2];
        uint8_t byte2 = frame_atual->code[frame_atual->pc + 3];
        uint16_t indice = concat16(byte1, byte2);
        frame_atual->fields[indice] = pop_operando();
        frame_atual->pc += 4;
    }
    else
    {
        uint8_t indice = frame_atual->code[frame_atual->pc + 1];
        frame_atual->fields[indice] = pop_operando();
        atualiza_pc();
    }
}

/**
 * @brief Armazena um double da pilha de operandos em duas posições consecutivas de variáveis locais, começando pela especificada.
 */
void dstore()
{
    Frame *frame_atual = get_frame_atual();
    if (wide_instruction)
    {
        uint8_t byte1 = frame_atual->code[frame_atual->pc + 2];
        uint8_t byte2 = frame_atual->code[frame_atual->pc + 3];
        uint16_t indice = concat16(byte1, byte2);
        int32_t menos_significativos = pop_operando();
        int32_t mais_significativos = pop_operando();

        frame_atual->fields[indice] = menos_significativos;
        frame_atual->fields[indice + 1] = mais_significativos;
        frame_atual->pc += 4;
    }
    else
    {
        Frame *frame_atual = get_frame_atual();
        uint8_t indice = frame_atual->code[frame_atual->pc + 1];
        int32_t menos_significativos = pop_operando();
        int32_t mais_significativos = pop_operando();

        frame_atual->fields[indice] = menos_significativos;
        frame_atual->fields[indice + 1] = mais_significativos;

        atualiza_pc();
    }
}

/**
 * @brief Armazena uma referência da pilha de operandos em uma variável local especificada.
 */
void astore()
{
    Frame *frame_atual = get_frame_atual();
    if (wide_instruction)
    {
        uint8_t byte1 = frame_atual->code[frame_atual->pc + 2];
        uint8_t byte2 = frame_atual->code[frame_atual->pc + 3];
        uint16_t indice = concat16(byte1, byte2);
        frame_atual->fields[indice] = pop_operando();
        frame_atual->pc += 4;
    }
    else
    {
        uint8_t indice = frame_atual->code[frame_atual->pc + 1];
        frame_atual->fields[indice] = pop_operando();
        atualiza_pc();
    }
}

/**
 * @brief Armazena um inteiro da pilha de operandos na primeira variável local.
 */
void istore_0()
{

    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[0] = pop_operando();
    atualiza_pc();
}

/**
 * @brief Armazena um inteiro da pilha de operandos na segunda variável local.
 */
void istore_1()
{
    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[1] = pop_operando();
    atualiza_pc();
}

/**
 * @brief Armazena um inteiro da pilha de operandos na terceira variável local.
 */
void istore_2()
{
    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[2] = pop_operando();
    atualiza_pc();
}

/**
 * @brief Armazena um inteiro da pilha de operandos na quarta variável local.
 */
void istore_3()
{
    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[3] = pop_operando();
    atualiza_pc();
}

/**
 * @brief Armazena um long da pilha de operandos começando pela primeira variável local.
 */
void lstore_0()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t indice = frame_atual->code[frame_atual->pc + 1];
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();

    frame_atual->fields[0] = menos_significativos;
    frame_atual->fields[1] = mais_significativos;

    atualiza_pc();
}

/**
 * @brief Armazena um long da pilha de operandos começando pela segunda variável local.
 */
void lstore_1()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t indice = frame_atual->code[frame_atual->pc + 1];
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();

    frame_atual->fields[1] = menos_significativos;
    frame_atual->fields[2] = mais_significativos;

    atualiza_pc();
}

/**
 * @brief Armazena um long da pilha de operandos começando pela terceira variável local.
 */
void lstore_2()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t indice = frame_atual->code[frame_atual->pc + 1];
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();

    frame_atual->fields[2] = menos_significativos;
    frame_atual->fields[3] = mais_significativos;

    atualiza_pc();
}

/**
 * @brief Armazena um long da pilha de operandos começando pela quarta variável local.
 */
void lstore_3()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t indice = frame_atual->code[frame_atual->pc + 1];
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();

    frame_atual->fields[3] = menos_significativos;
    frame_atual->fields[4] = mais_significativos;

    atualiza_pc();
}

/**
 * @brief Armazena um float da pilha de operandos na primeira variável local.
 */
void fstore_0()
{
    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[0] = pop_operando();
    atualiza_pc();
}


/**
 * @brief Armazena um float da pilha de operandos na segunda variável local.
 */
void fstore_1()
{
    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[1] = pop_operando();
    atualiza_pc();
}

/**
 * @brief Armazena um float da pilha de operandos na terceira variável local.
 */
void fstore_2()
{
    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[2] = pop_operando();
    atualiza_pc();
}

/**
 * @brief Armazena um float da pilha de operandos na quarta variável local.
 */
void fstore_3()
{
    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[3] = pop_operando();
    atualiza_pc();
}

/**
 * @brief Armazena um double da pilha de operandos começando pela primeira variável local.
 */
void dstore_0()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t indice = frame_atual->code[frame_atual->pc + 1];
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();

    frame_atual->fields[0] = menos_significativos;
    frame_atual->fields[1] = mais_significativos;

    atualiza_pc();
}

/**
 * @brief Armazena um double da pilha de operandos começando pela segunda variável local.
 */
void dstore_1()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t indice = frame_atual->code[frame_atual->pc + 1];
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();

    frame_atual->fields[1] = menos_significativos;
    frame_atual->fields[2] = mais_significativos;

    atualiza_pc();
}

/**
 * @brief Armazena um double da pilha de operandos começando pela terceira variável local.
 */
void dstore_2()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t indice = frame_atual->code[frame_atual->pc + 1];
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();

    frame_atual->fields[2] = menos_significativos;
    frame_atual->fields[3] = mais_significativos;

    atualiza_pc();
}

/**
 * @brief Armazena um double da pilha de operandos começando pela quarta variável local.
 */
void dstore_3()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t indice = frame_atual->code[frame_atual->pc + 1];
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();

    frame_atual->fields[3] = menos_significativos;
    frame_atual->fields[4] = mais_significativos;

    atualiza_pc();
}

/**
 * @brief Armazena uma referência da pilha de operandos na primeira variável local.
 */
void astore_0()
{
    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[0] = pop_operando();
    atualiza_pc();
}

/**
 * @brief Armazena uma referência da pilha de operandos na segunda variável local.
 */
void astore_1()
{
    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[1] = pop_operando();
    atualiza_pc();
}

/**
 * @brief Armazena uma referência da pilha de operandos na terceira variável local.
 */
void astore_2()
{
    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[2] = pop_operando();
    atualiza_pc();
}

/**
 * @brief Armazena uma referência da pilha de operandos na quarta variável local.
 */
void astore_3()
{
    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[3] = pop_operando();
    atualiza_pc();
}

/**
 * @brief Armazena um inteiro em um array de inteiros referenciado, usando um índice e valor fornecidos pela pilha de operandos.
 */
void iastore()
{
    int32_t valor = pop_operando();
    int32_t indice = pop_operando();
    int32_t *referencia = (int32_t *)(intptr_t)pop_operando();

    referencia[indice] = valor;
    atualiza_pc();
}

/**
 * @brief Armazena um long em um array de longs referenciado, usando um índice e valor fornecidos pela pilha de operandos.
 */
void lastore()
{
    Frame *frame_atual = get_frame_atual();
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();
    int32_t indice = pop_operando() * 2;
    int32_t *referencia = (int32_t *)(intptr_t)pop_operando();

    referencia[indice] = menos_significativos;
    referencia[indice + 1] = mais_significativos;

    atualiza_pc();
}

/**
 * @brief Armazena um float em um array de floats referenciado, usando um índice e valor fornecidos pela pilha de operandos.
 */
void fastore()
{
    int32_t valor = pop_operando();
    int32_t indice = pop_operando();
    int32_t *referencia = (int32_t *)(intptr_t)pop_operando();

    referencia[indice] = valor;
    atualiza_pc();
}

/**
 * @brief Armazena um double em um array de doubles referenciado, usando um índice e valor fornecidos pela pilha de operandos.
 */
void dastore()
{
    Frame *frame_atual = get_frame_atual();
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();
    int32_t indice = pop_operando() * 2;
    int32_t *referencia = (int32_t *)(intptr_t)pop_operando();

    referencia[indice] = menos_significativos;
    referencia[indice + 1] = mais_significativos;

    atualiza_pc();
}

/**
 * @brief Armazena uma referência em um array de referências referenciado, usando um índice e valor fornecidos pela pilha de operandos.
 */
void aastore()
{
    int32_t valor = pop_operando();
    int32_t indice = pop_operando();
    int32_t *referencia = (int32_t *)(intptr_t)pop_operando();

    referencia[indice] = valor;
    atualiza_pc();
}

/**
 * @brief Armazena um byte em um array de bytes referenciado, usando um índice e valor fornecidos pela pilha de operandos.
 */
void bastore()
{
    int8_t valor = pop_operando();
    int32_t indice = pop_operando();
    int8_t *referencia = (int8_t *)(intptr_t)pop_operando();

    referencia[indice] = valor;
    atualiza_pc();
}

/**
 * @brief Armazena um char em um array de chars referenciado, usando um índice e valor fornecidos pela pilha de operandos.
 */
void castore()
{

    int16_t valor = pop_operando();
    int32_t indice = pop_operando();
    int16_t *referencia = (int16_t *)(intptr_t)pop_operando();

    referencia[indice] = valor;
    atualiza_pc();
}

/**
 * @brief Armazena um short em um array de shorts referenciado, usando um índice e valor fornecidos pela pilha de operandos.
 */
void sastore()
{

    int16_t valor = pop_operando();
    int32_t indice = pop_operando();
    int16_t *referencia = (int16_t *)(intptr_t)pop_operando();

    referencia[indice] = valor;
    atualiza_pc();
}

/**
 * @brief Remove o elemento do topo da pilha de operandos.
 */
void pop()
{
    pop_operando();

    atualiza_pc();
}

/**
 * @brief Remove os dois elementos do topo da pilha de operandos.
 */
void pop2()
{

    pop_operando();
    pop_operando();

    atualiza_pc();
}

/**
 * @brief Duplica o elemento no topo da pilha de operandos.
 */
void dup()
{
    int32_t valor = pop_operando();

    push_operando(valor);
    push_operando(valor);
    atualiza_pc();
}

/**
 * @brief Duplica o elemento no topo da pilha de operandos e insere duas posições abaixo.
 */
void dup_x1()
{
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    push_operando(valor1);

    push_operando(valor2);

    push_operando(valor1);

    atualiza_pc();
}

/**
 * @brief Duplica o elemento no topo da pilha de operandos e insere três posições abaixo.
 */
void dup_x2()
{

    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();
    int32_t valor3 = pop_operando();

    push_operando(valor1);
    push_operando(valor3);
    push_operando(valor2);
    push_operando(valor1);

    atualiza_pc();
}

/**
 * @brief Duplica os dois elementos no topo da pilha de operandos.
 */
void dup2()
{

    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();

    push_operando(mais_significativos);
    push_operando(menos_significativos);
    push_operando(mais_significativos);
    push_operando(menos_significativos);

    atualiza_pc();
}

/**
 * @brief Duplica os dois elementos no topo da pilha de operandos e insere três posições abaixo.
 */
void dup2_x1()
{

    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();
    int32_t valor = pop_operando();

    push_operando(mais_significativos);
    push_operando(menos_significativos);
    push_operando(valor);
    push_operando(mais_significativos);
    push_operando(menos_significativos);

    atualiza_pc();
}

/**
 * @brief Duplica os dois elementos no topo da pilha de operandos e insere quatro posições abaixo.
 */
void dup2_x2()
{
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    push_operando(mais_significativos);
    push_operando(menos_significativos);
    push_operando(valor2);
    push_operando(valor1);
    push_operando(mais_significativos);
    push_operando(menos_significativos);

    atualiza_pc();
}

/**
 * @brief Troca os dois elementos no topo da pilha de operandos.
 */
void swap()
{
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    push_operando(valor1);
    push_operando(valor2);

    atualiza_pc();
}

/**
 * @brief Adiciona dois inteiros do topo da pilha de operandos e empurra o resultado de volta para a pilha.
 */
void iadd()
{
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    push_operando(valor2 + valor1);

    atualiza_pc();
}

/**
 * @brief Adiciona dois longs do topo da pilha de operandos e empurra o resultado de volta para a pilha.
 */
void ladd()
{
    int32_t menos_significativos1 = pop_operando();
    int32_t mais_significativos1 = pop_operando();
    int32_t menos_significativos2 = pop_operando();
    int32_t mais_significativos2 = pop_operando();

    int64_t valor1 = concat64(mais_significativos1, menos_significativos1);
    int64_t valor2 = concat64(mais_significativos2, menos_significativos2);

    Wide wide = divide_64(valor2 + valor1);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}

/**
 * @brief Adiciona dois floats do topo da pilha de operandos e empurra o resultado de volta para a pilha.
 */
void fadd()
{
    float valor_f1, valor_f2, resultado;
    int32_t valor_i;

    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    memcpy(&valor_f1, &valor1, sizeof(int32_t));
    memcpy(&valor_f2, &valor2, sizeof(int32_t));

    resultado = valor_f2 + valor_f1;

    memcpy(&valor_i, &resultado, sizeof(int32_t));

    push_operando(valor_i);

    atualiza_pc();
}


/**
 * @brief Adiciona dois doubles do topo da pilha de operandos e empurra o resultado de volta para a pilha.
 */
void dadd()
{
    double valor_d1, valor_d2, resultado_d;
    int64_t valor_i1, valor_i2, resultado_i;

    int32_t menos_significativos1 = pop_operando();
    int32_t mais_significativos1 = pop_operando();
    int32_t menos_significativos2 = pop_operando();
    int32_t mais_significativos2 = pop_operando();

    valor_i1 = concat64(mais_significativos1, menos_significativos1);
    valor_i2 = concat64(mais_significativos2, menos_significativos2);

    memcpy(&valor_d1, &valor_i1, sizeof(int64_t));
    memcpy(&valor_d2, &valor_i2, sizeof(int64_t));

    resultado_d = valor_d2 + valor_d1;

    memcpy(&resultado_i, &resultado_d, sizeof(int64_t));

    Wide wide = divide_64(resultado_i);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}

/**
 * @brief Subtrai o segundo inteiro do topo da pilha pelo primeiro e empurra o resultado de volta para a pilha.
 */
void isub()
{
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    push_operando(valor2 - valor1);

    atualiza_pc();
}

/**
 * @brief Subtrai o segundo long do topo da pilha pelo primeiro e empurra o resultado de volta para a pilha.
 */
void lsub()
{
    int32_t menos_significativos1 = pop_operando();
    int32_t mais_significativos1 = pop_operando();
    int32_t menos_significativos2 = pop_operando();
    int32_t mais_significativos2 = pop_operando();

    int64_t valor1 = concat64(mais_significativos1, menos_significativos1);
    int64_t valor2 = concat64(mais_significativos2, menos_significativos2);

    Wide wide = divide_64(valor2 - valor1);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}

/**
 * @brief Subtrai o segundo float do topo da pilha pelo primeiro e empurra o resultado de volta para a pilha.
 */
void fsub()
{
    float valor_f1, valor_f2, resultado;
    int32_t valor_i;

    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    memcpy(&valor_f1, &valor1, sizeof(int32_t));
    memcpy(&valor_f2, &valor2, sizeof(int32_t));

    resultado = valor_f2 - valor_f1;

    memcpy(&valor_i, &resultado, sizeof(int32_t));

    push_operando(valor_i);

    atualiza_pc();
}

/**
 * @brief Subtrai o segundo double do topo da pilha pelo primeiro e empurra o resultado de volta para a pilha.
 */
void dsub()
{
    double valor_d1, valor_d2, resultado_d;
    int64_t valor_i1, valor_i2, resultado_i;

    int32_t menos_significativos1 = pop_operando();
    int32_t mais_significativos1 = pop_operando();
    int32_t menos_significativos2 = pop_operando();
    int32_t mais_significativos2 = pop_operando();

    valor_i1 = concat64(mais_significativos1, menos_significativos1);
    valor_i2 = concat64(mais_significativos2, menos_significativos2);

    memcpy(&valor_d1, &valor_i1, sizeof(int64_t));
    memcpy(&valor_d2, &valor_i2, sizeof(int64_t));

    resultado_d = valor_d2 - valor_d1;

    memcpy(&resultado_i, &resultado_d, sizeof(int64_t));

    Wide wide = divide_64(resultado_i);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}

/**
 * @brief Multiplica dois inteiros do topo da pilha de operandos e empurra o resultado de volta para a pilha.
 */
void imul()
{
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    push_operando(valor2 * valor1);

    atualiza_pc();
}

/**
 * @brief Multiplica dois longs do topo da pilha de operandos e empurra o resultado de volta para a pilha.
 */
void lmul()
{
    int32_t menos_significativos1 = pop_operando();
    int32_t mais_significativos1 = pop_operando();
    int32_t menos_significativos2 = pop_operando();
    int32_t mais_significativos2 = pop_operando();

    int64_t valor1 = concat64(mais_significativos1, menos_significativos1);
    int64_t valor2 = concat64(mais_significativos2, menos_significativos2);

    Wide wide = divide_64(valor2 * valor1);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}

/**
 * @brief Multiplica dois floats do topo da pilha de operandos e empurra o resultado de volta para a pilha.
 */
void fmul()
{
    float valor_f1, valor_f2, resultado;
    int32_t valor_i;

    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    memcpy(&valor_f1, &valor1, sizeof(int32_t));
    memcpy(&valor_f2, &valor2, sizeof(int32_t));

    resultado = valor_f2 * valor_f1;

    memcpy(&valor_i, &resultado, sizeof(int32_t));

    push_operando(valor_i);

    atualiza_pc();
}


/**
 * @brief Multiplica dois doubles do topo da pilha de operandos e empurra o resultado de volta para a pilha.
 */
void dmul()
{
    double valor_d1, valor_d2, resultado_d;
    int64_t valor_i1, valor_i2, resultado_i;

    int32_t menos_significativos1 = pop_operando();
    int32_t mais_significativos1 = pop_operando();
    int32_t menos_significativos2 = pop_operando();
    int32_t mais_significativos2 = pop_operando();

    valor_i1 = concat64(mais_significativos1, menos_significativos1);
    valor_i2 = concat64(mais_significativos2, menos_significativos2);

    memcpy(&valor_d1, &valor_i1, sizeof(int64_t));
    memcpy(&valor_d2, &valor_i2, sizeof(int64_t));

    resultado_d = valor_d2 * valor_d1;

    memcpy(&resultado_i, &resultado_d, sizeof(int64_t));

    Wide wide = divide_64(resultado_i);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}

/**
 * @brief Divide o segundo inteiro do topo da pilha pelo primeiro e empurra o resultado de volta para a pilha.
 */
void idiv()
{
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    push_operando(valor2 / valor1);

    atualiza_pc();
}

/**
 * @brief Divide o segundo long do topo da pilha pelo primeiro e empurra o resultado de volta para a pilha.
 */
void jvm_ldiv()
{
    int32_t menos_significativos1 = pop_operando();
    int32_t mais_significativos1 = pop_operando();
    int32_t menos_significativos2 = pop_operando();
    int32_t mais_significativos2 = pop_operando();

    int64_t valor1 = concat64(mais_significativos1, menos_significativos1);
    int64_t valor2 = concat64(mais_significativos2, menos_significativos2);

    Wide wide = divide_64(valor2 / valor1);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}

/**
 * @brief Divide o segundo float do topo da pilha pelo primeiro e empurra o resultado de volta para a pilha.
 */
void fdiv()
{
    float valor_f1, valor_f2, resultado;
    int32_t valor_i;

    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    memcpy(&valor_f1, &valor1, sizeof(int32_t));
    memcpy(&valor_f2, &valor2, sizeof(int32_t));

    resultado = valor_f2 / valor_f1;

    memcpy(&valor_i, &resultado, sizeof(int32_t));

    push_operando(valor_i);

    atualiza_pc();
}

/**
 * @brief Divide o segundo double do topo da pilha pelo primeiro e empurra o resultado de volta para a pilha.
 */
void ddiv()
{
    double valor_d1, valor_d2, resultado_d;
    int64_t valor_i1, valor_i2, resultado_i;

    int32_t menos_significativos1 = pop_operando();
    int32_t mais_significativos1 = pop_operando();
    int32_t menos_significativos2 = pop_operando();
    int32_t mais_significativos2 = pop_operando();

    valor_i1 = concat64(mais_significativos1, menos_significativos1);
    valor_i2 = concat64(mais_significativos2, menos_significativos2);

    memcpy(&valor_d1, &valor_i1, sizeof(int64_t));
    memcpy(&valor_d2, &valor_i2, sizeof(int64_t));

    resultado_d = valor_d2 / valor_d1;

    memcpy(&resultado_i, &resultado_d, sizeof(int64_t));

    Wide wide = divide_64(resultado_i);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}

/**
 * @brief Calcula o resto da divisão do segundo inteiro do topo da pilha pelo primeiro e empurra o resultado de volta para a pilha.
 */
void irem()
{
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    push_operando(valor2 % valor1);
    atualiza_pc();
}

/**
 * @brief Calcula o resto da divisão do segundo long do topo da pilha pelo primeiro e empurra o resultado de volta para a pilha.
 */
void lrem()
{
    int32_t menos_significativos1 = pop_operando();
    int32_t mais_significativos1 = pop_operando();
    int32_t menos_significativos2 = pop_operando();
    int32_t mais_significativos2 = pop_operando();

    int64_t valor1 = concat64(mais_significativos1, menos_significativos1);
    int64_t valor2 = concat64(mais_significativos2, menos_significativos2);

    Wide wide = divide_64(valor2 % valor1);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}


/**
 * @brief Calcula o resto da divisão do segundo float do topo da pilha pelo primeiro e empurra o resultado de volta para a pilha.
 */
void frem()
{
    float valor_f1, valor_f2, resultado;
    int32_t valor_i;

    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    memcpy(&valor_f1, &valor1, sizeof(int32_t));
    memcpy(&valor_f2, &valor2, sizeof(int32_t));

    resultado = fmodf(valor_f2, valor_f1);

    memcpy(&valor_i, &resultado, sizeof(int32_t));

    push_operando(valor_i);

    atualiza_pc();
}

/**
 * @brief Calcula o resto da divisão do segundo double do topo da pilha pelo primeiro e empurra o resultado de volta para a pilha.
 */
void jvm_drem()
{
    double valor_d1, valor_d2, resultado_d;
    int64_t valor_i1, valor_i2, resultado_i;

    int32_t menos_significativos1 = pop_operando();
    int32_t mais_significativos1 = pop_operando();
    int32_t menos_significativos2 = pop_operando();
    int32_t mais_significativos2 = pop_operando();

    valor_i1 = concat64(mais_significativos1, menos_significativos1);
    valor_i2 = concat64(mais_significativos2, menos_significativos2);

    memcpy(&valor_d1, &valor_i1, sizeof(int64_t));
    memcpy(&valor_d2, &valor_i2, sizeof(int64_t));

    resultado_d = fmod(valor_d2, valor_d1);

    memcpy(&resultado_i, &resultado_d, sizeof(int64_t));

    Wide wide = divide_64(resultado_i);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}


/**
 * @brief Inverte o sinal do inteiro no topo da pilha.
 */
void ineg()
{
    int32_t valor = pop_operando();
    push_operando(-valor);
    atualiza_pc();
}

/**
 * @brief Inverte o sinal do long no topo da pilha.
 */
void lneg()
{
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();
    int64_t valor = concat64(mais_significativos, menos_significativos);

    valor = -valor;

    Wide wide = divide_64(valor);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}

/**
 * @brief Inverte o sinal do float no topo da pilha.
 */
void fneg()
{
    float valor_f;
    int32_t valor_i;

    int32_t valor = pop_operando();

    memcpy(&valor_f, &valor, sizeof(int32_t));

    valor_f = -valor_f;

    memcpy(&valor_i, &valor_f, sizeof(int32_t));

    push_operando(valor_i);

    atualiza_pc();
}

/**
 * @brief Inverte o sinal do double no topo da pilha.
 */
void dneg()
{
    double valor_d;
    int64_t valor_i;

    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();

    valor_i = concat64(mais_significativos, menos_significativos);

    memcpy(&valor_d, &valor_i, sizeof(int64_t));

    valor_d = -valor_d;

    memcpy(&valor_i, &valor_d, sizeof(int64_t));

    Wide wide = divide_64(valor_i);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}

/**
 * @brief Executa um deslocamento à esquerda no inteiro do topo da pilha pelo número de posições especificadas no segundo elemento do topo.
 */
void ishl()
{
    int32_t shift = pop_operando() & 0x1f;
    int32_t valor = pop_operando();

    push_operando(valor << shift);
    atualiza_pc();
}

/**
 * @brief Executa um deslocamento à esquerda no long do topo da pilha pelo número de posições especificadas no segundo elemento do topo.
 */
void lshl()
{
    int32_t shift = pop_operando() & 0x3f;
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();
    int64_t valor = concat64(mais_significativos, menos_significativos);

    Wide wide = divide_64(valor << shift);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}

/**
 * @brief Executa um deslocamento à direita no inteiro do topo da pilha pelo número de posições especificadas no segundo elemento do topo.
 */
void ishr()
{
    int32_t shift = pop_operando() & 0x1f;
    int32_t valor = pop_operando();

    push_operando(valor >> shift);
    atualiza_pc();
}

/**
 * @brief Executa um deslocamento à direita no long do topo da pilha pelo número de posições especificadas no segundo elemento do topo.
 */
void lshr()
{
    int32_t shift = pop_operando() & 0x3f;
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();
    int64_t valor = concat64(mais_significativos, menos_significativos);

    Wide wide = divide_64(valor >> shift);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}

/**
 * @brief Executa um deslocamento à direita sem sinal no inteiro do topo da pilha pelo número de posições especificadas no segundo elemento do topo.
 */
void iushr()
{

    int32_t shift = pop_operando() & 0x1f;
    uint32_t valor = pop_operando();

    push_operando(valor >> shift);
    atualiza_pc();
}

/**
 * @brief Executa um deslocamento à direita sem sinal no long do topo da pilha pelo número de posições especificadas no segundo elemento do topo.
 */
void lushr()
{
    int32_t shift = pop_operando() & 0x3f;
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();
    uint64_t valor = concat64(mais_significativos, menos_significativos);

    Wide wide = divide_64(valor >> shift);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}

/**
 * @brief Realiza uma operação AND bit a bit entre dois inteiros no topo da pilha e empurra o resultado de volta para a pilha.
 */
void iand()
{
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    push_operando(valor2 % valor1);
    atualiza_pc();
}

/**
 * @brief Realiza uma operação AND bit a bit entre dois longs no topo da pilha e empurra o resultado de volta para a pilha.
 */
void land()
{
    int32_t menos_significativos1 = pop_operando();
    int32_t mais_significativos1 = pop_operando();
    int32_t menos_significativos2 = pop_operando();
    int32_t mais_significativos2 = pop_operando();

    int64_t valor1 = concat64(mais_significativos1, menos_significativos1);
    int64_t valor2 = concat64(mais_significativos2, menos_significativos2);

    Wide wide = divide_64(valor2 & valor1);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}

/**
 * @brief Realiza uma operação OR bit a bit entre dois inteiros no topo da pilha e empurra o resultado de volta para a pilha.
 */
void ior()
{
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    push_operando(valor2 | valor1);
    atualiza_pc();
}

/**
 * @brief Realiza uma operação OR bit a bit entre dois longs no topo da pilha e empurra o resultado de volta para a pilha.
 */
void lor()
{
    int32_t menos_significativos1 = pop_operando();
    int32_t mais_significativos1 = pop_operando();
    int32_t menos_significativos2 = pop_operando();
    int32_t mais_significativos2 = pop_operando();

    int64_t valor1 = concat64(mais_significativos1, menos_significativos1);
    int64_t valor2 = concat64(mais_significativos2, menos_significativos2);

    Wide wide = divide_64(valor2 | valor1);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}

/**
 * @brief Realiza uma operação XOR bit a bit entre dois inteiros no topo da pilha e empurra o resultado de volta para a pilha.
 */
void ixor()
{
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    push_operando(valor2 ^ valor1);
    atualiza_pc();
}

/**
 * @brief Realiza uma operação XOR bit a bit entre dois longs no topo da pilha e empurra o resultado de volta para a pilha.
 */
void lxor()
{
    int32_t menos_significativos1 = pop_operando();
    int32_t mais_significativos1 = pop_operando();
    int32_t menos_significativos2 = pop_operando();
    int32_t mais_significativos2 = pop_operando();

    int64_t valor1 = concat64(mais_significativos1, menos_significativos1);
    int64_t valor2 = concat64(mais_significativos2, menos_significativos2);

    Wide wide = divide_64(valor2 ^ valor1);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}

/**
 * @brief Incrementa uma variável local inteira por uma constante.
 */
void iinc()
{
    Frame *frame_atual = get_frame_atual();
    
    if (wide_instruction)
    {
        uint8_t byte1 = frame_atual->code[frame_atual->pc + 1];
        uint8_t byte2 = frame_atual->code[frame_atual->pc + 1];
        uint16_t indice = concat16(byte1, byte2);
        uint8_t byte3 = frame_atual->code[frame_atual->pc + 1];
        uint8_t byte4 = frame_atual->code[frame_atual->pc + 1];
        uint16_t constante = concat16(byte3, byte4);


        frame_atual->fields[indice] += constante;
        frame_atual->pc += 6;
    }
    else
    {
        uint8_t indice = frame_atual->code[frame_atual->pc + 1];
        int8_t constante = frame_atual->code[frame_atual->pc + 2];

        frame_atual->fields[indice] += constante;
        atualiza_pc();
    }
}

/**
 * @brief Converte um inteiro para um long e empurra o resultado para a pilha.
 */
void i2l()
{
    int32_t valor = pop_operando();
    int64_t valor_l = valor;

    Wide wide = divide_64(valor_l);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}

/**
 * @brief Converte um inteiro para um float e empurra o resultado para a pilha.
 */
void i2f()
{
    int32_t valor = pop_operando();
    float valor_f = valor;
    int32_t valor_i;

    memcpy(&valor_i, &valor_f, sizeof(int32_t));

    push_operando(valor_i);
    atualiza_pc();
}

/**
 * @brief Converte um inteiro para um double e empurra o resultado para a pilha.
 */
void i2d()
{
    int32_t valor = pop_operando();
    double valor_d = valor;
    int64_t valor_i;

    memcpy(&valor_i, &valor_d, sizeof(int64_t));

    Wide wide = divide_64(valor_i);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}

/**
 * @brief Converte um long para um inteiro e empurra o resultado para a pilha.
 */
void l2i()
{
    int32_t menos_significativo = pop_operando();
    int32_t mais_significativo = pop_operando();

    push_operando(menos_significativo);
    atualiza_pc();
}

/**
 * @brief Converte um long para um float e empurra o resultado para a pilha.
 */
void l2f()
{
    int32_t menos_significativo = pop_operando();
    int32_t mais_significativo = pop_operando();
    int64_t valor_l = concat64(mais_significativo, menos_significativo);
    float valor_f = valor_l;
    int32_t valor_i;

    memcpy(&valor_i, &valor_f, sizeof(int32_t));

    push_operando(valor_i);
    atualiza_pc();
}

/**
 * @brief Converte um long para um double e empurra o resultado para a pilha.
 */
void l2d()
{
    int32_t menos_significativo = pop_operando();
    int32_t mais_significativo = pop_operando();
    int64_t valor_l = concat64(mais_significativo, menos_significativo);
    double valor_d = valor_l;

    memcpy(&valor_l, &valor_d, sizeof(int64_t));

    Wide wide = divide_64(valor_l);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);
    atualiza_pc();
}

/**
 * @brief Converte um float para um inteiro e empurra o resultado para a pilha.
 */
void f2i()
{
    int32_t valor = pop_operando();
    float valor_f;

    memcpy(&valor_f, &valor, sizeof(int32_t));

    int32_t valor_i = valor_f;

    push_operando(valor_i);
    atualiza_pc();
}

/**
 * @brief Converte um float para um long e empurra o resultado para a pilha.
 */
void f2l()
{
    int32_t valor = pop_operando();
    float valor_f;

    memcpy(&valor_f, &valor, sizeof(int32_t));

    int64_t valor_l = valor_f;

    Wide wide = divide_64(valor_l);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}

/**
 * @brief Converte um float para um double e empurra o resultado para a pilha.
 */
void f2d()
{
    int32_t valor = pop_operando();
    float valor_f;
    int64_t valor_l;

    memcpy(&valor_f, &valor, sizeof(int32_t));

    double valor_d = valor_f;

    memcpy(&valor_l, &valor_d, sizeof(int64_t));

    Wide wide = divide_64(valor_l);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}

/**
 * @brief Converte um double para um inteiro e empurra o resultado para a pilha.
 */
void d2i()
{
    int32_t menos_significativo = pop_operando();
    int32_t mais_significativo = pop_operando();
    int64_t valor_l = concat64(mais_significativo, menos_significativo);
    double valor_d;

    memcpy(&valor_d, &valor_l, sizeof(int64_t));

    push_operando(valor_d);
    atualiza_pc();
}

/**
 * @brief Converte um double para um long e empurra o resultado para a pilha.
 */
void d2l()
{
    int32_t menos_significativo = pop_operando();
    int32_t mais_significativo = pop_operando();
    int64_t valor_l = concat64(mais_significativo, menos_significativo);
    double valor_d;

    memcpy(&valor_d, &valor_l, sizeof(int64_t));

    valor_l = valor_d;

    Wide wide = divide_64(valor_l);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);
    atualiza_pc();
}

/**
 * @brief Converte um double para um float e empurra o resultado para a pilha.
 */
void d2f()
{
    int32_t menos_significativo = pop_operando();
    int32_t mais_significativo = pop_operando();
    int64_t valor_l = concat64(mais_significativo, menos_significativo);
    double valor_d;
    float valor_f;
    int32_t valor_i;

    memcpy(&valor_d, &valor_l, sizeof(int64_t));

    valor_f = valor_d;

    memcpy(&valor_i, &valor_f, sizeof(int32_t));

    push_operando(valor_i);
    atualiza_pc();
}

/**
 * @brief Converte um inteiro para um byte e empurra o resultado para a pilha.
 */
void i2b()
{
    int32_t valor = pop_operando();
    int8_t valor_b = valor;

    push_operando(valor_b);

    atualiza_pc();
}

/**
 * @brief Converte um inteiro para um char e empurra o resultado para a pilha.
 */
void i2c()
{
    int32_t valor = pop_operando();
    int16_t valor_c = valor;

    push_operando(valor_c);

    atualiza_pc();
}

/**
 * @brief Converte um inteiro para um short e empurra o resultado para a pilha.
 */
void i2s()
{
    int32_t valor = pop_operando();
    int16_t valor_c = valor;

    push_operando(valor_c);

    atualiza_pc();
}

/**
 * @brief Compara dois longs na pilha e empurra -1, 0, ou 1 se o segundo long é menor, igual, ou maior que o primeiro, respectivamente.
 */
void lcmp()
{
    int32_t menos_significativos1 = pop_operando();
    int32_t mais_significativos1 = pop_operando();
    int32_t menos_significativos2 = pop_operando();
    int32_t mais_significativos2 = pop_operando();

    int64_t valor1 = concat64(mais_significativos1, menos_significativos1);
    int64_t valor2 = concat64(mais_significativos2, menos_significativos2);

    if (valor2 == valor1)
    {
        push_operando(0);
    }
    else if (valor2 > valor1)
    {
        push_operando(1);
    }
    else if (valor2 < valor1)
    {
        push_operando(-1);
    }

    atualiza_pc();
}

/**
 * @brief Compara dois floats na pilha e empurra -1, 0, ou 1 se o segundo float é menor, igual, ou maior que o primeiro, respectivamente. Retorna -1 para NaN.
 */
void fcmpl()
{
    float valor_f1, valor_f2;
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    memcpy(&valor_f1, &valor1, sizeof(int32_t));
    memcpy(&valor_f2, &valor2, sizeof(int32_t));

    if (valor2 == valor1)
    {
        push_operando(0);
    }
    else if (valor2 > valor1)
    {
        push_operando(1);
    }
    else if (valor2 < valor1)
    {
        push_operando(-1);
    }
    else
    {
        push_operando(-1);
    }
}

/**
 * @brief Compara dois floats na pilha e empurra -1, 0, ou 1 se o segundo float é menor, igual, ou maior que o primeiro, respectivamente. Retorna 1 para NaN.
 */
void fcmpg()
{
    float valor_f1, valor_f2;
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    memcpy(&valor_f1, &valor1, sizeof(int32_t));
    memcpy(&valor_f2, &valor2, sizeof(int32_t));

    if (valor2 == valor1)
    {
        push_operando(0);
    }
    else if (valor2 > valor1)
    {
        push_operando(1);
    }
    else if (valor2 < valor1)
    {
        push_operando(-1);
    }
    else
    {
        push_operando(1);
    }
}

/**
 * @brief Compara dois doubles na pilha e empurra -1, 0, ou 1 se o segundo double é menor, igual, ou maior que o primeiro, respectivamente. Retorna -1 para NaN.
 */
void dcmpl()
{
    double valor_d1, valor_d2, resultado_d;
    int64_t valor_i1, valor_i2, resultado_i;

    int32_t menos_significativos1 = pop_operando();
    int32_t mais_significativos1 = pop_operando();
    int32_t menos_significativos2 = pop_operando();
    int32_t mais_significativos2 = pop_operando();

    valor_i1 = concat64(mais_significativos1, menos_significativos1);
    valor_i2 = concat64(mais_significativos2, menos_significativos2);

    memcpy(&valor_d1, &valor_i1, sizeof(int64_t));
    memcpy(&valor_d2, &valor_i2, sizeof(int64_t));

    resultado_d = fmod(valor_d2, valor_d1);

    if (valor_d2 > valor_d1)
    {
        push_operando((int32_t)1);
    }
    else if (valor_d2 == valor_d1)
    {
        push_operando((int32_t)0);
    }
    else if (valor_d2 < valor_d1)
    {
        push_operando((int32_t)-1);
    }
    else
    {
        push_operando(-1);
    }

    atualiza_pc();
}

/**
 * @brief Compara dois doubles na pilha e empurra -1, 0, ou 1 se o segundo double é menor, igual, ou maior que o primeiro, respectivamente. Retorna 1 para NaN.
 */
void dcmpg()
{
    double valor_d1, valor_d2, resultado_d;
    int64_t valor_i1, valor_i2, resultado_i;

    int32_t menos_significativos1 = pop_operando();
    int32_t mais_significativos1 = pop_operando();
    int32_t menos_significativos2 = pop_operando();
    int32_t mais_significativos2 = pop_operando();

    valor_i1 = concat64(mais_significativos1, menos_significativos1);
    valor_i2 = concat64(mais_significativos2, menos_significativos2);

    memcpy(&valor_d1, &valor_i1, sizeof(int64_t));
    memcpy(&valor_d2, &valor_i2, sizeof(int64_t));

    resultado_d = fmod(valor_d2, valor_d1);

    if (valor_d2 > valor_d1)
    {
        push_operando((int32_t)1);
    }
    else if (valor_d2 == valor_d1)
    {
        push_operando((int32_t)0);
    }
    else if (valor_d2 < valor_d1)
    {
        push_operando((int32_t)-1);
    }
    else
    {
        push_operando(1);
    }

    atualiza_pc();
}

/**
 * @brief Salta para um determinado offset se o valor no topo da pilha é zero.
 */
void ifeq()
{
    Frame *frame_atual = get_frame_atual();
    int32_t valor = pop_operando();
    uint8_t offset1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t offset2 = frame_atual->code[frame_atual->pc + 2];
    int16_t offset = concat16(offset1, offset2);

    if (valor == 0)
    {
        frame_atual->pc += offset;
    }
    else
    {
        atualiza_pc();
    }
}

/**
 * @brief Salta para um determinado offset se o valor no topo da pilha não é zero.
 */
void ifne()
{
    Frame *frame_atual = get_frame_atual();
    int32_t valor = pop_operando();
    uint8_t offset1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t offset2 = frame_atual->code[frame_atual->pc + 2];
    int16_t offset = concat16(offset1, offset2);

    if (valor != 0)
    {
        frame_atual->pc += offset;
    }
    else
    {
        atualiza_pc();
    }
}

/**
 * @brief Salta para um determinado offset se o valor no topo da pilha é menor que zero.
 */
void iflt()
{
    Frame *frame_atual = get_frame_atual();
    int32_t valor = pop_operando();
    uint8_t offset1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t offset2 = frame_atual->code[frame_atual->pc + 2];
    int16_t offset = concat16(offset1, offset2);

    if (valor < 0)
    {
        frame_atual->pc += offset;
    }
    else
    {
        atualiza_pc();
    }
}

/**
 * @brief Salta para um determinado offset se o valor no topo da pilha é maior ou igual a zero.
 */
void ifge()
{
    Frame *frame_atual = get_frame_atual();
    int32_t valor = pop_operando();
    uint8_t offset1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t offset2 = frame_atual->code[frame_atual->pc + 2];
    int16_t offset = concat16(offset1, offset2);

    if (valor >= 0)
    {
        frame_atual->pc += offset;
    }
    else
    {
        atualiza_pc();
    }
}

/**
 * @brief Salta para um determinado offset se o valor no topo da pilha é maior que zero.
 */
void ifgt()
{
    Frame *frame_atual = get_frame_atual();
    int32_t valor = pop_operando();
    uint8_t offset1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t offset2 = frame_atual->code[frame_atual->pc + 2];
    int16_t offset = concat16(offset1, offset2);

    if (valor > 0)
    {
        frame_atual->pc += offset;
    }
    else
    {
        atualiza_pc();
    }
}

/**
 * @brief Salta para um determinado offset se o valor no topo da pilha é menor ou igual a zero.
 */
void ifle()
{
    Frame *frame_atual = get_frame_atual();
    int32_t valor = pop_operando();
    uint8_t offset1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t offset2 = frame_atual->code[frame_atual->pc + 2];
    int16_t offset = concat16(offset1, offset2);

    if (valor <= 0)
    {
        frame_atual->pc += offset;
    }
    else
    {
        atualiza_pc();
    }
}

/**
 * @brief Salta para um determinado offset se os dois valores inteiros no topo da pilha são iguais.
 */
void if_icmpeq()
{
    Frame *frame_atual = get_frame_atual();
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();
    uint8_t offset1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t offset2 = frame_atual->code[frame_atual->pc + 2];
    int16_t offset = concat16(offset1, offset2);

    if (valor2 == valor1)
    {
        frame_atual->pc += offset;
    }
    else
    {
        atualiza_pc();
    }
}

/**
 * @brief Salta para um determinado offset se os dois valores inteiros no topo da pilha não são iguais.
 */
void if_icmpne()
{
    Frame *frame_atual = get_frame_atual();
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();
    uint8_t offset1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t offset2 = frame_atual->code[frame_atual->pc + 2];
    int16_t offset = concat16(offset1, offset2);

    if (valor2 != valor1)
    {
        frame_atual->pc += offset;
    }
    else
    {
        atualiza_pc();
    }
}

/**
 * @brief Salta para um determinado offset se o segundo valor inteiro no topo da pilha é menor que o primeiro.
 */
void if_icmplt()
{
    Frame *frame_atual = get_frame_atual();
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();
    uint8_t offset1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t offset2 = frame_atual->code[frame_atual->pc + 2];
    int16_t offset = concat16(offset1, offset2);

    if (valor2 < valor1)
    {
        frame_atual->pc += offset;
    }
    else
    {
        atualiza_pc();
    }
}

/**
 * @brief Salta para um determinado offset se o segundo valor inteiro no topo da pilha é maior ou igual ao primeiro.
 */
void if_icmpge()
{
    Frame *frame_atual = get_frame_atual();
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();
    uint8_t offset1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t offset2 = frame_atual->code[frame_atual->pc + 2];
    int16_t offset = concat16(offset1, offset2);

    if (valor2 >= valor1)
    {
        frame_atual->pc += offset;
    }
    else
    {
        atualiza_pc();
    }
}

/**
 * @brief Salta para um determinado offset se o segundo valor inteiro no topo da pilha é maior que o primeiro.
 */
void if_icmpgt()
{
    Frame *frame_atual = get_frame_atual();
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();
    uint8_t offset1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t offset2 = frame_atual->code[frame_atual->pc + 2];
    int16_t offset = concat16(offset1, offset2);

    if (valor2 > valor1)
    {
        frame_atual->pc += offset;
    }
    else
    {
        atualiza_pc();
    }
}

/**
 * @brief Salta para um determinado offset se o segundo valor inteiro no topo da pilha é menor ou igual ao primeiro.
 */
void if_icmple()
{
    Frame *frame_atual = get_frame_atual();
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();
    uint8_t offset1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t offset2 = frame_atual->code[frame_atual->pc + 2];
    int16_t offset = concat16(offset1, offset2);

    if (valor2 <= valor1)
    {
        frame_atual->pc += offset;
    }
    else
    {
        atualiza_pc();
    }
}

/**
 * @brief Salta para um determinado offset se os dois valores de referência no topo da pilha são iguais.
 */
void if_acmpeq()
{
    Frame *frame_atual = get_frame_atual();
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();
    uint8_t offset1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t offset2 = frame_atual->code[frame_atual->pc + 2];
    int16_t offset = concat16(offset1, offset2);

    if (valor2 == valor1)
    {
        frame_atual->pc += offset;
    }
    else
    {
        atualiza_pc();
    }
}

/**
 * @brief Salta para um determinado offset se os dois valores de referência no topo da pilha não são iguais.
 */
void if_acmpne()
{
    Frame *frame_atual = get_frame_atual();
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();
    uint8_t offset1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t offset2 = frame_atual->code[frame_atual->pc + 2];
    int16_t offset = concat16(offset1, offset2);

    if (valor2 != valor1)
    {
        frame_atual->pc += offset;
    }
    else
    {
        atualiza_pc();
    }
}

/**
 * @brief Realiza um salto incondicional para um determinado offset.
 */
void jvm_goto()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t offset1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t offset2 = frame_atual->code[frame_atual->pc + 2];
    int16_t offset = concat16(offset1, offset2);

    frame_atual->pc += offset;
}

/**
 * @brief Salta para um sub-rotina em um determinado offset e empurra o endereço de retorno para a pilha.
 */
void jsr()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t offset1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t offset2 = frame_atual->code[frame_atual->pc + 2];
    int16_t offset = concat16(offset1, offset2);

    push_operando(frame_atual->pc + 3);
    frame_atual->pc += offset;
}

/**
 * @brief Retorna de uma sub-rotina e continua a execução do endereço no topo da pilha.
 */
void ret()
{
    Frame *frame_atual = get_frame_atual();
    if (wide_instruction)
    {
        uint8_t byte1 = frame_atual->code[frame_atual->pc + 2];
        uint8_t byte2 = frame_atual->code[frame_atual->pc + 3];
        uint16_t indice = concat16(byte1, byte2);
        frame_atual->pc = frame_atual->fields[indice];
    }
    else
    {
        uint8_t indice = frame_atual->code[frame_atual->pc + 1];
        frame_atual->pc = frame_atual->fields[indice];
    }
}

/**
 * @brief Executa um salto baseado em uma chave de tabela de switch, salta para um endereço baseado no índice fornecido.
 */
void tableswitch()
{
    Frame *frame_atual = get_frame_atual();
    int32_t indice = pop_operando();
    uint32_t pc_aux = frame_atual->pc + ((4 - ((frame_atual->pc + 1) % 4)) % 4) + 1;
    int32_t default_v = 0;
    int32_t baixo = 0;
    int32_t alto = 0;
    bool definido = false;

    uint32_t pc_novo;
    int32_t qtd_offset, offset, posicao;

    for (int i = 0; i < 4; i++)
    {
        default_v = (default_v << 8) + frame_atual->code[pc_aux];
        pc_aux++;
    }

    for (int i = 0; i < 4; i++)
    {
        baixo = (baixo << 8) + frame_atual->code[pc_aux];
        pc_aux++;
    }

    if (indice < baixo && !definido)
    {
        definido = true;
        pc_novo = frame_atual->pc + default_v;
    }

    alto = 0;

    for (int i = 0; i < 4; i++)
    {
        alto = (alto << 8) + frame_atual->code[pc_aux];
        pc_aux++;
    }

    if (indice > alto && !definido)
    {
        definido = true;
        pc_novo = frame_atual->pc + default_v;
    }

    qtd_offset = 1 + alto - baixo;
    posicao = indice - baixo;
    for (int32_t i = 0; i < qtd_offset; i++)
    {
        if (i == posicao)
        {

            offset = 0;
            for (int j = 0; j < 4; j++)
            {
                offset = (offset << 8) + frame_atual->code[pc_aux];
                pc_aux++;
            }

            pc_novo = frame_atual->pc + offset;
            definido = true;

            break;
        }

        else
        {
            pc_aux += 4;
        }
    }

    frame_atual->pc = pc_novo;
}

/**
 * @brief Executa um salto baseado em uma chave de lookup switch, salta para um endereço específico ou padrão dependendo da chave fornecida.
 */
void lookupswitch()
{
    Frame *frame_atual = get_frame_atual();
    uint32_t pc_aux = frame_atual->pc + ((4 - ((frame_atual->pc + 1) % 4)) % 4) + 1;
    int32_t chave = pop_operando();
    int32_t default_v = 0;
    int32_t pares = 0;
    bool definido = false;

    uint32_t pc_novo;
    uint32_t offset;
    int32_t match;

    for (int i = 0; i < 4; i++)
    {
        default_v = (default_v << 8) + frame_atual->code[pc_aux];
        pc_aux++;
    }

    for (int i = 0; i < 4; i++)
    {
        pares = (pares << 8) + frame_atual->code[pc_aux];
        pc_aux++;
    }

    for (int32_t i = 0; i < pares; i++)
    {

        match = 0;
        for (int j = 0; j < 4; j++)
        {
            match = (match << 8) + frame_atual->code[pc_aux];
            pc_aux++;
        }

        if (chave == match)
        {

            offset = 0;
            for (int k = 0; k < 4; k++)
            {
                offset = (offset << 8) + frame_atual->code[pc_aux];
                pc_aux++;
            }

            pc_novo = frame_atual->pc + offset;

            definido = true;
        }

        else
        {

            for (int i = 0; i < 4; i++)
            {
                pc_aux++;
            }
        }
    }

    if (!definido)
    {
        pc_novo = frame_atual->pc + default_v;
    }

    frame_atual->pc = pc_novo;
}

/**
 * @brief Retorna um inteiro do método atual e o coloca no frame do chamador.
 */
void ireturn()
{
    Frame *frame_atual = get_frame_atual();

    if (pilha_frame->length > 1)
    {
        push_retorno(pop_operando());
    }

    frame_atual->pc = frame_atual->code_length;
}

/**
 * @brief Retorna um long do método atual e o coloca no frame do chamador.
 */
void lreturn()
{
    Frame *frame_atual = get_frame_atual();

    if (pilha_frame->length > 1)
    {
        int32_t menos_significativo = pop_operando();
        int32_t mais_significativo = pop_operando();

        push_retorno(mais_significativo);
        push_retorno(menos_significativo);
    }

    frame_atual->pc = frame_atual->code_length;
}

/**
 * @brief Retorna um float do método atual e o coloca no frame do chamador.
 */
void freturn()
{
    Frame *frame_atual = get_frame_atual();

    if (pilha_frame->length > 1)
    {
        push_retorno(pop_operando());
    }

    frame_atual->pc = frame_atual->code_length;
}

/**
 * @brief Retorna um double do método atual e o coloca no frame do chamador.
 */
void dreturn()
{
    Frame *frame_atual = get_frame_atual();

    if (pilha_frame->length > 1)
    {
        int32_t menos_significativo = pop_operando();
        int32_t mais_significativo = pop_operando();

        push_retorno(mais_significativo);
        push_retorno(menos_significativo);
    }

    frame_atual->pc = frame_atual->code_length;
}

/**
 * @brief Retorna uma referência do método atual e a coloca no frame do chamador.
 */
void areturn()
{
    Frame *frame_atual = get_frame_atual();

    if (pilha_frame->length > 1)
    {
        push_retorno(pop_operando());
    }

    frame_atual->pc = frame_atual->code_length;
}

/**
 * @brief Retorna do método atual sem retornar um valor.
 */
void jvm_return()
{
    Frame *frame_atual = get_frame_atual();
    frame_atual->pc = frame_atual->code_length;
}

/**
 * @brief Recupera um valor estático de uma classe específica e empurra para a pilha.
 */
void getstatic()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t byte1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t byte2 = frame_atual->code[frame_atual->pc + 2];
    uint16_t indice = concat16(byte1, byte2);
    uint16_t indice_classe = frame_atual->constant_pool[indice - 1].info.Fieldref.class_index;
    uint16_t indice_nome_tipo = frame_atual->constant_pool[indice - 1].info.Fieldref.name_and_type_index;
    char *nome_classe = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[indice_classe - 1].info.Class.name_index);
    char *nome_field = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[indice_nome_tipo - 1].info.NameAndType.name_index);
    char *descritor_field = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[indice_nome_tipo - 1].info.NameAndType.descriptor_index);

    if (!strcmp(nome_classe, "java/lang/System") && !strcmp(nome_field, "out") && !strcmp(descritor_field, "Ljava/io/PrintStream;"))
    {
        push_operando(0);
        atualiza_pc();
        return;
    }

    ClassFile *classe = carrega_classe(nome_classe);
    Campo *campo = campo_estatico_por_nome(classe, nome_field);

    if (descritor_field[0] == 'J' || descritor_field[0] == 'D')
    {
        push_operando(campo->valor1);
        push_operando(campo->valor2);
    }
    else
    {
        push_operando(campo->valor1);
    }

    atualiza_pc();
}


/**
 * @brief Armazena um valor estático em uma classe específica.
 */
void putstatic()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t byte1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t byte2 = frame_atual->code[frame_atual->pc + 2];
    uint16_t indice = concat16(byte1, byte2);
    uint16_t indice_classe = frame_atual->constant_pool[indice - 1].info.Fieldref.class_index;
    uint16_t indice_nome_tipo = frame_atual->constant_pool[indice - 1].info.Fieldref.name_and_type_index;
    char *nome_classe = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[indice_classe - 1].info.Class.name_index);
    char *nome_field = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[indice_nome_tipo - 1].info.NameAndType.name_index);
    char *descritor_field = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[indice_nome_tipo - 1].info.NameAndType.descriptor_index);
    ClassFile *classe = carrega_classe(nome_classe);

    if (descritor_field[0] == 'J' || descritor_field[0] == 'D')
    {
        int32_t valor2 = pop_operando();
        int32_t valor1 = pop_operando();
        Campo *campo = campo_estatico_por_nome(classe, nome_field);

        campo->valor1 = valor1;
        campo->valor2 = valor2;
    }
    else
    {
        int32_t valor1 = pop_operando();
        Campo *campo = campo_estatico_por_nome(classe, nome_field);

        campo->valor1 = valor1;
        campo->valor2 = 0;
    }

    atualiza_pc();
}

/**
 * @brief Recupera o campo de um objeto e empurra o valor para a pilha.
 */
void getfield()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t byte1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t byte2 = frame_atual->code[frame_atual->pc + 2];
    uint16_t indice = concat16(byte1, byte2);
    uint16_t indice_classe = frame_atual->constant_pool[indice - 1].info.Fieldref.class_index;
    uint16_t nome_tipo_indice = get_frame_atual()->constant_pool[indice - 1].info.Fieldref.name_and_type_index;

    char *nome = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[nome_tipo_indice - 1].info.NameAndType.name_index);
    char *tipo = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[nome_tipo_indice - 1].info.NameAndType.descriptor_index);

    Objeto *obj = (Objeto *)pop_operando();

    Campo *campo = campo_por_nome(obj, nome);

    if (tipo[0] == 'J' || tipo[0] == 'D')
    {
        push_operando(campo->valor1);
        push_operando(campo->valor2);
    }
    else
    {
        push_operando(campo->valor1);
    }

    atualiza_pc();
}

/**
 * @brief Define o valor de um campo em um objeto.
 */
void putfield()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t byte1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t byte2 = frame_atual->code[frame_atual->pc + 2];
    uint16_t indice = concat16(byte1, byte2);
    uint16_t indice_classe = frame_atual->constant_pool[indice - 1].info.Fieldref.class_index;
    uint16_t nome_tipo_indice = frame_atual->constant_pool[indice - 1].info.Fieldref.name_and_type_index;

    char *nome = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[nome_tipo_indice - 1].info.NameAndType.name_index);
    char *tipo = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[nome_tipo_indice - 1].info.NameAndType.descriptor_index);

    if (tipo[0] == 'J' || tipo[0] == 'D')
    {
        int32_t valor2 = pop_operando();
        int32_t valor1 = pop_operando();
        Objeto *obj = (Objeto *)pop_operando();
        Campo *campo = campo_por_nome(obj, nome);

        campo->valor1 = valor1;
        campo->valor2 = valor2;
    }
    else
    {
        int32_t valor1 = pop_operando();
        Objeto *obj = (Objeto *)pop_operando();
        Campo *campo = campo_por_nome(obj, nome);

        campo->valor1 = valor1;
        campo->valor2 = 0;
    }

    atualiza_pc();
}

/**
 * @brief Invoca um método de instância de um objeto.
 */
void invokevirtual()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t byte1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t byte2 = frame_atual->code[frame_atual->pc + 2];
    uint16_t indice_metodo = concat16(byte1, byte2);
    uint16_t indice_classe = frame_atual->constant_pool[indice_metodo - 1].info.Methodref.class_index;
    uint16_t indice_nome_tipo = frame_atual->constant_pool[indice_metodo - 1].info.Methodref.name_and_type_index;
    char *nome_classe = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[indice_classe - 1].info.Class.name_index);
    char *nome_metodo = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[indice_nome_tipo - 1].info.NameAndType.name_index);
    char *descritor_metodo = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[indice_nome_tipo - 1].info.NameAndType.descriptor_index);

    if (!strcmp(nome_classe, "java/io/PrintStream") && (!strcmp(nome_metodo, "println") || !strcmp(nome_metodo, "print")))
    {
        if (!strcmp(descritor_metodo, "()V"))
        {
            printf("\n");
        }
        else if (!strcmp(descritor_metodo, "(Z)V"))
        {
            bool valor = pop_operando();
            printf("%s%s", valor ? "true" : "false", !strcmp(nome_metodo, "println") ? "\n" : "");
        }
        else if (!strcmp(descritor_metodo, "(C)V"))
        {
            uint32_t valor = pop_operando();
            printf("%c%s", valor, !strcmp(nome_metodo, "println") ? "\n" : "");
        }
        else if (!strcmp(descritor_metodo, "(I)V"))
        {
            int32_t valor = pop_operando();
            printf("%d%s", valor, !strcmp(nome_metodo, "println") ? "\n" : "");
        }
        else if (!strcmp(descritor_metodo, "(J)V"))
        {
            int32_t valor2 = pop_operando();
            int32_t valor1 = pop_operando();
            int64_t valor = concat64(valor1, valor2);
            printf("%lld%s", valor, !strcmp(nome_metodo, "println") ? "\n" : "");
        }
        else if (!strcmp(descritor_metodo, "(F)V"))
        {
            int32_t valor_i = pop_operando();
            float valor_f;
            memcpy(&valor_f, &valor_i, sizeof(int32_t));
            printf("%f%s", valor_f, !strcmp(nome_metodo, "println") ? "\n" : "");
        }
        else if (!strcmp(descritor_metodo, "(D)V"))
        {
            int32_t valor2_i = pop_operando();
            int32_t valor1_i = pop_operando();
            int64_t valor_l = concat64(valor1_i, valor2_i);
            double valor_d;
            memcpy(&valor_d, &valor_l, sizeof(int64_t));
            printf("%lf%s", valor_d, !strcmp(nome_metodo, "println") ? "\n" : "");
        }
        else if (!strcmp(descritor_metodo, "(Ljava/lang/String;)V"))
        {
            char *valor = (char *)(intptr_t)pop_operando();
            printf("%s%s", valor, !strcmp(nome_metodo, "println") ? "\n" : "");
        }
        else
        {
            printf("ERRO: println nao implementada para tipo %s\n", descritor_metodo);
            exit(1);
        }

        pop_operando();
        atualiza_pc();
        return;
    }

    if (!strcmp(nome_classe, "java/lang/StringBuffer"))
    {
        if (!strcmp(nome_metodo, "append"))
        {
            if (!strcmp(descritor_metodo, "(Ljava/lang/String;)Ljava/lang/StringBuffer;"))
            {
                char *string = (char *)(intptr_t)pop_operando();
                if (!string_buffer)
                {
                    string_buffer = calloc(strlen(string), sizeof(char));
                    strcpy(string_buffer, string);
                }
                else
                {
                    char *temp = calloc(strlen(string_buffer), sizeof(char));
                    strcpy(temp, string_buffer);
                    string_buffer = realloc(string_buffer, (strlen(temp) + strlen(string)) * sizeof(char));
                    strcpy(string_buffer, string);
                    strcat(string_buffer, temp);
                }

                atualiza_pc();
                return;
            }
            else
            {
                printf("ERRO: StringBuffer.append nao implementada para descritor %s\n", descritor_metodo);
                exit(1);
            }
        }

        if (!strcmp(nome_metodo, "toString"))
        {
            pop_operando();
            char *temp = calloc(strlen(string_buffer), sizeof(char));
            strcpy(temp, string_buffer);
            push_operando((intptr_t)temp);
            string_buffer = NULL;
            atualiza_pc();
            return;
        }
    }

    ClassFile *classe = carrega_classe(nome_classe);
    MethodRef *metodo_ref = busca_metodo(classe, nome_metodo, descritor_metodo);

    if (metodo_ref == NULL)
    {
        printf("ERRO: Método não econtrado!\n");
        exit(1);
    }

    int32_t numero_parametros = get_numero_parametros(metodo_ref->classe, metodo_ref->metodo);
    int32_t *fields = calloc(sizeof(int32_t), numero_parametros + 1);

    for (int32_t i = 0; i <= numero_parametros; i++)
    {
        fields[i] = pop_operando();
    }

    push_frame(metodo_ref->classe->constant_pool, metodo_ref->metodo);
    frame_atual = get_frame_atual();

    for (int32_t i = 0; i <= numero_parametros; i++)
    {
        frame_atual->fields[i] = fields[numero_parametros - i];
    }

    executa_frame_atual();

    atualiza_pc();
    return;
}

/**
 * @brief Invoca um método especial de uma instância.
 */
void invokespecial()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t byte1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t byte2 = frame_atual->code[frame_atual->pc + 2];
    uint16_t indice_metodo = concat16(byte1, byte2);
    uint16_t indice_classe = frame_atual->constant_pool[indice_metodo - 1].info.Methodref.class_index;
    uint16_t indice_nome_tipo = frame_atual->constant_pool[indice_metodo - 1].info.Methodref.name_and_type_index;
    char *nome_classe = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[indice_classe - 1].info.Class.name_index);

    if (!strcmp(nome_classe, "java/lang/StringBuffer"))
    {
        pop_operando();
        atualiza_pc();
        return;
    }

    char *nome_metodo = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[indice_nome_tipo - 1].info.NameAndType.name_index);
    char *descritor_metodo = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[indice_nome_tipo - 1].info.NameAndType.descriptor_index);

    ClassFile *classe = carrega_classe(nome_classe);
    MethodRef *metodo_ref = busca_metodo(classe, nome_metodo, descritor_metodo);

    if (metodo_ref == NULL)
    {
        printf("ERRO: Método não econtrado!\n");
        exit(1);
    }

    int32_t numero_parametros = get_numero_parametros(metodo_ref->classe, metodo_ref->metodo);
    int32_t *fields = calloc(sizeof(int32_t), numero_parametros + 1);

    for (int32_t i = 0; i <= numero_parametros; i++)
    {
        fields[i] = pop_operando();
    }

    push_frame(metodo_ref->classe->constant_pool, metodo_ref->metodo);
    frame_atual = get_frame_atual();

    for (int32_t i = 0; i <= numero_parametros; i++)
    {
        frame_atual->fields[i] = fields[numero_parametros - i];
    }

    executa_frame_atual();

    atualiza_pc();
    return;
}

/**
 * @brief Invoca um método estático de uma classe.
 */
void invokestatic()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t byte1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t byte2 = frame_atual->code[frame_atual->pc + 2];
    uint16_t indice = concat16(byte1, byte2);
    uint16_t indice_classe = frame_atual->constant_pool[indice - 1].info.Methodref.class_index;
    uint16_t nome_tipo_indice = frame_atual->constant_pool[indice - 1].info.Methodref.name_and_type_index;
    char *nome_classe = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[indice_classe - 1].info.Class.name_index);
    char *nome_metodo = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[nome_tipo_indice - 1].info.NameAndType.name_index);
    char *descritor_metodo = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[nome_tipo_indice - 1].info.NameAndType.descriptor_index);

    if (!strcmp(nome_classe, "java/lang/Object") && !strcmp(nome_metodo, "registerNatives") && !strcmp(descritor_metodo, "()V"))
    {
        atualiza_pc();
        return;
    }

    ClassFile *classe = carrega_classe(nome_classe);
    MethodRef *metodo_ref = busca_metodo(classe, nome_metodo, descritor_metodo);

    if (metodo_ref == NULL)
    {
        printf("ERRO: Método não econtrado!\n");
        exit(1);
    }

    int32_t numero_parametros = get_numero_parametros(metodo_ref->classe, metodo_ref->metodo);
    int32_t *fields = calloc(sizeof(int32_t), numero_parametros);

    for (int32_t i = 0; i < numero_parametros; i++)
    {
        fields[i] = pop_operando();
    }

    push_frame(metodo_ref->classe->constant_pool, metodo_ref->metodo);
    frame_atual = get_frame_atual();

    for (int32_t i = 0; i < numero_parametros; i++)
    {
        frame_atual->fields[i] = fields[i];
    }

    executa_frame_atual();

    atualiza_pc();
    return;
}

/**
 * @brief Invoca um método de uma interface.
 */
void invokeinterface()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t byte1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t byte2 = frame_atual->code[frame_atual->pc + 2];
    uint16_t indice_metodo = concat16(byte1, byte2);
    uint16_t indice_classe = frame_atual->constant_pool[indice_metodo - 1].info.Methodref.class_index;
    uint16_t indice_nome_tipo = frame_atual->constant_pool[indice_metodo - 1].info.Methodref.name_and_type_index;
    char *nome_classe = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[indice_classe - 1].info.Class.name_index);
    char *nome_metodo = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[indice_nome_tipo - 1].info.NameAndType.name_index);
    char *descritor_metodo = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[indice_nome_tipo - 1].info.NameAndType.descriptor_index);
    ClassFile *classe = carrega_classe(nome_classe);
    MethodRef *metodo_interface_ref = busca_metodo(classe, nome_metodo, descritor_metodo);

    if (metodo_interface_ref == NULL)
    {
        printf("ERRO: Método não econtrado!\n");
        exit(1);
    }

    int32_t numero_parametros = get_numero_parametros(metodo_interface_ref->classe, metodo_interface_ref->metodo);
    int32_t *fields = calloc(sizeof(int32_t), numero_parametros + 1);

    for (int32_t i = 0; i <= numero_parametros; i++)
    {
        fields[i] = pop_operando();
    }

    Objeto *objeto = (Objeto *)(intptr_t)fields[numero_parametros];
    ClassFile *classe_objeto = objeto->classe;

    MethodRef *metodo_ref = busca_metodo(classe_objeto, nome_metodo, descritor_metodo);

    if (metodo_interface_ref == NULL)
    {
        printf("ERRO: Método não econtrado!\n");
        exit(1);
    }

    push_frame(metodo_ref->classe->constant_pool, metodo_ref->metodo);
    frame_atual = get_frame_atual();

    for (int32_t i = 0; i <= numero_parametros; i++)
    {
        frame_atual->fields[i] = fields[numero_parametros - i];
    }

    executa_frame_atual();

    atualiza_pc();
    return;
}

/**
 * @brief Cria uma nova instância de uma classe e empurra uma referência para ela na pilha.
 */
void jvm_new()
{
    Frame *frame_atual = get_frame_atual();
    uint16_t byte1 = frame_atual->code[frame_atual->pc + 1];
    uint16_t byte2 = frame_atual->code[frame_atual->pc + 2];
    uint16_t indice = concat16(byte1, byte2);
    char *nome_classe = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[indice - 1].info.Class.name_index);

    if (!strcmp(nome_classe, "java/lang/StringBuffer"))
    {
        push_operando(0);
        atualiza_pc();
        return;
    }

    ClassFile *classe = carrega_classe(nome_classe);
    Objeto *objeto = cria_objeto(classe);

    if (objeto == NULL)
    {
        printf("ERRO: Objeto não foi corretamente alocado\n");
    }

    push_operando((intptr_t)objeto);
    atualiza_pc();
}

/**
 * @brief Cria um novo array de primitivos e empurra uma referência para ele na pilha.
 */
void newarray()
{
    Frame *frame_atual = get_frame_atual();
    int32_t length = pop_operando();
    uint8_t tipo = frame_atual->code[frame_atual->pc + 1];
    int8_t bytes;

    switch (tipo)
    {
    case 11:
    case 7:
        bytes = 8;
        break;

    case 10:
    case 6:
    case 0:
        bytes = 4;
        break;

    case 9:
    case 5:
        bytes = 2;
        break;

    case 8:
    case 4:
        bytes = 1;
        break;
    }

    push_operando((intptr_t)cria_array(length, bytes, NULL));

    atualiza_pc();
}

/**
 * @brief Cria um novo array de referências e empurra uma referência para ele na pilha.
 */
void anewarray()
{

    Frame *frame_atual = get_frame_atual();
    int32_t length = pop_operando();
    uint8_t byte1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t byte2 = frame_atual->code[frame_atual->pc + 2];
    uint16_t indice_classe = concat16(byte1, byte2);
    uint16_t indice_nome = frame_atual->constant_pool[indice_classe - 1].info.Class.name_index;
    char *nome_classe = read_string_cp(frame_atual->constant_pool, indice_nome);

    push_operando((intptr_t)cria_array(length, 4, nome_classe));

    atualiza_pc();
}

/**
 * @brief Empurra o comprimento de um array na pilha.
 */
void arraylength()
{

    int32_t *array = (int32_t *)(intptr_t)pop_operando();
    int i = 0;

    for (uint32_t i = 0; i < lista_arrays.length; i++)
    {
        if (lista_arrays.arrays[i].array == array)
        {

            push_operando(lista_arrays.arrays[i].length);
            atualiza_pc();
            return;
        }
    }

    printf("ERRO: array nao encontrado\n");
    exit(1);
}

/**
 * @brief Atualiza o contador de programa (program counter - PC) e encerra a execução da função atual.
 */
void athrow()
{
    atualiza_pc();
}

/**
 * @brief Verifica se um objeto é de um determinado tipo e lança uma exceção se não for.
 */
void checkcast()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t byte1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t byte2 = frame_atual->code[frame_atual->pc + 2];
    uint16_t indice = concat16(byte1, byte2);

    Objeto *objeto = (Objeto *)(intptr_t)pop_operando();

    if (objeto == NULL)
    {
        printf("Objeto nulo!\n");
    }

    char *nome_classe_objeto = read_string_cp(objeto->classe->constant_pool, objeto->classe->constant_pool[objeto->classe->this_class].info.Class.name_index);
    char *nome_classe_cp = read_string_cp(frame_atual->constant_pool, indice);

    if (strcmp(nome_classe_objeto, nome_classe_cp) != 0)
    {
        printf("ERRO: checkcast inválido\n");
        exit(1);
    }

    push_operando((intptr_t)objeto);
    atualiza_pc();
}

/**
 * @brief Determina se um objeto é da instância de uma classe e empurra o resultado (1 ou 0) na pilha.
 */
void instanceof ()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t byte1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t byte2 = frame_atual->code[frame_atual->pc + 2];
    uint16_t indice = concat16(byte1, byte2);

    Objeto *objeto = (Objeto *)(intptr_t)pop_operando();

    if (objeto == NULL)
    {
        printf("Objeto nulo!\n");
    }

    char *nome_classe_objeto = read_string_cp(objeto->classe->constant_pool, objeto->classe->constant_pool[objeto->classe->this_class].info.Class.name_index);
    char *nome_classe_cp = read_string_cp(frame_atual->constant_pool, indice);

    if (strcmp(nome_classe_objeto, nome_classe_cp) == 0)
    {
        push_operando(1);
    }
    else
    {
        push_operando(0);
    }

    atualiza_pc();
}

void monitorenter()
{
    atualiza_pc();
}

void monitorexit()
{
    atualiza_pc();
}

/**
 * @brief Extensão para suportar instruções com larguras de operandos maiores.
 */
void wide()
{
    Frame *frame_atual = get_frame_atual();
    wide_instruction = true;
    instrucoes[frame_atual->pc + 1].exec();
    wide_instruction = false;
}


/**
 * @brief Cria um novo array multidimensional.
 */
void multianewarray()
{
    printf("ERRO: multianewarray nao implementado\n");
    exit(1);
}

/**
 * @brief Pula para um endereço se a referência no topo da pilha for nula.
 */
void ifnull()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t byte1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t byte2 = frame_atual->code[frame_atual->pc + 2];
    uint16_t offset = concat16(byte1, byte2);
    int32_t valor = pop_operando();

    if (valor == 0)
    {
        get_frame_atual()->pc += offset;
    }
    else
    {
        atualiza_pc();
    }
}

/**
 * @brief Pula para um endereço se a referência no topo da pilha não for nula.
 */
void ifnonnull()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t byte1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t byte2 = frame_atual->code[frame_atual->pc + 2];
    uint16_t offset = concat16(byte1, byte2);
    int32_t valor = pop_operando();

    if (valor != 0)
    {
        get_frame_atual()->pc += offset;
    }
    else
    {
        atualiza_pc();
    }
}

/**
 * @brief Executa um salto incondicional para um endereço longo (wide index).
 */
void goto_w()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t byte1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t byte2 = frame_atual->code[frame_atual->pc + 2];
    uint8_t byte3 = frame_atual->code[frame_atual->pc + 3];
    uint8_t byte4 = frame_atual->code[frame_atual->pc + 4];
    int32_t deslocamento;

    deslocamento = (byte1 & 0xFF) << 24;
    deslocamento |= (byte2 & 0xFF) << 16;
    deslocamento |= (byte3 & 0xFF) << 8;
    deslocamento |= (byte4 & 0xFF);

    frame_atual->pc += deslocamento;
}

/**
 * @brief Salta para uma sub-rotina em um endereço longo e empurra o endereço de retorno.
 */
void jsr_w()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t byte1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t byte2 = frame_atual->code[frame_atual->pc + 2];
    uint8_t byte3 = frame_atual->code[frame_atual->pc + 3];
    uint8_t byte4 = frame_atual->code[frame_atual->pc + 4];
    int32_t deslocamento;

    deslocamento = (byte1 & 0xFF) << 24;
    deslocamento |= (byte2 & 0xFF) << 16;
    deslocamento |= (byte3 & 0xFF) << 8;
    deslocamento |= (byte4 & 0xFF);

    push_operando(frame_atual->pc + 5);
    frame_atual->pc += deslocamento;
}