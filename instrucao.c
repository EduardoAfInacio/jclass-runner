#include "includes/instrucao.h"
#include "includes/frame.h"
#include "includes/utils.h"
#include "includes/area_metodos.h"
#include "includes/carregador.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdbool.h>

Instrucao instrucoes[NUM_INSTRUCOES];

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

void nop()
{
    atualiza_pc();
}

void aconst_null()
{
    push_operando(0);
    atualiza_pc();
}

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

void bipush()
{
    Frame *frame_atual = get_frame_atual();
    int32_t argumento = frame_atual->code[frame_atual->pc + 1];

    push_operando(argumento);

    atualiza_pc();
}

void sipush()
{
    Frame *frame_atual = get_frame_atual();
    int32_t byte1, byte2;

    byte1 = frame_atual->code[(frame_atual->pc + 1)];
    byte2 = frame_atual->code[(frame_atual->pc + 2)];

    push_operando((byte1 << 8) + byte2);
    atualiza_pc();
}

void ldc()
{
    Frame *frame_atual = get_frame_atual();
    uint32_t indice = frame_atual->code[frame_atual->pc + 1];
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
        push_operando((intptr_t) read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[indice - 1].info.String.string_index));
        break;

    default:
        printf("ERRO: ldc não implementada para tag %d\n", tag);
        exit(1);
        break;
    }

    atualiza_pc();
}

void ldc_w()
{
    Frame *frame_atual = get_frame_atual();
    uint32_t indice = concat16(frame_atual->code[frame_atual->pc + 1], frame_atual->code[frame_atual->pc + 2]);
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
        push_operando((intptr_t) read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[indice - 1].info.String.string_index));
        break;

    default:
        printf("ERRO: ldc_w não implementada para tag %d\n", tag);
        exit(1);
        break;
    }

    atualiza_pc();
}

void ldc2_w()
{
    Frame *frame_atual = get_frame_atual();

    uint32_t indice = concat16(frame_atual->code[frame_atual->pc + 1], frame_atual->code[frame_atual->pc + 2]);
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

void iload()
{
    ;
    Frame *frame_atual = get_frame_atual();
    int32_t indice = frame_atual->code[frame_atual->pc + 1];

    push_operando(frame_atual->fields[indice]);
    atualiza_pc();
}

void lload()
{
    Frame *frame_atual = get_frame_atual();

    int32_t indice = frame_atual->code[frame_atual->pc + 1];
    int32_t mais_significativos = frame_atual->fields[indice];
    int32_t menos_significativos = frame_atual->fields[indice + 1];

    push_operando(mais_significativos);
    push_operando(menos_significativos);

    atualiza_pc();
}

void fload()
{
    Frame *frame_atual = get_frame_atual();
    int32_t indice = frame_atual->code[get_frame_atual()->pc + 1];

    push_operando(frame_atual->fields[indice]);
    atualiza_pc();
}

void dload()
{
    Frame *frame_atual = get_frame_atual();
    int32_t indice = frame_atual->code[frame_atual->pc + 1];
    int32_t mais_significativos = frame_atual->fields[indice];
    int32_t menos_significativos = frame_atual->fields[indice + 1];

    push_operando(mais_significativos);
    push_operando(menos_significativos);

    atualiza_pc();
}

void aload()
{
    Frame *frame_atual = get_frame_atual();
    int32_t indice = frame_atual->code[frame_atual->pc + 1];

    push_operando(frame_atual->fields[indice]);
    atualiza_pc();
}

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
    int32_t mais_significativos = frame_atual->fields[0];
    int32_t menos_significativos = frame_atual->fields[1];

    push_operando(mais_significativos);
    push_operando(menos_significativos);

    atualiza_pc();
}

void lload_1()
{
    Frame *frame_atual = get_frame_atual();
    int32_t mais_significativos = frame_atual->fields[1];
    int32_t menos_significativos = frame_atual->fields[2];

    push_operando(mais_significativos);
    push_operando(menos_significativos);

    atualiza_pc();
}

void lload_2()
{
    Frame *frame_atual = get_frame_atual();
    int32_t mais_significativos = frame_atual->fields[2];
    int32_t menos_significativos = frame_atual->fields[3];

    push_operando(mais_significativos);
    push_operando(menos_significativos);

    atualiza_pc();
}

void lload_3()
{
    Frame *frame_atual = get_frame_atual();
    int32_t mais_significativos = frame_atual->fields[3];
    int32_t menos_significativos = frame_atual->fields[4];

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
    int32_t mais_significativos = frame_atual->fields[0];
    int32_t menos_significativos = frame_atual->fields[1];

    push_operando(mais_significativos);
    push_operando(menos_significativos);

    atualiza_pc();
}

void dload_1()
{
    Frame *frame_atual = get_frame_atual();
    int32_t mais_significativos = frame_atual->fields[1];
    int32_t menos_significativos = frame_atual->fields[2];

    push_operando(mais_significativos);
    push_operando(menos_significativos);

    atualiza_pc();
}

void dload_2()
{
    Frame *frame_atual = get_frame_atual();
    int32_t mais_significativos = frame_atual->fields[2];
    int32_t menos_significativos = frame_atual->fields[3];

    push_operando(mais_significativos);
    push_operando(menos_significativos);

    atualiza_pc();
}

void dload_3()
{
    Frame *frame_atual = get_frame_atual();
    int32_t mais_significativos = frame_atual->fields[3];
    int32_t menos_significativos = frame_atual->fields[4];

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
    push_operando(get_frame_atual()->fields[1]);
    atualiza_pc();
}

void aload_3()
{
    push_operando(get_frame_atual()->fields[1]);
    atualiza_pc();
}

void iaload()
{
    int32_t indice = pop_operando();
    int32_t *referencia = (int32_t *)(intptr_t)pop_operando();

    push_operando(referencia[indice]);
    atualiza_pc();
}

void laload()
{
    int32_t indice = pop_operando();
    int32_t *referencia = (int32_t *)(intptr_t)pop_operando();

    push_operando(referencia[indice]);
    push_operando(referencia[indice + 1]);
    atualiza_pc();
}

void faload()
{
    int32_t indice = pop_operando();
    int32_t *referencia = (int32_t *)(intptr_t)pop_operando();

    push_operando(referencia[indice]);
    atualiza_pc();
}

void daload()
{
    int32_t indice = pop_operando();
    int32_t *referencia = (int32_t *)(intptr_t)pop_operando();

    push_operando(referencia[indice]);
    push_operando(referencia[indice + 1]);
    atualiza_pc();
}

void aaload()
{

    int32_t indice = pop_operando();
    int32_t *referencia = (int32_t *)(intptr_t)pop_operando();

    push_operando(referencia[indice]);
    atualiza_pc();
}

void baload()
{
    int32_t indice = pop_operando();
    int8_t *referencia = (int8_t *)(intptr_t)pop_operando();

    push_operando(referencia[indice]);
    atualiza_pc();
}

void caload()
{
    int32_t indice = pop_operando();
    int16_t *referencia = (int16_t *)(intptr_t)pop_operando();

    push_operando(referencia[indice]);
    atualiza_pc();
}

void saload()
{

    int32_t indice = pop_operando();
    int16_t *referencia = (int16_t *)(intptr_t)pop_operando();

    push_operando(referencia[indice]);
    atualiza_pc();
}

void istore()
{
    Frame *frame_atual = get_frame_atual();
    int32_t indice = frame_atual->code[frame_atual->pc + 1];

    frame_atual->fields[indice] = pop_operando();
    atualiza_pc();
}

void lstore()
{
    Frame *frame_atual = get_frame_atual();
    int32_t indice = frame_atual->code[frame_atual->pc + 1];
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();

    frame_atual->fields[indice] = mais_significativos;
    frame_atual->fields[indice] = menos_significativos;

    atualiza_pc();
}

void fstore()
{

    Frame *frame_atual = get_frame_atual();
    int32_t indice = frame_atual->code[frame_atual->pc + 1];

    frame_atual->fields[indice] = pop_operando();
    atualiza_pc();
}

void dstore()
{
    Frame *frame_atual = get_frame_atual();
    int32_t indice = frame_atual->code[frame_atual->pc + 1];
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();

    frame_atual->fields[indice] = mais_significativos;
    frame_atual->fields[indice] = menos_significativos;

    atualiza_pc();
}

void astore()
{

    Frame *frame_atual = get_frame_atual();
    int32_t indice = frame_atual->code[frame_atual->pc + 1];

    frame_atual->fields[indice] = pop_operando();
    atualiza_pc();
}

void istore_0()
{

    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[0] = pop_operando();
    atualiza_pc();
}

void istore_1()
{
    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[1] = pop_operando();
    atualiza_pc();
}

void istore_2()
{
    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[2] = pop_operando();
    atualiza_pc();
}

void istore_3()
{
    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[3] = pop_operando();
    atualiza_pc();
}

void lstore_0()
{
    Frame *frame_atual = get_frame_atual();
    int32_t indice = frame_atual->code[frame_atual->pc + 1];
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();

    frame_atual->fields[0] = mais_significativos;
    frame_atual->fields[1] = menos_significativos;

    atualiza_pc();
}

void lstore_1()
{
    Frame *frame_atual = get_frame_atual();
    int32_t indice = frame_atual->code[frame_atual->pc + 1];
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();

    frame_atual->fields[1] = mais_significativos;
    frame_atual->fields[2] = menos_significativos;

    atualiza_pc();
}

void lstore_2()
{
    Frame *frame_atual = get_frame_atual();
    int32_t indice = frame_atual->code[frame_atual->pc + 1];
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();

    frame_atual->fields[2] = mais_significativos;
    frame_atual->fields[3] = menos_significativos;

    atualiza_pc();
}

void lstore_3()
{
    Frame *frame_atual = get_frame_atual();
    int32_t indice = frame_atual->code[frame_atual->pc + 1];
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();

    frame_atual->fields[3] = mais_significativos;
    frame_atual->fields[4] = menos_significativos;

    atualiza_pc();
}

void fstore_0()
{
    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[0] = pop_operando();
    atualiza_pc();
}

void fstore_1()
{
    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[1] = pop_operando();
    atualiza_pc();
}

void fstore_2()
{
    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[2] = pop_operando();
    atualiza_pc();
}

void fstore_3()
{
    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[3] = pop_operando();
    atualiza_pc();
}

void dstore_0()
{
    Frame *frame_atual = get_frame_atual();
    int32_t indice = frame_atual->code[frame_atual->pc + 1];
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();

    frame_atual->fields[0] = mais_significativos;
    frame_atual->fields[1] = menos_significativos;

    atualiza_pc();
}

void dstore_1()
{
    Frame *frame_atual = get_frame_atual();
    int32_t indice = frame_atual->code[frame_atual->pc + 1];
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();

    frame_atual->fields[1] = mais_significativos;
    frame_atual->fields[2] = menos_significativos;

    atualiza_pc();
}

void dstore_2()
{
    Frame *frame_atual = get_frame_atual();
    int32_t indice = frame_atual->code[frame_atual->pc + 1];
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();

    frame_atual->fields[2] = mais_significativos;
    frame_atual->fields[3] = menos_significativos;

    atualiza_pc();
}

void dstore_3()
{
    Frame *frame_atual = get_frame_atual();
    int32_t indice = frame_atual->code[frame_atual->pc + 1];
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();

    frame_atual->fields[3] = mais_significativos;
    frame_atual->fields[4] = menos_significativos;

    atualiza_pc();
}

void astore_0()
{
    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[0] = pop_operando();
    atualiza_pc();
}

void astore_1()
{
    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[1] = pop_operando();
    atualiza_pc();
}

void astore_2()
{
    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[2] = pop_operando();
    atualiza_pc();
}

void astore_3()
{
    Frame *frame_atual = get_frame_atual();

    frame_atual->fields[3] = pop_operando();
    atualiza_pc();
}

void iastore()
{
    int32_t valor = pop_operando();
    int32_t indice = pop_operando();
    int32_t *referencia = (int32_t *)(intptr_t)pop_operando();

    referencia[indice] = valor;
    atualiza_pc();
}

void lastore()
{
    Frame *frame_atual = get_frame_atual();
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();
    int32_t indice = pop_operando();
    int32_t *referencia = (int32_t *)(intptr_t)pop_operando();

    referencia[indice] = mais_significativos;
    referencia[indice + 1] = menos_significativos;

    atualiza_pc();
}

void fastore()
{
    int32_t valor = pop_operando();
    int32_t indice = pop_operando();
    int32_t *referencia = (int32_t *)(intptr_t)pop_operando();

    referencia[indice] = valor;
    atualiza_pc();
}

void dastore()
{
    Frame *frame_atual = get_frame_atual();
    int32_t menos_significativos = pop_operando();
    int32_t mais_significativos = pop_operando();
    int32_t indice = pop_operando();
    int32_t *referencia = (int32_t *)(intptr_t)pop_operando();

    referencia[indice] = mais_significativos;
    referencia[indice + 1] = menos_significativos;

    atualiza_pc();
}

void aastore()
{
    int32_t valor = pop_operando();
    int32_t indice = pop_operando();
    int32_t *referencia = (int32_t *)(intptr_t)pop_operando();

    referencia[indice] = valor;
    atualiza_pc();
}

void bastore()
{
    int8_t valor = pop_operando();
    int32_t indice = pop_operando();
    int8_t *referencia = (int8_t *)(intptr_t)pop_operando();

    referencia[indice] = valor;
    atualiza_pc();
}

void castore()
{

    int16_t valor = pop_operando();
    int32_t indice = pop_operando();
    int16_t *referencia = (int16_t *)(intptr_t)pop_operando();

    referencia[indice] = valor;
    atualiza_pc();
}

void sastore()
{

    int16_t valor = pop_operando();
    int32_t indice = pop_operando();
    int16_t *referencia = (int16_t *)(intptr_t)pop_operando();

    referencia[indice] = valor;
    atualiza_pc();
}

void pop()
{
    pop_operando();

    atualiza_pc();
}

void pop2()
{

    pop_operando();
    pop_operando();

    atualiza_pc();
}

void dup()
{
    int32_t valor = pop_operando();

    push_operando(valor);
    push_operando(valor);
    atualiza_pc();
}

void dup_x1()
{
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    push_operando(valor1);

    push_operando(valor2);

    push_operando(valor1);

    atualiza_pc();
}

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

void swap()
{
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    push_operando(valor1);
    push_operando(valor2);

    atualiza_pc();
}

void iadd()
{
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    push_operando(valor2 + valor1);

    atualiza_pc();
}

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

void isub()
{
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    push_operando(valor2 - valor1);

    atualiza_pc();
}

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

void imul()
{
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    push_operando(valor2 * valor1);

    atualiza_pc();
}

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

void idiv()
{
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    push_operando(valor2 / valor1);

    atualiza_pc();
}

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

void irem()
{
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    push_operando(valor2 % valor1);
    atualiza_pc();
}

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

void ineg()
{
    int32_t valor = pop_operando();
    push_operando(-valor);
    atualiza_pc();
}

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

void ishl()
{
    int32_t shift = pop_operando() & 0x1f;
    int32_t valor = pop_operando();

    push_operando(valor << shift);
    atualiza_pc();
}

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

void ishr()
{
    int32_t shift = pop_operando() & 0x1f;
    int32_t valor = pop_operando();

    push_operando(valor >> shift);
    atualiza_pc();
}

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

void iushr()
{

    int32_t shift = pop_operando() & 0x1f;
    uint32_t valor = pop_operando();

    push_operando(valor >> shift);
    atualiza_pc();
}

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

void iand()
{
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    push_operando(valor2 % valor1);
    atualiza_pc();
}

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

void ior()
{
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    push_operando(valor2 | valor1);
    atualiza_pc();
}

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

void ixor()
{
    int32_t valor1 = pop_operando();
    int32_t valor2 = pop_operando();

    push_operando(valor2 ^ valor1);
    atualiza_pc();
}

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

void iinc()
{
    Frame *frame_atual = get_frame_atual();
    int8_t indice = frame_atual->code[frame_atual->pc + 1];
    int8_t constante = frame_atual->code[frame_atual->pc + 2];

    frame_atual->fields[indice] += constante;
    atualiza_pc();
}

void i2l()
{
    int32_t valor = pop_operando();
    int64_t valor_l = valor;

    Wide wide = divide_64(valor_l);

    push_operando(wide.mais_significativo);
    push_operando(wide.menos_significativo);

    atualiza_pc();
}

void i2f()
{
    int32_t valor = pop_operando();
    float valor_f = valor;
    int32_t valor_i;

    memcpy(&valor_i, &valor_f, sizeof(int32_t));

    push_operando(valor_i);
    atualiza_pc();
}

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

void l2i()
{
    int32_t menos_significativo = pop_operando();
    int32_t mais_significativo = pop_operando();

    push_operando(menos_significativo);
    atualiza_pc();
}

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

void f2i()
{
    int32_t valor = pop_operando();
    float valor_f;

    memcpy(&valor_f, &valor, sizeof(int32_t));

    int32_t valor_i = valor_f;

    push_operando(valor_i);
    atualiza_pc();
}

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

void i2b()
{
    int32_t valor = pop_operando();
    int8_t valor_b = valor;

    push_operando(valor_b);

    atualiza_pc();
}

void i2c()
{
    int32_t valor = pop_operando();
    int16_t valor_c = valor;

    push_operando(valor_c);

    atualiza_pc();
}

void i2s()
{
    int32_t valor = pop_operando();
    int16_t valor_c = valor;

    push_operando(valor_c);

    atualiza_pc();
}

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

void jvm_goto()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t offset1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t offset2 = frame_atual->code[frame_atual->pc + 2];
    int16_t offset = concat16(offset1, offset2);

    frame_atual->pc += offset;
}

void jsr()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t offset1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t offset2 = frame_atual->code[frame_atual->pc + 2];
    int16_t offset = concat16(offset1, offset2);

    push_operando(frame_atual->pc + 3);
    frame_atual->pc += offset;
}

void ret()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t indice = frame_atual->code[frame_atual->pc + 1];
    frame_atual->pc = frame_atual->fields[indice];
}

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

void lookupswitch()
{
    Frame *frame_atual = get_frame_atual();
    uint32_t pc_aux = frame_atual->pc + ((4 - ((pc_aux + 1) % 4)) % 4) + 1;
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

void ireturn()
{
    Frame *frame_atual = get_frame_atual();

    if (pilha_frame->length > 1)
    {
        push_retorno(pop_operando());
    }

    frame_atual->pc = frame_atual->code_length;
}

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

void freturn()
{
    Frame *frame_atual = get_frame_atual();

    if (pilha_frame->length > 1)
    {
        push_retorno(pop_operando());
    }

    frame_atual->pc = frame_atual->code_length;
}

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

void areturn()
{
    Frame *frame_atual = get_frame_atual();

    if (pilha_frame->length > 1)
    {
        push_retorno(pop_operando());
    }

    frame_atual->pc = frame_atual->code_length;
}

void jvm_return()
{
    Frame *frame_atual = get_frame_atual();
    frame_atual->pc = frame_atual->code_length;
}

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
        free(nome_classe);
        free(nome_field);
        free(descritor_field);
        push_operando(0);
        atualiza_pc();
        return;
    }

    printf("ERRO: getstatic não implementada\n");
    exit(1);
}

void putstatic()
{
    printf("ERRO: putstatic não implementada\n");
    exit(1);
}

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

    free(nome);
    free(tipo);
    atualiza_pc();
}

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

    free(nome);
    free(tipo);
    atualiza_pc();
}

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
        if (!strcmp(descritor_metodo, "(Z)V"))
        {
            bool valor = pop_operando(); 
            printf("%s%s", valor ? "true" : "false", !strcmp(nome_metodo, "println") ? "\n" : "");
        }
        else if(!strcmp(descritor_metodo, "(C)V"))
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
            char *valor = (char*)(intptr_t)pop_operando();
            printf("%s%s", valor, !strcmp(nome_metodo, "println") ? "\n" : "");
        }
        else
        {
            printf("ERRO: println nao implementada para tipo %s\n", descritor_metodo);
            exit(1);
        }

        free(nome_classe);
        free(nome_metodo);
        free(descritor_metodo);  
        pop_operando();
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

    free(fields);
    free(metodo_ref);
    free(nome_classe);
    free(nome_metodo);
    free(descritor_metodo);
    atualiza_pc();
    return;
}

void invokespecial()
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

    free(fields);
    free(metodo_ref);
    free(nome_classe);
    free(nome_metodo);
    free(descritor_metodo);
    atualiza_pc();
    return;
}

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

    free(fields);
    free(metodo_ref);
    free(nome_classe);
    free(nome_metodo);
    free(descritor_metodo);
    atualiza_pc();
    return;
}

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

    Objeto *objeto = (Objeto*)(intptr_t) fields[numero_parametros];
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

    free(fields);
    free(metodo_interface_ref);
    free(metodo_ref);
    free(nome_classe);
    free(nome_metodo);
    free(descritor_metodo);
    atualiza_pc();
    return;
}

void jvm_new()
{
    Frame *frame_atual = get_frame_atual();
    uint16_t byte1 = frame_atual->code[frame_atual->pc + 1];
    uint16_t byte2 = frame_atual->code[frame_atual->pc + 2];
    uint32_t indice = concat16(byte1, byte2);
    char *nome_classe = read_string_cp(frame_atual->constant_pool, frame_atual->constant_pool[indice - 1].info.Class.name_index);
    ClassFile *classe = carrega_classe(nome_classe);
    Objeto *objeto = cria_objeto(classe);

    if (objeto == NULL)
    {
        printf("ERRO: Objeto não foi corretamente alocado\n");
    }

    push_operando((intptr_t)objeto);
    free(nome_classe);
    atualiza_pc();
}

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

void athrow()
{
    atualiza_pc();
}

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

    free(nome_classe_objeto);
    free(nome_classe_cp);
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

void wide()
{
}

void multianewarray()
{
    Frame *frame_atual = get_frame_atual();
    uint8_t byte1 = frame_atual->code[frame_atual->pc + 1];
    uint8_t byte2 = frame_atual->code[frame_atual->pc + 2];
    uint8_t dimensoes = frame_atual->code[frame_atual->pc + 3];
    uint16_t indice_classe = concat16(byte1, byte2);
    uint16_t indice_nome_classe = frame_atual->constant_pool[indice_classe - 1].info.Class.name_index;
    char *nome_classe = read_string_cp(frame_atual->constant_pool, indice_nome_classe);

    char* type_value = NULL;
    int i = 0;
    while (nome_classe[i] == '[')
        i++;
    char *nome_classe_limpo = calloc(strlen(nome_classe) - (i + 2), sizeof(char));
    
    for (int j = i; j < strlen(nome_classe); j++)
    {
        nome_classe_limpo[j - i] = nome_classe[j - i];
    }

    if (nome_classe[i] == 'L')
    {
        if (strcmp(nome_classe_limpo, "java/lang/String"))
        {
            carrega_classe(nome_classe_limpo);
        }
        
        type_value = nome_classe_limpo;
    }
}

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