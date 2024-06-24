/**
 * @file leitor.c
 * @brief Implementa as funções de leitura de arquivos de classe Java (.class).
 * Este arquivo é responsável por ler e decodificar os dados binários de um arquivo .class,
 * construindo uma representação em memória da classe, incluindo métodos, campos, constant pool,
 * e outras estruturas internas.
 */

#include "./includes/leitor.h"

#include <stdlib.h>
#include <string.h>

#include "./includes/exibidor.h"

/**
 * @brief Lê e processa um arquivo .class, construindo a estrutura de dados ClassFile.
 * @param nomeClass Nome do arquivo .class a ser lido.
 * @return Ponteiro para a estrutura ClassFile carregada, ou NULL em caso de falha na abertura do arquivo.
 */
ClassFile* class_reader(char* nomeClass) {
  FILE* file;
  file = fopen(nomeClass, "rb");

  if (file == NULL) {
    return 0;
  }

  ClassFile* classfile = NULL;

  classfile = (ClassFile*)calloc(sizeof(ClassFile), 1);

  if (classfile == NULL) printf("taNULL");

  general_info(classfile, file);

  constant_pool(classfile, file);

  secondGeneralInfo(classfile, file);

  fclose(file);

  return classfile;
}

/**
 * @brief Lê e armazena as informações gerais do arquivo .class no objeto ClassFile.
 * @param classfile Estrutura de dados onde as informações serão armazenadas.
 * @param file Ponteiro para o arquivo .class aberto.
 */
void general_info(ClassFile* classfile, FILE* file) {
  classfile->magic = read_four_bytes(file);
  if (classfile->magic != 0xCAFEBABE) {
    printf("Arquivo .class inválido!!\n\n");
    exit(0);
  }
  classfile->minor_version = read_two_bytes(file);
  classfile->major_version = read_two_bytes(file);
  classfile->constant_pool_count = read_two_bytes(file);
}


/**
 * @brief Lê o pool de constantes de um arquivo .class e armazena no objeto ClassFile.
 * @param classfile Estrutura de dados onde o pool de constantes será armazenado.
 * @param file Ponteiro para o arquivo .class aberto.
 */
void constant_pool(ClassFile* classfile, FILE* file) {
  classfile->constant_pool =
      (ConstantPool*)malloc((classfile->constant_pool_count - 1) * sizeof(ConstantPool));
  ConstantPool* cp;

  int i = 0;
  for (cp = classfile->constant_pool; i < (classfile->constant_pool_count - 1); cp++) {
    cp->tag = read_one_byte(file);
    switch (cp->tag) {
      case CONSTANT_Class:
        cp->info.Class.name_index = read_two_bytes(file);
        break;
      case CONSTANT_Fieldref:
        cp->info.Fieldref.class_index = read_two_bytes(file);
        cp->info.Fieldref.name_and_type_index = read_two_bytes(file);
        break;
      case CONSTANT_NameAndType:
        cp->info.NameAndType.name_index = read_two_bytes(file);
        cp->info.NameAndType.descriptor_index = read_two_bytes(file);
        break;
      case CONSTANT_Utf8:
        cp->info.Utf8.length = read_two_bytes(file);
        cp->info.Utf8.bytes =
            (uint8_t*)calloc((cp->info.Utf8.length) + 1, sizeof(uint8_t));
        fread(cp->info.Utf8.bytes, 1, cp->info.Utf8.length, file);
        cp->info.Utf8.bytes[cp->info.Utf8.length] = '\0';
        break;
      case CONSTANT_Methodref:
        cp->info.Methodref.class_index = read_two_bytes(file);
        cp->info.Methodref.name_and_type_index = read_two_bytes(file);
        break;
      case CONSTANT_InterfaceMethodref:
        cp->info.InterfaceMethodref.class_index = read_two_bytes(file);
        cp->info.InterfaceMethodref.name_and_type_index = read_two_bytes(file);
        break;
      case CONSTANT_String:
        cp->info.String.string_index = read_two_bytes(file);
        break;
      case CONSTANT_Integer:
        cp->info.Integer.bytes = read_four_bytes(file);
        break;
      case CONSTANT_Float:
        cp->info.Float.bytes = read_four_bytes(file);
        break;
      case CONSTANT_Double:
        cp->info.Double.high_bytes = read_four_bytes(file);
        cp->info.Double.low_bytes = read_four_bytes(file);
        cp++;
        i++;
        break;
      case CONSTANT_Long:
        cp->info.Long.high_bytes = read_four_bytes(file);
        cp->info.Long.low_bytes = read_four_bytes(file);
        cp++;
        i++;
        break;
      default:
        break;
    }
    i++;
  }
}

/**
 * @brief Lê informações sobre interfaces do arquivo .class.
 * @param classfile Estrutura de dados ClassFile onde as interfaces serão armazenadas.
 * @param file Ponteiro para o arquivo .class aberto.
 * @param interfaces_count Número de interfaces a serem lidas.
 */
void interfaceInfo(ClassFile* classfile, FILE* file, uint16_t interfaces_count) {
  if (interfaces_count == 0)
    return;
  else {
    classfile->interfaces = (uint16_t*)malloc((interfaces_count) * sizeof(uint16_t));

    for (int i = 0; i < interfaces_count; i++) {
      classfile->interfaces[i] = read_two_bytes(file);
    }
  }
}


/**
 * @brief Lê informações sobre os campos de um arquivo .class e os armazena na estrutura ClassFile.
 * @param classfile Estrutura de dados ClassFile onde os campos serão armazenados.
 * @param file Ponteiro para o arquivo .class aberto.
 * @param fields_count Número de campos a serem lidos.
 */
void fieldInfo(ClassFile* classfile, FILE* file, uint16_t fields_count) {
  if (fields_count == 0)
    return;
  else {
    classfile->fields = (Field*)malloc(fields_count * sizeof(Field));

    for (int i = 0; i < fields_count; i++) {
      classfile->fields[i].access_flags = read_two_bytes(file);
      classfile->fields[i].name_index = read_two_bytes(file);
      classfile->fields[i].descriptor_index = read_two_bytes(file);

      classfile->fields[i].attributes_count = read_two_bytes(file);

      classfile->fields[i].attributes =
          (ConstantValue*)malloc(classfile->fields[i].attributes_count * sizeof(ConstantValue));

      for (int j = 0; j < classfile->fields[i].attributes_count; j++) {
        classfile->fields[i].attributes->name_index = read_two_bytes(file);
        classfile->fields[i].attributes->length = read_four_bytes(file);

        classfile->fields[i].attributes->index = read_two_bytes(file);
      }
    }
  }
}

/**
 * @brief Lê informações sobre métodos de um arquivo .class e os armazena na estrutura ClassFile.
 * @param classfile Estrutura de dados ClassFile onde os métodos serão armazenados.
 * @param file Ponteiro para o arquivo .class aberto.
 * @param methods_count Número de métodos a serem lidos.
 */
void methodInfo(ClassFile* classfile, FILE* file, uint16_t methods_count) {
  uint16_t name_ind;
  uint32_t att_len;

  if (methods_count == 0)
    return;
  else {
    classfile->methods = (Method*)malloc(methods_count * sizeof(Method));
    Method* cp = classfile->methods;
    for (int i = 0; i < methods_count; cp++) {
      cp->access_flags = read_two_bytes(file);

      if (cp->access_flags == 0x010a || cp->access_flags == 0x0101 ||
          cp->access_flags == 0x0111) {
        cp->name_index = read_two_bytes(file);
        cp->descriptor_index = read_two_bytes(file);
        cp->attributes_count = read_two_bytes(file);

        i++;
        for (int j = 0; j < cp->attributes_count; j++) {
          int64_t temp, temp2;

          temp = read_two_bytes(file);

          temp = read_four_bytes(file);

          for (int k = 0; k < temp; k++) {
            temp2 = read_one_byte(file);
          }
        }
        continue;
      }

      cp->name_index = read_two_bytes(file);
      cp->descriptor_index = read_two_bytes(file);
      cp->attributes_count = read_two_bytes(file);
      for (int j = 0; j < cp->attributes_count; j++) {
        name_ind = read_two_bytes(file);
        att_len = read_four_bytes(file);

        if (strcmp((char*)classfile->constant_pool[name_ind - 1].info.Utf8.bytes,
                   "Code") == 0) {
          cp->code_attribute = (CodeAttribute*)malloc(sizeof(CodeAttribute));

          read_code(&(cp->code_attribute), name_ind, att_len, file);
        }

        else if (strcmp((char*)classfile->constant_pool[name_ind - 1].info.Utf8.bytes,
                        "Exceptions") == 0) {
          cp->exception_attribute =
              (ExceptionAttribute*)malloc(sizeof(ExceptionAttribute));

          read_exc(&(cp->exception_attribute), name_ind, att_len, file);
        }
      }
      i++;
    }
  }
}

/**
 * @brief Lê um atributo de exceção de um arquivo .class.
 * @param exc_atrb Ponteiro para o atributo de exceção que será lido.
 * @param name_ind Índice do nome do atributo no pool de constantes.
 * @param att_len Comprimento do atributo de exceção.
 * @param file Ponteiro para o arquivo .class aberto.
 */
void read_exc(ExceptionAttribute** exc_atrb, uint16_t name_ind, uint32_t att_len, FILE* file) {
  (*exc_atrb)->name_index = name_ind;
  (*exc_atrb)->length = att_len;

  (*exc_atrb)->number_of_exceptions = read_two_bytes(file);

  (*exc_atrb)->exception_index_table = (uint16_t*)malloc(
      (*exc_atrb)->number_of_exceptions * sizeof(ExceptionTable));

  for (int k = 0; k < (*exc_atrb)->number_of_exceptions; k++) {
    (*exc_atrb)->exception_index_table[k] = read_two_bytes(file);
  }
}

/**
 * @brief Lê um atributo de código de um arquivo .class.
 * @param cd_atrb Ponteiro para o atributo de código que será lido.
 * @param name_ind Índice do nome do atributo no pool de constantes.
 * @param att_len Comprimento do atributo de código.
 * @param file Ponteiro para o arquivo .class aberto.
 */
void read_code(CodeAttribute** cd_atrb, uint16_t name_ind, uint32_t att_len, FILE* file) {
  int posicao_inicial = ftell(file);

  (*cd_atrb)->name_index = name_ind;
  (*cd_atrb)->length = att_len;

  (*cd_atrb)->max_stack = read_two_bytes(file);
  (*cd_atrb)->max_locals = read_two_bytes(file);
  (*cd_atrb)->code_length = read_four_bytes(file);

  save_instructions(cd_atrb, file);

  (*cd_atrb)->exception_table_length = read_two_bytes(file);

  (*cd_atrb)->exception_table = (ExceptionTable*)malloc(
      (*cd_atrb)->exception_table_length * sizeof(ExceptionTable));

  for (int k = 0; k < (*cd_atrb)->exception_table_length; k++) {
    (*cd_atrb)->exception_table[k].start_pc = read_two_bytes(file);
    (*cd_atrb)->exception_table[k].end_pc = read_two_bytes(file);
    (*cd_atrb)->exception_table[k].catch_type = read_two_bytes(file);
  }

  (*cd_atrb)->attributes_count = read_two_bytes(file);

  (*cd_atrb)->attributes = (Attribute*)malloc(
      (*cd_atrb)->attributes_count * sizeof(Attribute));

  while (ftell(file) - posicao_inicial <
         (int32_t)((*cd_atrb)->length)) {
    read_one_byte(file);
  }
}

/**
 * @brief Salva as instruções de bytecode de um atributo de código.
 * @param cd_atrb Ponteiro para o atributo de código que contém as instruções a serem salvas.
 * @param file Ponteiro para o arquivo .class aberto.
 */
void save_instructions(CodeAttribute** cd_atrb, FILE* file) {
  int opcode, pos_referencia;
  int bytes_preench, offsets;
  uint32_t default_v, low, high, npairs;

  (*cd_atrb)->code =
      (uint8_t*)malloc((*cd_atrb)->code_length * sizeof(uint8_t));

  for (uint32_t k = 0; k < (*cd_atrb)->code_length;) {
    fread(&((*cd_atrb)->code[k]), 1, 1, file);

    opcode = (*cd_atrb)->code[k];
    k++;

    if (opcode == TABLESWITCH) {
      pos_referencia = k - 1;

      bytes_preench = (4 - (k % 4)) % 4;
      for (int l = 0; l < bytes_preench; l++) {
        k++;
        fread(&((*cd_atrb)->code[k]), 1, 1, file);
      }

      default_v = 0;
      for (int l = 0; l < 4; l++) {
        fread(&((*cd_atrb)->code[k]), 1, 1, file);
        default_v = (default_v << 8) + (*cd_atrb)->code[k];
        k++;
      }

      low = 0;
      for (int l = 0; l < 4; l++) {
        fread(&((*cd_atrb)->code[k]), 1, 1, file);
        low = (low << 8) + (*cd_atrb)->code[k];
        k++;
      }

      high = 0;
      for (int l = 0; l < 4; l++) {
        fread(&((*cd_atrb)->code[k]), 1, 1, file);
        high = (high << 8) + (*cd_atrb)->code[k];
        k++;
      }

      offsets = 1 + high - low;
      for (int l = 0; l < offsets; l++) {
        for (int i = 0; i < 4; i++) {
          fread(&((*cd_atrb)->code[k]), 1, 1, file);
          k++;
        }
      }
    }

    else if (opcode == LOOKUPSWITCH) {
      pos_referencia = k - 1;

      bytes_preench = (4 - (k % 4)) % 4;
      for (int l = 0; l < bytes_preench; l++) {
        k++;
        fread(&((*cd_atrb)->code[k]), 1, 1, file);
      }

      default_v = 0;
      for (int l = 0; l < 4; l++) {
        fread(&((*cd_atrb)->code[k]), 1, 1, file);
        default_v = (default_v << 8) + (*cd_atrb)->code[k];
        k++;
      }

      npairs = 0;
      for (int l = 0; l < 4; l++) {
        fread(&((*cd_atrb)->code[k]), 1, 1, file);
        npairs = (npairs << 8) + (*cd_atrb)->code[k];
        k++;
      }

      for (uint32_t l = 0; l < npairs; l++) {
        for (int i = 0; i < 4; i++) {
          fread(&((*cd_atrb)->code[k]), 1, 1, file);
          k++;
        }

        for (int i = 0; i < 4; i++) {
          fread(&((*cd_atrb)->code[k]), 1, 1, file);
          k++;
        }
      }

    }

    else if (opcode == WIDE) {
      fread(&((*cd_atrb)->code[k]), 1, 1, file);
      opcode = (*cd_atrb)->code[k];
      k++;

      if (opcode == ILOAD || opcode == FLOAD || opcode == ALOAD ||
          opcode == LLOAD || opcode == DLOAD || opcode == ISTORE ||
          opcode == FSTORE || opcode == ASTORE || opcode == LSTORE ||
          opcode == DSTORE || opcode == RET) {
        fread(&((*cd_atrb)->code[k]), 1, 1, file);
        k++;

        fread(&((*cd_atrb)->code[k]), 1, 1, file);
        k++;

      }

      else if (opcode == IINC) {
        fread(&((*cd_atrb)->code[k]), 1, 1, file);
        k++;

        fread(&((*cd_atrb)->code[k]), 1, 1, file);
        k++;

        fread(&((*cd_atrb)->code[k]), 1, 1, file);
        k++;

        fread(&((*cd_atrb)->code[k]), 1, 1, file);
        k++;

      }

      else {
        printf("arquivo .class invalido na instrucao wide");
        exit(1);
      }
    }

    else {
      int num_bytes = instrucoes[opcode].bytes;
      for (int l = 0; l < num_bytes; l++) {
        fread(&((*cd_atrb)->code[k]), 1, 1, file);

        k++;
      }
    }
  }
}

/**
 * @brief Lê informações de atributos adicionais de um arquivo .class.
 * @param classfile Estrutura de dados ClassFile onde os atributos serão armazenados.
 * @param file Ponteiro para o arquivo .class aberto.
 * @param attributes_count Número de atributos a serem lidos.
 */
void attributeInfo(ClassFile* classfile, FILE* file, uint16_t attributes_count) {
  if (attributes_count == 0)
    return;
  else {
    classfile->attributes =
        (Attribute*)malloc(attributes_count * sizeof(Attribute));
    Attribute* cp = classfile->attributes;

    for (int i = 0; i < attributes_count; cp++) {
      cp->name_index = read_two_bytes(file);
      cp->length = read_four_bytes(file);
      cp->info = (uint8_t*)malloc((cp->length) * sizeof(uint8_t));
      for (uint32_t j = 0; j < cp->length; j++) {
        fread(&cp->info[j], 1, 1, file);
      }
      i++;
    }
  }
}

/**
 * @brief Lê informações gerais adicionais do arquivo .class.
 * @param classfile Estrutura de dados ClassFile onde as informações adicionais serão armazenadas.
 * @param file Ponteiro para o arquivo .class aberto.
 */
void secondGeneralInfo(ClassFile* classfile, FILE* file) {
  classfile->access_flags = read_two_bytes(file);
  classfile->this_class = read_two_bytes(file);
  classfile->super_class = read_two_bytes(file);

  classfile->interfaces_count = read_two_bytes(file);
  interfaceInfo(classfile, file, classfile->interfaces_count);

  classfile->fields_count = read_two_bytes(file);
  fieldInfo(classfile, file, classfile->fields_count);

  classfile->methods_count = read_two_bytes(file);
  methodInfo(classfile, file, classfile->methods_count);
  classfile->attributes_count = read_two_bytes(file);
  attributeInfo(classfile, file, classfile->attributes_count);
}

/**
 * @brief Lê um byte do arquivo.
 * @param fp Ponteiro para o arquivo de onde o byte será lido.
 * @return O byte lido.
 */
static inline uint8_t read_one_byte(FILE* fp) {
  uint8_t ret = getc(fp);
  return ret;
}

/**
 * @brief Lê dois bytes do arquivo e os combina em um uint16_t.
 * @param fp Ponteiro para o arquivo de onde os bytes serão lidos.
 * @return O uint16_t formado pelos dois bytes lidos.
 */
static inline uint16_t read_two_bytes(FILE* fp) {
  uint16_t ret = getc(fp);
  ret = (ret << 8) | (getc(fp));
  return ret;
}

/**
 * @brief Lê quatro bytes do arquivo e os combina em um uint32_t.
 * @param fp Ponteiro para o arquivo de onde os bytes serão lidos.
 * @return O uint32_t formado pelos quatro bytes lidos.
 */
static inline uint32_t read_four_bytes(FILE* fp) {
  uint32_t ret = getc(fp);
  ret = (ret << 8) | (getc(fp));
  ret = (ret << 8) | (getc(fp));
  ret = (ret << 8) | (getc(fp));
  return ret;
}
