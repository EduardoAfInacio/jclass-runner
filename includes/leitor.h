#ifndef LEITOR_EXIBIDOR_H
#define LEITOR_EXIBIDOR_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "decodificador.h"

/* Definições de constantes para tipos de constant pool */
#define CONSTANT_Class 7
#define CONSTANT_Fieldref 9
#define CONSTANT_Methodref 10
#define CONSTANT_InterfaceMethodref 11
#define CONSTANT_String 8
#define CONSTANT_Integer 3
#define CONSTANT_Float 4
#define CONSTANT_Long 5
#define CONSTANT_Double 6
#define CONSTANT_NameAndType 12
#define CONSTANT_Utf8 1

/* Flags de acesso para entidades Java */
#define Public 0x0001
#define Private 0x0002
#define Protected 0x0004
#define Static 0x0008
#define Final 0x0010
#define Super 0x0020
#define Volatile 0x0040
#define Transient 0x0080
#define Native 0x0100
#define Interface 0x0200
#define Abstract 0x0400
#define Strict 0x0800

/* Número máximo de opcodes de instruções JVM */
#define MAX_INSTRUCTIONS_NUMBER 256

/* Opcodes para instruções especiais */
#define TABLESWITCH 170
#define LOOKUPSWITCH 171
#define WIDE 196

/* Opcodes necessários para a instrução `wide` */
#define ILOAD 21
#define FLOAD 23
#define ALOAD 25
#define LLOAD 22
#define DLOAD 24
#define ISTORE 54
#define FSTORE 56
#define ASTORE 58
#define LSTORE 55
#define DSTORE 57
#define RET 169
#define IINC 132

/* Estruturas de dados para vários atributos e entidades em um arquivo ClassFile
 * de Java */
typedef struct attribute_info {
  uint16_t attribute_name_index;
  uint32_t attribute_length;
  uint8_t* info;
} attribute_info;

typedef struct ConstantValue_attribute {
  uint16_t attribute_name_index;
  uint32_t attribute_length;
  uint16_t constantvalue_index;
} CV_info;

typedef struct exception_table {
  uint16_t start_pc;
  uint16_t end_pc;
  uint16_t catch_type;
} exception_table;

typedef struct code_attribute {
  uint16_t attribute_name_index;
  uint32_t attribute_length;
  uint16_t max_stack;
  uint16_t max_locals;
  uint32_t code_length;
  uint8_t* code;
  uint16_t exception_table_length;
  exception_table* exception_table;
  uint16_t attributes_count;
  attribute_info* attributes;
} code_attribute;

typedef struct exceptions_attribute {
  uint16_t attribute_name_index;
  uint32_t attribute_length;
  uint16_t number_of_exceptions;
  uint16_t* exception_index_table;
} exceptions_attribute;

typedef struct field_info {
  uint16_t access_flags;
  uint16_t name_index;
  uint16_t descriptor_index;
  uint16_t attributes_count;
  CV_info* attributes;
} field_info;

typedef struct method_info {
  uint16_t access_flags;
  uint16_t name_index;
  uint16_t descriptor_index;
  uint16_t attributes_count;
  code_attribute* cd_atrb;
  exceptions_attribute* exc_atrb;
} method_info;

typedef struct cp_info {
  uint8_t tag;
  union {
    struct {
      uint16_t name_index;
    } Class;
    struct {
      uint16_t class_index;
      uint16_t name_and_type_index;
    } Fieldref;
    struct {
      uint16_t name_index;
      uint16_t descriptor_index;
    } NameAndType;
    struct {
      uint16_t length;
      uint8_t* bytes;
    } Utf8;
    struct {
      uint16_t class_index;
      uint16_t name_and_type_index;
    } Methodref;
    struct {
      uint16_t class_index;
      uint16_t name_and_type_index;
    } InterfaceMethodref;
    struct {
      uint16_t string_index;
    } String;
    struct {
      uint32_t bytes;
    } Integer;
    struct {
      uint32_t bytes;
    } Float;
    struct {
      uint32_t high_bytes;
      uint32_t low_bytes;
    } Long;
    struct {
      uint32_t high_bytes;
      uint32_t low_bytes;
    } Double;
  } info;
} cp_info;

typedef struct ClassFile {
  uint32_t magic;
  uint16_t minor_version;
  uint16_t major_version;
  uint16_t constant_pool_count;
  cp_info* constant_pool;
  uint16_t access_flags;
  uint16_t this_class;
  uint16_t super_class;
  uint16_t interfaces_count;
  uint16_t* interfaces;
  uint16_t fields_count;
  field_info* fields;
  uint16_t methods_count;
  method_info* methods;
  uint16_t attributes_count;
  attribute_info* attributes;
} ClassFile;

/* Protótipos de funções para ler e exibir componentes de ClassFile */
int main(int argc, char* argv[]);
void general_info(ClassFile* cf, FILE* file);
void constant_pool(ClassFile* cf, FILE* file);
void methodInfo(ClassFile* cf, FILE* file, uint16_t methods_count);
void attributeInfo(ClassFile* cf, FILE* file, uint16_t attributes_count);
void secondGeneralInfo(ClassFile* cf, FILE* file);
void print_prompt(ClassFile* cf);
void read_exc(exceptions_attribute** exc_atrb, uint16_t name_ind,
              uint32_t att_len, FILE* file);
void read_code(code_attribute** cd_atrb, uint16_t name_ind, uint32_t att_len,
               FILE* file);
void save_instructions(code_attribute** cd_atrb, FILE* file);
ClassFile* class_reader(char* class_name);
static inline uint8_t read_one_byte(FILE* fp);
static inline uint16_t read_two_bytes(FILE* fp);
static inline uint32_t read_four_bytes(FILE* fp);

#endif