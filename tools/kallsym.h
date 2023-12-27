#ifndef _KALLSYM_H_
#define _KALLSYM_H_

#include <stdint.h>

// script/kallsym.c
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

#define KSYM_TOKEN_NUMS 256
#define KSYM_SYMBOL_LEN 512

#define KSYM_MIN_NEQ_SYMS 25600
#define KSYM_MIN_MARKER (KSYM_MIN_NEQ_SYMS / 256)
#define KSYM_FIND_NAMES_USED_MARKER 5

#define ARM64_RELO_MIN_NUM 4000

enum ksym_type
{
    // Seen in actual kernels
    ABSOLUTE = 'A',
    BSS = 'B',
    DATA = 'D',
    RODATA = 'R',
    TEXT = 'T',
    WEAK_OBJECT_WITH_DEFAULT = 'V',
    WEAK_SYMBOL_WITH_DEFAULT = 'W',
    // Seen on nm's manpage
    SMALL_DATA = 'G',
    INDIRECT_FUNCTION = 'I',
    DEBUGGING = 'N',
    STACK_UNWIND = 'P',
    COMMON = 'C',
    SMALL_BSS = 'S',
    UNDEFINED = 'U',
    UNIQUE_GLOBAL = 'u',
    WEAK_OBJECT = 'v',
    WEAK_SYMBOL = 'w',
    STABS_DEBUG = '-',
    UNKNOWN = '?',
};

enum arch_type
{
    ARM64 = 1,
    X86_64,
    ARM_BE,
    ARM_LE,
    X86
};

typedef struct
{
    enum arch_type arch;
    int32_t is_64;
    int32_t is_be;

    int32_t img_offset;

    struct
    {
        uint8_t _;
        uint8_t patch;
        uint8_t minor;
        uint8_t major;
    } version;

    int32_t banner_num;
    int32_t linux_banner_offset[4];
    int32_t symbol_banner_idx;

    int32_t vectors_offset;
    int32_t vectors_index;

    char *kallsyms_token_table[KSYM_TOKEN_NUMS];
    int32_t asm_long_size;
    int32_t asm_PTR_size;
    int32_t kallsyms_num_syms;

    int32_t has_relative_base;
    int32_t kallsyms_addresses_offset;
    int32_t kallsyms_offsets_offset;
    // int32_t kallsyms_relative_base_offset;  // maybe 0
    int32_t kallsyms_num_syms_offset;
    int32_t kallsyms_names_offset;
    int32_t kallsyms_markers_offset;
    //kallsyms_seqs_of_names  // todo: v6.2
    int32_t kallsyms_token_table_offset;
    int32_t kallsyms_token_index_offset;

    int32_t _approx_addresses_or_offsets_offset;
    int32_t _approx_addresses_or_offsets_end;
    int32_t _approx_addresses_or_offsets_num;
    int32_t _marker_num;

    int32_t try_relo;
    int32_t relo_applied;
    int32_t elf64_rela_num;
    int32_t elf64_rela_offset;

} kallsym_t;

int analyze_kallsym_info(kallsym_t *info, char *img, int32_t imglen, enum arch_type arch, int32_t is_64);
int dump_all_symbols(kallsym_t *info, char *img);
int get_symbol_index_offset(kallsym_t *info, char *img, int32_t index);
int32_t get_symbol_offset(kallsym_t *info, char *img, char *symbol);
int on_each_symbol(kallsym_t *info, char *img, void *userdata,
                   int32_t (*fn)(int32_t index, char *type, const char *symbol, int32_t offset, void *userdata));

#endif // _KALLSYM_H_
