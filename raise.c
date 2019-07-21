#include <asm/ldt.h>
#include <elf.h>
#include <errno.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/procfs.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#define OK 0
#define ERROR 1

void loadRegisters(void);

// Name all relevant registers
// to have an easy access to them 'by symbols' in assembler function
int ebx_value, ecx_value, edx_value, esi_value, edi_value,
        ebp_value, eax_value, eip_value, eflags_value, esp_value;

int pad(int x) {
    int y = x % 4;
    return y ? 4 - y : 0;
}

struct file_map_range {
    long start;
    long end;
    long file_offset;
};

struct file_map {
    struct file_map_range *range;
    char *name;
};

struct file_map_node {
    struct file_map value;
    struct file_map_node *next;
};

struct file_map_list {
    long page_size;
    struct file_map_node *begin;
    struct file_map_node *end;
};

void list_init(struct file_map_list *list) {
    list->begin = list->end = NULL;
}

// If list_append returns ERROR, the state of the list is unchanged
int list_append(struct file_map_list *list, struct file_map_range *range, char *name) {
    if (list->begin == NULL) {
        list->begin = list->end = malloc(sizeof(struct file_map_list));
        if (list->begin == NULL) {
            printf("Error in malloc new list\n");
            return ERROR;
        }
    }
    else {
        list->end->next = malloc(sizeof(struct file_map_list));
        if (list->end->next == NULL) {
            printf("Error cannot malloc space for new list node\n");
            return ERROR;
        }
        list->end = list->end->next;
    }
    list->end->value.range = range;
    list->end->value.name = name;
    list->end->next = NULL;
    return OK;
}

struct file_map *list_find(struct file_map_list *list, long vaddr) {
    struct file_map_node *head = list->begin;
    while (head != NULL) {
        if (head->value.range->start == vaddr) {
            return &head->value;
        }
        head = head->next;
    }
    return NULL;
}

void setGlobalRegistersValue(elf_gregset_t *gp_registers) {
    ebx_value = *((int *) gp_registers + EBX);
    ecx_value = *((int *) gp_registers + ECX);
    edx_value = *((int *) gp_registers + EDX);
    esi_value = *((int *) gp_registers + ESI);
    edi_value = *((int *) gp_registers + EDI);
    ebp_value = *((int *) gp_registers + EBP);
    eax_value = *((int *) gp_registers + EAX);
    eip_value = *((int *) gp_registers + EIP);
    eflags_value = *((int *) gp_registers + EFL);
    esp_value = *((int *) gp_registers + UESP);
}

int isElfHeaderCorrect(const Elf32_Ehdr *header) {
    int ok = 1;
    ok &= header->e_ident[EI_MAG0] == ELFMAG0;
    ok &= header->e_ident[EI_MAG1] == ELFMAG1;
    ok &= header->e_ident[EI_MAG2] == ELFMAG2;
    ok &= header->e_ident[EI_MAG3] == ELFMAG3;
    ok &= header->e_ident[EI_CLASS] == ELFCLASS32;
    ok &= header->e_ident[EI_VERSION] == EV_CURRENT;
    ok &= header->e_ident[EI_OSABI] == ELFOSABI_SYSV;
    ok &= header->e_type == ET_CORE;
    ok &= header->e_machine == EM_386;
    ok &= header->e_version == EV_CURRENT;
    return ok;
}

int readElfHeader(FILE *elfFile, Elf32_Ehdr *elfHeader) {
    if (fread(elfHeader, 1, sizeof(Elf32_Ehdr), elfFile) != sizeof(Elf32_Ehdr)) {
        printf("Error reading elf header\n");
        return ERROR;
    }
    if (!isElfHeaderCorrect(elfHeader)) {
        printf("Error elf header is not correct\n");
        return ERROR;
    }
    return OK;
};

int readSegmentHeaders(FILE *elf_file, const Elf32_Ehdr *elf_header, Elf32_Phdr **segment_headers) {
    if (elf_header->e_phentsize != sizeof(Elf32_Phdr)) {
        printf("Program header table entry size different than Elf32_Phdr size");
        return ERROR;
    }

    const size_t program_header_table_size = elf_header->e_phnum * elf_header->e_phentsize;
    *segment_headers = (Elf32_Phdr *) malloc(program_header_table_size);
    if (*segment_headers == NULL) {
        printf("Error segment headers malloc");
        return ERROR;
    }
    if (fseek(elf_file, elf_header->e_phoff, SEEK_SET) == -1) {
        printf("Error fseek segment headers in elf file: %s\n", strerror(errno));
        free(*segment_headers);
        return ERROR;
    }
    if (fread(*segment_headers, 1, program_header_table_size, elf_file) !=
            program_header_table_size) {
        printf("Error read segment headers");
        free(*segment_headers);
        return ERROR;
    }
    return OK;
}

int processPTNote(FILE *elf_file, Elf32_Phdr *segment_header,
                  struct file_map_list *list, struct user_desc **tls, int *tls_records_ct) {
    void *desc;
    struct elf_prstatus *prstatus;
    long fcount;
    long *nt_files;
    char *file_name;

    void *note_data = malloc(segment_header->p_filesz);
    if (note_data == NULL) {
        printf("Error malloc note_data\n");
        return ERROR;
    }
    if (fseek(elf_file, segment_header->p_offset, SEEK_SET) == -1) {
        printf("Error fseek PT_NOTE offset in elf file: %s\n", strerror(errno));
        free(note_data);
        return ERROR;
    }
    if (fread(note_data, 1, segment_header->p_filesz, elf_file) != segment_header->p_filesz) {
        printf("Error read note_data\n");
        free(note_data);
        return ERROR;
    }

    int description_offset;
    Elf32_Nhdr *note_header = (Elf32_Nhdr *) note_data;
    while ((int) note_header < (int) note_data + segment_header->p_filesz) {
        int name_pad = pad(note_header->n_namesz);
        description_offset = sizeof(*note_header) + note_header->n_namesz + name_pad;
        desc = (char *) note_header + description_offset;
        switch (note_header->n_type) {
            case NT_PRSTATUS:
                prstatus = (struct elf_prstatus *) desc;
                setGlobalRegistersValue(&prstatus->pr_reg);
                break;

            case NT_FILE:
                nt_files = (long *) desc;
                fcount = *nt_files++;
                list->page_size = *nt_files++;
                file_name = (char *) (nt_files + 3 * fcount);
                for (int i = 0; i < fcount; ++i) {
                    if (list_append(list, (struct file_map_range *) nt_files, file_name) == ERROR) {
                        free(note_data);
                        return ERROR;
                    }

                    nt_files += 3;
                    file_name += strlen(file_name) + 1;
                }
                break;

            case NT_386_TLS:
                // I assume that descriptor size is a multiple of the struct user_desc size
                *tls_records_ct = note_header->n_descsz / sizeof(struct user_desc);
                *tls = (struct user_desc *) desc;
                break;

            default:
                break;
        }

        int desc_pad = pad(note_header->n_descsz);
        note_header = (Elf32_Nhdr *) ((char *) desc + note_header->n_descsz + desc_pad);
    }
    return OK;
}

int mmapPTLoad(FILE *elf_file, Elf32_Phdr *segment_header, struct file_map_list *list) {
    struct file_map *fm;

    int prot = 0;
    if (segment_header->p_flags & PF_X) prot |= PROT_EXEC;
    if (segment_header->p_flags & PF_W) prot |= PROT_WRITE;
    if (segment_header->p_flags & PF_R) prot |= PROT_READ;

    if (segment_header->p_filesz < segment_header->p_memsz) {
        if ((fm = list_find(list, segment_header->p_vaddr)) != NULL) {
            size_t len = (size_t) (fm->range->end - fm->range->start);
            FILE *file;
            if ((file = fopen(fm->name, "r")) == NULL) {
                printf("Error open file indicated by PT_LOAD: %s\n", strerror(errno));
                return ERROR;
            }
            long offset = fm->range->file_offset * list->page_size;
            if (mmap((void *) segment_header->p_vaddr, len, prot,
                     MAP_PRIVATE | MAP_FIXED, fileno(file), offset) == MAP_FAILED) {
                printf("Error mmap PT_LOAD segment from NT_FILE: %s\n", strerror(errno));
                fclose(file);
                return ERROR;
            }
            fclose(file);
        }
        else {
            if (mmap((void *) segment_header->p_vaddr, segment_header->p_memsz, prot,
                     MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0) == MAP_FAILED) {
                printf("Error mmap anonymous PT_LOAD segment: %s\n", strerror(errno));
                return ERROR;
            }
        }
    }
    // Additional check because mmap fails when called with len == 0
    if (segment_header->p_filesz > 0) {
        if (mmap((void *) segment_header->p_vaddr, segment_header->p_filesz, prot,
                 MAP_PRIVATE | MAP_FIXED, fileno(elf_file), segment_header->p_offset) == MAP_FAILED) {
            printf("Error mmap PT_LOAD segment: %s\n", strerror(errno));
            return ERROR;
        }
    }
    return OK;
}

int solution(char *elf_file_name_tmp) {
    // elf_file_name_tmp can points above standard load address
    // which will be munmaped soon
    char *elf_file_name = malloc(strlen(elf_file_name_tmp) + 1);
    if (elf_file_name == NULL) {
        printf("Error malloc efl_file_name\n");
        exit(1);
    }
    strncpy(elf_file_name, elf_file_name_tmp, strlen(elf_file_name_tmp) + 1);

    size_t min_kernel_addr = 0xC0000000;
    size_t standard_load_addr = 0x08048000;
    if (munmap((void *) standard_load_addr, min_kernel_addr - standard_load_addr) == -1) {
        printf("Error munmap user space addresses: %s\n", strerror(errno));
        exit(1);
    }

    FILE *elf_file = NULL;
    Elf32_Ehdr elf_header;
    Elf32_Phdr *segment_headers = NULL;
    struct file_map_list fm_list;
    struct user_desc *tls = NULL;
    int tls_records_ct = 0;
    list_init(&fm_list);

    if ((elf_file = fopen(elf_file_name, "r")) == NULL) {
        printf("Error opening file: %s\n", strerror(errno));
        exit(1);
    }
    if (readElfHeader(elf_file, &elf_header) == ERROR) {
        exit(1);
    }

    if (readSegmentHeaders(elf_file, &elf_header, &segment_headers) == ERROR) {
        exit(1);
    }
    // I have to guarantee that PT_NOTE is processed before PT_LOADs
    for (int id = 0; id < elf_header.e_phnum; ++id) {
        if (segment_headers[id].p_type == PT_NOTE) {
            if (processPTNote(elf_file, segment_headers + id, &fm_list,
                              &tls, &tls_records_ct) == ERROR) {
                exit(1);
            }
        }
    }
    for (int id = 0; id < elf_header.e_phnum; ++id) {
        if (segment_headers[id].p_type == PT_LOAD) {
            if (mmapPTLoad(elf_file, segment_headers + id, &fm_list) == ERROR) {
                exit(1);
            }
        }
    }

    if (tls != NULL) {
        for (int i = 0; i < tls_records_ct; ++i) {
            if (syscall(SYS_set_thread_area, tls + i) == -1) {
                printf("Error setting thread area: %s\n", strerror(errno));
                exit(1);
            }
        }
        // Some magic. According to glibc we have to do this
        // even if the numeric value of the descriptor does not change.
        // Loading the segment register causes the segment information
        // from the GDT to be loaded which is necessary since we have changed it.
        asm("movw %w0, %%gs"::"q" (tls->entry_number * 8 + 3));
    }
    loadRegisters();
    // loadRegister loads also instruction pointer register
    // therefore it should never reach this point
    exit(1);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("usage: %s ELF_FILE\n", argv[0]);
        return 1;
    }
    char *elf_file_name = argv[1];

    ucontext_t context;
    if (getcontext(&context) == -1) {
        perror("Error get context");
        return 1;
    }

    void *stack_pointer = (void *) 0x07648000;
    size_t stack_size = 0x800000;
    if (mmap(stack_pointer, stack_size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED) {
        perror("Error mmap new stack\n");
        return 1;
    }

    context.uc_stack.ss_sp = stack_pointer;
    context.uc_stack.ss_size = stack_size;
    context.uc_link = NULL; // Just to be sure
    makecontext(&context, (void (*)()) solution, 1, elf_file_name);
    if (setcontext(&context) == -1) {
        perror("Error set context");
        return 1;
    }
    return 1; // Control should never return from setcontext
}
