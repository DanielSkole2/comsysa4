#include "memory.h"
#include "read_elf.h"
#include "disassemble.h"
#include "simulate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h> 

uint32_t R[32] = {0}; 
uint32_t PC = 0;
uint64_t instruction_count = 0; 
bool running = true;

enum PredictorType { PRED_NT, PRED_BTFNT, PRED_BIMODAL, PRED_GSHARE, PRED_NONE };        

extern enum PredictorType current_predictor;
extern uint32_t PHT_SIZE;
extern void reset_predictors();

bool is_detailed_log = false;

void terminate(const char *error)    
{
    printf("%s\n", error);
    printf("RISC-V Simulator v0.11.0: Usage:\n"); 
    printf(" sim riscv-elf sim-options -- prog-args\n");
    printf("   sim-options: options to the simulator\n");
    printf("     sim riscv-elf -d                // disassemble text segment of riscv-elf file to stdout\n");
    printf("     sim riscv-elf -l log            // simulate and log each instruction to file 'log'\n");
    printf("     sim riscv-elf -s log            // simulate and log only summary to file 'log'\n");
    printf("     sim riscv-elf -p NT -s log      // simulate with Not Taken predictor\n");
    printf("     sim riscv-elf -p Bimodal 4K -s log // simulate with Bimodal 4K-entry predictor\n");
    printf("   prog-args: arguments to the simulated program\n");
    printf("                       these arguments are provided through argv. Puts '--' in argv[0]\n");
    printf("     sim riscv-elf -- gylletank      // run riscv-elf with 'gylletank' in argv[1]\n");
    exit(-1);
}

int pass_args_to_program(struct memory* mem, int argc, char* argv[]) {
    int seperator_position = 1; 
    int seperator_found = 0;
    while (seperator_position < argc) {
        seperator_found = strcmp(argv[seperator_position],"--") == 0;
        if (seperator_found) break;
        seperator_position++;
    }
    if (seperator_found) { 
        int first_arg = seperator_position;
        int num_args = argc - first_arg;
        unsigned count_addr = 0x1000000;
        unsigned argv_addr = 0x1000004;
        unsigned str_addr = argv_addr + 4 * num_args;
        memory_wr_w(mem, count_addr, num_args);
        for (int index = 0; index < num_args; ++index) {
            memory_wr_w(mem, argv_addr + 4 * index, str_addr);
            char* cp = argv[first_arg + index];
            int c;
            do {
                c = *cp++;
                memory_wr_b(mem, str_addr++, c);
            } while (c);
        }
    }
    return seperator_position;
}

void disassemble_to_stdout(struct memory* mem, struct program_info* prog_info, struct symbols* symbols) 
{
    const int buf_size = 100;
    char disassembly[buf_size];
    for (unsigned int addr = prog_info->text_start; addr < prog_info->text_end; addr += 4) {
        unsigned int instruction = memory_rd_w(mem, addr);
        disassemble(addr, instruction, disassembly, buf_size, symbols);
        printf("%8x : %08X       %s\n", addr, instruction, disassembly);
    }
}

int main(int argc, char *argv[])
{
    struct memory *mem = memory_create();
    int sim_argc = pass_args_to_program(mem, argc, argv);
    
    if (sim_argc < 2) {
        terminate("Missing riscv-elf file name.");
    }

    FILE *log_file = NULL;
    bool disassemble_mode = false;
    for (int i = 2; i < sim_argc; ++i) {
        if (!strcmp(argv[i], "-d")) {
            disassemble_mode = true;
        } 
        else if (!strcmp(argv[i], "-l")) {
            if (i + 1 >= sim_argc) terminate("Error: -l requires a log filename.");
            log_file = fopen(argv[++i], "w");
            if (log_file == NULL) terminate("Could not open file for detailed log, terminating.");
            is_detailed_log = true; 
        }
        else if (!strcmp(argv[i], "-s")) {
            if (i + 1 >= sim_argc) terminate("Error: -s requires a log filename.");
            log_file = fopen(argv[++i], "w");
            if (log_file == NULL) terminate("Could not open file for summary log, terminating.");
        }
        else if (!strcmp(argv[i], "-p")) {
            if (i + 1 >= sim_argc) terminate("Error: -p requires a predictor name (NT, BTFNT, Bimodal, gShare).");
            
            char* pred_name = argv[++i];

            if (!strcmp(pred_name, "NT")) {
                current_predictor = PRED_NT;
            } else if (!strcmp(pred_name, "BTFNT")) {
                current_predictor = PRED_BTFNT;
            } else if (!strcmp(pred_name, "Bimodal") || !strcmp(pred_name, "gShare")) {
                if (i + 1 >= sim_argc) terminate("Error: Bimodal/gShare requires a size (256, 1K, 4K, 16K).");
                
                char* size_str = argv[++i];

                if (!strcmp(size_str, "256")) PHT_SIZE = 256;
                else if (!strcmp(size_str, "1K")) PHT_SIZE = 1024;
                else if (!strcmp(size_str, "4K")) PHT_SIZE = 4096;
                else if (!strcmp(size_str, "16K")) PHT_SIZE = 16384;
                else terminate("Error: Invalid predictor size. Use 256, 1K, 4K, or 16K.");
                
                if (!strcmp(pred_name, "Bimodal")) current_predictor = PRED_BIMODAL;
                else current_predictor = PRED_GSHARE;
                
            } else {
                terminate("Error: Invalid predictor name.");
            }
        }
        else {
            char error_msg[100];
            snprintf(error_msg, 100, "Unknown option: %s", argv[i]);
            terminate(error_msg);
        }
    }
    
    struct program_info prog_info;
    int status = read_elf(mem, &prog_info, argv[1], log_file);
    if (status) exit(status);
    
    struct symbols* symbols = symbols_read_from_elf(argv[1]);
    if (symbols == NULL) {
        exit(-1);
    }
    
    if (disassemble_mode) {
        disassemble_to_stdout(mem, &prog_info, symbols);
        exit(0);
    }
    
    int start_addr = prog_info.start;
    clock_t before = clock();
    struct Stat stats = simulate(mem, start_addr, log_file, symbols);
    long int num_insns = stats.insns;
    clock_t after = clock();
    int ticks = after - before;
    double mips = (1.0 * num_insns * CLOCKS_PER_SEC) / ticks / 1000000;
      
    if (log_file)
    {
        fprintf(log_file, "\nSimulated %ld instructions in %d host ticks (%f MIPS)\n", num_insns, ticks, mips);
        fclose(log_file);
    }
    else
    {
        printf("\nSimulated %ld instructions in %d host ticks (%f MIPS)\n", num_insns, ticks, mips);
    }
    
    memory_delete(mem); 
} 