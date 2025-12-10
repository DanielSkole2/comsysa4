#include "simulate.h"
#include "memory.h"
#include "read_elf.h"
#include "disassemble.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h> 

extern uint32_t R[32];
extern uint32_t PC;
extern uint64_t instruction_count;
extern bool running; 
extern bool is_detailed_log;  

enum PredictorType { PRED_NT, PRED_BTFNT, PRED_BIMODAL, PRED_GSHARE, PRED_NONE };                


enum PredictorType current_predictor = PRED_NONE;  
uint32_t PHT_SIZE = 0; 

#define MAX_PHT_SIZE 16384

static uint8_t pht[MAX_PHT_SIZE];  
static uint32_t bhr = 0; 

struct PredictorStats {
    long long total_branches;
    long long mispredictions;
};
static struct PredictorStats stats = {0, 0};     

void reset_predictors() { 
    stats.total_branches = 0;
    stats.mispredictions = 0;
    bhr = 0;

    
    if (current_predictor == PRED_BIMODAL || current_predictor == PRED_GSHARE) {
        uint32_t init_size = PHT_SIZE;
        for (uint32_t i = 0; i < init_size; i++) {
            pht[i] = 2; 
        }
    }
}
static int32_t sign_extend(uint32_t value, int bits) {       
    if ((value >> (bits - 1)) & 1) {
        return (int32_t) (value | (~0U << bits));
    }
    return (int32_t) value;
}

static int32_t decode_imm_I(uint32_t inst) {
    uint32_t imm = (inst >> 20) & 0xFFF;
    return sign_extend(imm, 12);
}

static int32_t decode_imm_S(uint32_t inst) {
    uint32_t imm = ((inst >> 7) & 0x1F) | ((inst >> 25) & 0x7F) << 5;
    return sign_extend(imm, 12);
}

static int32_t decode_imm_B(uint32_t inst) {
    uint32_t imm = ((inst >> 8) & 0xF) << 1 | 
                     ((inst >> 25) & 0x3F) << 5 | 
                     ((inst >> 7) & 0x1) << 11 | 
                     ((inst >> 31) & 0x1) << 12;
    return sign_extend(imm, 13);
}

static int32_t decode_imm_U(uint32_t inst) {
    return (int32_t)(inst & 0xFFFFF000);
}

static int32_t decode_imm_J(uint32_t inst) {
    uint32_t imm = ((inst >> 21) & 0x3FF) << 1 |
                     ((inst >> 20) & 0x1) << 11 |
                     ((inst >> 12) & 0xFF) << 12 |
                     ((inst >> 31) & 0x1) << 20;
    return sign_extend(imm, 21);
}

#define OPCODE(inst) ((inst) & 0x7F)
#define RD(inst) (((inst) >> 7) & 0x1F)
#define FUNCT3(inst) (((inst) >> 12) & 0x7)
#define RS1(inst) (((inst) >> 15) & 0x1F)
#define RS2(inst) (((inst) >> 20) & 0x1F)
#define FUNCT7(inst) (((inst) >> 25) & 0x7F)

struct Stat simulate(struct memory *mem, int start_addr, FILE *log_file, struct symbols* symbols)
{
    PC = start_addr;
    instruction_count = 0;
    bool log_execution = is_detailed_log; 

    uint32_t pc_current;
    uint32_t inst;
    uint32_t opcode, rd, funct3, rs1, rs2, funct7;
    int32_t imm;
    char disasm_buf[128];
    bool branch_taken = false;
    
    if (current_predictor != PRED_NONE) {
        reset_predictors();
    }

    while (running)
    {
        pc_current = PC;
        inst = memory_rd_w(mem, pc_current);

        opcode = OPCODE(inst);
        rd = RD(inst);
        funct3 = FUNCT3(inst);
        rs1 = RS1(inst);
        rs2 = RS2(inst);
        funct7 = FUNCT7(inst);
        
        uint32_t pc_next = pc_current + 4;
        
        branch_taken = false; 

        
        if (log_execution && instruction_count > 0) {

        }

        switch (opcode)
        {
            
            case 0x33: 
                if (funct7 == 0x01) {
                    switch (funct3) {
                        case 0x0: 
                            R[rd] = R[rs1] * R[rs2];
                            break;
                        case 0x1: 
                            R[rd] = ((int64_t)(int32_t)R[rs1] * (int64_t)(int32_t)R[rs2]) >> 32; 
                            break;
                        case 0x2: 
                            R[rd] = ((int64_t)(int32_t)R[rs1] * (uint64_t)R[rs2]) >> 32;
                            break;
                        case 0x3: 
                            R[rd] = ((uint64_t)R[rs1] * (uint64_t)R[rs2]) >> 32;
                            break;
                        case 0x4: 
                            if (R[rs2] == 0) R[rd] = 0xFFFFFFFF; 
                            else if (R[rs1] == 0x80000000 && R[rs2] == 0xFFFFFFFF) R[rd] = 0x80000000; 
                            else R[rd] = (int32_t)R[rs1] / (int32_t)R[rs2];
                            break;
                        case 0x5: 
                            if (R[rs2] == 0) R[rd] = 0xFFFFFFFF; 
                            else R[rd] = R[rs1] / R[rs2];
                            break;
                        case 0x6: 
                            if (R[rs2] == 0) R[rd] = R[rs1]; 
                            else if (R[rs1] == 0x80000000 && R[rs2] == 0xFFFFFFFF) R[rd] = 0; 
                            else R[rd] = (int32_t)R[rs1] % (int32_t)R[rs2];
                            break;
                        case 0x7: 
                            if (R[rs2] == 0) R[rd] = R[rs1]; 
                            else R[rd] = R[rs1] % R[rs2];
                            break;
                    }
                } else {
                    switch (funct3) {
                        case 0x0: 
                            if (funct7 == 0x00) R[rd] = R[rs1] + R[rs2]; 
                            else if (funct7 == 0x20) R[rd] = R[rs1] - R[rs2]; 
                            break;
                        case 0x1: 
                            R[rd] = R[rs1] << (R[rs2] & 0x1F);
                            break;
                        case 0x2: 
                            R[rd] = ((int32_t)R[rs1] < (int32_t)R[rs2]) ? 1 : 0;
                            break;
                        case 0x3: 
                            R[rd] = (R[rs1] < R[rs2]) ? 1 : 0;
                            break;
                        case 0x4: 
                            R[rd] = R[rs1] ^ R[rs2];
                            break;
                        case 0x5: 
                            if (funct7 == 0x00) R[rd] = R[rs1] >> (R[rs2] & 0x1F); 
                            else if (funct7 == 0x20) R[rd] = (int32_t)R[rs1] >> (R[rs2] & 0x1F); 
                            break;
                        case 0x6: 
                            R[rd] = R[rs1] | R[rs2];
                            break;
                        case 0x7: 
                            R[rd] = R[rs1] & R[rs2];
                            break;
                    }
                }
                break;

            case 0x13: 
                imm = decode_imm_I(inst);
                switch (funct3) {
                    case 0x0: 
                        R[rd] = R[rs1] + imm;
                        break;
                    case 0x2: 
                        R[rd] = ((int32_t)R[rs1] < imm) ? 1 : 0;
                        break;
                    case 0x3: 
                        R[rd] = (R[rs1] < (uint32_t)imm) ? 1 : 0;
                        break;
                    case 0x4: 
                        R[rd] = R[rs1] ^ imm;
                        break;
                    case 0x6: 
                        R[rd] = R[rs1] | imm;
                        break;
                    case 0x7: 
                        R[rd] = R[rs1] & imm;
                        break;
                    case 0x1: 
                        R[rd] = R[rs1] << (imm & 0x1F);
                        break;
                    case 0x5: 
                        if (funct7 == 0x00) R[rd] = R[rs1] >> (imm & 0x1F); 
                        else if (funct7 == 0x20) R[rd] = (int32_t)R[rs1] >> (imm & 0x1F); 
                        break;
                }
                break;

            case 0x67: 
                imm = decode_imm_I(inst);
                uint32_t next_pc = (R[rs1] + imm) & ~1;
                R[rd] = pc_current + 4;
                pc_next = next_pc;
                break;

            case 0x03: 
                imm = decode_imm_I(inst);
                uint32_t mem_addr = R[rs1] + imm;
                switch (funct3) {
                    case 0x0: 
                        R[rd] = sign_extend(memory_rd_b(mem, mem_addr), 8);
                        break;
                    case 0x1: 
                        R[rd] = sign_extend(memory_rd_h(mem, mem_addr), 16);
                        break;
                    case 0x2: 
                        R[rd] = memory_rd_w(mem, mem_addr);
                        break;
                    case 0x4: 
                        R[rd] = memory_rd_b(mem, mem_addr);
                        break;
                    case 0x5: 
                        R[rd] = memory_rd_h(mem, mem_addr);
                        break;
                }
                break;

            case 0x23: 
                imm = decode_imm_S(inst);
                mem_addr = R[rs1] + imm;
                switch (funct3) {
                    case 0x0: 
                        memory_wr_b(mem, mem_addr, R[rs2] & 0xFF);
                        break;
                    case 0x1: 
                        memory_wr_h(mem, mem_addr, R[rs2] & 0xFFFF);
                        break;
                    case 0x2: 
                        memory_wr_w(mem, mem_addr, R[rs2]);
                        break;
                }
                break;

            
            case 0x63: 
                imm = decode_imm_B(inst);
                bool condition = false;
                switch (funct3) {
                    case 0x0: 
                        condition = (R[rs1] == R[rs2]);
                        break;
                    case 0x1: 
                        condition = (R[rs1] != R[rs2]);
                        break;
                    case 0x4: 
                        condition = ((int32_t)R[rs1] < (int32_t)R[rs2]);
                        break;
                    case 0x5: 
                        condition = ((int32_t)R[rs1] >= (int32_t)R[rs2]);
                        break;
                    case 0x6: 
                        condition = (R[rs1] < R[rs2]);
                        break;
                    case 0x7: 
                        condition = (R[rs1] >= R[rs2]);
                        break;
                }
                
                if (current_predictor != PRED_NONE) {
                    bool prediction = false;
                    uint32_t pht_mask_local = PHT_SIZE - 1; 

                    if (current_predictor == PRED_NT) {
                        prediction = false; 
                    } 
                    else if (current_predictor == PRED_BTFNT) {
                        prediction = (imm < 0); 
                    }
                    else if (current_predictor == PRED_BIMODAL || current_predictor == PRED_GSHARE) {
                        uint32_t index;

                        if (current_predictor == PRED_BIMODAL) {
                            index = (pc_current >> 2) & pht_mask_local;
                        } else { 
                            uint32_t pc_index = (pc_current >> 2) & pht_mask_local;
                            uint32_t bhr_masked = bhr & pht_mask_local; 
                            index = pc_index ^ bhr_masked;
                        }

                        prediction = (pht[index] >= 2);
                        
                        if (condition) { 
                            if (pht[index] < 3) pht[index]++; 
                        } else { 
                            if (pht[index] > 0) pht[index]--; 
                        }
                        
                        bhr = (bhr << 1) | condition;
                        
                        bhr &= pht_mask_local; 
                    }

                    stats.total_branches++;
                    if (prediction != condition) {
                        stats.mispredictions++;
                    }
                }

                if (condition) {
                    pc_next = pc_current + imm;
                    branch_taken = true;
                }
                break;

            case 0x37: 
                imm = decode_imm_U(inst);
                R[rd] = (uint32_t)imm;
                break;

            case 0x17: 
                imm = decode_imm_U(inst);
                R[rd] = pc_current + (uint32_t)imm;
                break;

            case 0x6F: 
                imm = decode_imm_J(inst);
                R[rd] = pc_current + 4;
                pc_next = pc_current + imm;
                break;
            
            case 0x73: 
                imm = decode_imm_I(inst);
                if (funct3 == 0x0) { 
                    if (imm == 0x000) { 
                        uint32_t syscall_num = R[17];
                        if (syscall_num == 1) R[10] = getchar(); 
                        else if (syscall_num == 2) { putchar((char)R[10]); fflush(stdout); } 
                        else if (syscall_num == 3 || syscall_num == 93) running = false; 
                        else fprintf(stderr, "ECALL: Ignoring unsupported syscall number %u. Continuing.\n", syscall_num);
                    } else if (imm == 0x001) fprintf(stderr, "ECALL: EBREAK encountered (0x%x). Continuing.\n", pc_current);
                }
                break;

            default:
                fprintf(stderr, "Unknown opcode 0x%x at 0x%x. Terminating.\n", opcode, pc_current);
                running = false;
                break;
        }

        R[0] = 0; 
        instruction_count++;
        PC = pc_next;

        if (log_execution) {
            disassemble(pc_current, inst, disasm_buf, sizeof(disasm_buf), symbols);
            fprintf(log_file, "%*lu => 0x%x : 0x%08x %s", 5, instruction_count, pc_current, inst, disasm_buf);  
            
            if (opcode == 0x63) {
                fprintf(log_file, "\t\t{%c}", branch_taken ? 'T' : 'N');
            }
            
            if (opcode == 0x6f || opcode == 0x67 || opcode == 0x33 || opcode == 0x13 || opcode == 0x37 || opcode == 0x17 || opcode == 0x03) {
                if (rd != 0) {
                    fprintf(log_file, "\t\tR[%d] <- 0x%x", rd, R[rd]);
                }
            }

            if (opcode == 0x23) {
                 imm = decode_imm_S(inst);
                 uint32_t mem_addr = R[rs1] + imm;
                 uint32_t data = R[rs2];
                 fprintf(log_file, "\t\tM[0x%x] <- 0x%x", mem_addr, data);
            }
            fprintf(log_file, "\n"); 
        }

        if (log_file && instruction_count % 1000000 == 0) {
              fflush(log_file); 
        }
    }

    if (log_file && current_predictor != PRED_NONE) {
        fprintf(log_file, "\n\n--- Predictor Statistics ---\n");
        const char *pred_name = "ERROR";
        if (current_predictor == PRED_NT) pred_name = "NT";
        else if (current_predictor == PRED_BTFNT) pred_name = "BTFNT";
        else if (current_predictor == PRED_BIMODAL) pred_name = "Bimodal";
        else if (current_predictor == PRED_GSHARE) pred_name = "gShare";
        
        fprintf(log_file, "Predictor Type: %s", pred_name);
        if (current_predictor == PRED_BIMODAL || current_predictor == PRED_GSHARE) {
            fprintf(log_file, " (%u entries)", PHT_SIZE);
        }
        fprintf(log_file, "\n");
        fprintf(log_file, "Total Branches: %lld\n", stats.total_branches);
        fprintf(log_file, "Mispredictions: %lld\n", stats.mispredictions);
        if (stats.total_branches > 0) {
            double misprediction_rate = (double)stats.mispredictions / stats.total_branches * 100.0;
            fprintf(log_file, "Misprediction Rate: %.2f%%\n", misprediction_rate);
        }
        fprintf(log_file, "--------------------------\n");
    }           
    
    struct Stat result;
    result.insns = instruction_count; 
    return result;
} 