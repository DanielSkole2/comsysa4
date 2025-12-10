#include "simulate.h"
#include "memory.h"
#include "read_elf.h"
#include "disassemble.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

extern uint32_t R[32];
extern uint32_t PC;
extern uint64_t instruction_count;
extern bool running; 

#define PHT_SIZE_256 (256)  
#define PHT_SIZE_1K (1024)
#define PHT_SIZE_4K (4096)
#define PHT_SIZE_16K (16384)

uint8_t pht[PHT_SIZE_4K]; 
uint32_t bhr;
uint32_t pht_mask = PHT_SIZE_4K - 1; 

void reset_predictors() {
    for (int i = 0; i < PHT_SIZE_4K; i++) {
        pht[i] = 2; 
    }
    bhr = 0;
}


#define OPCODE(inst) ((inst) & 0x7F)
#define RD(inst) (((inst) >> 7) & 0x1F)
#define FUNCT3(inst) (((inst) >> 12) & 0x7)
#define RS1(inst) (((inst) >> 15) & 0x1F)
#define RS2(inst) (((inst) >> 20) & 0x1F)
#define FUNCT7(inst) (((inst) >> 25) & 0x7F)

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
    uint32_t imm = ((FUNCT7(inst) << 5) | RD(inst));
    return sign_extend(imm, 12);
}

static int32_t decode_imm_B(uint32_t inst) {
    uint32_t imm = (
        ((inst >> 31) << 12) |            
        (((inst >> 7) & 0x1) << 11) |    
        (((inst >> 25) & 0x3F) << 5) |   
        (((inst >> 8) & 0xF) << 1)       
    );
    return sign_extend(imm, 13);
}

static int32_t decode_imm_U(uint32_t inst) {
    return (int32_t) (inst & 0xFFFFF000);
}

static int32_t decode_imm_J(uint32_t inst) {
    uint32_t imm = (
        ((inst >> 31) << 20) |           
        (((inst >> 21) & 0x3FF) << 1) | 
        (((inst >> 20) & 0x1) << 11) |  
        (((inst >> 12) & 0xFF) << 12)   
    );
    return sign_extend(imm, 21);
}


struct Stat simulate(struct memory *mem, int start_addr, FILE *log_file, struct symbols* symbols) {

    PC = start_addr;
    instruction_count = 0;
    running = true;

    
    R[2] = 0x40000000;
    R[0] = 0; 

    bool log_execution = (log_file != NULL);
    char disasm_buf[128];

    uint32_t inst, pc_current, opcode, rd, funct3, rs1, rs2, funct7;
    int32_t imm;
    uint32_t shamt;

    while (running) {
        pc_current = PC;
        inst = memory_rd_w(mem, pc_current);
        PC += 4;

        opcode = OPCODE(inst);
        rd = RD(inst);
        funct3 = FUNCT3(inst);
        rs1 = RS1(inst);
        rs2 = RS2(inst);
        funct7 = FUNCT7(inst);

        switch (opcode) {
            case 0x33: 
                switch (funct3) {
                    case 0x0:
                        if (funct7 == 0x00) R[rd] = R[rs1] + R[rs2];
                        else if (funct7 == 0x20) R[rd] = R[rs1] - R[rs2];
                        else if (funct7 == 0x01) R[rd] = R[rs1] * R[rs2];
                        else { fprintf(stderr, "Invalid R-type funct7: 0x%x\n", funct7); running = false; }
                        break;
                    case 0x1:
                        if (funct7 == 0x00) R[rd] = R[rs1] << R[rs2];
                        else if (funct7 == 0x01) R[rd] = (uint32_t)((int64_t)(int32_t)R[rs1] * (int64_t)(int32_t)R[rs2] >> 32);
                        else { fprintf(stderr, "Invalid R-type funct7: 0x%x\n", funct7); running = false; }
                        break;
                    case 0x2:
                        if (funct7 == 0x00) R[rd] = ((int32_t)R[rs1] < (int32_t)R[rs2]) ? 1 : 0;
                        else if (funct7 == 0x01) { }
                        else { fprintf(stderr, "Invalid R-type funct7: 0x%x\n", funct7); running = false; }
                        break;
                    case 0x3:
                        if (funct7 == 0x00) R[rd] = (R[rs1] < R[rs2]) ? 1 : 0;
                        else if (funct7 == 0x01) { }
                        else { fprintf(stderr, "Invalid R-type funct7: 0x%x\n", funct7); running = false; }
                        break;
                    case 0x4:
                        if (funct7 == 0x00) R[rd] = R[rs1] ^ R[rs2];
                        else if (funct7 == 0x01) R[rd] = ((int32_t)R[rs2] == 0) ? (int32_t)-1 : ((int32_t)R[rs1] / (int32_t)R[rs2]);
                        else { fprintf(stderr, "Invalid R-type funct7: 0x%x\n", funct7); running = false; }
                        break;
                    case 0x5:
                        shamt = R[rs2] & 0x1F;
                        if (funct7 == 0x00) R[rd] = R[rs1] >> shamt;
                        else if (funct7 == 0x20) R[rd] = (uint32_t)((int32_t)R[rs1] >> shamt);
                        else if (funct7 == 0x01) R[rd] = (R[rs2] == 0) ? 0xFFFFFFFFU : (R[rs1] / R[rs2]);
                        else { fprintf(stderr, "Invalid R-type funct7: 0x%x\n", funct7); running = false; }
                        break;
                    case 0x6:
                        if (funct7 == 0x00) R[rd] = R[rs1] | R[rs2];
                        else if (funct7 == 0x01) R[rd] = ((int32_t)R[rs2] == 0) ? R[rs1] : (uint32_t)((int32_t)R[rs1] % (int32_t)R[rs2]);
                        else { fprintf(stderr, "Invalid R-type funct7: 0x%x\n", funct7); running = false; }
                        break;
                    case 0x7:
                        if (funct7 == 0x00) R[rd] = R[rs1] & R[rs2];
                        else if (funct7 == 0x01) R[rd] = (R[rs2] == 0) ? R[rs1] : (R[rs1] % R[rs2]);
                        else { fprintf(stderr, "Invalid R-type funct7: 0x%x\n", funct7); running = false; }
                        break;
                    default: fprintf(stderr, "Invalid R-type funct3: 0x%x\n", funct3); running = false; break;
                }
                break;

            case 0x13: 
                imm = decode_imm_I(inst);
                switch (funct3) {
                    case 0x0: R[rd] = R[rs1] + imm; break;
                    case 0x1: R[rd] = R[rs1] << (imm & 0x1F); break;
                    case 0x2: R[rd] = ((int32_t)R[rs1] < imm) ? 1 : 0; break;
                    case 0x3: R[rd] = (R[rs1] < (uint32_t)imm) ? 1 : 0; break;
                    case 0x4: R[rd] = R[rs1] ^ imm; break;
                    case 0x5:
                        shamt = imm & 0x1F;
                        if (funct7 == 0x00) R[rd] = R[rs1] >> shamt;
                        else if (funct7 == 0x20) R[rd] = (uint32_t)((int32_t)R[rs1] >> shamt);
                        else { fprintf(stderr, "Invalid shift imm: 0x%x\n", funct7); running = false; }
                        break;
                    case 0x6: R[rd] = R[rs1] | imm; break;
                    case 0x7: R[rd] = R[rs1] & imm; break;
                    default: fprintf(stderr, "Invalid I-type funct3: 0x%x\n", funct3); running = false; break;
                }
                break;

            case 0x03: 
                imm = decode_imm_I(inst);
                uint32_t addr = R[rs1] + imm;
                switch (funct3) {
                    case 0x0: R[rd] = (uint32_t)(int32_t)memory_rd_b(mem, addr); break;
                    case 0x1: R[rd] = (uint32_t)(int32_t)memory_rd_h(mem, addr); break;
                    case 0x2: R[rd] = (uint32_t)memory_rd_w(mem, addr); break;
                    case 0x4: R[rd] = (uint32_t)memory_rd_b(mem, addr) & 0xFF; break;
                    case 0x5: R[rd] = (uint32_t)memory_rd_h(mem, addr) & 0xFFFF; break;
                    default: fprintf(stderr, "Invalid Load funct3: 0x%x\n", funct3); running = false; break;
                }
                break;

            case 0x23: 
                imm = decode_imm_S(inst);
                addr = R[rs1] + imm;
                switch (funct3) {
                    case 0x0: memory_wr_b(mem, addr, R[rs2]); break;
                    case 0x1: memory_wr_h(mem, addr, R[rs2]); break;
                    case 0x2: memory_wr_w(mem, addr, R[rs2]); break;
                    default: fprintf(stderr, "Invalid Store funct3: 0x%x\n", funct3); running = false; break;
                }
                break;

            case 0x63: 
                imm = decode_imm_B(inst);
                bool branch_taken = false;
                switch (funct3) {
                    case 0x0: branch_taken = (R[rs1] == R[rs2]); break;
                    case 0x1: branch_taken = (R[rs1] != R[rs2]); break;
                    case 0x4: branch_taken = ((int32_t)R[rs1] < (int32_t)R[rs2]); break;
                    case 0x5: branch_taken = ((int32_t)R[rs1] >= (int32_t)R[rs2]); break;
                    case 0x6: branch_taken = (R[rs1] < R[rs2]); break;
                    case 0x7: branch_taken = (R[rs1] >= R[rs2]); break;
                    default: fprintf(stderr, "Invalid Branch funct3: 0x%x\n", funct3); running = false; break;
                }
                if (branch_taken) PC = pc_current + imm;
                break;

            case 0x67: 
                imm = decode_imm_I(inst);
                R[rd] = pc_current + 4;
                PC = (R[rs1] + imm) & ~1;
                break;

            case 0x6f: 
                imm = decode_imm_J(inst);
                R[rd] = pc_current + 4;
                PC = pc_current + imm;
                break;

            case 0x37: 
                imm = decode_imm_U(inst);
                R[rd] = (uint32_t)imm;
                break;

            case 0x17: 
                imm = decode_imm_U(inst);
                R[rd] = pc_current + (uint32_t)imm;
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

        if (log_execution) {
            disassemble(pc_current, inst, disasm_buf, sizeof(disasm_buf), symbols);
            fprintf(log_file, "%7llu => 0x%08x : %08x %s\n", (unsigned long long)instruction_count, pc_current, inst, disasm_buf);
        }
    }

    struct Stat final_stats = { .insns = instruction_count };
    return final_stats;
}  