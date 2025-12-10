#include "disassemble.h" 
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>


static const char *reg_names[] = {
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1",
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3",
    "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
    "t5", "t6"
};

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
    uint32_t imm = (((inst >> 25) & 0x7F) << 5) | ((inst >> 7) & 0x1F);
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


void disassemble(uint32_t pc, uint32_t inst, char *buf, size_t buf_size, struct symbols* symbols) {
    (void)symbols; 
    
    uint32_t opcode = inst & 0x7F;
    uint32_t rd = (inst >> 7) & 0x1F;
    uint32_t funct3 = (inst >> 12) & 0x7;
    uint32_t rs1 = (inst >> 15) & 0x1F;
    uint32_t rs2 = (inst >> 20) & 0x1F;
    uint32_t funct7 = (inst >> 25) & 0x7F;
    
    int32_t imm; 
    uint32_t shamt = rs2; 

    const char *sym_name = NULL;
    char imm_str[64];

    switch (opcode) {
        

        case 0x33:
            switch (funct3) {
                case 0x0: 
                    if (funct7 == 0x00) snprintf(buf, buf_size, "add %s, %s, %s", reg_names[rd], reg_names[rs1], reg_names[rs2]);
                    else if (funct7 == 0x20) snprintf(buf, buf_size, "sub %s, %s, %s", reg_names[rd], reg_names[rs1], reg_names[rs2]);
                    else if (funct7 == 0x01) snprintf(buf, buf_size, "mul %s, %s, %s", reg_names[rd], reg_names[rs1], reg_names[rs2]);
                    else snprintf(buf, buf_size, "unknown_r_0x%x_0x%x", funct3, funct7);
                    break;
                case 0x1: 
                    if (funct7 == 0x00) snprintf(buf, buf_size, "sll %s, %s, %s", reg_names[rd], reg_names[rs1], reg_names[rs2]);
                    else if (funct7 == 0x01) snprintf(buf, buf_size, "mulh %s, %s, %s", reg_names[rd], reg_names[rs1], reg_names[rs2]);
                    else snprintf(buf, buf_size, "unknown_r_0x%x_0x%x", funct3, funct7);
                    break;
                case 0x2: 
                    if (funct7 == 0x00) snprintf(buf, buf_size, "slt %s, %s, %s", reg_names[rd], reg_names[rs1], reg_names[rs2]);
                    else if (funct7 == 0x01) snprintf(buf, buf_size, "mulhsu %s, %s, %s", reg_names[rd], reg_names[rs1], reg_names[rs2]);
                    else snprintf(buf, buf_size, "unknown_r_0x%x_0x%x", funct3, funct7);
                    break;
                case 0x3: 
                    if (funct7 == 0x00) snprintf(buf, buf_size, "sltu %s, %s, %s", reg_names[rd], reg_names[rs1], reg_names[rs2]);
                    else if (funct7 == 0x01) snprintf(buf, buf_size, "mulhu %s, %s, %s", reg_names[rd], reg_names[rs1], reg_names[rs2]);
                    else snprintf(buf, buf_size, "unknown_r_0x%x_0x%x", funct3, funct7);
                    break;
                case 0x4: 
                    if (funct7 == 0x00) snprintf(buf, buf_size, "xor %s, %s, %s", reg_names[rd], reg_names[rs1], reg_names[rs2]);
                    else if (funct7 == 0x01) snprintf(buf, buf_size, "div %s, %s, %s", reg_names[rd], reg_names[rs1], reg_names[rs2]);
                    else snprintf(buf, buf_size, "unknown_r_0x%x_0x%x", funct3, funct7);
                    break;
                case 0x5: 
                    if (funct7 == 0x00) snprintf(buf, buf_size, "srl %s, %s, %s", reg_names[rd], reg_names[rs1], reg_names[rs2]);
                    else if (funct7 == 0x20) snprintf(buf, buf_size, "sra %s, %s, %s", reg_names[rd], reg_names[rs1], reg_names[rs2]);
                    else if (funct7 == 0x01) snprintf(buf, buf_size, "divu %s, %s, %s", reg_names[rd], reg_names[rs1], reg_names[rs2]);
                    else snprintf(buf, buf_size, "unknown_r_0x%x_0x%x", funct3, funct7);
                    break;
                case 0x6: 
                    if (funct7 == 0x00) snprintf(buf, buf_size, "or %s, %s, %s", reg_names[rd], reg_names[rs1], reg_names[rs2]);
                    else if (funct7 == 0x01) snprintf(buf, buf_size, "rem %s, %s, %s", reg_names[rd], reg_names[rs1], reg_names[rs2]);
                    else snprintf(buf, buf_size, "unknown_r_0x%x_0x%x", funct3, funct7);
                    break;
                case 0x7: 
                    if (funct7 == 0x00) snprintf(buf, buf_size, "and %s, %s, %s", reg_names[rd], reg_names[rs1], reg_names[rs2]);
                    else if (funct7 == 0x01) snprintf(buf, buf_size, "remu %s, %s, %s", reg_names[rd], reg_names[rs1], reg_names[rs2]);
                    else snprintf(buf, buf_size, "unknown_r_0x%x_0x%x", funct3, funct7);
                    break;
                default:
                    snprintf(buf, buf_size, "unknown_r_0x%x", funct3);
                    break;
            }
            break;
            

        case 0x13:
            imm = decode_imm_I(inst);
            switch (funct3) {
                case 0x0: 
                    snprintf(buf, buf_size, "addi %s, %s, %d", reg_names[rd], reg_names[rs1], imm);
                    break;
                case 0x1: 
                    shamt = rs2;
                    snprintf(buf, buf_size, "slli %s, %s, %u", reg_names[rd], reg_names[rs1], shamt);
                    break;
                case 0x2: 
                    snprintf(buf, buf_size, "slti %s, %s, %d", reg_names[rd], reg_names[rs1], imm);
                    break;
                case 0x3: 
                    snprintf(buf, buf_size, "sltiu %s, %s, %u", reg_names[rd], reg_names[rs1], imm);
                    break;
                case 0x4: 
                    snprintf(buf, buf_size, "xori %s, %s, %d", reg_names[rd], reg_names[rs1], imm);
                    break;
                case 0x5: 
                    shamt = rs2;
                    if (funct7 == 0x00) snprintf(buf, buf_size, "srli %s, %s, %u", reg_names[rd], reg_names[rs1], shamt);
                    else if (funct7 == 0x20) snprintf(buf, buf_size, "srai %s, %s, %u", reg_names[rd], reg_names[rs1], shamt);
                    else snprintf(buf, buf_size, "unknown_i_shift_0x%x", funct7);
                    break;
                case 0x6: 
                    snprintf(buf, buf_size, "ori %s, %s, %d", reg_names[rd], reg_names[rs1], imm);
                    break;
                case 0x7: 
                    snprintf(buf, buf_size, "andi %s, %s, %d", reg_names[rd], reg_names[rs1], imm);
                    break;
                default:
                    snprintf(buf, buf_size, "unknown_i_0x%x", funct3);
                    break;
            }
            break;


        case 0x03:
            imm = decode_imm_I(inst);
            switch (funct3) {
                case 0x0: 
                    snprintf(buf, buf_size, "lb %s, %d(%s)", reg_names[rd], imm, reg_names[rs1]);
                    break;
                case 0x1: 
                    snprintf(buf, buf_size, "lh %s, %d(%s)", reg_names[rd], imm, reg_names[rs1]);
                    break;
                case 0x2: 
                    snprintf(buf, buf_size, "lw %s, %d(%s)", reg_names[rd], imm, reg_names[rs1]);
                    break;
                case 0x4: 
                    snprintf(buf, buf_size, "lbu %s, %d(%s)", reg_names[rd], imm, reg_names[rs1]);
                    break;
                case 0x5: 
                    snprintf(buf, buf_size, "lhu %s, %d(%s)", reg_names[rd], imm, reg_names[rs1]);
                    break;
                default:
                    snprintf(buf, buf_size, "unknown_load_0x%x", funct3);
                    break;
            }
            break;
            

        case 0x23:
            imm = decode_imm_S(inst);
            switch (funct3) {
                case 0x0: 
                    snprintf(buf, buf_size, "sb %s, %d(%s)", reg_names[rs2], imm, reg_names[rs1]);
                    break;
                case 0x1: 
                    snprintf(buf, buf_size, "sh %s, %d(%s)", reg_names[rs2], imm, reg_names[rs1]);
                    break;
                case 0x2: 
                    snprintf(buf, buf_size, "sw %s, %d(%s)", reg_names[rs2], imm, reg_names[rs1]);
                    break;
                default:
                    snprintf(buf, buf_size, "unknown_store_0x%x", funct3);
                    break;
            }
            break;
        

        case 0x63:
            imm = decode_imm_B(inst);

            
            if (sym_name) {
                snprintf(imm_str, sizeof(imm_str), "%s <+%d>", sym_name, imm);
            } else {
                snprintf(imm_str, sizeof(imm_str), "0x%x", pc + imm);
            }
            
            switch (funct3) {
                case 0x0: 
                    snprintf(buf, buf_size, "beq %s, %s, %s", reg_names[rs1], reg_names[rs2], imm_str);
                    break;
                case 0x1: 
                    snprintf(buf, buf_size, "bne %s, %s, %s", reg_names[rs1], reg_names[rs2], imm_str);
                    break;
                case 0x4: 
                    snprintf(buf, buf_size, "blt %s, %s, %s", reg_names[rs1], reg_names[rs2], imm_str);
                    break;
                case 0x5: 
                    snprintf(buf, buf_size, "bge %s, %s, %s", reg_names[rs1], reg_names[rs2], imm_str);
                    break;
                case 0x6: 
                    snprintf(buf, buf_size, "bltu %s, %s, %s", reg_names[rs1], reg_names[rs2], imm_str);
                    break;
                case 0x7: 
                    snprintf(buf, buf_size, "bgeu %s, %s, %s", reg_names[rs1], reg_names[rs2], imm_str);
                    break;
                default:
                    snprintf(buf, buf_size, "unknown_branch_0x%x", funct3);
                    break;
            }
            break;
            

        case 0x67: 
            imm = decode_imm_I(inst);
            snprintf(buf, buf_size, "jalr %s, %s, %d", reg_names[rd], reg_names[rs1], imm);
            break;
            

        case 0x6f: 
            imm = decode_imm_J(inst);

            
            if (sym_name) {
                snprintf(imm_str, sizeof(imm_str), "%s <+%d>", sym_name, imm);
            } else {
                snprintf(imm_str, sizeof(imm_str), "0x%x", pc + imm);
            }
            snprintf(buf, buf_size, "jal %s, %s", reg_names[rd], imm_str);
            break;


        case 0x37: 
            imm = decode_imm_U(inst);
            snprintf(buf, buf_size, "lui %s, 0x%x", reg_names[rd], (uint32_t)imm >> 12);
            break;


        case 0x17: 
            imm = decode_imm_U(inst);
            snprintf(buf, buf_size, "auipc %s, 0x%x", reg_names[rd], (uint32_t)imm >> 12);
            break;

        case 0x73: 
            imm = decode_imm_I(inst); 
            
            if (funct3 == 0x0) { 
                if (imm == 0x000) {
                    snprintf(buf, buf_size, "ecall");
                } else if (imm == 0x001) {
                    snprintf(buf, buf_size, "ebreak");
                } else {
                    snprintf(buf, buf_size, "skip_priv_0x%x", imm);
                }
            } else {
                snprintf(buf, buf_size, "skip_csr_0x%x", funct3);
            }
            break;
            
        default: 
            snprintf(buf, buf_size, "unknown_opcode_0x%x", opcode);
            break;
    }
}