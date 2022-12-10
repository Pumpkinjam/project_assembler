import sys
import string
import re
import struct

# 28 bits except cond
inst_format = {
    "dp" : "00{I}{opcode}{S}{Rn}{Rd}{operand2}",
    "mul" : "000000{A}{S}{Rd}{Rn}{Rs}1001{Rm}",
    "mull" : "00001{U}{A}{S}{RdHi}{RdLo}{Rs}1001{Rm}",
    "ldrstr" : "01{I}{P}{U}{B}{W}{L}{Rn}{Rd}{offset}",
    "ldrh_imm" : "000{P}{U}1{W}{L}{Rn}{Rd}{offst1}1{S}{H}1{offst2}",
    "ldrh_reg" : "000{P}{U}0{W}{L}{Rn}{Rd}00001{S}{H}1{Rm}",
    "ldmstm" : "100{P}{U}{S}{W}{L}{Rn}{reglist}",
    "b" : "101{L}{offset}",
    "bx" : "000100101111111100000001{Rn}",
    "swi" : "1111{swinum}",
    "swp" : "00010{B}00{Rn}{Rd}00001001{Rm}",
    "ldcsdc" : "110{P}{U}{N}{W}{L}{Rn}{CRd}{CPNum}{offset}",
    "coproc" : "1110{op1}{CRn}{CRd}{CPNum}{op2}0{CRm}",
    "mrcmcr" : "1110{op1}{L}{CRn}{CRd}{CPNum}{op2}1{CRm}",
    "msr" : "00010{P}101001111100000000{Rm}",
    "mrs" : "00{I}10{P}10{field}1111{operand2}"
}

cond_dict = {
    'eq': '0000', 'ne': '0001', 'hs': '0010', 'cs': '0010', 'lo': '0011',
    'cc': '0011', 'mi': '0100', 'pl': '0101', 'vs': '0110', 'vc': '0111',
    'hi': '1000', 'ls': '1001', 'ge': '1010', 'lt': '1011', 'gt': '1100',
    'le': '1101', 'al': '1110', 'nv': '1111', '': '1110'
}

registers = {
    'r0': '0000', 'r1': '0001', 'r2': '0010', 'r3': '0011', 'r4': '0100',
    'r5': '0101', 'r6': '0110', 'r7': '0111', 'r8': '1000', 'r9': '1001',
    'r10': '1010', 'r11': '1011', 'r12': '1100', 'r13': '1101',
    'r14': '1110', 'r15': '1111', 'sl': '1010', 'fp': '1011',
    'ip': '1100', 'sp': '1101', 'lr': '1110', 'pc': '1111'
}

opcode_dict = {
    'and': '0000', 'eor': '0001', 'sub': '0010', 'rsb': '0011',
    'add': '0100', 'adc': '0101', 'sbc': '0110', 'rsc': '0111',
    'tst': '1000', 'teq': '1001', 'cmp': '1010', 'cmn': '1011',
    'orr': '1100', 'mov': '1101', 'bic': '1110', 'mvn': '1111'
}

class SyntaxErrorException(Exception):
    def __init__(self, msg='', line_number: int = None):
        error_msg = 'Syntax Error : ' + ('Unknown Syntax' if msg=='' else msg)
        if line_number is not None: error_msg += f' in line {line_number}'

        print(error_msg)
        sys.exit(1)

def rotate_right(binary: str, rot: int):
    if (len(binary) < 32):
        binary = '0'*(32-len(binary)) + binary

    return binary[32-rot:] + binary[:32-rot]

'''
#123    -> 123
#0b1111 -> 15
#0xff   -> 255
#024    -> 20

also considering rot
'''
def imm_to_operand2(literal: str) -> str:

    if literal[0] != '#':   # will not be happened. maybe...
        print('expected \'#\' for immediate value.')
        raise Exception()
    
    
    if (literal.startswith('#0x')):
        res = bin(int(literal[3:], 16))[2:]
    elif (literal.startswith('#0b')):
        res = literal[3:]
    elif (literal.startswith('#0')):
        res = bin(int(literal[2:], 8))[2:]
    else:
        res = bin(int(literal[1:]))[2:]

    
    for i in range(0,32,2):
        tmp = rotate_right(res, i).strip('0')
        if len(tmp) <= 8: 
            operand2 = f'{bin(i//2)[2:]:0>4}{tmp:0>8}'
            break
    else:
        raise SyntaxErrorException('Invalid Immediate Value')
    
    
    return operand2

def bin_to_hex(binary_code: str) -> str:
    print(f'binary : {binary_code:0>32}')

    hex_code = hex(int(binary_code, 2))
    print(f'hex : {hex_code}')

    return hex_code

def data_processing(opcode, tokens: list) -> str:

    # remove ',' in the tokens
    try:
        while True:
            tokens.remove(',')
    except:
        pass

    tmp = tokens[0].replace(opcode, '')

    # special case : mrs
    # mrs{<cond>} Rm, <cpsr|spsr>
    if opcode == 'mrs':
        cond = cond_dict[tmp]
        Rm = tokens[1]
        P = '0' if tokens[2] == 'cpsr' else '1' if tokens[2] == 'spsr' else '-'
        if P == '-': raise SyntaxErrorException('neither cpsr nor spsr')

        binary_code = cond + f'00010{P}101001111100000000{Rm}'
    
    # special case : msr
    # msr{<cond>} <cpsr|spsr>_<fields>, Rm
    # msr{<cond>} <cpsr|spsr>_<fields>, #imm
    elif opcode == 'msr':
        cond = cond_dict[tmp]
        
        if tokens[2].startswith('#'):
            I = '1'
            operand2 = imm_to_operand2(tokens[2])
        else:
            I = '0'
            operand2 = '0' * 8 + tokens[2]

        psr = tokens[1]

        if psr.startswith('cpsr'):
            P = '0'
        elif psr.startswith('spsr'):
            P = '1'
        else:
            raise SyntaxErrorException('neither cpsr nor spsr')
        
        field_str = psr[5:]
        if field_str == '':
            field = '1111'
        else:
            field = ''
            field += '1' if 'f' in field_str else '0'
            field += '1' if 's' in field_str else '0'
            field += '1' if 'x' in field_str else '0'
            field += '1' if 'c' in field_str else '0'
        
        binary_code = cond + f'00{I}10{P}10{field}1111{operand2}'

    # mov, mvn, cmp, teq, tst : [opcode, Rd] + [imm]    or 
    #                           [Rm (, rrx)]            or
    #                           [Rm (, sh, #shift)]     or 
    #                           [Rm (, sh, Rs)]
    # else : [opcode, Rd, Rn] + [Rm, ...] (3 cases are same to mov family)
    else:
        S = '0'
        if tmp.endswith('s'):
            S = '1'
            tmp = tmp[:len(tmp)-1]
        cond = cond_dict[tmp]

        Rd = registers[tokens[1]]
        if opcode in ('mov', 'mvn', 'cmp', 'teq', 'tst'):
            Rn = '0000'
            op2_tokens = tokens[2:]
        else:
            Rn = registers[tokens[2]]
            op2_tokens = tokens[3:]


        if (op2_tokens == []):
            raise SyntaxErrorException('mov : missing operand')

        if op2_tokens[0].startswith('#'):
            I = '1'
            operand2 = imm_to_operand2(op2_tokens[0])
        else:
            I = '0'
            Rm = registers[op2_tokens[0]]

            if len(op2_tokens) == 1:
                operand2 = f'00000000{Rm}'
            else:
                if op2_tokens[1] == 'rrx':
                    operand2 = f'00000110{registers[Rm]}'

                else:
                    shift_dict = {
                        'lsl' : '00',
                        'lsr' : '01',
                        'asr' : '10',
                        'ror' : '11'
                    }
                    shift_inst = op2_tokens[1] # lsl, lsr, asr, ror
                    shift = shift_dict[shift_inst]

                    if op2_tokens[2].startswith('#'):
                        operand2 = f'{bin(int(op2_tokens[2][1:]))[2:]}{shift}0{Rm}'

                    else:
                        operand2 = f'{registers[op2_tokens[2]]}0{shift}1{Rm}'

        binary_code = cond + inst_format['dp'].format(I=I, opcode=opcode_dict[opcode], S=S, Rn=Rn, Rd=Rd, operand2=operand2)
            
    return bin_to_hex(binary_code)

def msrmrs_processing(inst, toekns: list) -> str:
    # remove ',' in the tokens
    try:
        while True:
            print('asdf')
            tokens.remove(',')
    except:
        pass

    tmp = tokens[0].replace(inst, '')

    # special case : mrs
    # mrs{<cond>} Rm, <cpsr|spsr>
    if inst == 'mrs':
        cond = cond_dict[tmp]
        Rm = registers[Rm]
        P = '0' if tokens[2] == 'cpsr' else '1' if tokens[2] == 'spsr' else '-'
        if P == '-': raise SyntaxErrorException('neither cpsr nor spsr')

        binary_code = cond + f'00010{P}101001111100000000{Rm}'
    
    # special case : msr
    # msr{<cond>} <cpsr|spsr>_<fields>, Rm
    # msr{<cond>} <cpsr|spsr>_<fields>, #imm
    elif inst == 'msr':
        cond = cond_dict[tmp]
        
        if tokens[2].startswith('#'):
            I = '1'
            operand2 = imm_to_operand2(tokens[2])
        else:
            I = '0'
            operand2 = '0' * 8 + registers[tokens[2]]

        psr = tokens[1]

        if psr.startswith('cpsr'):
            P = '0'
        elif psr.startswith('spsr'):
            P = '1'
        else:
            raise SyntaxErrorException('neither cpsr nor spsr')
        
        field_str = psr[5:]
        if field_str == '':
            field = '1111'
        else:
            field = ''
            field += '1' if 'f' in field_str else '0'
            field += '1' if 's' in field_str else '0'
            field += '1' if 'x' in field_str else '0'
            field += '1' if 'c' in field_str else '0'
        
        binary_code = cond + f'00{I}10{P}10{field}1111{operand2}'

    print('asdfasdf')
    return bin_to_hex(binary_code)

def other_instructions(inst, tokens: list) -> str:
    pass

# not used. maybe..?
def split(line: str, target: tuple) -> list:
    res = []
    last_idx = 0
    for i in range(len(line)):
        if line[i] in target:
            res.append(line[last_idx:i])
            res.append(line[i])
            last_idx = i+1
    
    return res
    
def trim(tokens: list, target: tuple) -> list:
    return [c for c in tokens if c not in target]


### main() starts here ###
    
#lines = sys.stdin.readlines()
lines = ('_start: .global _start',
'mov r0, #1',
'movlt r1, r0',
'movs r2, r0, lsl #2',
'mov r3, #4, lsl #5',
'add r1, r2, r3',
'rsb r2, r1, r0, lsl, r5',
'eor r1, r1, r0',
'subgt r2, r1, r0, ror, #5',
'msr spsr_c, r0')
splitter = re.compile(r'([ \t\n,])')

line_number = 0
   
for line in lines:
    line_number += 1

    line = line.lower()
    print(line)
    tokens = splitter.split(line)
    #print(tokens)
    #tokens = [tok for tok in tokens
    #          if re.match('\s*$', tok) == None]
    tokens = trim(tokens, ('', ' ', ',', '@')) # ex) ['add', 'r0', 'r1', 'r2', 'lsl', '#5']
    #print(tokens)


    while len(tokens) > 0:
        if tokens[0].endswith(':'): # process label
            print('\tLABEL ' + tokens[0].rstrip(':') + ' FOUND')
            tokens = tokens[1:]
            continue
        elif tokens[0].startswith('.'): # process directive
            print('\tDIRECTIVE ' + tokens[0] + ' FOUND')
            tokens = tokens[1:]
            continue
        else: break # process instruction
    else: continue  # no instruction after, or an empty line

    instruction = tokens[0]

    for target in opcode_dict:
        if target in instruction:
            data_processing(target, tokens)
            break
    else:
        if instruction in ('mrs', 'msr'):
            msrmrs_processing(instruction, tokens)
        else:
            try:
                other_instructions(instruction, tokens)
            except:
                raise SyntaxErrorException('instruction not found', line_number)

    


    
