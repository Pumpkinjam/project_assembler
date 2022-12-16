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
    "b" : "101{L}{offset:0>24}",
    "bx" : "000100101111111100000001{Rn}",                      # not used. just be processed with "b"
    "swi" : "1111{swinum:0>24}",                                # not used. generates format in function
    "swp" : "00010{B}00{Rn}{Rd}00001001{Rm}",
    "ldcsdc" : "110{P}{U}{N}{W}{L}{Rn}{CRd}{CPNum}{offset}",    # how..?
    "cdp" : "1110{op1}{CRn}{CRd}{CPNum}{op2}0{CRm}",            # how..?
    "mrcmcr" : "1110{op1}{L}{CRn}{CRd}{CPNum}{op2}1{CRm}",      # how..?
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

def rotate_left(binary: str, rot: int):
    if (len(binary) < 32):
        binary = f'{binary:0>32}'
    return rotate_right(binary, 32-rot)

'''
complement_two("1111")      => '0001'
complement_two("100100")    => '011100'
'''
def complement_two(binary: str):
    res = ''
    for i in range(len(binary)):
        res += '1' if binary[i] == '0' else '0'
    
    tmp = ''
    for i in range(len(res)-1, -1, -1):
        if res[i] == '0':
            tmp = '1' + tmp
            break
        else:
            tmp = '0' + tmp
    
    return res[:i] + tmp

'''
imm_to_binary("#12", 0)     => '1100'
imm_to_binary("#3", 1)      => '11'
imm_to_binary("#0xff", 10)  => '0011111111'
imm_to_binary("#-10")       => '0110'
imm_to_binary("#-0xff", ignore_sign = True) => '11111111'
'''
def imm_to_binary(literal: str, length: int = 0, ignore_sign: bool = False) -> str:
    if literal[0] != '#':   # will not be happened. maybe...
        literal = '#' + literal
    
    neg = False
    if literal[1] == '-':
        neg = True
        literal = '#' + literal[2:]
    
    if (literal.startswith('#0x')):
        res = f'{bin( int( literal[3:], 16))[2:]}'
    elif (literal.startswith('#0b')):
        res = literal[3:]
    elif (literal.startswith('#0')):
        res = f'{bin(int(literal[2:], 8))[2:]}'
    else:
        res = f'{bin(int(literal[1:]))[2:]}'

    res = '0' * (length-len(res)) + res
    
    return res if (not neg or ignore_sign) else complement_two(res)

'''
#123    -> 000001111011
#0b1111 -> 000000001111
#0xff   -> 000011111111
#024    -> 000000010100

also considering rot
'''
def imm_to_operand2(literal: str) -> str:

    res = imm_to_binary(literal, 32)

    for i in range(0,32,2):
        tmp = rotate_left(res, i).lstrip('0')

        if len(tmp) <= 8:
            operand2 = f'{bin(i//2)[2:]:0>4}{tmp:0>8}'
            break
    else:
        raise SyntaxErrorException('Invalid Immediate Value')
    
    
    return operand2

def shift_to_operand2(tokens: list) -> str:
    Rm = registers[tokens[0]]

    # case : no barrel shift
    if len(tokens) == 1: 
        operand2 = f'00000000{Rm}'
    else:
        if tokens[1] == 'rrx':
            operand2 = f'00000110{Rm}'

        else:
            shift_dict = {
                'lsl' : '00',
                'lsr' : '01',
                'asr' : '10',
                'ror' : '11'
            }
            shift_inst = tokens[1] # lsl, lsr, asr, ror
            shift = shift_dict[shift_inst]

            if tokens[2].startswith('#'):
                operand2 = f'{bin(int(tokens[2][1:]))[2:]:0>5}{shift}0{Rm}'

            else:
                operand2 = f'{registers[tokens[2]]}0{shift}1{Rm}'
        
        return operand2

def bit4_to_hex(bits: str) -> str:
    bits = f'{bits:0>4}'
    if len(bits) != 4: raise Exception(f'Must receive just 4 bits. given string is {bits}')
    return hex(int(bits, 2))[2:]

def bin_to_hex(binary_code: str) -> str:
    print(f'binary : {binary_code:0>32}')

    hex_code = '0x'
    for i in range(0, 32, 4):
        tmp = binary_code[i:i+4]
        hex_code += bit4_to_hex(tmp)

    print(f'hex : {hex_code}')

    return hex_code

def data_processing(opcode, tokens: list, line_number: int) -> str:

    # remove ',' in the tokens
    try:
        while True:
            tokens.remove(',')
    except:
        pass

    operand2 = '0'*12
    tmp = tokens[0].replace(opcode, '')

    # special case : mrs
    # mrs{<cond>} Rm, <cpsr|spsr>
    if opcode == 'mrs':
        cond = cond_dict[tmp]
        Rm = tokens[1]
        P = '0' if tokens[2] == 'cpsr' else '1' if tokens[2] == 'spsr' else '-'
        if P == '-': raise SyntaxErrorException('neither cpsr nor spsr', line_number)

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
            raise SyntaxErrorException('neither cpsr nor spsr', line_number)
        
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

    # mov, mvn, cmp, cmn, teq, tst: [opcode, Rd] + [imm]    or 
    #                               [Rm (, rrx)]            or
    #                               [Rm (, sh, #shift)]     or 
    #                               [Rm (, sh, Rs)]
    # else : [opcode, Rd, Rn] + [Rm, ...] (3 cases are same to mov family)
    else:
        l = len(tmp)
        S = '0'
        cond = '1110'

        if l==0: pass
        elif l==1:    # check s flag
            if tmp=='s':
                S = '1'
            else: raise SyntaxErrorException('Invalid mnemonic', line_number)

        elif l==2:  # check condition
            if tmp in cond_dict:
                cond = cond_dict[tmp]
            else: raise SyntaxErrorException('Invalid mnemonic', line_number)

        elif l==3:  # check both
            if tmp[0] != 's' or tmp[1:] not in cond_dict: 
                raise SyntaxErrorException('Invalid mnemonic', line_number)
            S = '1'
            cond = cond_dict[tmp[1:]]

        else: raise SyntaxErrorException('Invalid mnemonic', line_number)


        Rd = registers[tokens[1]]
        if opcode in ('cmp', 'cmn', 'teq', 'tst'):
            S = '1'
            Rn = Rd
            Rd = '0000'
            op2_tokens = tokens[2:]

        elif opcode in ('mov', 'mvn'):
            Rn = '0000'
            op2_tokens = tokens[2:]

        else:
            Rn = registers[tokens[2]]
            op2_tokens = tokens[3:]

        # no operand exception (missing Rm or imm)
        if (op2_tokens == []):
            raise SyntaxErrorException('missing operand', line_number)

        # check immediate value
        if op2_tokens[0].startswith('#'):
            I = '1'
            operand2 = imm_to_operand2(op2_tokens[0])

        else:
            I = '0'
            shift_to_operand2(op2_tokens)

#        print(f'I = {I} / opcode = {opcode} / S = {S} / Rn = {Rn} / Rd = {Rd} / operand2 = {operand2}')
        binary_code = cond + inst_format['dp'].format(I=I, opcode=opcode_dict[opcode], S=S, Rn=Rn, Rd=Rd, operand2=operand2)
            
    return bin_to_hex(binary_code)

def msrmrs_processing(inst, toekns: list, line_number: int) -> str:
    # remove ',' in the tokens
    try:
        while True:
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
        if P == '-': raise SyntaxErrorException('neither cpsr nor spsr', line_number)

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
            raise SyntaxErrorException('neither cpsr nor spsr', line_number)
        
        field_str = psr[5:]
        if field_str == '':
            field = '1111'
        else:
            if field_str=='all': 
                field='1111'
            else:
                field = ''
                for c in ('f', 's', 'x', 'c'):
                    field += '1' if c in field_str else '0'
            
        
        binary_code = cond + f'00{I}10{P}10{field}1111{operand2}'

    return bin_to_hex(binary_code)

def other_instructions(inst, tokens: list, line_number: int) -> str:

    scon = inst[3:]
    try:
        if len(scon) == 2:
            S = '0'
            cond = cond_dict[scon]
        else:
            S = '1'
            cond = cond_dict[scon[1:]]
    except(KeyError):
        pass

    # instruction starts with 'b', must be 'b' 'bl' 'bx' kinds of thing
    # and these guys never has S flag
    # todo : offset must be pc-relative
    if inst.startswith('b'):
        tmp = len(inst)
        res = inst_format['b']

        # just 'b'
        if tmp==1:
            cond = '1110'
            L = '0'

        # just 'bx' or 'bl'
        elif tmp==2:
            cond = '1110'
            L = '1'

        # b{cond}
        elif tmp==3:
            cond = cond_dict[inst[1:]]
            inst = 'b'
            L = '0'
        
        # bx{cond} or bl{cond}
        elif tmp==4:
            cond = cond_dict[inst[2:]]
            inst = inst[:2]
            L = '1'
        
        else:
            raise SyntaxErrorException('Invalid mnemonic')

        
        if inst=='bx':  # bx gets register
            offset = f'00101111111100000001{registers[tokens[1]]}'
        else:           # b, bl gets immediate value or label
            if tokens[1][0].isnumeric(): 
                offset = imm_to_binary(tokens[1], 24)
            else:
                try: label_address = symbol_table[tokens[1]]
                except NameError: raise SyntaxErrorException('Unknown label', line_number)

                current_address = 0x8080 + (line_number * 4) - start_offset + 8
                offset = imm_to_binary(str((label_address - current_address)//4), 24)

                

        binary_code = cond + res.format(L=L, offset=offset)

    # swp, no S flag
    # swp{b}{cond} Rd, Rm, [Rn]
    elif inst.startswith('swp'):
        res = inst_format['swp']
        bcon = inst[3:]
        
        B = '0'
        cond = '1110'
        
        # cond never starts with 'b'
        if bcon[0] == 'b':
            B = '1'
            bcon = bcon[1:]

        if len(bcon) == 2:
            cond = cond_dict[bcon]

        Rd = registers[tokens[0]]
        Rm = registers[tokens[1]]
        Rn = registers[tokens[2][1:-1]] # remove bracket
        
        binary_code = cond + res.format(B=B, Rn=Rn, Rd=Rd, Rm=Rm)
    
    # no S flag
    # swi{cond} swi_number
    elif inst.startswith('swi'):
        res = inst_format['swi']
        cond = cond_dict[inst[3:]]

        num_literal = tokens[1]
        if num_literal == '0':
            num = 0
        elif num_literal.startswith('0x'):
            num = int(num_literal[2:], 16)
        elif num_literal.startswith('0b'):
            num = int(num_literal[2:], 2)
        elif num_literal.startswith('0'):
            num = int(num_literal[1:], 8)
        else:
            num = int(num_literal)

        binary_code = cond + '1111' + f'{num:0>24b}'

    # mul{cond}{S} Rd, Rm, Rs
    # mla{cond}{S} Rd, Rm, Rs, Rn
    elif inst.startswith('mul') or inst.startswith('mla'):
        res = inst_format['mul']
        
        A = '1' if inst=='mla' else '0'

        Rd = registers[tokens[1]]
        Rm = registers[tokens[2]]
        Rs = registers[tokens[3]]
        try:
            Rn = registers[tokens[4]]
        except:
            Rn = '0000'
        
        binary_code = cond + res.format(A=A, S=S, Rd=Rd, Rn=Rn, Rs=Rs, Rm=Rm)

    # <u|s><mul|mla>l{cond}{S} Rd, Rm, Rs, Rn
    elif inst.startswith('umull') or inst.startswith('smull') or\
            inst.startswith('umlal') or inst.startswith('smlal'):

        res = inst_format['mull']
        scon = inst[5:]

        if len(scon) == 2:
            S = '0'
            cond = cond_dict[scon]
        else:
            S = '1'
            cond = cond_dict[scon[1:]]

        U = '1' if inst.startswith('u') else '0'
        A = '1' if ('mla' in inst) else '0'
        
        RdLo = registers[tokens[1]]
        RdHi = registers[tokens[2]]
        Rm = registers[tokens[3]]
        Rs = registers[tokens[4]]

        binary_code = cond + res.format(U=U, A=A, S=S, RdHi=RdHi, RdLo=RdLo, Rs=Rs, Rm=Rm)

    # <ldr|str>{B}{cond} Rd, <Address>
    elif inst.startswith('ldr') or inst.startswith('str'):
        res = inst_format['ldrstr']
        
        L = '1' if inst[0] == 'l' else '0'
        B = '1' if inst[-1] == 'b' else '0'
        # we already have cond
        
        Rd = registers[tokens[1]]
        
        index_tokens = []   # replace the index tokens to list

        
        if tokens[2][0] == '=': # ldr = format
            pass #todo
        else:                   # ldr [] format
            index_tokens.append(tokens[2][1:])  # remove opening bracket
            tokens.pop(2)
            while ']' not in index_tokens[-1]:
                index_tokens.append(tokens[2])
                tokens.pop(2)
            tmp = index_tokens[-1]

            # remove closing bracket
            if tmp[-1] == '!':
                W = '1'
                index_tokens[-1] = tmp[:-2]
            else:
                W = '0'
                index_tokens[-1] = tmp[:-1]    

            tokens.insert(2, index_tokens)
#            print(f'debug : {tokens}')
            
            Rn = registers[index_tokens[0]]

            I = '0'
            P = '1'
            U = '1'

            # merge cases of pre/post-indexed
            if len(tokens) > 3:     # case of post-indexed
                P = '0'
                index_tokens = tokens[2:]
            
            if len(index_tokens) == 1:  # no offset
                offset = '0' * 12

            else:                       # offset
                if index_tokens[1].startswith('#'):   # immediate offset
                    if index_tokens[1][1] == '-':
                        U = '0'
                        index_tokens[1] = '#' + index_tokens[1][2:]
                    offset = imm_to_binary(index_tokens[1], 12, ignore_sign=True)
                else:
                    I = '1'
                    if index_tokens[1][0] == '-':
                        U = '0'
                        index_tokens[1] = index_tokens[1][1:]
                    offset = shift_to_operand2(index_tokens[1:])
        
        # todo
        binary_code = cond + res.format(I=I, P=P, U=U, B=B, W=W, L=L, Rn=Rn, Rd=Rd, offset=offset)
        
    # <ldr>{h|sb|sh}{cond} Rd, <Address>
    elif inst.startswith('ldrh') or inst.startswith('strh'):
        res = inst_format['ldrh_imm']
        res = inst_format['ldrh_reg']
        pass

    #todo
    elif inst.startswith('ldm') or inst.startswith('stm'):
        res = inst_format['ldmstm']
        pass

    # <ldc|sdc>{cond}{L} p#, cd, <Address>
    elif inst.startswith('ldc') or inst.startswith('sdc'):
        raise Exception('cannot handle instruction : ldc/sdc')
        
    # what...
    elif inst.startswith('cdp'):
        raise Exception('cannot handle instruction : cdp')
    
    # whaaat.....
    elif inst.startswith('mrc') or inst.startswith('mcr'):
        res = inst_format['mrcmcr']
        raise Exception('cannot handle instruction : mrc & mcr')
    
    try: return bin_to_hex(binary_code)
    except NameError: SyntaxErrorException('invalid instruction', line_number)


def split(line: str, target: tuple) -> list:
    res = []
    last_idx = 0
    for i in range(len(line)):
        if line[i] in target:
            res.append(line[last_idx:i])
            #res.append(line[i])
            last_idx = i+1
    res.append(line[last_idx:])
    
    return res
    
def trim(tokens: list, target: tuple) -> list:
    return [c for c in tokens if c not in target]


### main() starts here ###
    
lines = sys.stdin.readlines()

# test code without stdin
"""
lines = ('''data:
str: .asciz "Hello"
arr: .skip 12
num: .word 19

_start:
@ data processing
mov r0, #1      @ comment
cmp r1, r0
movlt r1, r0
movs r2, r0, lsl #2 
and r1, r1, r2
eorsgt r0, r1, sp
sub r2, r3, r4
rsb r5, r2, r0, asr #3
add r4, r0, #300
adc r7, r1, r4
sbc r1, r2, r9
rsc r0, r2, fp
tst r0, lr
teq r2, sp
cmn r9, #1
orr r0, r4, r8
bic r0, r1, r3
mvn r1, r1

@ mul
mul r1, r2, r3
umull r1, r2, r3, r4
smullgt r2, r3, r4, r5

@ load/store
ldrlt r0, [r1]
ldrb r1, [r2, #3]
ldr r3, [r4, -r5, lsl #3]!
streq r0, [r2], #4
strb r2, [r3], -r4, asr #5

@ branch
mov r0, #1
lab: add r0, r0, #1
cmp r0, #3
beq lab

@ swi
swi 0
''')
"""

lines = split(lines, ('\n'))

splitter = re.compile(r'([ \t\n,])')

if type(lines[0]) is list: lines = sum(lines, [])  # flatten the list
# first pass
line_number = 0
starting_address = 0x8080
symbol_table = {}

for line in lines:
    line_number += 1
	
    line = line.lower()
#    print(line)
    tokens = splitter.split(line)

    tokens = trim(tokens, ('', ' ', ',')) # ex) ['lab:', 'mov', 'r1', 'r2', '@', 'my_comment']
    
    tmp = []
    for i in range(len(tokens)):
        if '@' in tokens[i]:
            before_cra = tokens[i][:tokens[i].index('@')]
            if before_cra != '': tmp.append(before_cra)
            break
        tmp.append(tokens[i])
    
    tokens = tmp

    if len(tokens) < 1: continue

    while len(tokens) > 0:
        if tokens[0].endswith(':'): # process label
            label_name =  tokens[0].rstrip(':')
            print('\tLABEL ' + label_name + ' FOUND')
            if label_name in symbol_table:
                raise SyntaxErrorException('label repetition detected.', line_number)

            symbol_table[label_name] = starting_address + (line_number * 4)
            tokens = tokens[1:]
            continue

        elif tokens[0].startswith('.'): # process directive
            print('\tDIRECTIVE ' + tokens[0] + ' FOUND')
            tokens = tokens[1:]
            while len(tokens) > 0: del tokens[0]
            continue

        else: break # process instruction
    else: continue  # no instruction after, or an empty line


try: start_offset = symbol_table['_start'] - 0x8080
except: raise SyntaxErrorException('"_start" label not found.')

start_line = start_offset // 4
for i in symbol_table.keys():
    symbol_table[i] -= start_offset

print("Symbol Table")
for label, address in symbol_table.items():
    print(f'{label} : 0x{address:x}')


# second pass    
line_number = 0
inst_pointer = 0x8080
for line in lines:
    line_number += 1
    if line_number < start_line: continue   # start assembling from _start label

    line = line.lower()
    print()
    print(line)
    tokens = splitter.split(line)
    #print(tokens)
    #tokens = [tok for tok in tokens
    #          if re.match('\s*$', tok) == None]
    tokens = trim(tokens, ('', ' ', ',', '\n')) # ex) ['add', 'r0', 'r1', 'r2', 'lsl', '#5']
    
    tmp = []
    for i in range(len(tokens)):
        if '@' in tokens[i]:
            before_cra = tokens[i][:tokens[i].index('@')]
            if before_cra != '': tmp.append(before_cra)
            break
        tmp.append(tokens[i])
    
    tokens = tmp
    if len(tokens) < 1: continue
    while len(tokens) > 0:
        if tokens[0].endswith(':'): # process label
            tokens = tokens[1:]
            continue

        elif tokens[0].startswith('.'): # process directive
            tokens = tokens[1:]
            while len(tokens) > 0: del tokens[0]
            continue

        else: break # process instruction
    else: continue  # no instruction after, or an empty line
    instruction = tokens[0]

    for target in opcode_dict:
        if target in instruction:
            data_processing(target, tokens, line_number)
            break
    else:
        if instruction in ('mrs', 'msr'):
            msrmrs_processing(instruction[:3], tokens, line_number)
        else:
            other_instructions(instruction, tokens, line_number)
