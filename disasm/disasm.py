from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

ELF = "/tmp/opencode/x3c8021x"
data = open(ELF, "rb").read()

START = 0x00400134   # after ELF/PHDR/INTERP/DYNAMIC headers
END   = 0x00406874   # end of executable LOAD segment
code = data[START:END]

md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
md.detail = True

with open("/tmp/opencode/x3c8021x.dis", "w") as f:
    for insn in md.disasm(code, START):
        f.write(f"{insn.address:08x}: {insn.mnemonic}\t{insn.op_str}\n")

print("done, disassembled bytes:", len(code))
# count instructions
n = sum(1 for _ in md.disasm(code, START))
print("instructions:", n)