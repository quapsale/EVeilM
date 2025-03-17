import copy
from contract.metadata import isolate_metadata_cbor
from opcodes.opcodes import *
from disassembler.disassembler import opcode_to_bytecode, bytecode_to_opcode
from utils.hex_math import *
from utils.print_colors import colors as c

class Contract:
    def __init__(self, filename, bytecode: list):
        """
        Initialize the Contract class.

        Parameters:
            filename (str): The name of the file containing the contract's bytecode.
            bytecode (list): The EVM bytecode of the contract (combined creation + runtime).
        """
        self.name = filename.split("/")[-1].split(".evm")[0]  # Extract contract name from filename

        # Treat the entire incoming bytecode as the "main" bytecode:
        self._bytecode = bytecode  # Store raw bytecode
        self._opcode = bytecode_to_opcode(bytecode)  # Convert to opcode objects

        # Because we no longer differentiate, we can remove references to 'creation' or 'runtime' separation:
        self.creation_bytecode = []  # No creation bytecode
        self.creation_length = 0
        self.bytecode = bytecode    # Will call setter below

        # Metadata
        self.metadata, self.cbor_2bytes, self.ipfs = isolate_metadata_cbor(self._bytecode)

        # Length tracking
        self.length = len(bytecode) // 2
        self.original_length = copy.deepcopy(self.length)

        # Placeholder for function signatures, etc.
        self.func_sig = {}

    # Bytecode and opcode getters/setters
    @property
    def bytecode(self):
        return self._bytecode

    @bytecode.setter
    def bytecode(self, new_bytecode):
        self._bytecode = new_bytecode
        self._opcode = bytecode_to_opcode(new_bytecode)
        self.length = len(new_bytecode) // 2

    @property
    def opcode(self):
        return self._opcode

    @opcode.setter
    def opcode(self, new_opcode_list):
        self._opcode = new_opcode_list
        new_bytecode = opcode_to_bytecode(new_opcode_list)
        self._bytecode = new_bytecode
        self.length = len(new_bytecode) // 2

    def __str__(self) -> str:
        pc_opcode = pc_opcode_dict(self.opcode)
        opcode_full_print = ""
        
        for pc, opcode in pc_opcode.items():
            if opcode.pc != hex(pc)[2:]:
                print(f"Error at {pc} : {opcode.pc} != {hex(pc)[2:]} (PC update issue)")
            
            opcode_infos = f"({opcode.pc}) {opcode.opcode[2:]} {opcode.name} {c.rst}\n"
            if((isinstance(opcode, (JUMPDEST, JUMPI, PUSH)) and opcode.random)):
                opcode_full_print += f"{c.Yellow}{opcode_infos}"
            elif(isinstance(opcode, PUSH) and opcode.updated):
                opcode_full_print += f"{c.Blue}{opcode_infos}"
            elif(isinstance(opcode, JUMPDEST) and opcode.linked):
                opcode_full_print += f"{c.Cyan}{opcode_infos}"
            elif(opcode.obfuscated):
                opcode_full_print += f"{c.Green}{opcode_infos}"
            else:
                opcode_full_print += f"{opcode_infos}"
                
        return opcode_full_print

    def get_jumpdests(self, random_jumpdest=False):
        """
        Retrieve all JUMPDEST opcodes in the contract.
        """
        pc_opcode = pc_opcode_dict(self.opcode)
        jumpdest_list = []
        for opcode_obj in pc_opcode.values():
            if isinstance(opcode_obj, JUMPDEST):
                # If random_jumpdest is False, only gather "normal" jumpdest
                if not random_jumpdest and not opcode_obj.linked:
                    jumpdest_list.append(opcode_obj)
                # Else gather those that are specifically flagged random
                elif random_jumpdest and opcode_obj.random:
                    jumpdest_list.append(opcode_obj)
        return jumpdest_list

    def link_jumpdest_push(self):
        """
        Link JUMP and JUMPI opcodes to their corresponding JUMPDESTs.
        """
        print("Linking JUMPDESTs to PUSHs")

        jumpdest_list = self.get_jumpdests()
        pc_opcode = pc_opcode_dict(self.opcode)
        for i in range(len(pc_opcode)):
            jump_opcode = list(pc_opcode.items())[i][1]
            push_opcode = list(pc_opcode.items())[i - 1][1]

            if isinstance(jump_opcode, (JUMP, JUMPI)) and isinstance(push_opcode, PUSH):
                jumpdest_pc = push_opcode.value
                jumpdest_opcode = pc_opcode.get(hex_str_to_int(jumpdest_pc))

                if jumpdest_opcode is not None and isinstance(jumpdest_opcode, JUMPDEST):
                    push_opcode.jumpdest = jumpdest_opcode

            elif not isinstance(jump_opcode, (JUMP, JUMPI)) and isinstance(push_opcode, PUSH):
                for jumpdest in jumpdest_list:
                    if hex_str_to_int(jumpdest.pc) == hex_str_to_int(push_opcode.value):
                        push_opcode.jumpdest = jumpdest

    def update_pc(self):
        """
        Update the program counter (PC) for each opcode in the contract's opcode list.
        """
        pc_opcode = pc_opcode_dict(self.opcode)
        for pc, opcode_obj in pc_opcode.items():
            opcode_obj.pc = hex(pc)[2:]
        self.opcode = self.opcode

    def get_full_bytecode(self):
        """
        Return the full bytecode (which in this case is just self.bytecode).
        """
        return self.bytecode

    def get_pc(self, unknown_opcode: OPCODE):
        """
        Compute PC of a given opcode object in the contract.
        """
        pc_opcode = pc_opcode_dict(self.opcode)
        pc_b10 = 0
        for pc, opcode_obj in pc_opcode.items():
            if opcode_obj is unknown_opcode:
                return pc_b10
            pc_b10 += 1


def pc_opcode_dict(opcode_list):
    """
    Create a dictionary of OPCODE objects keyed by their PC (program counter).
    """
    pc = 0
    pc_bytecode_dict = {}
    for opcode in opcode_list:
        pc_bytecode_dict[pc] = opcode
        # If PUSH, skip extra bytes as needed
        if isinstance(opcode, PUSH):
            pc += opcode.byte_amount + 1
        else:
            pc += 1
    return pc_bytecode_dict
