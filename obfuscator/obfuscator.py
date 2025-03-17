from copy import deepcopy
import random
import secrets

from opcodes.opcodes import *
from contract.contract import Contract
from utils.eth_sig import *
from utils.utils import object_list_to_type_list
from obfuscator.utils import *
from obfuscator.patterns import PATTERNS
from utils.print_colors import colors as c

# Constants for how many random JUMPDESTs to insert
NB_JUMPDEST_SPAM = 18  # Must be an even number
JUMPDEST_CFG_SPAM = 10 # Must be an even number < NB_JUMPDEST_SPAM

class Obfuscator:
    def __init__(self, contract: Contract, obf_type: str):
        """
        Constructor for the Obfuscator class.
        
        Parameters:
            contract (Contract): An instance of the Contract class representing the Ethereum smart contract to be obfuscated.
            obf_type   (str)    : Type of obfuscation (e.g., "full", "addmanip", "funcsigtransfo", "spamjumpdest", "jumptransfo")
        """
        self.contract = contract
        self.obf_type = obf_type

    def obfuscate_contract(self):
        """
        Perform the obfuscation process on the unified contract bytecode (no creation/runtime split).
        """
        if NB_JUMPDEST_SPAM % 2 != 0:
            raise Exception("NB_JUMPDEST_SPAM must be an even number.")
        if JUMPDEST_CFG_SPAM > NB_JUMPDEST_SPAM:
            raise Exception("JUMPDEST_CFG_SPAM must be smaller than NB_JUMPDEST_SPAM.")
        
        # Insert random JUMPDEST spam if needed
        if self.obf_type in ("full", "spamjumpdest", "jumptransfo"):
            self.spam_jumpdest(NB_JUMPDEST_SPAM)

        # Perform CFG spam if needed
        if self.obf_type in ("full", "jumptransfo"):
            self.cfg_spammer(JUMPDEST_CFG_SPAM)

        # Update PCs after the spamming
        self.contract.update_pc()

        # Match and replace opcode patterns
        self.match_patterns()
        self.contract.update_pc()
        
        return self.contract

    def match_patterns(self):
        """
        Identify and replace opcode patterns in the unified contract bytecode with obfuscated versions if applicable.
        """
        opcode_type_list = object_list_to_type_list(self.contract.opcode)

        for pattern in PATTERNS:
            print(f"\n{c.BackgroundLightYellow}Searching for {pattern.name} in the bytecode{c.rst}")
            if set(pattern.original) <= set(opcode_type_list):
                if pattern.replaceable:
                    # Obfuscate if the pattern is marked "replaceable"
                    self.obfuscate_pattern(pattern.original, pattern.obfuscated, pattern.name)
                else:
                    print(f"\"{pattern.name}\" is not replaceable\n")

    def obfuscate_pattern(self, pattern, instanciated_pattern, name):
        """
        Obfuscate a specific pattern in the contract's unified opcode list.

        Parameters:
            pattern            (list): The original opcode sequence to match.
            instanciated_pattern (list): The obfuscated opcode sequence to replace with.
            name               (str) : The name of the pattern (e.g., "FUNC_SELECTOR", "ADD", etc.).
        """
        i = 0
        while i < len(self.contract.opcode):
            window = self.contract.opcode[i:i+len(pattern)]
            if object_list_to_type_list(window) == pattern:
                # Handle specialized transformations:
                if name == "FUNC_SELECTOR" and self.obf_type in ("full", "funcsigtransfo"):
                    print(f"\nApplying {c.Bold}Function Signature Transformer{c.rst}...")
                    added_bytes = self.func_sig_transformer(i, window)
                    i += added_bytes
                    self.contract.update_pc()

                elif name == "JUMPTRANSFO" and not is_opcode_list_obfuscated(window) and self.obf_type in ("full", "jumptransfo"):
                    print(f"Applying {c.Bold}Jump Address Transformer{c.rst}...")
                    added_bytes = self.jump_address_transformer(i, window)
                    i += added_bytes
                    self.contract.update_pc()

                elif name == "ADD" and not is_opcode_list_obfuscated(window) and self.obf_type in ("full", "addmanip"):
                    # Random chance to apply ADD obfuscation, if desired
                    if random.randint(1, 3) == 1:
                        print("Applying ADD Opcode Stack Manipulation...")
                        set_obf_attr_to_true(instanciated_pattern)
                        original_bytes = get_opcode_list_byte_length(window)
                        self.contract.opcode[i:i+len(pattern)] = deepcopy(instanciated_pattern)
                        added_bytes = get_opcode_list_byte_length(instanciated_pattern) - original_bytes
                        i += added_bytes
                        self.contract.update_pc()
                    else:
                        i += 1
                else:
                    i += 1
            else:
                i += 1

    def spam_jumpdest(self, nb_new_jumpdest: int):
        """
        Insert a specified number of random JUMPDEST opcodes into the contract's unified opcode list.
        
        Parameters:
            nb_new_jumpdest (int): Number of random JUMPDEST opcodes to insert.
        """
        print(f"\nSpamming {nb_new_jumpdest} new JUMPDEST...")
        for _ in range(nb_new_jumpdest):
            # Insert in a random valid position, avoiding possible metadata region at the very end
            insert_pos = random.randint(500, max(len(self.contract.opcode) - 200, 500))
            rd_jumpdest = JUMPDEST(random=True)
            self.contract.opcode[insert_pos:insert_pos] = [rd_jumpdest]
            self.contract.update_pc()
        print(f"Added {nb_new_jumpdest} random JUMPDESTs.")

    def cfg_spammer(self, nb_jumpdest_to_spam: int):
        """
        Insert control-flow obfuscating sequences at random JUMPDEST positions in the contract's opcode list.
        
        Parameters:
            nb_jumpdest_to_spam (int): Number of random JUMPDEST opcodes to transform for CFG spam.
        """
        print(f"Applying {c.Bold}Control Flow Graph Spammer{c.rst} on {nb_jumpdest_to_spam} random JUMPDEST...")
        
        jumpdest_list = self.contract.get_jumpdests(random_jumpdest=True)
        if len(jumpdest_list) < nb_jumpdest_to_spam:
            # If there aren't enough random JUMPDESTs, just use as many as we have
            nb_jumpdest_to_spam = len(jumpdest_list)
        jumpdests_to_spam = random.sample(jumpdest_list, nb_jumpdest_to_spam)

        while len(jumpdests_to_spam) > 1:
            # Take two random jumpdests at a time
            jumpdest_top = jumpdests_to_spam.pop()
            jumpdest_bot = jumpdests_to_spam.pop()

            # We create a small snippet of push/jump logic to link them
            dummy_push_top_1 = PUSH(1, secrets.token_hex(1), True)
            dummy_push_top_2 = PUSH(1, secrets.token_hex(1), True)
            linked_push_top = PUSH(1,"ff", True)  # placeholder to link with jumpdest_bot
            jumpi_top = JUMPI(random=True)

            # Insert at the top jumpdest
            jumpdest_pc_top = self.contract.get_pc(jumpdest_top)
            sequence_top = [dummy_push_top_1, dummy_push_top_2, linked_push_top, jumpi_top]
            self.contract.opcode[jumpdest_pc_top:jumpdest_pc_top] = sequence_top
            self.contract.update_pc()

            # Link push to bottom jumpdest
            linked_push_top.jumpdest = jumpdest_bot

            # Now create matching snippet for the bottom jumpdest
            push_00 = PUSH(1, "00", random=True)  # This "cancels" the jump
            push_pc_bot = PUSH(1, "ff", random=True)
            push_pc_bot.jumpdest = jumpdest_top
            jumpi_bot = JUMPI(random=True)
            
            jumpdest_pc_bot = self.contract.get_pc(jumpdest_bot)
            # Insert a PUSH(0) right before the jumpdest
            self.contract.opcode[jumpdest_pc_bot:jumpdest_pc_bot] = [push_00]
            # Insert push_pc_bot, jumpi_bot right after the jumpdest
            self.contract.opcode[jumpdest_pc_bot+1:jumpdest_pc_bot+1] = [push_pc_bot, jumpi_bot]
            self.contract.update_pc()

    def func_sig_transformer(self, start_index: int, contract_func: list):
        """
        Transform Ethereum function selectors in the contract by altering their PUSH(4) opcodes.
        
        Parameters:
            start_index  (int) : The position in self.contract.opcode where the pattern begins.
            contract_func (list): List of opcode objects representing the matched function sequence.
        
        Returns:
            (int): Number of additional bytes added due to the transformation.
        """
        original_bytes = get_opcode_list_byte_length(contract_func)
        added_bytes = 0

        for i in range(len(contract_func)):
            if isinstance(contract_func[i], PUSH) and contract_func[i].byte_amount == 4:
                func_sig = contract_func[i].value
                # Store original signature & function name
                self.contract.func_sig[func_sig] = get_function_name(func_sig)

                # Generate a random function signature smaller than the original
                rd_func_sig = gen_random_func_sig_lower_than(func_sig)

                # Adjust the existing push
                transformed_func_sig = compute_adjusted_push(contract_func[i], -int(rd_func_sig,16))
                contract_func[i].value = transformed_func_sig

                # Insert new push+ADD so the final signature on stack is the same
                contract_func.insert(i+1, PUSH(4, rd_func_sig, random=True))
                contract_func.insert(i+2, ADD())

                set_obf_attr_to_true(contract_func)

                # Update in the main opcode list
                self.contract.opcode[start_index:start_index+len(contract_func)] = contract_func
                self.contract.opcode = self.contract.opcode  # Trigger re-calculation

                added_bytes = get_opcode_list_byte_length(contract_func) - original_bytes
                return added_bytes

        return added_bytes

    def jump_address_transformer(self, start_index: int, push_jump_sequence: list):
        """
        Transform JUMP / JUMPI sequences by splitting the PUSH with an additional random value.
        
        Parameters:
            start_index       (int): The position in self.contract.opcode where the jump pattern begins.
            push_jump_sequence (list): The matched [PUSH, JUMPI] sequence of opcodes.
        
        Returns:
            (int): Number of additional bytes added.
        """
        original_bytes = get_opcode_list_byte_length(push_jump_sequence)

        if len(push_jump_sequence) >= 2:
            push_op = push_jump_sequence[0]
            jump_op = push_jump_sequence[1]

            if isinstance(push_op, PUSH) and isinstance(jump_op, JUMPI):
                # Create a new random push
                rd_push_value = gen_push_value_lower_than(push_op.value)
                new_push = PUSH(len(push_op.value)//2, rd_push_value, random=True)

                push_op.linked_lower = new_push

                # Insert new_push and an ADD between them
                push_jump_sequence.insert(0, new_push)
                push_jump_sequence.insert(2, ADD())
                set_obf_attr_to_true(push_jump_sequence)

                # Update the opcode list
                self.contract.opcode[start_index:start_index+2] = push_jump_sequence
                self.contract.opcode = self.contract.opcode

                added_bytes = get_opcode_list_byte_length(push_jump_sequence) - original_bytes
                return added_bytes

        return 0

    def insert_random_func(self, start_index: int):
        """
        Insert a sequence of opcodes representing a random Ethereum function selector at the given index.
        
        Parameters:
            start_index (int): The position at which to insert the random function.
        """
        rd_func_sig = gen_random_func_sig()
        random_func = [DUP(1), PUSH(4, rd_func_sig), EQ(), PUSH(1, "00"), JUMPI()]
        self.contract.opcode[start_index:start_index] = random_func
        self.contract.update_pc()
