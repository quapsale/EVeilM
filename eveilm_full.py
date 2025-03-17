import sys
import os
import multiprocessing
from obfuscator.obfuscator import Obfuscator
from disassembler.disassembler import evmcode_string_to_list
from contract.contract import Contract

TIMEOUT = 120

def obfuscate_bytecode(bytecode, contract_name):
    """
    Obfuscates a given bytecode string using the Obfuscator with mode='full'.
    Returns the obfuscated bytecode or a placeholder if it times out.
    """
    try:
        evmcode = evmcode_string_to_list(bytecode)
        contract = Contract(contract_name, evmcode)

        obfuscator = Obfuscator(contract, 'full')
        contract.update_pc()
        obfuscator.obfuscate_contract()
        contract.update_pc()

        return contract.get_full_bytecode()
    except Exception as e:
        return f"ERROR: {str(e)}"

def obfuscate_with_timeout(bytecode, contract_name):
    """
    Runs obfuscate_bytecode in a separate process with a timeout.
    """
    with multiprocessing.Pool(1) as pool:
        result = pool.apply_async(obfuscate_bytecode, (bytecode, contract_name))
        try:
            return result.get(TIMEOUT)  # Get result with timeout
        except multiprocessing.TimeoutError:
            return "PLACEHOLDER: Skipped due to timeout"

def obfuscate_lines(input_file, output_file):
    """
    Read each line in 'input_file' as a separate bytecode string,
    obfuscate it using Obfuscator (with mode='full') with a timeout,
    and write each result as a line in 'output_file'.
    """
    with open(input_file, 'r') as fin, open(output_file, 'w') as fout:
        for i, line in enumerate(fin, start=1):
            bytecode = line.strip()
            if not bytecode:
                fout.write("\n")  # Preserve empty lines
                continue

            contract_name = f"contract_{i}"
            obf_bytecode = obfuscate_with_timeout(bytecode, contract_name)

            fout.write(obf_bytecode + "\n")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <input.txt> <output.txt>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    if not os.path.exists(input_file):
        print(f"Error: The file '{input_file}' does not exist.")
        sys.exit(1)

    obfuscate_lines(input_file, output_file)
    print(f"Obfuscation complete. Results saved to '{output_file}'.")

if __name__ == "__main__":
    main()
