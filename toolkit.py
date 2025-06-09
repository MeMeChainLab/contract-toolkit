import ctypes
import subprocess
import glob
import os
import json
import re
import argparse
from eth_abi import encode
from eth_hash.auto import keccak
import platform
from pathlib import Path

if platform.system() == "Windows":
    lib_names = ['./libsdk_v0.1.0.so.dll',]
    encoding = "gbk"
    solc_path = 'solc-windows.exe'
else:
    lib_names = ['./libsdk_v0.1.0.so', ]
    encoding = "utf-8"
    solc_path = 'solc'

lib = None
for lib_name in lib_names:
    try:
        lib = ctypes.CDLL(lib_name)
        break  
    except OSError:
        lib = None

if lib is None:
    raise RuntimeError("Unable to load any of the specified libraries")

lib.export_long_pkey.argtypes = [ctypes.c_char_p]
lib.export_long_pkey.restype = ctypes.c_longlong
lib.get_addr.argtypes = [ctypes.c_longlong]
lib.get_addr.restype = ctypes.c_char_p
lib.deploy_contract.argtypes = [ctypes.c_char_p,
                           ctypes.c_char_p,
                           ctypes.c_char_p,
                           ctypes.c_char_p,  
                           ctypes.c_longlong,
                           ctypes.c_char_p, 
                           ctypes.c_int]
lib.deploy_contract.restype = ctypes.c_char_p  

lib.call_contract.argtypes = [ctypes.c_char_p,
                           ctypes.c_char_p,
                           ctypes.c_char_p,  
                           ctypes.c_char_p, 
                           ctypes.c_char_p,
                           ctypes.c_char_p, 
                           ctypes.c_longlong,
                           ctypes.c_char_p, 
                           ctypes.c_int]
lib.call_contract.restype = None


lib.normal_transaction.argtypes = [ctypes.c_char_p,
                           ctypes.c_char_p,
                           ctypes.c_char_p,
                           ctypes.c_char_p,    
                           ctypes.c_ulonglong, 
                           ctypes.c_longlong,
                           ctypes.c_char_p, 
                           ctypes.c_int,
                           ctypes.c_bool]
lib.normal_transaction.restype =  None

lib.get_avaliable_asset.argtypes =  [
                           ctypes.c_char_p, 
                           ctypes.c_int]
lib.get_avaliable_asset.restype = ctypes.c_int

class UtxoDeployer(ctypes.Structure):
    _fields_ = [("utxo", ctypes.c_char * 256),
                ("deployer", ctypes.c_char * 256)]

lib.get_utxo_deployer.argtypes = [
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_char_p,
]
lib.get_utxo_deployer.restype = UtxoDeployer

KEY_STORE = Path("keystore")
CONTRACTDIR_DIRECTORY = Path("contractdir")
OUTPUT_DIRECTORY = Path("output")
CONFIG_FILE = Path("config.json")
CONTRACT_MAP_FILE = Path("contractMap.txt")
AVAILABLE_ASSET_TYPE = Path("availableAssetType.txt")
NODE_MODULES = Path("node_modules")
DEFAULT_CONFIG = {
    'ip': '192.168.1.100',
    'port': 13134
}

def create_map_contract(contractutxo, contractaddress, contractsolcname, contractdeployer):
    lines = read_file_map(CONTRACT_MAP_FILE)
    found = False

    if not contractutxo or not contractaddress:
        print("Error: Deployment contract failure.")
        return  

    for i, line in enumerate(lines):
        if len(line) == 4 and line[2] == contractsolcname and line[3] == contractdeployer:
            lines[i] = [contractutxo, contractaddress, contractsolcname, contractdeployer]
            found = True
            break

    if not found:
        lines.append([contractutxo, contractaddress, contractsolcname, contractdeployer])

    write_file_map(CONTRACT_MAP_FILE, lines)

def read_file_map(filename):
    results = []
    if not os.path.exists(filename):
        return results  
    try:

        with open(filename, 'r') as file:
            for line in file:
                parts = line.strip().strip('[]').split(', ')  
                results.append(parts)  
    except Exception as e:
        print(f"Error reading file {filename}: {e}")  

    return results

def write_file_map(filename, lines):
    with open(filename, 'w') as file:
        for line in lines:
            line_str = f"[{line[0]}, {line[1]}, {line[2]}, {line[3]}]\n"
            file.write(line_str)


def display_asset_types(file_path):
    try:
        with open(file_path, 'r') as file:
            print("\n{:<70} {:<10}".format("Hash", "Asset Name"))
            print("-" * 85)
            for line in file:
                line = line.strip()
                if line.startswith("hash:") and "asset name:" in line:
                    parts = line.split("asset name:")
                    hash_part = parts[0].strip()
                    asset_name = parts[1].strip()
                    print("{:<70} {:<10}".format(hash_part, asset_name))
            print("-" * 85)
    except FileNotFoundError:
        print(f"Error: File {file_path} not found")
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")

def compile_solidity_in_directory(source_dir, output_dir):
    sol_files = glob.glob(os.path.join(source_dir, '*.sol'))
    if not sol_files:
        print(f"No Solidity files found in the {CONTRACTDIR_DIRECTORY}.")
        exit()

    contract_files = get_contract_files(sol_files)
    contract_file_name = select_contract(contract_files)
    full_contract_path = contract_files[contract_file_name]
    compile_solidity(full_contract_path, output_dir)
    return contract_file_name
    
def compile_solidity(source_file, output_file):
    file_name = os.path.splitext(os.path.basename(source_file))[0]
    json_output = os.path.join(output_file, f"{file_name}.json")
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    include_path = os.path.join(current_dir, 'node_modules')
    base_path = current_dir
    
    try:
        subprocess.run(
            [solc_path, '--optimize', '--combined-json', 'abi,bin',
            '--include-path', include_path,
            '--base-path', base_path, 
            source_file, '-o', output_file, '--overwrite'],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        combined_json_path = os.path.join(output_file, 'combined.json')
        if os.path.exists(combined_json_path):
            if os.path.exists(json_output):
                os.remove(json_output)
            os.rename(combined_json_path, json_output)
            
    except subprocess.CalledProcessError as e:
        print("Compilation failed.")
        print(e.stderr)


def get_long_pkey(addr):
    pkey = lib.export_long_pkey(addr)
    return pkey

def get_addr(pk):
    addr = lib.get_addr(pk)
    return addr

def autodeploy(contract,addr,params,assettype,pkey,ip,port):
    bin_content_bytes = contract.encode(encoding) 
    bin_content_c = ctypes.c_char_p(bin_content_bytes)
    ip = ip.encode(encoding)
    params = params.encode(encoding)
    assettype=assettype.encode(encoding)
    contract_addr_utxo  = lib.deploy_contract(bin_content_c, addr,params,assettype,pkey, ip, port)
    return contract_addr_utxo

def autocall(addr,params,contractaddr,deployer,deployutxo,assettype,pkey,ip,port):
    contractaddr_bytes = contractaddr.encode(encoding)
    deployer_bytes = deployer.encode(encoding)
    deployutxo_bytes = deployutxo.encode(encoding)
    ip = ip.encode(encoding)
    params = params.encode(encoding)
    assettype = assettype.encode(encoding)
    lib.call_contract(addr, params,contractaddr_bytes,deployer_bytes,deployutxo_bytes,assettype,pkey,ip,port)

def autonormaltransaction(sendaddress,receiveaddress,assettype,otherassettype,amount,pkey,ip,port,gastrade):
    receiveaddress=receiveaddress.encode(encoding)
    assettype=assettype.encode(encoding)
    otherassettype=otherassettype.encode(encoding)
    ip = ip.encode(encoding)
    lib.normal_transaction(sendaddress,receiveaddress,assettype,otherassettype,amount,pkey,ip,port,gastrade)

def getavaliableasset(ip,port):
    ip = ip.encode(encoding)
    result = lib.get_avaliable_asset(ip,port)
    if result < 0:
        exit()

def get_utxo_deployer(ip, port, contract_addr):
    ip_encoded = ip.encode('utf-8')
    contract_addr_encoded = contract_addr.encode('utf-8') 
    result = lib.get_utxo_deployer(ip_encoded, port, contract_addr_encoded)
    return result

def parse_abi_for_constructor(abi):
    constructor_inputs = None
    for item in abi:
        if item.get('type') == 'constructor':
            constructor_inputs = item.get('inputs', [])
            break
    if constructor_inputs:
        return [{'name': param['name'], 'type': param['type']} for param in constructor_inputs]
    else:
        return None

def validate_input(param_name, param_type, user_input):
    if param_type == 'string':
        return isinstance(user_input, str) and len(user_input) > 0
    elif param_type == 'uint256' or param_type == 'int':
        try:
            int_value = int(user_input)
            return int_value >= 0 if param_type == 'uint256' else True
        except ValueError:
            return False
    elif param_type == 'uint8' or param_type == 'int8':
        try:
            int_value = int(user_input)
            if param_type == 'uint8':
                # uint8: 0 <= int_value <= 255
                return 0 <= int_value <= 255
            elif param_type == 'int8':
                # int8: -128 <= int_value <= 127
                return -128 <= int_value <= 127
        except ValueError:
            return False
    elif param_type == 'address':
        return bool(re.match(r"^0x[a-fA-F0-9]{40}$", user_input))
    elif param_type == 'bool':
        return user_input.lower() in ['true', 'false']
    elif param_type == 'bytes32':
        return bool(re.match(r"^[0-9a-fA-F]{64}$", user_input))
    elif param_type == 'bytes':
        return bool(re.match(r"^[0-9a-fA-F]*$", user_input))
    elif '[]' in param_type:
        base_type = param_type[:-2]  
        elements = user_input.split(',')
        return all(validate_input(param_name, base_type, elem.strip()) for elem in elements)
    elif param_type.startswith('fixed') or param_type.startswith('ufixed'):
        match = re.match(r"^(fixed|ufixed)(\d+)(x\d+)?$", param_type)
        if match:
            try:
                user_input = float(user_input)
                return True  
            except ValueError:
                return False
        else:
            return False
    elif param_type.startswith('tuple'):
        return all(validate_input(param_name, sub_type, elem.strip()) for sub_type, elem in zip(param_type[6:-1].split(','), user_input.split(',')))
    else:
        print(f"Unsupported type: {param_type}")
        return False

def get_funtion_inputs(constructor_params):
    validated_inputs = []
    for param in constructor_params:
        param_name = param['name'] 
        param_type = param['type'] 
        while True:
            user_input = input(f"Please enter the value for {param_name} ({param_type}): ")
            
            if validate_input(param_name, param_type, user_input):
                if param_type == 'uint256' or param_type == 'int':
                    user_input = int(user_input)
                elif param_type == 'uint8' or param_type == 'int8':
                    user_input = int(user_input)
                elif param_type == 'bool':
                    user_input = user_input.lower() == 'true'
                elif param_type == 'bytes32':
                    user_input = bytes.fromhex(user_input)
                elif param_type == 'bytes':
                    user_input = bytes.fromhex(user_input)
                elif param_type == 'address':
                    user_input = user_input.lower()
                elif '[]' in param_type:
                    base_type = param_type[:-2]  
                    user_input = [validate_input(param_name, base_type, elem.strip()) for elem in user_input.split(',')]
                validated_inputs.append(user_input)
                break
            else:
                print(f"Invalid input for {param_name}. Please enter a valid {param_type}.")
    
    return validated_inputs



def get_constructor_calldata(abi, validated_inputs):
    for item in abi:
        if item.get('type') == 'constructor':
            constructor_abi = item
            break
    if not constructor_abi:
        raise ValueError("Constructor not found in ABI")
    
    types = [input['type'] for input in constructor_abi['inputs']]

    encoded_params = encode(types, validated_inputs)
    return encoded_params.hex()

def init():
    current_directory = os.getcwd()
    create_directory(os.path.join(current_directory, KEY_STORE))
    create_directory(os.path.join(current_directory, CONTRACTDIR_DIRECTORY))
    create_directory(os.path.join(current_directory, OUTPUT_DIRECTORY))
    create_directory(os.path.join(current_directory, NODE_MODULES))
    initialize_config()

def initialize_config():
    if not os.path.exists(CONFIG_FILE):
        print(f"config not found, creating with default values.")
        with open(CONFIG_FILE, 'w') as config_file:
            json.dump(DEFAULT_CONFIG, config_file, indent=4)
    else:
        with open(CONFIG_FILE, 'r') as config_file:
            config = json.load(config_file)
        print(f"Loaded config: {config}")

def get_config():
    with open(CONFIG_FILE, 'r') as config_file:
        return json.load(config_file)

def create_directory(directory_path):
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)

def print_separator():
    print("=============================")

def parse_contract_addr_utxo(contract_addr_utxo):
    if isinstance(contract_addr_utxo, bytes):
        contract_addr_utxo = contract_addr_utxo.decode(encoding)
    
    return contract_addr_utxo.split('-') if '-' in contract_addr_utxo else ("", "")

def process_contract(contract_addr_utxo, address, contract_file_name):
    contractaddr, utxo = parse_contract_addr_utxo(contract_addr_utxo)
    address_str = address.decode(encoding)
    create_map_contract(utxo, contractaddr, contract_file_name, address_str)

def get_contract_files(json_files):
    contract_files = {}
    for json_file in json_files:
        file_name = os.path.splitext(os.path.basename(json_file))[0]
        contract_files[file_name] = json_file
    return contract_files

def get_function_calldata(abi, inputs):
    try:
        function_name = abi['name']
        parameter_types = [param['type'] for param in abi['inputs']]
        function_signature = f"{function_name}({','.join(parameter_types)})"
        function_selector = keccak(function_signature.encode())[:4].hex()
        encoded_parameters = encode(parameter_types, inputs).hex()
        return function_selector + encoded_parameters
    except Exception as e:
        print(f"Error generating calldata: {e}")
        return None

def get_entry_by_solcname_and_deployer(lines):
    solcname_set = {line[2] for line in lines} 
    print("Available contractsolcname values:")
    for solcname in solcname_set:
        print(f" - {solcname}")


    selected_solcname = input("Please enter the contractsolcname: ").strip()


    matching_entries = [line for line in lines if line[2] == selected_solcname]

    if not matching_entries:
        print(f"No entries found for contractsolcname: {selected_solcname}")
        return None

    if len(matching_entries) == 1:
        return matching_entries[0]


    print(f"Multiple entries found for contractsolcname: {selected_solcname}")
    print("Available deployer values for this contractsolcname:")
    for entry in matching_entries:
        print(f" - {entry[3]}")  

    selected_deployer = input("Please enter the contractdeployer: ").strip()

    final_entry = next(
        (entry for entry in matching_entries if entry[3] == selected_deployer), None
    )

    if final_entry:
        return final_entry
    else:
        print(f"No entry found for deployer: {selected_deployer}")
        return None

def select_contract(contract_files):
    while True:
        print("Available contracts sol file:")
        print_separator()
        for contract_name in contract_files:
            print(contract_name)
        print_separator()
        
        contract_file_name = input("Enter the contract sol file name from the list above: ").strip()
        if contract_file_name in contract_files:
            return contract_file_name
        else:
            print("Invalid contract file. Please try again.")

def load_contract_data(selected_json):
    with open(selected_json, 'r') as f:
        return json.load(f)

def select_contract_name(contract_data):
    contracts = list(contract_data['contracts'].keys())
    contract_names = [
    contract.split(":")[1] 
    for contract in contracts 
    if "contractdir/" in contract
]

    print("The contracts in the sol file above:")
    print_separator()
    for name in contract_names:
        print(name)
    print_separator()

    if len(contract_names) == 1:
        contract_name_input = contract_names[0]
        print(f"Only one contract available: Automatically selecting {contract_name_input}.")
        return contract_name_input
    else:
        return input("Enter the name of the contract you want to deploy/call: ").strip()

def get_contract_info(contract_data, contract_name_input):
    contracts = list(contract_data['contracts'].keys())
    selected_contract_key = next(contract for contract in contracts if contract.split(":")[1] == contract_name_input)
    return contract_data['contracts'][selected_contract_key]

def is_valid_ethereum_address(address):
    pattern = r'^(0x)?[a-fA-F0-9]{40}$'
    return re.match(pattern, address) is not None

def get_amount():
    while True:
        amount_input = input("Please enter the amount: ")
        try:
            amount = ctypes.c_ulonglong(int(amount_input))
            return amount  
        except ValueError:
            print("Invalid input. Please enter a valid integer.")
        except OverflowError:
            print("Input is too large. Please enter a smaller integer.")
def auto_transtion(addr,long_pkey,config):
    while True:
        receiveaddress = input("Please enter the receiving address: ")
        if not is_valid_ethereum_address(receiveaddress):
            print("Invalid Ethereum address. Please try again.")
            continue  
        break  
    display_asset_types(AVAILABLE_ASSET_TYPE)
    assettype = input("Please enter the asset type to be transferred(hash): ")

    while True:
        user_input = input("Would you like to pay your handling fee separately ? [0] no  [1] yes :").strip()
        if user_input in ('0', '1'):
            gas_trade = ctypes.c_bool(user_input == '1')
            break
        else:
            print("Invalid input. Please reenter 0 or 1")
    if gas_trade:
        otherassettype = input("Please enter the type of asset you want to use to pay the gas (hash):")
    else:
        otherassettype = "" 
    amount = get_amount()
    autonormaltransaction(addr,receiveaddress,assettype,otherassettype,amount,long_pkey, config['ip'], config['port'],gas_trade)

def auto_call_contract(addr, long_pkey, config):
    json_files = glob.glob('./output/*.json')
    contract_files = get_contract_files(json_files)
    if not contract_files:
        return

    lines = read_file_map(CONTRACT_MAP_FILE)
    line = get_entry_by_solcname_and_deployer(lines)
    if line is None:
        return 
    deployutxo, contractaddr, solcname, deployer = line

    contract_file_name = solcname
    if contract_file_name in contract_files:
        selected_json = contract_files[contract_file_name]
        contract_data = load_contract_data(selected_json)

        contract_name_input = select_contract_name(contract_data)
        if contract_name_input in [contract.split(":")[1] for contract in contract_data['contracts'].keys()]:
            contract_info = get_contract_info(contract_data, contract_name_input)
            abi = contract_info['abi']
            print(f"Contract {contract_name_input} selected successfully.")
        else:
            print("Invalid contract name. Please try again.")
            return

        if not abi:
            print("No ABI found in the contract JSON.")
            return

        functions = [item for item in abi if item["type"] == "function"]
        if not functions:
            print("No functions found in the ABI.")
            return

        state_changing_functions = []
        view_functions = []


        for func in functions:
            if func.get("stateMutability") in ["nonpayable", "payable"]:
                state_changing_functions.append(func)
            elif func.get("stateMutability") == "view":
                view_functions.append(func)

        print("Available state-changing functions:")
        for idx, func in enumerate(state_changing_functions):
            inputs = ", ".join([f"{inp['internalType']} {inp['name']}" for inp in func["inputs"]])
            print(f"{idx + 1}. {func['name']}({inputs})")

        print("\nAvailable view functions:")
        for idx, func in enumerate(view_functions):
            inputs = ", ".join([f"{inp['internalType']} {inp['name']}" for inp in func["inputs"]])
            print(f"{idx + 1 + len(state_changing_functions)}. {func['name']}({inputs})")

        try:
            choice = int(input("\nEnter the number of the function you want to view: ")) - 1
            if 0 <= choice < len(state_changing_functions):
                selected_function = state_changing_functions[choice]
            elif len(state_changing_functions) <= choice < len(functions):
                selected_function = view_functions[choice - len(state_changing_functions)]
            else:
                print("Invalid choice. Please choose a valid function number.")
                return
        except ValueError:
            print("Invalid input. Please enter a number.")
            return

        while True:
            user_choice = input("Do you want to manually input calldata (0) or use manually input params (1)? (0/1): ").strip()
            if user_choice == '0':
                calldata = input("Please enter the calldata (without 0x prefix): ").strip()
                params = "0x" + calldata
                print(f"Manually provided calldata: {params}")
                break  
            elif user_choice == '1':
                constructor_params = selected_function['inputs']
                validated_inputs = get_funtion_inputs(constructor_params)
                calldata = get_function_calldata(selected_function, validated_inputs)
                if calldata:
                    params = calldata
                    print(f"Generated calldata: {params}")
                    break  
                else:
                    print("Failed to generate calldata. Please try again.")
            else:
                print("Invalid choice. Please select 0 or 1.")
        display_asset_types(AVAILABLE_ASSET_TYPE)
        assettype = input("Please enter the type of asset you want to use to pay the gas (hash): ")
        autocall(addr, params, contractaddr, deployer, deployutxo, assettype,long_pkey, config['ip'], config['port'])

def auto_deploy_contract(address, long_pkey, config):
    contract_file_name = compile_solidity_in_directory(CONTRACTDIR_DIRECTORY, OUTPUT_DIRECTORY)

    json_files = glob.glob('./output/*.json')
    contract_files = get_contract_files(json_files)
    if not contract_files:
        print("No compiled contract files found.")
        return

    selected_json = contract_files[contract_file_name]
    contract_data = load_contract_data(selected_json)

    contract_name_input = select_contract_name(contract_data)
    contract_info = get_contract_info(contract_data, contract_name_input)
    bin_content = contract_info['bin']
    abi = contract_info['abi']
    print(f"Contract {contract_name_input} selected successfully.")

    params = ""
    constructor_params = parse_abi_for_constructor(abi)
    if constructor_params:
        while True:
            user_choice = input("Do you want to manually input calldata (0) or use manually input params (1)? (0/1): ").strip()
            if user_choice == '0':
                calldata = input("Please enter the calldata (without 0x prefix): ")
                params = "0x" + calldata
                print(f"Manually provided calldata: {params}")
                break  
            elif user_choice == '1':
                validated_inputs = get_funtion_inputs(constructor_params)
                calldata = get_constructor_calldata(abi, validated_inputs)
                if calldata:
                    params = "0x" + calldata
                    print(f"Generated calldata: {params}")
                    break  
                else:
                    print("Failed to generate calldata.")
            else:
                print("Invalid choice. Please select 0 or 1.")
    display_asset_types(AVAILABLE_ASSET_TYPE)
    assettype = input("Please enter the type of asset you want to use to pay the gas (hash): ")
    contract_addr_utxo = autodeploy(bin_content, address, params,assettype ,long_pkey, config['ip'], config['port'])
    process_contract(contract_addr_utxo, address, contract_file_name)

def load_json_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.read()
    except FileNotFoundError:
        print(f"Error: File not found - {file_path}")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def get_json_files(directory):
    return ['0x' + f[:-5] for f in os.listdir(directory) if f.endswith('.json')]


def readkeystore():
    json_files = get_json_files(KEY_STORE)
    
    if not json_files:
        print("No account information")
        exit() 

    if len(json_files) == 1:
        selected_file = json_files[0]
        print("Only one account, default selection:",selected_file)
    else:
        print("The account that exists in the directory:")
        print_separator()
        for filename in json_files:
            print(filename)
        print_separator()
        selected_file = input("Please select an account: ")
       

        if selected_file not in json_files:
            print("Invalid choice")
            exit()
    selected_file = selected_file.lstrip('0x') 
    file_path = os.path.join(KEY_STORE, selected_file + '.json')

    account_string = load_json_file(file_path)
    if account_string:
        account_c_char_p = ctypes.c_char_p(account_string.encode('utf-8'))
        return account_c_char_p
    else:
        print("Unable to load file contents")

def generate_calldata(function_selector, inputs):
    try:
        parameter_types = ['uint256']  
        encoded_parameters = encode(parameter_types, inputs).hex()  
        calldata = function_selector + encoded_parameters  
        return calldata
    except Exception as e:
        print(f"Error generating calldata: {e}")
        return None

def inflow(address, long_pkey, config):
    contractaddr = input("Please enter the contract address: ").strip()
    ip = config['ip']
    port = config['port']
    deployer = get_utxo_deployer(ip, port, contractaddr)
    deployutxo = deployer.utxo.decode()
    deployer_value = deployer.deployer.decode()
    if not deployutxo or not deployer_value:
        print("UTXO or Deployer is empty")
        return  
    function_selector = "0x6e27d889"  
    amount = int(input("Please enter the amount of tokens to inflow: "))
    inputs = [amount] 
    params = generate_calldata(function_selector[2:], inputs) 
    display_asset_types(AVAILABLE_ASSET_TYPE)
    assettype = input("Please enter the type of asset you want to use to pay the gas (hash): ")
    autocall(address, params, contractaddr, deployer_value, deployutxo, assettype,long_pkey, config['ip'], config['port'])


def outflow(address, long_pkey, config):
    contractaddr = input("Please enter the contract address: ").strip()
    ip = config['ip']
    port = config['port']
    deployer = get_utxo_deployer(ip, port, contractaddr)
    deployutxo = deployer.utxo.decode()
    deployer_value = deployer.deployer.decode()
    if not deployutxo or not deployer_value:
        print("UTXO or Deployer is empty")
        return  
    function_selector = "0x7c405325"  
    amount = int(input("Please enter the amount of tokens to outflow: "))
    inputs = [amount] 
    params = generate_calldata(function_selector[2:], inputs) 
    display_asset_types(AVAILABLE_ASSET_TYPE)
    assettype = input("Please enter the type of asset you want to use to pay the gas (hash): ")
    autocall(address, params, contractaddr, deployer_value, deployutxo, assettype,long_pkey, config['ip'], config['port'])

def other(address, long_pkey, config):
    contractaddr = input("Please enter the contract address: ").strip()
    ip = config['ip']
    port = config['port']
    deployer = get_utxo_deployer(ip, port, contractaddr)
    deployutxo = deployer.utxo.decode()
    deployer_value = deployer.deployer.decode()
    print("UTXO:", deployutxo)
    print("Deployer:", deployer_value)
    if not deployutxo or not deployer_value:
        print("UTXO or Deployer is empty")
        return  
    calldata = input("Please enter the calldata (without 0x prefix): ").strip()
    params = "0x" + calldata
    print(f"Manually provided calldata: {params}")
    display_asset_types(AVAILABLE_ASSET_TYPE)
    assettype = input("Please enter the type of asset you want to use to pay the gas (hash): ")
    autocall(address, params, contractaddr, deployer_value, deployutxo, assettype,long_pkey, config['ip'], config['port'])


def main():
    try:
        parser = argparse.ArgumentParser(description="Solidity contract deployment helper")
        parser.add_argument('-t', '--test', action='store_true', help="Run initialization and exit")
        args = parser.parse_args()
        
        if args.test:
            init()
            print("Initialization complete. Exiting...")
            return  
        init()
        config = get_config()
        account_string=readkeystore()
        long_pkey = get_long_pkey(account_string)
        if(long_pkey < 0):
            exit()
        address = get_addr(long_pkey)
        getavaliableasset(config['ip'], config['port'])
        while True: 
            print("\n============Menu===========")           
            print("0. Exit")
            print("1. Normal transtion")
            print("2. Call contract")
            print("3. Deploy contract")
            print("4. InFlow")
            print("5. OutFlow") 
            choice = input("Please select an option (0/1/2/3/4/5): ").strip()
            if choice == "1":
                auto_transtion(address,long_pkey,config)
            elif choice == "2":
                auto_call_contract(address,long_pkey,config)
            elif choice == "3":
                auto_deploy_contract(address, long_pkey, config)
            elif choice == "4":  
                inflow(address, long_pkey, config)
            elif choice == "5":  
                outflow(address, long_pkey, config)
            elif choice == "6":  
                other(address, long_pkey, config)
            elif choice == "0":
                exit()
            else:
                print("Invalid option! Please try again.")

        
            
    except KeyboardInterrupt:
        print("\nProgram interrupted by user.")
        exit()

if __name__ == "__main__":
    main()