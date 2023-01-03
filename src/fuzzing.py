from IPSEC_Mapper import IPSEC_Mapper
from utils import *
from random import randint, sample
from boofuzz import *
import time

CONNECTION_TIMEOUT = 4
IGNORE_RETRANSMISSION = True

# params that proved annoying for fuzzing
IGNORED_PARAMS = ["ck_i", "ck_r", "ke_pk", "nc"]
MISS_THRESHHOLD = 3

mapper = IPSEC_Mapper(CONNECTION_TIMEOUT, IGNORE_RETRANSMISSION)
model = read_dot("A2.dot") # reads LearnedModel.dot by default
state = state_machine(model) # our state machine based on model

# Fuzz values TODO: add more
short_list = [0,200,65535]
int_list = [0, 200, 2147483647]
eight_b_list = [0, 200, b"\xff\xff\xff\xff\xff\xff\xff\xff"]
byte_list = [0, 10, 255]
transf_isa_list = [
    [('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'TEST'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)],
    [('Encryption', 'TEST'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)],
    [('Encryption', 'TEST-SMALL'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)],
    [('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'TEST'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)],
    [('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', 'TEST'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)],
    [('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'TEST'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)],
    [('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'TEST-SMALL'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)]
]

transf_esp_list = [ 
    [('KeyLengthESP', 256), ('AuthenticationESP', 'TEST'), ('EncapsulationESP', 'Tunnel'), ('LifeTypeESP', 'Seconds'), ('LifeDurationESP', 3600)],
    [('KeyLengthESP', 256), ('AuthenticationESP', 'HMAC-SHA'), ('EncapsulationESP', 'TEST'), ('LifeTypeESP', 'Seconds'), ('LifeDurationESP', 3600)],
    [('KeyLengthESP', 256), ('AuthenticationESP', 'HMAC-SHA'), ('EncapsulationESP', 'Tunnel'), ('LifeTypeESP', 'TEST'), ('LifeDurationESP', 3600)]

]
data_list = [b"\xFF"*36, b"\xFF"*24, b"\xFF"*256, b"\xFF"*128]

# Helper function that returns a random parameter from target method
def get_rand_param(func):
    params = func.__code__.co_varnames[:func.__code__.co_argcount]
    params = list(params[1:]) # exclude self
    for i in IGNORED_PARAMS:
        if i in params:
            params.remove(i)
    return random.choice(params)

def get_rand_params(func, n):
    params = get_all_params(func)
    if n >= len(params):
        return params
    return sample(params, n)

def get_all_params(func):
    params = func.__code__.co_varnames[:func.__code__.co_argcount]
    params = list(params[1:]) # exclude self
    for i in IGNORED_PARAMS:
        if i in params:
            params.remove(i)
    return params

def get_fuzz_values(param):
    if param in ["sa_len", "prp_len", "tf_len", "ke_len", "nc_len", "hash_len"]:
        return short_list
    elif param in ["isa_len"]:
        return int_list
    elif param in ["ck_i", "ck_r"]:
        return eight_b_list
    elif param in ["prp_num"]:
        return byte_list
    elif param in ["tf"]:
        return transf_isa_list
    elif param in ["tf_esp"]:
        return transf_esp_list
    elif param in ["nc", "hash", "ke_pk"]:
        return data_list

def get_boofuzz_values(param):
    # setup generators
    if param in ["sa_len", "prp_len", "tf_len", "ke_len", "nc_len", "hash_len"]:
        return Bytes(size=2)
    elif param in ["isa_len"]:
        return Bytes(size=4)
    elif param in ["ck_i", "ck_r"]:
        return Bytes(size=8)
    elif param in ["prp_num"]:
        return Byte()
    elif param in ["tf"]:
        return transf_isa_list
    elif param in ["tf_esp"]:
        return transf_esp_list
    elif param in ["nc", "hash", "ke_pk"]:
        return [b"\xff"*i for i in range(0,300,10)]
    
# Filtering phase --> use small subset of values to find changeable states
def filter():
    file = open("fuzz_results.txt", "w+")

    # go on random 15-input long walks, check that state machine is equivalent each step (might have problem that not all states are covered well)


    # TODO: restructure, get fuzz data and stuff first, then run in loop for all fuzz cases
    # alternatively, choose random runs from learning process
    runs = get_rand_runs() # can specify ammount, blank for all

    for run in runs:
        run_done = False # to break out of run
        run = run[0]
        run = run.replace("self.", "")
        run = run.split(",")
        run = [i.strip() for i in run if (i and i != " ")] # remove empty strings

        # replace random element in run with fuzzed verion:
        to_replace = randint(0, len(run)-1)

        # copy of original input
        og_input = run[to_replace]

        if "_err" in run[to_replace]:
            run[to_replace] = run[to_replace].replace("_err", "")
        run[to_replace] += "_fuzz"
        run[to_replace] = run[to_replace].strip()
        dprint(run)

        func = getattr(mapper, run[to_replace]) # our function that will be fuzzed
        # get fuzz cases:
        # for random params
        params = get_rand_params(func, 3) # choose how many randomly chosen params to test
        for param in params:
            print(f"param: {param}")
            # get fitting input for field
            fuzz_values = get_fuzz_values(param)
            for fv in fuzz_values:
                miss_count = 0
                for input in run:
                    print("$" + input)
                    # sanity checks
                    assert(input != "")
                    assert(input != " ")
                    
                    ret_expected = ""
                    ret_real = ""
                    if "_fuzz" in input:
                        print(f"\n!!  Testing param: {param} with fuzz value: {fv} on input: {input}")
                        func = getattr(mapper, input)
                        parameters = {param:fv}
                        try:
                            ret_real = func(**parameters)
                        except SystemExit: # if the function fails to be decrypted, try to reset machine and save run info
                            print("\n***************************", file=file)
                            print("Differing states!\n", file=file)
                            print(f"Fuzzing: {param} with {fv} in run:", file=file)
                            print(run,file=file)
                            print("***************************\n", file=file)
                            run_done = True
                            break # end current run          
                        
                        # we assume the fuzzed cases to be invalid and return errors, so are more interested if some are valid
                        # hence we use the _err version of messages on the state machine
                        if "_err" not in og_input:
                            og_input += "_err"
                        ret_expected = state.next(og_input)
                    else:
                        func = getattr(mapper, input)
                        
                        try:
                            ret_real = func()
                        except SystemExit: # if the function fails to be decrypted, try to reset machine and save run info
                            print("\n***************************", file=file)
                            print("Differing states!\n", file=file)
                            print(f"Fuzzing: {param} with {fv} in run:", file=file)
                            print(run,file=file)
                            print("***************************\n", file=file)
                            run_done = True
                            break # end current run
                        
                        ret_expected = state.next(input)
                    
                    if str(ret_real) != ret_expected: # str needed for None returns
                        miss_count += 1
                        print("\n***************************")
                        print("Differing states!\n")
                        print(f"For input: {input} or {og_input}")
                        print(f"Got: ${ret_real}$ vs exexpected: ${ret_expected}$")
                        dprint(run)
                        print("***************************\n")

                        if miss_count >= MISS_THRESHHOLD:
                            print("\n***************************", file=file)
                            print("Differing states!\n", file=file)
                            print(f"Fuzzing: {param} with {fv} in run:", file=file)
                            print(run,file=file)
                            print("***************************\n", file=file)
                            run_done = True
                            break # end current run
                    else:
                        print(" --> " + str(ret_real))

                # TODO: add check to see if we are in phase 1 or phase 2 again
                mapper.delete()
                mapper.reset()
                state.reset()

                if run_done:
                    break
            if run_done:
                print("Moving on to next run")
                continue

    file.close()

# testing function
def test(testcase, param, fv):
    for t in testcase:
        print(f"${t}")
        if "fuzz" in t:
            print("%%%%%%%%%%%%%%%%%%%%")
            func = getattr(mapper, t)
            parameters = {param:fv}
            ret = func(**parameters)
            ret_ex = state.next(t.replace("fuzz", "err"))
        else:
            func = getattr(mapper, t)
            ret = func()
            ret_ex = state.next(t)
        print(f"**********\nExpected: {ret_ex} | Received: {ret}\n**********\n")
    mapper.delete()
    mapper.reset()
    state.reset()

# Fuzzing phase --> use relevant states for fuzzing in boofuzz
def fuzz(testcase):
    file = open(f"fuzz_results_{time.strftime('%Y%m%d-%H%M%S')}.txt", "w+")
    # get name of function to be fuzzed
    assert(any("_fuzz" in (fuzz_name := item) for item in testcase))

    # get function to be fuzzed
    func = getattr(mapper, fuzz_name) # our function that will be fuzzed
    
    # Get fuzzable fields of fuzzed function
    params = get_all_params(func)
    dprint(params)

    # fuzz all params, 
    # Run testcase using current values for params of fuzzed function
    for param in params:
        # TODO keep track of learned states and if no new ones appear for a long time, move on

        # get iterator for param
        values = get_boofuzz_values(param)
        if type(values) == Byte or type(values) == Bytes:
            values = values.mutations(b"")
        for fv in values:
            if callable(fv):
                continue
            for t in testcase:
                print(f"${t}")
                print(f"${t}", file=file)
                if "fuzz" in t:
                    print("%%%%%%%%%%%%%%%%%%%%")
                    print("%%%%%%%%%%%%%%%%%%%%", file=file)
                    func = getattr(mapper, t)

                    parameters = {param:fv}
                    try:
                        ret = func(**parameters)
                    except SystemExit: # if the function fails to be decrypted, try to reset machine and save run info
                        print("\nCaught Exception!\n", file=file)
                    ret_ex = state.next(t.replace("fuzz", "err"))
                else:
                    func = getattr(mapper, t)
                    try:
                        ret = func()
                    except SystemExit: # if the function fails to be decrypted, try to reset machine and save run info
                        print("\nCaught Exception!\n", file=file)
                    ret_ex = state.next(t)
                print(f"**********\nExpected: {ret_ex} | Received: {ret}\n**********\n")
                print(f"**********\nExpected: {ret_ex} | Received: {ret}\n**********\n", file=file)

            mapper.delete()
            mapper.reset()
            state.reset()
            print("\n\n", file=file)

    file.close()

# main
# filter()
# data = [('KeyLengthESP', 256), ('AuthenticationESP', 'TEST'), ('EncapsulationESP', 'TEST'), ('LifeTypeESP', 'Seconds'), ('LifeDurationESP', 3600)]

# tc = ['sa_quick_err', 'ack_quick', 'sa_main', 'sa_quick_err', 'authenticate_err', 'sa_quick_err', 'key_ex_main', 'authenticate', 'sa_quick_fuzz', 'sa_quick', 'ack_quick', 'sa_quick', 'key_ex_main_err', 'sa_quick', 'sa_quick_err', 'authenticate', 'sa_quick_err', 'sa_main_err', 'sa_main', 'sa_quick_err', 'sa_main']
# test(tc, "tf_esp", data)

fuzz(['sa_quick_fuzz'])