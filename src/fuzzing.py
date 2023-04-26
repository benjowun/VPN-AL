from IPSEC_Mapper import IPSEC_Mapper
from utils import *
from random import randint, sample
from boofuzz import *
from Connector import *
import time
import ast

CONNECTION_TIMEOUT = 4
IGNORE_RETRANSMISSION = True

# params that proved annoying for fuzzing
IGNORED_PARAMS = ["ck_i", "ck_r", "ke_pk", "nc"]
MISS_THRESHHOLD = 3

conn = Connector("10.0.2.1", 500, 500, CONNECTION_TIMEOUT)
mapper = IPSEC_Mapper(IGNORE_RETRANSMISSION, conn)
if libre:
    model = read_dot("A2_libre.dot")
else:
    model = read_dot("A2.dot") # reads LearnedModel.dot by default
#state = state_machine(model) # our state machine based on model

# Random Seed
random.seed()


# Fuzz values TODO: add more
short_list = [0,200,65535]
int_list = [0, 200, 2147483647]
eight_b_list = [0, 200, b"\xff\xff\xff\xff\xff\xff\xff\xff"]
byte_list = [0, 10, 255]
transf_isa_list = [
    [('Encryption', 'TEST'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '2048MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)],
    [('Encryption', 'TEST_SMALL'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '2048MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)],
    [('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'TEST'), ('GroupDesc', '2048MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)],
    [('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', 'TEST'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)],
    [('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '2048MODPgr'), ('Authentication', 'TEST'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)],
    [('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '2048MODPgr'), ('Authentication', 'TEST_SMALL'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)]
]

transf_esp_list = [ 
    [('KeyLengthESP', 256), ('AuthenticationESP', 'TEST'), ('EncapsulationESP', 'Tunnel'), ('LifeTypeESP', 'Seconds'), ('LifeDurationESP', 3600)],
    [('KeyLengthESP', 256), ('AuthenticationESP', 'HMAC-SHA'), ('EncapsulationESP', 'TEST'), ('LifeTypeESP', 'Seconds'), ('LifeDurationESP', 3600)],
    [('KeyLengthESP', 256), ('AuthenticationESP', 'HMAC-SHA'), ('EncapsulationESP', 'Tunnel'), ('LifeTypeESP', 'TEST'), ('LifeDurationESP', 3600)],
    [('KeyLengthESP', 256), ('AuthenticationESP', 'TEST_SMALL'), ('EncapsulationESP', 'Tunnel'), ('LifeTypeESP', 'Seconds'), ('LifeDurationESP', 3600)]

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

def clean_value(value, param):
    if param in ["sa_len", "prp_len", "tf_len", "ke_len", "nc_len", "hash_len", "isa_len", "prp_num"] and type(value) is bytes:
        return int.from_bytes(value, 'big')
    else:
        return value

# Filtering phase --> use small subset of values to find changeable states
def filter():
    file = open("filter_results.txt", "w+")

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
                        ret_expected = model.step(og_input)
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
                        
                        ret_expected = model.step(input)
                    
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
                model.reset_to_initial()

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
            ret_ex = model.step(t.replace("fuzz", "err"))
        else:
            func = getattr(mapper, t)
            ret = func()
            ret_ex = model.step(t)
        print(f"**********\nExpected: {ret_ex} | Received: {ret}\n**********\n")
    mapper.delete()
    mapper.reset()
    model.reset_to_initial()

def sanity():
    print("sa_main")
    mapper.sa_main()
    print("key_ex_main")
    mapper.key_ex_main()
    print("authenticate")
    mapper.authenticate()
    print("sa_quick")
    mapper.sa_quick()
    print("ack_quick")
    mapper.ack_quick()

    # time.sleep(5)
    # print("delete")
    # mapper.delete_v2()
    # mapper.reset()

    # # print("Moving on to fuzzing tests...")
    # # # time.sleep(5)
    # print("sa_main_fuzz")
    # mapper.sa_main_fuzz()
    # print("key_ex_main_fuzz")
    # mapper.key_ex_main_fuzz()
    # print("authenticate_fuzz")
    # mapper.authenticate_fuzz()
    # print("sa_quick_fuzz")
    # mapper.sa_quick_fuzz()
    # print("ack_quick_fuzz")
    # mapper.ack_quick_fuzz()

    # print("delete_v2")
    # mapper.delete_v2()
    # mapper.reset()

# Fuzzing phase --> use relevant states for fuzzing in boofuzz
# returns number of found interesting states
def fuzz(testcase):
    if libre:
        file = open(f"fuzz_results_libre_new.txt", "a+")
    else:
        file = open(f"fuzz_results_new.txt", "a+")
    counter = 0
    responses = [] # (t, output)

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
        # get iterator for param
        values = get_boofuzz_values(param)
        if type(values) == Byte or type(values) == Bytes:
            values = values.mutations(b"")
        for fv in values:
            print(f"Fuzzing {param} with: {fv}\nRun: {testcase}")

            if callable(fv):
                continue
        
            fv = clean_value(fv, param)
            print(fv)
            for t in testcase:
                print(f"${t}")
                if "fuzz" in t:
                    print("%%%%%%%%%%%%%%%%%%%%")
                    func = getattr(mapper, t)

                    parameters = {param:fv}
                    try:
                        print(f"Param: {param} Fuzz value: {fv}")
                        ret = func(**parameters)
                    except SystemExit: # if the function fails to be decrypted, try to reset machine and save run info
                        print("\nCaught Exception!\n", file=file)
                    t = t.replace("fuzz", "err")
                    ret_ex = model.step(t)

                else:
                    func = getattr(mapper, t)
                    try:
                        ret = func()
                    except SystemExit: # if the function fails to be decrypted, try to reset machine and save run info
                        print("\nCaught Exception!\n", file=file)
                    ret_ex = model.step(t)
                print(f"**********\nExpected: {ret_ex} | Received: {ret}\n**********\n")
                if str(ret_ex) != str(ret):
                    inp = (t, str(ret))
                    if inp not in responses:
                        print(f"Fuzzing {param} with: {fv}\nRun: {testcase}", file=file)
                        print(f"${t}", file=file)
                        print(f"**********\nExpected: {ret_ex} | Received: {ret}\n**********\n", file=file)
                        print("%%%%%%%%%%%%%%%%%%%%", file=file)
                        responses.append(inp)
                    else:
                        print("skipped")

            mapper.delete()
            mapper.reset()
            model.reset_to_initial()
            print("Done with run\n\n")
            counter += 1

    print(responses)
    print(f"Number of tests run: {counter}")
    print(f"Number of tests run: {counter}", file=file)
    file.close()

def fuzz_each_input(run):
    tested=[]
    for i in range(len(run)) :
        temp_run = run.copy()
        if "_err" in temp_run[i]:
            temp_run[i] = temp_run[i].replace("_err", "")
        temp_run[i] = temp_run[i] + "_fuzz"
        tested.append(temp_run)
        fuzz(temp_run)
    print(tested)

def fuzz_all(filename):
    d_file = open(filename, "r")
    
    i = iter(d_file.readlines())
    for line in i:
        line = line.strip()
        if line == "***************************": # start parsing block
            next(i) # is empty line
            next(i) # results
            next(i)
            run = next(i).strip()
            run = ast.literal_eval(run)
            print(run)
            fuzz(run)
            assert(next(i).strip() == "***************************")

# flips a word
def flip(word: str):
    if "_err" in word:
        return word.replace("_err", "")
    else:
        return word + "_err"

# returns a random word
def rand_word():
    words = ['sa_main', 'key_ex_main', 'authenticate', 'sa_quick', 'ack_quick', 'sa_main_err', 'key_ex_main_err', 'authenticate_err', 'sa_quick_err', 'ack_quick_err']
    return random.choice(words)

# mutate a none-empty run, either by swapping a packet for an errorneous version, or by adding a new packet
# takes a list of words
def mutate(run=[], amount=1):
    assert(len(run) > 0)

    for i in range(amount):
        if randint(0,1): # 50 % chance to flip
            if randint(1,5) == 1: # 20% chance to flip random word, 80% to flip latest word
                index = randint(0,len(run)-1)
                run[index] = flip(run[index])
            else:
                run[-1] = flip(run[-1])
        else: # 50% chance to add new word
            if randint(1,10) == 1: # 10% chance to add at random spot, 90% to add at end
                index = randint(0,len(run)-1)
                run.insert(index, rand_word())
            else:
                run.insert(-1, rand_word())
    return run

# counts the total number of new states found, divided by the number of words in run
def score_mutation(run):
    file = open(f"logs2.txt", "a+")
    score = 0
    skipped = 0
    total_states = [x.state_id for x in model.states] # extract the state labels from aalpy states
    visited_states = set()
    
    for word in run:
        current_run = run.copy()
        responses = [] # (t, output), on a per-fuzzed input basis

        index = current_run.index(word)
        
        if "_err" in current_run[index]:
            current_run[index] = current_run[index].replace("_err", "")
        current_run[index] = current_run[index] + "_fuzz"
        print(current_run)

        func = getattr(mapper, current_run[index]) # our function that will be fuzzed
        params = get_all_params(func)

        for param in params:
            # get fitting input for field
            fuzz_values = get_fuzz_values(param)
            for fv in fuzz_values:
                fv = clean_value(fv, param)
                for input in current_run:                    
                    ret_expected = ""
                    ret_real = ""
                    if "_fuzz" in input:
                        func = getattr(mapper, input)
                        parameters = {param:fv}
                        try:
                            ret_real = func(**parameters)
                        except SystemExit:
                            print("Exception")
                            break # end current run          
                        ret_expected = model.step(input.replace("fuzz", "err"))
                    else:
                        func = getattr(mapper, input)
                        
                        try:
                            ret_real = func()
                        except SystemExit:
                            print("Exception")
                            break # end current run   
                        ret_expected = model.step(input)
                        visited_states.add(model.current_state.state_id)    # update coverage stats   
                    if str(ret_real) != ret_expected: # str needed for None returns
                        inp = (input, str(ret_real))
                        if inp not in responses:
                            score += 1
                            print(f"**********\nExpected: {ret_expected} | Received: {ret_real}\n**********\n")
                            responses.append(inp)
                        else: 
                            print("Skipped, already discovered")
                            skipped += 1
                mapper.delete()
                mapper.reset()
                model.reset_to_initial()

    print(f"Skipped: {skipped}", file=file)
    print(f"Coverage: Visited: {visited_states}, total: {total_states}", file=file)
    print(f"Score unweighted: {score} #: {len(run)}", file=file)
    print(f"Score weighted: {score / len(run)}", file=file)
    print(f"Score new weighting: {score * (len(visited_states)/(len(total_states)))}", file=file)
    print(f"Weighted, clean: {score / len(run) * (len(visited_states) / len(total_states))}", file=file)
    return score / len(run) * (len(visited_states) / len(total_states)) # average # of unique interesting behavior per fuzzed state weighted by the amount of total states covered to promote good coverage

# want: generate run --> check if it performs better or worse than previous, keep mutation or go to next else
# save resultant final mutation to file (with each param _fuzz ince), use it for fuzzing
# takes a list of words
def generate_runs(baseline=[], num_mutations=20):
    file = open(f"mutations_{num_mutations}.txt", "w+")

    if len(baseline) == 0:
        current = rand_word()
    else:
        current = baseline
    
    current_max = score_mutation(current) / 2 #start a bit lower to promote mutations

    for i in range(num_mutations):
        suggestion = mutate(current.copy())
        score = score_mutation(suggestion)

        if score > current_max:
            current = suggestion
            current_max = score
            print(f"Mutation: {i}, score: {score}\n {suggestion}\n\n", file=file)
        else: 
            print(f"Mutation {i}, score: {score}\n Discarded \n ({suggestion})", file=file)

    print(f"Max score: {current_max}\n {current}\n\n", file=file)
    return current

# for comparison with mutation-based approach
def generate_random_run(length=5):
    run = []
    for i in range(length):
        run.append(rand_word())
    return run

def calc_baseline(length=5, num_sequences=5):
    total = 0
    runs = []
    for i in range(num_sequences):
        run = generate_random_run(length)
        runs.append(run)
        score = score_mutation(run)
        total += score
    
    print(f"Average score: {total / num_sequences}")

# creates 2 spliced populations from two parents
def crossover(pop1, pop2):
    # Randomly select crossover points
    point1 = random.randint(0, len(pop1)-1)
    point2 = random.randint(0, len(pop2)-1)
    
    # Exchange parts of the strings after the crossover points
    offspring1 = pop1[:point1] + pop2[point2:]
    offspring2 = pop2[:point2] + pop1[point1:]
    
    return offspring1, offspring2

# genetic programming approach for input sequence generation
# num_populations: the total number of input sequences to have in each generation
# num_kept: the subset of those, which are kept between iterations (best performing ones)
# num_iterations: number of iterations to go through
# mutation_amount: number of mutations to apply to populations each step
# starting_length: length of initially created random populations
# starting_populations: an optional set of starting populations
# 
# Workflow: starting populations (random, or set) --> mutate --> score --> keep best performing, discard rest --> (splice) --> refill missing populations with random --> repeat
def generate_run_genetic(num_populations=10, num_kept=3, num_iterations=5, mutation_amount=2, starting_length=5, starting_populations=[]):
    file = open(f"genetic_{num_iterations}.txt", "w+")
    populations = starting_populations
    scores = [] # top scorers and scores

    assert(num_kept < num_populations)
    
    if not starting_populations:
        for i in range(num_populations):
            populations.append(generate_random_run(starting_length)) # starting length defaults to 5

    # we now have our starting population
    print(f"Starting populations: {populations}", file=file)

    for i in range(num_iterations):
        scores = [] # list of tuples, (score, population)

        # mutation phase
        for population in populations:
            population = mutate(population, mutation_amount)
            score = score_mutation(population)
            scores.append((score, population))
            print(f"Score: {score}")


        print(f"Populations before filtering: {populations}", file=file)
        # keep top scorers
        scores.sort(key=lambda x: x[0], reverse=True)
        populations = []
        for i in range(num_kept):
            populations.append(scores[i][1])

        print(f"Kept populations: {populations}", file=file)

        # splice by creating two populations out of combinations of existing ones "crossover operator"
        spliced = 0

        if num_kept < num_populations and num_kept >= 2:
            random.shuffle(populations) # ensure random order
            pop1 = populations[0]
            pop2 = populations[1]
            for pop in crossover(pop1, pop2):
                populations.append(pop)
            spliced = 2
            print(f"Spliced populations: {populations}", file=file)

        # fill up again, with random input sequences with length between 1 and max length + 2
        max_size = len(max(populations, key=len))
        for i in range(num_populations - (num_kept + spliced)):
            rand_length = randint(1, max_size+2)
            populations.append(generate_random_run(rand_length))
        
        assert(len(populations) == num_populations)

    print(f"Final top scores: {scores}", file=file)


starttime = time.time()
# main
# filter()

# data = [('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '2048MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)]
# tc = ['sa_main', 'key_ex_main', 'authenticate', 'sa_quick', 'ack_quick']
# test(tc, "tf", data)

run =  ['sa_main', 'key_ex_main', 'key_ex_main', 'sa_main_err', 'key_ex_main_err', 'sa_main_err', 'sa_quick_err', 'sa_main', 'sa_main_err', 'authenticate', 'authenticate']

#run = ['sa_main', 'key_ex_main_fuzz', 'authenticate']
# fuzz(run) # goes through each method once, hopefully finds any serious errors
# fuzz_all("filter_results.txt")
fuzz_each_input(run)

# generate_runs(['sa_main', 'key_ex_main', 'authenticate'], 25)
# generate_run_genetic(starting_length=3)
# calc_baseline(18, 10)

print(f"Runtime: {time.time() - starttime} seconds")