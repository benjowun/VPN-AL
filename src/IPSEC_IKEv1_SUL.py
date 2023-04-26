from aalpy.base.SUL import SUL
from aalpy.oracles import RandomWalkEqOracle, StatePrefixEqOracle
from aalpy.learning_algs.deterministic.LStar import run_Lstar
from aalpy.learning_algs.deterministic.KV import run_KV
from statistics import mean
import utils

from Connector import Connector

from IPSEC_Mapper import IPSEC_Mapper
from time import sleep

# timing params in seconds
WAIT_TIME = 1
CONNECTION_TIMEOUT = 2
IGNORE_RETRANSMISSION = True

conn = Connector("10.0.2.1", 500, 500, CONNECTION_TIMEOUT)

class IPSEC_IKEv1_SUL(SUL):
    def __init__(self): 
        super().__init__()
        self.ipsec = IPSEC_Mapper(IGNORE_RETRANSMISSION, conn)
        self.logs_run = []
        self.file = open("logs.txt", "w+")
        #self.ipsec.reset()

    def __exit__(self):
        self.file.close()

    def pre(self):
        print("\n***Ran pre***")
        self.ipsec.reset()
        for s in self.logs_run:
            self.file.write("self." + str(s) + ", ")
        self.file.write("\n")
        self.logs_run = []
        #self.ipsec.print_info()

    def post(self):
        print("***Ran post***\n")
        sleep(WAIT_TIME)
        self.ipsec.delete()
        #self.ipsec.print_info()
    
    # map to concrete implementation
    def step(self, letter):
        #print(self.ipsec.print_info())
        print("$" + str(letter))
        self.logs_run.append(letter)
        func = getattr(self.ipsec, letter)
        ret = func()
        print(" --> " + str(ret))
        return ret
        
def learn(kv=True):
    # alternatively load a previously learned automaton from dot file and use it for learning
    # automation = load_automaton_from_file('path_to_file.dot', automation_type='mealy')

    sul = IPSEC_IKEv1_SUL()
    input_al = ['sa_main', 'key_ex_main', 'authenticate', 'sa_quick', 'ack_quick', 'sa_main_err', 'key_ex_main_err', 'authenticate_err', 'sa_quick_err', 'ack_quick_err'] # removed rekey, as it is essentially just another sa and ack, TODO: add delete again
    #input_al = ['sa_main', 'key_ex_main', 'authenticate', 'sa_quick', 'ack_quick'] # removed rekey, as it is essentially just another sa and ack, TODO: add delete again


    #eq_oracle = RandomWalkEqOracle(input_al, sul, num_steps=2000, reset_after_cex=True, reset_prob=0.15)
    eq_oracle = StatePrefixEqOracle(input_al, sul, walks_per_state=10, walk_len=10)

    learned_ipsec = None
    info = None
    if kv:
        learned_ipsec, info = run_KV(input_al, sul, eq_oracle, automaton_type='mealy', print_level=3, cex_processing='rs', return_data=True)
    else:
        learned_ipsec, info = run_Lstar(input_al, sul, eq_oracle=eq_oracle, automaton_type='mealy', cache_and_non_det_check=True, print_level=3, return_data=True)

    print(learned_ipsec)

    if utils.libre:
        learned_ipsec.save("libre.dot")
        learned_ipsec.visualize("LearnedModelLibreLatest")
        sul.ipsec.delete_v2()
    else:
        learned_ipsec.save("strong.dot")
        learned_ipsec.visualize("LearnedModelStrongLatest")
        sul.ipsec.delete() # call at end to clean any leftover connections
    
    return info

# learning rounds, automaton size, learning queries, setps learning, eq oracle queries, eq oracle steps, 
# learning time, eq oracle time, total time
def time(num_runs=10):
    results_kv = []
    lr_kv = []
    as_kv = []
    lqr_kv = []
    slr_kv = []
    eqqr_kv = []
    seq_kv = []
    lt_kv = []
    eqt_kv = []
    tt_kv = []

    results_lstar = []
    lr_ls = []
    as_ls = []
    lqr_ls = []
    slr_ls = []
    eqqr_ls = []
    seq_ls = []
    lt_ls = []
    eqt_ls = []
    tt_ls = []

    i = 0
    while i <= num_runs:
        info = learn(kv=True)
        if info['automaton_size'] == 6: # filter out occasional outlier due to timing issues in server
            results_kv.append(info)
            lr_kv.append(info['learning_rounds'])
            as_kv.append(info['automaton_size'])
            lqr_kv.append(info['queries_learning'])
            slr_kv.append(info['steps_learning'])
            eqqr_kv.append(info['queries_eq_oracle'])
            seq_kv.append(info['steps_eq_oracle'])
            lt_kv.append(info['learning_time'])
            eqt_kv.append(info['eq_oracle_time'])
            tt_kv.append(info['total_time'])
            i += 1
            
    i = 0

    while i <= num_runs:
        info = learn(kv=False)
        if info['automaton_size'] == 6:
            results_lstar.append(info)
            lr_ls.append(info['learning_rounds'])
            as_ls.append(info['automaton_size'])
            lqr_ls.append(info['queries_learning'])
            slr_ls.append(info['steps_learning'])
            eqqr_ls.append(info['queries_eq_oracle'])
            seq_ls.append(info['steps_eq_oracle'])
            lt_ls.append(info['learning_time'])
            eqt_ls.append(info['eq_oracle_time'])
            tt_ls.append(info['total_time'])
            i += 1

    print(f"KV RESULTS:\n{results_kv}\n\n")
    print(f"L* RESULTS:\n{results_lstar}\n\n")

    print("KV averages:")
    print("*******************************")
    print(f"Learning Rounds: {mean(lr_kv)}")
    print(f"Automaton Size: {mean(as_kv)}")
    print(f"Learning Queries: {mean(lqr_kv)}")
    print(f"Learning Steps: {mean(slr_kv)}")
    print(f"Learning Time: {mean(lt_kv)}")
    print(f"Eq Oracle Queries: {mean(eqqr_kv)}")
    print(f"Eq Oracle Steps: {mean(seq_kv)}")
    print(f"Eq Oracle Time: {mean(eqt_kv)}")
    print(f"Total Time: {mean(tt_kv)}")
    print("*******************************")

    print("L* averages:")
    print("*******************************")
    print(f"Learning Rounds: {mean(lr_ls)}")
    print(f"Automaton Size: {mean(as_ls)}")
    print(f"Learning Queries: {mean(lqr_ls)}")
    print(f"Learning Steps: {mean(slr_ls)}")
    print(f"Learning Time: {mean(lt_ls)}")
    print(f"Eq Oracle Queries: {mean(eqqr_ls)}")
    print(f"Eq Oracle Steps: {mean(seq_ls)}")
    print(f"Eq Oracle Time: {mean(eqt_ls)}")
    print(f"Total Time: {mean(tt_ls)}")
    print("*******************************")


learn(kv=True)
#time()