from aalpy.base.SUL import SUL
from aalpy.oracles import RandomWalkEqOracle, StatePrefixEqOracle
from aalpy.learning_algs.deterministic.LStar import run_Lstar
from aalpy.learning_algs.deterministic.KV import run_KV

from IPSEC_Mapper import IPSEC_Mapper
from time import sleep

# timing params in seconds
WAIT_TIME = 1
CONNECTION_TIMEOUT = 4
IGNORE_RETRANSMISSION = True

class IPSEC_IKEv1_SUL(SUL):
    def __init__(self): 
        super().__init__()
        self.ipsec = IPSEC_Mapper(CONNECTION_TIMEOUT, IGNORE_RETRANSMISSION)
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
        print("$" + letter)
        self.logs_run.append(letter)
        func = getattr(self.ipsec, letter)
        ret = func()
        print(" --> " + str(ret))
        return ret
        

# alternatively load a previously learned automaton from dot file and use it for learning
# automation = load_automaton_from_file('path_to_file.dot', automation_type='mealy')

sul = IPSEC_IKEv1_SUL()
input_al = ['sa_main', 'key_ex_main', 'authenticate', 'sa_quick', 'ack_quick', 'sa_main_err', 'key_ex_main_err', 'authenticate_err', 'sa_quick_err', 'ack_quick_err'] # removed rekey, as it is essentially just another sa and ack, TODO: add delete again

#eq_oracle = RandomWalkEqOracle(input_al, sul, num_steps=2000, reset_after_cex=True, reset_prob=0.15)
eq_oracle = StatePrefixEqOracle(input_al, sul, walks_per_state=10, walk_len=10)

#learned_ipsec = run_Lstar(input_al, sul, eq_oracle=eq_oracle, automaton_type='mealy', cache_and_non_det_check=True, print_level=3)
learned_ipsec = run_KV(input_al, sul, eq_oracle, automaton_type='mealy', print_level=3, cex_processing='rs')

print(learned_ipsec)

learned_ipsec.save()
learned_ipsec.visualize()

sul.ipsec.delete() # call at end to clean any leftover connections
