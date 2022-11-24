from aalpy.base.SUL import SUL
from aalpy.oracles import RandomWalkEqOracle, StatePrefixEqOracle
from aalpy.learning_algs import run_Lstar
from aalpy.utils import visualize_automaton

from IPSEC_Mapper import IPSEC_Mapper
from time import sleep

# timing params in seconds
WAIT_TIME = 1
CONNECTION_TIMEOUT = 3

class IPSEC_IKEv1_SUL(SUL):
    def __init__(self): 
        super().__init__()
        self.ipsec = IPSEC_Mapper(CONNECTION_TIMEOUT)
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
        self.ipsec.delete()
        #sleep(WAIT_TIME) # --> there is a read that times out here anyways
        #self.ipsec.delete()
        #self.ipsec.print_info()
    
    # map to concrete implementation
    def step(self, letter):
        #print(self.ipsec.print_info())
        print("$" + letter)
        self.logs_run.append(letter)
        if letter == 'sa_main':
            ret = self.ipsec.sa_main()
            print(" --> " + str(ret))
            return ret
        elif letter == 'key_ex_main':
            ret = self.ipsec.key_ex_main()
            print(" --> " + str(ret))
            return ret
        elif letter == 'authenticate':
            ret = self.ipsec.authenticate()
            print(" --> " + str(ret))
            return ret
        elif letter == 'sa_quick':
            ret = self.ipsec.sa_quick()
            print(" --> " + str(ret))
            return ret
        elif letter == 'ack_quick':
            ret = self.ipsec.ack_quick()
            print(" --> " + str(ret))
            return ret
        elif letter == 'delete_main':
            ret = self.ipsec.ISAKMP_delete_packet()
            print(" --> " + str(ret))
            return ret
        elif letter == 'delete_quick':
            ret = self.ipsec.IPSEC_delete_packet()
            print(" --> " + str(ret))
            return ret 
        # elif letter == 'rekey_quick':
        #     return self.ipsec.rekey_quick()
        else:
            print("Unexpected Input: " + str(letter))
            self.ipsec.print_info()
            exit(-1)
        

sul = IPSEC_IKEv1_SUL()
input_al = ['sa_main', 'key_ex_main', 'authenticate', 'sa_quick', 'ack_quick', 'delete_main', 'delete_quick'] # removed rekey, as it is essentially just another sa and ack, TODO: add delete again

#eq_oracle = RandomWalkEqOracle(input_al, sul, num_steps=2000, reset_after_cex=True, reset_prob=0.15)
eq_oracle = StatePrefixEqOracle(input_al, sul, walks_per_state=10, walk_len=10)

learned_ipsec= run_Lstar(input_al, sul, eq_oracle=eq_oracle, automaton_type='mealy', cache_and_non_det_check=True, print_level=3)

# TODO: is none-det check important?

visualize_automaton(learned_ipsec)

sul.ipsec.delete() # call at end to clean
