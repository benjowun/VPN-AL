from aalpy.base import SUL
from aalpy.oracles import RandomWalkEqOracle
from aalpy.learning_algs import run_Lstar
from aalpy.utils import visualize_automaton

from IPSEC_Mapper import IPSEC_Mapper

class IPSEC_IKEv1_SUL(SUL):
    def __init__(self):
        super().__init__()
        self.ipsec = IPSEC_Mapper()
        self.logs_run = []
        self.file = open("logs.txt", "w+")
        #self.ipsec.reset()

    def __exit__(self):
        self.file.close()

    def pre(self):
        print("\nRan pre")
        self.ipsec.delete()
        self.ipsec.reset()
        for s in self.logs_run:
            self.file.write(str(s) + ", ")
        self.file.write("\n")
        self.logs_run = []

    def post(self):
        pass
        #self.ipsec.delete()
    
    # map to concrete implementation
    def step(self, letter):
        #print(self.ipsec.print_info())
        print(letter)
        self.logs_run.append(letter)
        if letter == 'sa_main':
            ret = self.ipsec.sa_main()
            print(" RET - " + str(ret))
            return ret
        elif letter == 'key_ex_main':
            ret = self.ipsec.key_ex_main()
            print(" RET - " + str(ret))
            return ret
        elif letter == 'authenticate':
            ret = self.ipsec.authenticate()
            print(" RET - " + str(ret))
            return ret
        elif letter == 'sa_quick':
            ret = self.ipsec.sa_quick()
            print(" RET - " + str(ret))
            return ret
        elif letter == 'ack_quick':
            ret = self.ipsec.ack_quick()
            print(" RET - " + str(ret))
            return ret
        elif letter == 'delete':
            ret = self.ipsec.delete()
            print(" RET - " + str(ret))
            return ret 
        # elif letter == 'rekey_quick':
        #     return self.ipsec.rekey_quick()
        else:
            print("Unexpected Input: " + str(letter))
            exit(-1)
        

sul = IPSEC_IKEv1_SUL()
input_al = ['sa_main', 'key_ex_main', 'authenticate', 'sa_quick', 'ack_quick'] # removed rekey, as it is essentially just another sa and ack

eq_oracle = RandomWalkEqOracle(input_al, sul, num_steps=2000, reset_after_cex=True, reset_prob=0.15)

learned_mqtt= run_Lstar(input_al, sul, eq_oracle=eq_oracle, automaton_type='mealy', cache_and_non_det_check=True,
                  print_level=2)

# TODO: is none-det check important?

visualize_automaton(learned_mqtt)