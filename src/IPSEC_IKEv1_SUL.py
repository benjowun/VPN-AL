from aalpy.base import SUL
from aalpy.oracles import RandomWalkEqOracle
from aalpy.learning_algs import run_Lstar
from aalpy.utils import visualize_automaton

from IPSEC_Mapper import IPSEC_Mapper

class IPSEC_IKEv1_SUL(SUL):
    def __init__(self):
        super().__init__()
        self.ipsec = IPSEC_Mapper()

    def pre(self):
        #self.ipsec.delete()
        pass

    def post(self):
        pass
        #self.ipsec.delete()
    
    # map to concrete implementation
    def step(self, letter):
        print(letter)
        #print(self.ipsec.print_info())
        if letter == 'sa_main':
            return self.ipsec.sa_main()
        elif letter == 'key_ex_main':
            return self.ipsec.key_ex_main()
        elif letter == 'authenticate':
            return self.ipsec.authenticate()
        elif letter == 'sa_quick':
            return self.ipsec.sa_quick()
        elif letter == 'ack_quick':
            return self.ipsec.ack_quick()
        elif letter == 'delete':
            return self.ipsec.delete()
        elif letter == 'rekey_quick':
            return self.ipsec.rekey_quick()
        else:
            pass
        

sul = IPSEC_IKEv1_SUL()
input_al = ['sa_main', 'key_ex_main', 'authenticate', 'sa_quick', 'ack_quick', 'delete', 'rekey_quick']

eq_oracle = RandomWalkEqOracle(input_al, sul, num_steps=2000, reset_after_cex=True, reset_prob=0.15)

learned_mqtt= run_Lstar(input_al, sul, eq_oracle=eq_oracle, automaton_type='mealy', cache_and_non_det_check=True,
                  print_level=2)

visualize_automaton(learned_mqtt)