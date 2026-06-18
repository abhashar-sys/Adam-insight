from tools.xiphos import find_mitigation_context
from tools.customer_api import find_customer_context
from tools.chakra_rs import find_attack_context

tn="193.203.230.149/32"
loc=["fll1","ips9"]
ci=3410
cn="sia"
print("-------mitigation tool-------")
mitigation=find_mitigation_context(tn,loc)
print(mitigation)
print("-------customer tool---------")
customers=find_customer_context(tn)
print(customers)
print("-------attack tool-----------")
if customers:
    for c in customers:
        res=find_attack_context(
            c["customer_id"],
            c["customer"],
            tn
        )
        print(res)
else:
    print("no customers")