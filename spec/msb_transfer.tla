---- MODULE msb_transfer ----
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Proc, Enclave, GPA, HPA

VARIABLES ept, cap, ownership

vars == <<ept, cap, ownership>>

Permission == {"TRANSFER", "MAP_SHARED"}

TypeOK ==
    /\ ept \in [Enclave -> [GPA -> HPA \cup {None}]]
    /\ cap \in [Enclave -> SUBSET(Enclave \X Permission)]
    /\ ownership \in [HPA -> Enclave]

Init ==
    /\ ept = [e \in Enclave |-> [g \in GPA |-> None]]
    /\ cap = [e \in Enclave |-> {}]
    /\ ownership = [h \in HPA |-> 1]

HC_Transfer(src, dst, src_gpa, dst_gpa) ==
    /\ \exists h \in HPA: ept[src][src_gpa] = h
    /\ \exists p \in Permission: <<dst, p>> \in cap[src] /\ p = "TRANSFER"
    /\ ownership[ept[src][src_gpa]] = src
    /\ LET hpa == ept[src][src_gpa]
       IN  /\ ept' = [ept EXCEPT ![src][src_gpa] = None, ![dst][dst_gpa] = hpa]
           /\ ownership' = [ownership EXCEPT ![hpa] = dst]
           /\ UNCHANGED cap

Next ==
    \/ \exists src, dst \in Enclave, src_gpa, dst_gpa \in GPA:
        HC_Transfer(src, dst, src_gpa, dst_gpa)
    \/ UNCHANGED vars

Spec == Init /\ [][Next]_vars

NoDoubleMap ==
    \A h \in HPA:
        Cardinality({<<e, g>> \in DOMAIN(ept) \X DOMAIN(ept[e]) : ept[e][g] = h}) \leq 1

OwnershipConsistent ==
    \A h \in HPA, e \in Enclave:
        (\exists g \in GPA: ept[e][g] = h) => (ownership[h] = e)

====