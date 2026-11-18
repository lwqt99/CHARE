import copy
import unittest
from plot_paper_study import summarize, validate_study

class StudyChecks(unittest.TestCase):
    def test_duplicate_replicates_cannot_become_error_bars(self):
        rows=[dict(metric="x",series="s",unit="ms",capacity=4,replicate=i,value=i) for i in (1,2,3)]
        self.assertEqual(summarize(rows)[0]["median"],2)
        rows[-1]["replicate"]=2
        with self.assertRaises(ValueError): summarize(rows)

    def test_failed_or_missing_service_is_rejected(self):
        cfg=dict(capacity=4,replicate=1,paper_study=True)
        ev=dict(schema="chare-native-study-v1",comparison_order=["rebuild","delta"],
                helper_equal=True,own_helper_equal=True,old_state_unchanged=True,changed_cohort_rejected=True,services=[])
        for i,g in enumerate(("tree","cycle")):
            ev["services"].append(dict(graph=g,participants=4,directions=2,edges=3+i,contributions=8,pad_deliveries=2*(3+i),
                aggregate_equal=True,strict_prefix_protected=True,one_pad_protected=i==1,cut_pads_protected=False,recovery_key_equal=True))
        validate_study(cfg,ev)
        for field in ("helper_equal","old_state_unchanged"):
            bad=copy.deepcopy(ev);bad[field]=False
            with self.assertRaises(ValueError): validate_study(cfg,bad)
        bad=copy.deepcopy(ev);bad["services"][1]["one_pad_protected"]=False
        with self.assertRaises(ValueError): validate_study(cfg,bad)

if __name__=="__main__": unittest.main()
