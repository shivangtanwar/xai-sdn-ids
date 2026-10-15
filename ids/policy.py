"""Confidence-Gated Response Engine (CGRE).

Decides whether an ML alert is allowed to change the network. A source is only mitigated
when the gates hold:
  G1 confidence   - class probability above a threshold
  G2 persistence  - flagged in >= k of the last n windows
  G3 explanation  - the top SHAP features match the attack class's expected signature
  G4 asset safety - the source is not a protected asset
The response is graduated: NONE < ALERT < RATE_LIMIT < BLOCK.
"""
import time
from collections import defaultdict, deque

from ids import config as C

NONE, ALERT, RATE_LIMIT, BLOCK = "NONE", "ALERT", "RATE_LIMIT", "BLOCK"
SEVERITY = {NONE: 0, ALERT: 1, RATE_LIMIT: 2, BLOCK: 3}


class ResponseEngine:
    def __init__(self, gates=("G1", "G2", "G3", "G4")):
        # `gates` makes the ablation study possible: () = naive "block on any positive".
        self.gates = set(gates)
        self.history = defaultdict(lambda: deque(maxlen=C.PERSIST_N))
        self.active = {}  # src -> (action, expiry timestamp)

    def current_action(self, src, now=None):
        now = now or time.time()
        action, expiry = self.active.get(src, (NONE, 0))
        if now >= expiry:
            self.active.pop(src, None)
            return NONE
        return action

    def decide(self, src, label, prob, top_features, now=None):
        """Returns (action, gate results dict, reason)."""
        now = now or time.time()
        is_attack = label != "benign"
        self.history[src].append(is_attack and prob >= C.TAU_LIMIT)

        if not is_attack:
            return NONE, {}, "benign"

        if not self.gates:   # naive baseline
            return self._commit(src, BLOCK, now), {}, "naive: block on any positive"

        g = {
            "G1_block": prob >= C.TAU_BLOCK,
            "G1_limit": prob >= C.TAU_LIMIT,
            "G2": sum(self.history[src]) >= C.PERSIST_K,
            "G3": bool({f["feature"] for f in top_features} & C.SIGNATURES.get(label, set())),
            "G4": src not in C.PROTECTED_IPS,
        }
        for gate, keys in (("G1", ("G1_block", "G1_limit")), ("G2", ("G2",)),
                           ("G3", ("G3",)), ("G4", ("G4",))):
            if gate not in self.gates:
                for k in keys:
                    g[k] = True

        if not g["G1_limit"]:
            return NONE, g, f"low confidence ({prob:.2f} < {C.TAU_LIMIT})"
        if not g["G4"]:
            return ALERT, g, "protected asset: alert only"
        if not g["G3"]:
            return ALERT, g, "explanation inconsistent with attack signature"
        if not g["G2"]:
            return ALERT, g, f"not persistent yet (<{C.PERSIST_K}/{C.PERSIST_N} windows)"
        if g["G1_block"]:
            return self._commit(src, BLOCK, now), g, "all gates passed"
        return self._commit(src, RATE_LIMIT, now), g, "medium confidence: rate-limit"

    def _commit(self, src, action, now):
        """Record an action unless an equal or stronger one is already active."""
        if SEVERITY[self.current_action(src, now)] >= SEVERITY[action]:
            return NONE
        timeout = C.BLOCK_HARD_TIMEOUT if action == BLOCK else C.LIMIT_HARD_TIMEOUT
        self.active[src] = (action, now + timeout)
        return action
