# Aura Protocol — Formal Verification
#
# Targets:
#   make all            — run release-scope verification (handshake + ratchet + active proverif + group proverif)
#   make tamarin        — verify both Tamarin models
#   make handshake      — Tamarin: X3DH handshake (secrecy, auth, FS)
#   make ratchet        — Tamarin: double ratchet (PCS, key secrecy, agreement, reachability)
#   make tamarin-full   — Tamarin: full combined model (may be very slow)
#   make proverif       — run the active ProVerif model (4/4 proof-scope queries discharged)
#   make proverif-group — run the group ProVerif scoped model (6/6 queries discharged)
#   make clean          — remove generated artifacts

TAMARIN  ?= tamarin-prover
PROVERIF ?= proverif

SPTHY_FULL      := tamarin/aura.spthy
SPTHY_HANDSHAKE := tamarin/aura_handshake.spthy
SPTHY_RATCHET   := tamarin/aura_ratchet.spthy
PV              := proverif/aura.pv
PV_GROUP        := proverif/aura_group.pv

.PHONY: all tamarin handshake ratchet tamarin-full proverif proverif-group clean check-tamarin check-proverif

all: tamarin proverif proverif-group

tamarin: handshake ratchet

check-tamarin:
	@command -v $(TAMARIN) >/dev/null 2>&1 || \
		{ echo "Error: $(TAMARIN) not found. Install: https://tamarin-prover.com/manual/master/book/002_installation.html"; exit 1; }

check-proverif:
	@command -v $(PROVERIF) >/dev/null 2>&1 || \
		{ echo "Error: $(PROVERIF) not found. Install: https://bblanche.gitlabpages.inria.fr/proverif/"; exit 1; }

handshake: check-tamarin
	$(TAMARIN) --prove --heuristic=S --derivcheck-timeout=60 $(SPTHY_HANDSHAKE)

ratchet: check-tamarin
	$(TAMARIN) --prove --heuristic=S $(SPTHY_RATCHET)

tamarin-full: check-tamarin
	$(TAMARIN) --prove --heuristic=S $(SPTHY_FULL)

proverif: check-proverif
	$(PROVERIF) $(PV)

proverif-group: check-proverif
	$(PROVERIF) $(PV_GROUP)

clean:
	rm -rf tamarin/output proverif/output
	rm -f tamarin/*.tmp proverif/*.tmp
