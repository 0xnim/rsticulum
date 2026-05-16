"""Test RNS resource transfer between nodes."""

from pathlib import Path

from lib.orchestrator import Orchestrator, RnsNode

TOPOLOGY_3 = Path(__file__).parent.parent / "configs" / "mesh_3_python.yaml"
WORK_DIR = Path("/tmp") / "rstest-resource"


def test_nodes_can_announce_for_resource():
    """Both nodes can announce destinations suitable for resource serving."""
    orch = Orchestrator(str(TOPOLOGY_3), WORK_DIR)
    orch.setup()
    orch.start_all()

    try:
        alpha = orch.get("alpha")
        gamma = orch.get("gamma")
        assert isinstance(alpha, RnsNode)
        assert isinstance(gamma, RnsNode)

        resp_a = alpha.announce("resource_alpha")
        resp_g = gamma.announce("resource_gamma")

        assert resp_a.get("status") == "ok"
        assert resp_g.get("status") == "ok"

        assert len(alpha.identity_hash()) == 16
        assert len(gamma.identity_hash()) == 16
    finally:
        orch.stop_all()
