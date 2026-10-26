from catalog import ADDITIVE, CATALOG, UNDO, Tier


def test_the_catalog_is_exactly_adr_0006s():
    """Changing this table is an ADR 0006 amendment. If this test fails,
    the change needs that review first."""
    assert CATALOG == {
        "preserve_evidence": Tier.AUTO,
        "notify_channel": Tier.AUTO,
        "hold_promotion": Tier.AUTO,
        "rollback_latest": Tier.APPROVAL,
        "block_client_ip": Tier.APPROVAL,
        "lift_promotion_hold": Tier.APPROVAL,
    }


def test_tier_c_actions_are_not_in_the_catalog():
    never = {"revoke_credentials", "rotate_credentials", "delete_image", "delete_data", "stop_service", "edit_workflow", "run_command"}
    assert never.isdisjoint(CATALOG)


def test_every_auto_action_is_additive_or_has_an_undo():
    for name, tier in CATALOG.items():
        if tier == Tier.AUTO:
            assert name in ADDITIVE or UNDO[name] is not None, name


def test_a_promotion_hold_and_its_lift_undo_each_other():
    assert UNDO["hold_promotion"] == "lift_promotion_hold"
    assert UNDO["lift_promotion_hold"] == "hold_promotion"


def test_lifting_a_hold_always_needs_approval():
    assert CATALOG["lift_promotion_hold"] == Tier.APPROVAL