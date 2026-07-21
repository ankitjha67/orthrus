"""Team mode / RBAC on the operator graph (PRD §9)."""

from __future__ import annotations

import asyncio

import pytest

from orthrus.model.entities import role_allows
from orthrus.model.store import ProgramGraph


def _graph(tmp_path, name="team.db") -> ProgramGraph:
    return ProgramGraph(f"sqlite+aiosqlite:///{(tmp_path / name).as_posix()}")


def test_role_ordering():
    assert role_allows("owner", "viewer") and role_allows("owner", "owner")
    assert role_allows("member", "viewer") and not role_allows("member", "owner")
    assert role_allows("viewer", "viewer") and not role_allows("viewer", "member")
    assert not role_allows(None, "viewer")          # no role → denied
    assert not role_allows("bogus", "viewer")


def test_users_keys_and_membership(tmp_path):
    async def run():
        g = _graph(tmp_path)
        await g.init()
        pid = (await g.create_program("Acme", "self-owned-lab", platform="self")).id

        lead = await g.create_user("lead@acme.test", name="Lead")
        intern = await g.create_user("intern@acme.test")
        assert lead.id and lead.email == "lead@acme.test"

        # unique email + email validation
        with pytest.raises(ValueError, match="already exists"):
            await g.create_user("LEAD@acme.test")       # case-insensitive dupe
        with pytest.raises(ValueError, match="valid email"):
            await g.create_user("not-an-email")

        # api key: raw returned once, only the hash is stored, resolves back
        raw = await g.generate_api_key(lead.id)
        assert raw and (await g.get_user(lead.id)).api_key_hash != raw
        assert (await g.get_user_by_api_key(raw)).id == lead.id
        assert await g.get_user_by_api_key("wrong-key") is None

        # rotating the key invalidates the old one
        raw2 = await g.generate_api_key(lead.id)
        assert raw2 != raw
        assert await g.get_user_by_api_key(raw) is None
        assert (await g.get_user_by_api_key(raw2)).id == lead.id

        # roles gate correctly
        await g.add_member(pid, lead.id, "owner")
        await g.add_member(pid, intern.id, "viewer")
        assert await g.user_can(pid, lead.id, "owner")
        assert await g.user_can(pid, intern.id, "viewer")
        assert not await g.user_can(pid, intern.id, "member")

        # a non-member has no access; an inactive user loses key auth
        stranger = await g.create_user("stranger@acme.test")
        assert await g.effective_role(pid, stranger.id) is None
        await g.set_user_active(lead.id, False)
        assert await g.get_user_by_api_key(raw2) is None       # inactive → key rejected

        # upsert role change + revoke
        await g.add_member(pid, intern.id, "member")
        assert (await g.get_membership(pid, intern.id)).role == "member"
        assert await g.remove_member(pid, intern.id) is True
        assert await g.effective_role(pid, intern.id) is None

        with pytest.raises(ValueError, match="role must be one of"):
            await g.add_member(pid, stranger.id, "superuser")
        await g.close()

    asyncio.run(run())


def test_admin_is_implicit_owner_everywhere(tmp_path):
    async def run():
        g = _graph(tmp_path, "team2.db")
        await g.init()
        a = (await g.create_program("A", "self-owned-lab", platform="self")).id
        b = (await g.create_program("B", "self-owned-lab", platform="self")).id
        admin = await g.create_user("root@acme.test", is_admin=True)
        # no memberships anywhere, yet admin is owner on every program
        assert await g.effective_role(a, admin.id) == "owner"
        assert await g.user_can(b, admin.id, "owner")
        await g.close()

    asyncio.run(run())
