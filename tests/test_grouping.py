import unittest

from switchyard.grouping import build_groups, load_groups


def work(host="one", backend="podman", scope="user:1000", native="container-a", project="notes"):
    return {"id": ":".join((host, backend, scope, native)), "host_id": host, "backend": backend,
            "scope": scope, "native_id": native, "extensions": {"container.v1": {"project": project}}}


def declaration():
    return {"id": "notes", "name": "Notes application", "host_id": "one", "backend": "podman",
            "scope": "user:1000", "native_ids": ["container-a", "database-b"], "provenance": "Operator association only"}


class GroupingTests(unittest.TestCase):
    def test_project_names_do_not_merge_hosts_backends_or_scopes(self):
        records = [work(), work(host="two"), work(backend="docker", scope="system"), work(scope="user:1001")]
        groups = build_groups([], records)
        self.assertEqual(len(groups), 4)
        self.assertEqual(len({g["id"] for g in groups}), 4)
        for group, record in zip(groups, records):
            self.assertEqual(group["member_ids"], [record["id"]])
            self.assertFalse(group["atomic"])
            self.assertEqual(group["management"], "discovered")

    def test_declared_group_does_not_fabricate_missing_members_or_duplicate_project_members(self):
        declared = load_groups({"application_groups": [declaration()]}, {"one"})
        records = [work()]
        groups = build_groups(declared, records)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["member_ids"], [records[0]["id"]])
        self.assertEqual(groups[0]["missing_native_ids"], ["database-b"])
        replacement = work(native="replacement-container")
        labelled = build_groups([], [records[0]])
        self.assertEqual(labelled[0]["id"], build_groups([], [replacement])[0]["id"])

    def test_rejects_ambiguous_membership_and_unknown_hosts(self):
        for changed in ({**declaration(), "id": "second"}, {**declaration(), "host_id": "missing"}):
            with self.assertRaises(ValueError):
                load_groups({"application_groups": [declaration(), changed]}, {"one"})
        with self.assertRaises(ValueError):
            load_groups({"application_groups": [{**declaration(), "native_ids": ["same", "same"]}]}, {"one"})

    def test_no_implicit_group_from_similar_resource_names(self):
        resources = [work(backend="systemd", native="notes.service"), work(backend="systemd", native="notes.timer")]
        self.assertEqual(build_groups([], resources), [])


if __name__ == "__main__":
    unittest.main()
