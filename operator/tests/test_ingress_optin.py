"""Unit tests for operator/code/ingress_optin.py: which Ingresses the operator
handles and what the diff-base storage writes for each body. kopf itself is
not installed here; the storage test stands in a minimal fake for it."""

import os
import sys
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
CODE_DIR = os.path.join(os.path.dirname(HERE), "code")
if CODE_DIR not in sys.path:
    sys.path.insert(0, CODE_DIR)

import ingress_optin  # noqa: E402

ENABLE = ingress_optin.ENABLE_ANNOTATION
KOPF_KEY = "kopf.zalando.org/last-handled-configuration"
KEYS = [KOPF_KEY]


def ingress(annotations=None, kind="Ingress"):
    body = {"apiVersion": "networking.k8s.io/v1", "metadata": {"name": "web", "namespace": "shop"}}
    if kind is not None:
        body["kind"] = kind
    if annotations is not None:
        body["metadata"]["annotations"] = annotations
    return body


class OptInTests(unittest.TestCase):
    def test_the_enable_annotation_opts_in_whatever_its_value(self):
        self.assertTrue(ingress_optin.is_opted_in(ingress({ENABLE: "true"})))
        self.assertTrue(ingress_optin.is_opted_in(ingress({ENABLE: "false"})), "handled, so its Scanners go away")
        self.assertFalse(ingress_optin.is_opted_in(ingress({"other/annotation": "x"})))
        self.assertFalse(ingress_optin.is_opted_in(ingress({})))
        self.assertFalse(ingress_optin.is_opted_in(ingress()))

    def test_other_annotations_under_the_prefix_do_not_opt_in(self):
        self.assertFalse(ingress_optin.is_opted_in(ingress({ingress_optin.ANNOTATION_PREFIX + "profile": "web"})))

    def test_enable_field_is_a_tuple_because_the_key_has_dots(self):
        self.assertEqual(ingress_optin.ENABLE_FIELD, ("metadata", "annotations", "samma-io.alpha.kubernetes.io/enable"))

    def test_is_ingress(self):
        self.assertTrue(ingress_optin.is_ingress(ingress()))
        self.assertFalse(ingress_optin.is_ingress({"kind": "Scanner", "metadata": {}}))
        self.assertFalse(ingress_optin.is_ingress({"metadata": {}}))


class DiffBaseActionTests(unittest.TestCase):
    def action(self, body):
        return ingress_optin.diffbase_action(body, KEYS)

    def test_opted_in_ingress_is_stored_as_kopf_would(self):
        self.assertEqual(self.action(ingress({ENABLE: "true"})), ingress_optin.STORE)
        self.assertEqual(self.action(ingress({ENABLE: "false", KOPF_KEY: "{}"})), ingress_optin.STORE)

    def test_other_ingresses_get_nothing_written(self):
        self.assertEqual(self.action(ingress()), ingress_optin.SKIP)
        self.assertEqual(self.action(ingress({})), ingress_optin.SKIP)
        self.assertEqual(self.action(ingress({"cert-manager.io/cluster-issuer": "le"})), ingress_optin.SKIP)

    def test_a_leftover_diff_base_is_cleared(self):
        # Written by 0.2.x on every Ingress, or by this operator before the
        # enable annotation was removed again.
        self.assertEqual(self.action(ingress({KOPF_KEY: "{}"})), ingress_optin.CLEAR)
        self.assertEqual(self.action(ingress({"other/annotation": "x", KOPF_KEY: "{}"})), ingress_optin.CLEAR)

    def test_scanners_and_bodies_without_a_kind_are_stored(self):
        self.assertEqual(self.action({"kind": "Scanner", "metadata": {"name": "s"}}), ingress_optin.STORE)
        self.assertEqual(self.action({"metadata": {"name": "s"}}), ingress_optin.STORE)


class _FakeBaseStorage(object):
    """What make_diffbase_storage() uses of kopf.AnnotationsDiffBaseStorage:
    the key, make_keys() and a store() that records what it was asked to write."""

    def __init__(self):
        self.key = "last-handled-configuration"
        self.stored = []

    def make_keys(self, key, body=None):
        return ["kopf.zalando.org/" + key]

    def store(self, *, body, patch, essence):
        self.stored.append(essence)
        patch.metadata.annotations["kopf.zalando.org/" + self.key] = "stored"


class _FakePatch(dict):
    """kopf.Patch is a dict with a .metadata.annotations view."""

    def __init__(self):
        super(_FakePatch, self).__init__({"metadata": {"annotations": {}}})

    @property
    def metadata(self):
        return types.SimpleNamespace(annotations=self["metadata"]["annotations"])


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.saved = sys.modules.get("kopf")
        fake = types.ModuleType("kopf")
        fake.AnnotationsDiffBaseStorage = _FakeBaseStorage
        sys.modules["kopf"] = fake

    def tearDown(self):
        if self.saved is None:
            del sys.modules["kopf"]
        else:
            sys.modules["kopf"] = self.saved

    def test_store_skip_and_clear(self):
        storage = ingress_optin.make_diffbase_storage()

        patch = _FakePatch()
        storage.store(body=ingress({ENABLE: "true"}), patch=patch, essence={"spec": 1})
        self.assertEqual(storage.stored, [{"spec": 1}])
        self.assertEqual(patch["metadata"]["annotations"], {KOPF_KEY: "stored"})

        patch = _FakePatch()
        storage.store(body=ingress({"cert-manager.io/cluster-issuer": "le"}), patch=patch, essence={"spec": 1})
        self.assertEqual(storage.stored, [{"spec": 1}], "nothing more was stored")
        self.assertEqual(patch["metadata"]["annotations"], {}, "an unrelated Ingress is not patched")

        patch = _FakePatch()
        storage.store(body=ingress({KOPF_KEY: "{}"}), patch=patch, essence={"spec": 2})
        self.assertEqual(storage.stored, [{"spec": 1}])
        self.assertEqual(patch["metadata"]["annotations"], {KOPF_KEY: None}, "the leftover is removed")

        patch = _FakePatch()
        storage.store(body={"kind": "Scanner", "metadata": {"name": "s"}}, patch=patch, essence={"spec": 3})
        self.assertEqual(storage.stored[-1], {"spec": 3}, "other kinds are stored as before")
