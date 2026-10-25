"""Which Ingresses the operator handles, and nothing else.

The operator watches every Ingress in the cluster but acts only on the ones
that carry the samma-io.alpha.kubernetes.io/enable annotation. Two things
make that true:

1. The kopf handlers in operator_handler.py are registered with
   ``annotations={ENABLE_ANNOTATION: kopf.PRESENT}``, so an Ingress without
   the annotation matches no handler. One more update handler watches the
   annotation itself going away (old present, new absent) and removes the
   Scanners, since the filtered handlers no longer match at that point.
2. An Ingress outside the operator's own namespace has to be listed in
   SAMMA_INGRESS_NAMESPACES ('*' is every namespace) for the handlers to
   run on it; the predicate :func:`ingress_namespace_allowed` is the
   check they use. The ClusterRole stays cluster-wide, so the list can
   change with an env edit.
3. kopf stores its diff base (the kopf.zalando.org/last-handled-configuration
   annotation) on every object it watches, handlers or no handlers; that is
   how 0.2.x annotated every Ingress in the cluster. The storage built by
   :func:`make_diffbase_storage` keeps that annotation on opted-in Ingresses
   (kopf needs it to tell an update from a creation), writes nothing on any
   other Ingress, and removes a leftover one the next time such an Ingress
   changes. Scanners and every other kind are stored as before.

Everything here except :func:`make_diffbase_storage` is plain Python, so it
is unit tested without kopf.
"""

ANNOTATION_PREFIX = 'samma-io.alpha.kubernetes.io/'
ENABLE_ANNOTATION = ANNOTATION_PREFIX + 'enable'
# The annotation as a kopf field path: a tuple, because the key has dots.
ENABLE_FIELD = ('metadata', 'annotations', ENABLE_ANNOTATION)

STORE, SKIP, CLEAR = 'store', 'skip', 'clear'


def annotations_of(body):
    metadata = body.get('metadata') or {}
    return metadata.get('annotations') or {}


def is_ingress(body):
    """kopf fills in ``kind`` on listed objects; watch events carry it."""
    return body.get('kind') == 'Ingress'


def is_opted_in(body):
    """The Ingress carries the enable annotation with any value, like kopf's
    PRESENT filter. A value such as "false" still counts: the handler then
    runs and removes the Scanners."""
    return ENABLE_ANNOTATION in annotations_of(body)


def ingress_namespace_allowed(namespace, own_namespace, allowed):
    """Whether the operator acts on an Ingress in ``namespace``. Its own
    namespace is always allowed, even with an empty allow-list; every other
    namespace has to be listed, and ``'*'`` in the list allows all of them.
    Plain str/list arguments: the tests run without kopf installed."""
    if namespace == own_namespace:
        return True
    return '*' in allowed or namespace in allowed


def diffbase_action(body, keys):
    """What the diff-base storage does for ``body``: STORE as kopf would,
    SKIP (write nothing), or CLEAR the ``keys`` that are present, which are
    leftovers from an operator that stored them on every Ingress."""
    if not is_ingress(body) or is_opted_in(body):
        return STORE
    if any(key in annotations_of(body) for key in keys):
        return CLEAR
    return SKIP


def make_diffbase_storage():
    """kopf's annotation diff-base storage, restricted to opted-in
    Ingresses as described above. kopf is imported here, lazily: it is only
    installed in the operator image."""
    import kopf

    class OptInDiffBaseStorage(kopf.AnnotationsDiffBaseStorage):
        def store(self, *, body, patch, essence):
            keys = list(self.make_keys(self.key, body=body))
            action = diffbase_action(body, keys)
            if action == STORE:
                super().store(body=body, patch=patch, essence=essence)
            elif action == CLEAR:
                present = annotations_of(body)
                for key in keys:
                    if key in present:
                        patch.metadata.annotations[key] = None  # merge-patch: removed

    return OptInDiffBaseStorage()
