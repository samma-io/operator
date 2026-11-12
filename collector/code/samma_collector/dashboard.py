"""The samma.io read API, as the collector uses it.

  GET /api/v1/targets?limit=100&cursor=    {targets: [...], nextCursor?}
  GET /api/v1/targets/<id>/results?limit=500
                                           {targetId, runs: [...], results: [...]}

Both take ``Authorization: Bearer <token>``; a read-only token is enough.
The token never appears in a message or an exception.
"""

import json
import urllib.error
import urllib.parse
import urllib.request

TARGET_PAGE = 100
RESULT_LIMIT = 500


class DashboardError(Exception):
    """``kind`` is the metric label: auth, http or network."""

    def __init__(self, kind, message, status=None):
        super().__init__(message)
        self.kind = kind
        self.status = status


class NotFound(DashboardError):
    def __init__(self, message):
        super().__init__("http", message, status=404)


class Dashboard(object):
    def __init__(self, base_url, token, timeout=15, version="dev", opener=None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.user_agent = "samma-collector/{0}".format(version)
        self._open = opener or urllib.request.urlopen

    def targets(self):
        """Every target of the token's organisation."""
        found = []
        cursor = None
        while True:
            query = {"limit": str(TARGET_PAGE)}
            if cursor:
                query["cursor"] = cursor
            body = self._get("/api/v1/targets?" + urllib.parse.urlencode(query))
            found.extend(body.get("targets") or [])
            cursor = body.get("nextCursor")
            if not cursor:
                return found

    def results(self, target_id):
        """The latest run per scanner and up to RESULT_LIMIT latest findings."""
        path = "/api/v1/targets/{0}/results?limit={1}".format(urllib.parse.quote(str(target_id), safe=""), RESULT_LIMIT)
        return self._get(path)

    def _get(self, path):
        request = urllib.request.Request(
            self.base_url + path,
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/json",
                "User-Agent": self.user_agent,
            },
        )
        endpoint = path.split("?", 1)[0]
        try:
            with self._open(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            exc.close()
            if exc.code == 404:
                raise NotFound("{0}: not found".format(endpoint))
            if exc.code in (401, 403):
                raise DashboardError("auth", "{0}: HTTP {1}, check the API token".format(endpoint, exc.code), exc.code)
            raise DashboardError("http", "{0}: HTTP {1}".format(endpoint, exc.code), exc.code)
        except (urllib.error.URLError, OSError) as exc:
            raise DashboardError("network", "{0}: {1}".format(endpoint, getattr(exc, "reason", exc)))
        except ValueError:
            raise DashboardError("http", "{0}: response is not JSON".format(endpoint))
