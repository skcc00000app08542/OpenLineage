# SPDX-License-Identifier: Apache-2.0.
import logging
from urllib.parse import urljoin

import attr

from typing import Optional, Dict

from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util import parse_url

from openlineage.client.run import RunEvent
from openlineage.client.serde import Serde
from openlineage.client.transport.transport import Config, Transport
from openlineage.client.utils import get_only_specified_fields

log = logging.getLogger(__name__)


@attr.s
class HttpConfig(Config):
    url: str = attr.ib()
    timeout: float = attr.ib(default=5.0)
    # check TLS certificates
    verify: bool = attr.ib(default=True)
    auth: Dict[str, str] = attr.ib(factory=dict)

    # not set by TransportFactory
    session: Optional[Session] = attr.ib(factory=Session)
    # not set by TransportFactory
    adapter: Optional[HTTPAdapter] = attr.ib(default=None)

    @classmethod
    def from_dict(cls, params: dict) -> 'HttpConfig':
        if 'url' not in params:
            raise RuntimeError("`url` key not passed to HttpConfig")
        return cls(**get_only_specified_fields(cls, params))

    @classmethod
    def from_options(cls, url: str, options, session: Optional[Session]) -> 'HttpConfig':
        return cls(
            url=url,
            timeout=options.timeout,
            verify=options.verify,
            auth={"api_key": options.api_key},
            session=session if session else Session(),
            adapter=options.adapter
        )


class HttpTransport(Transport):
    kind = "http"
    config = HttpConfig

    def __init__(self, config: HttpConfig):
        url = config.url.strip()
        try:
            parsed = parse_url(url)
            if not (parsed.scheme and parsed.netloc):
                raise ValueError(f"Need valid url for OpenLineageClient, passed {url}")
        except Exception as e:
            raise ValueError(f"Need valid url for OpenLineageClient, passed {url}. Exception: {e}")
        self.url = url
        self.session = config.session
        self.session.headers['Content-Type'] = 'application/json'
        self.timeout = config.timeout
        self.verify = config.verify

        if 'api_key' in config.auth:
            self._add_auth(config.auth['api_key'])
        if config.adapter:
            self.set_adapter(config.adapter)

    def set_adapter(self, adapter: HTTPAdapter):
        self.session.mount(self.url, adapter)

    def emit(self, event: RunEvent):
        event = Serde.to_json(event)
        if log.isEnabledFor(logging.DEBUG):
            log.debug(f"Sending openlineage event {event}")
        resp = self.session.post(
            urljoin(self.url, 'api/v1/lineage'),
            event,
            timeout=self.timeout,
            verify=self.verify
        )
        resp.raise_for_status()
        return resp

    def _add_auth(self, api_key: str):
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}"
        })
