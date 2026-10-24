# -*- coding: utf-8 -*-
from .base import MyApiTestCase
from urllib.parse import urlencode, quote
from privacyidea.lib.policy import set_policy, delete_policy, SCOPE
from privacyidea.lib.policies.actions import PolicyAction
from privacyidea.lib.utils import get_plugin_info_from_useragent
import mock


class RSSTest(MyApiTestCase):

    def test_01_get_rss(self):
        with self.app.test_request_context('/info/rss',
                                           method='GET',
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            feeds = result.get("value")
            self.assertEqual(3, len(feeds))
            self.assertIn("Community News", feeds)
            self.assertIn("privacyIDEA News", feeds)
            self.assertIn("NetKnights News", feeds)

    def test_02_get_specific_rss(self):
        with self.app.test_request_context('/info/rss',
                                           method='GET',
                                           query_string=urlencode({"channel": "Community News"}),
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            feeds = result.get("value")
            self.assertEqual(1, len(feeds))
            self.assertIn("Community News", feeds)
            self.assertNotIn("privacyIDEA News", feeds)
            self.assertNotIn("NetKnights News", feeds)

    def test_03_custom_rssfeeds_success(self):
        set_policy("rssfeed", scope=SCOPE.WEBUI,
                   action={PolicyAction.RSS_FEEDS: "'Community News':'https://community.privacyidea.org/c/news.rss'-"
                                             "'privacyIDEA News':'https://privacyidea.org/feed'"})

        with self.app.test_request_context('/info/rss', method='GET', headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            feeds = result.get("value")

            self.assertIn("Community News", feeds)
            self.assertIn("privacyIDEA News", feeds)
            self.assertNotIn("NetKnights News", feeds)
            self.assertEqual(2, len(feeds))

        delete_policy("rssfeed")

    def test_04_custom_rssfeeds_fail(self):
        # Wrong policy (wrong separator)
        action = {PolicyAction.RSS_FEEDS: "'Community News': 'https://community.privacyidea.org/c/news.rss', "
                                    "'privacyIDEA News':'https://privacyidea.org/feed'"}

        set_policy("rssfeed", scope=SCOPE.WEBUI, action=action)
        with mock.patch("logging.Logger.debug") as mock_log:
            with self.app.test_request_context('/info/rss',
                                               method='GET',
                                               headers={'Authorization': self.at}):
                res = self.app.full_dispatch_request()
                self.assertTrue(res.status_code == 200, res)
                result = res.json.get("result")
                feeds = result.get("value")
                # Get the default due to faulty policy
                self.assertIn("Community News", feeds)
                self.assertIn("privacyIDEA News", feeds)
                self.assertIn("NetKnights News", feeds)
                self.assertEqual(3, len(feeds))

                expected = ("Invalid action format. The key-value pair is not separated by ':': "
                            "Community News': 'https://community.privacyidea.org/c/news.rss")
                mock_log.assert_called_with(expected)
        delete_policy("rssfeed")


class IntegrationsTest(MyApiTestCase):

    def test_01_admin_gets_the_catalog(self):
        with self.app.test_request_context('/info/integrations',
                                           method='GET',
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            integrations = res.json.get("result").get("value")
            by_id = {entry["id"]: entry for entry in integrations}
            self.assertIn("privacyidea-cp", by_id)
            cp = by_id["privacyidea-cp"]
            self.assertEqual("Windows Credential Provider", cp["label"])
            self.assertTrue(cp["api_client"])
            self.assertTrue(cp["dashboard"])
            self.assertIn("privacyidea-cp", cp["agent_names"])
            # The Authenticator App is never an API-client client_type.
            self.assertFalse(by_id["privacyidea-app"]["api_client"])
            # Policy-condition-only integrations have no dashboard row.
            self.assertFalse(by_id["privacyidea-webui"]["dashboard"])

    def test_02_self_service_user_is_rejected(self):
        self.setUp_user_realms()
        self.authenticate_selfservice_user()
        with self.app.test_request_context('/info/integrations',
                                           method='GET',
                                           headers={'Authorization': self.at_user}):
            res = self.app.full_dispatch_request()
            self.assertEqual(401, res.status_code, res)
            # AUTHENTICATE_MISSING_RIGHT
            self.assertEqual(4306, res.json.get("result").get("error").get("code"))

    def test_03_webui_entry_matches_the_console_user_agent(self):
        # The console sends ``AMFA-WebUI/<version>`` as its User-Agent header. The policy
        # ``user_agents`` condition matches the parsed agent name against the stored
        # ``policy_value`` verbatim, so the catalog's WebUI entry has to carry ``AMFA-WebUI``
        # as both its policy value and one of its known agent names, or a policy restricting
        # the console to itself never matches the console. The old, unbranded header stays
        # recognised for backward compatibility.
        with self.app.test_request_context('/info/integrations',
                                           method='GET',
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            by_id = {entry["id"]: entry for entry in res.json.get("result").get("value")}
            webui = by_id["privacyidea-webui"]
            self.assertEqual("AMFA WebUI", webui["label"])
            self.assertEqual("AMFA-WebUI", webui["policy_value"])
            # The exact header the console sends, run through the same parser the request
            # handler uses, must land on the entry's agent names and policy value.
            agent_name, _version, _comment = get_plugin_info_from_useragent("AMFA-WebUI/3.14+g1f03ef713")
            self.assertEqual("AMFA-WebUI", agent_name)
            self.assertIn(agent_name, webui["agent_names"])
            self.assertEqual(agent_name, webui["policy_value"])
            self.assertIn("privacyIDEA-WebUI", webui["agent_names"])
