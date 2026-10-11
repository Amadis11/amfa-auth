"""AMFA: zapis polityki zawezony do zakresu docelowego (zgloszenie #40).

Silnik dopuszcza zapis polityki, gdy administrator ma pelne ``policywrite``/``policydelete`` albo
prawo zawezone do zakresu **docelowej** polityki (``policywrite_<zakres>``/``policydelete_<zakres>``).
Zakresu ``admin`` na liscie zawezonej nie ma — inaczej konto serwisowe panelu (sprzedane klientowi
wraz z plikiem poswiadczen) moglo by nadac sobie dowolne prawa, przepisujac polityke administracyjna.

Te testy pilnuja granicy, a nie sciezki szczesliwej: kazdy przypadek odmowy jest sprawdzony osobno,
bo wlasnie od nich zalezy, czy granica jest w silniku, czy tylko w kodzie klienta.
"""
from privacyidea.lib.policies.actions import PolicyAction, policy_write_action
from privacyidea.lib.policy import SCOPE, delete_policy, get_policies, set_policy

from .base import MyApiTestCase


class ScopedPolicyWriteTestCase(MyApiTestCase):
    """Administrator ``testadmin`` z prawami ograniczonymi przez polityke administracyjna."""

    def _sprzataj(self, *nazwy):
        """Usun polityke tylko wtedy, gdy istnieje — czesc przypadkow konczy sie celowa odmowa."""
        def _usun():
            for nazwa in nazwy:
                if get_policies(name=nazwa):
                    delete_policy(nazwa)
        return _usun

    def _ogranicz(self, action):
        set_policy("amfa-ograniczony", scope=SCOPE.ADMIN, action=action, adminuser="testadmin")
        self.addCleanup(self._sprzataj("amfa-ograniczony"))

    def _post(self, name, scope, action="otppin=userstore", json_body=True):
        tresc = {"name": name, "scope": scope, "action": action, "active": True}
        with self.app.test_request_context(f"/policy/{name}", method="POST",
                                          json=tresc if json_body else None,
                                          data=None if json_body else tresc,
                                          headers={"Authorization": self.at}):
            return self.app.full_dispatch_request()

    def _delete(self, name):
        with self.app.test_request_context(f"/policy/{name}", method="DELETE",
                                           headers={"Authorization": self.at}):
            return self.app.full_dispatch_request()

    def test_01_prawo_zawezone_tworzy_polityke_swojego_zakresu(self):
        self._ogranicz(policy_write_action(SCOPE.AUTH))
        self.addCleanup(self._sprzataj("amfa-test-auth"))

        odpowiedz = self._post("amfa-test-auth", SCOPE.AUTH)

        self.assertEqual(odpowiedz.status_code, 200, odpowiedz.json)
        self.assertTrue(get_policies(name="amfa-test-auth"), "polityka nie powstala")

    def test_02_prawo_zawezone_nie_tworzy_polityki_administracyjnej(self):
        """To jest wlasnie ta granica: konto z prawem zawezonym nie zapisze polityki `admin`."""
        self._ogranicz(policy_write_action(SCOPE.AUTH))
        self.addCleanup(self._sprzataj("amfa-test-admin"))

        odpowiedz = self._post("amfa-test-admin", SCOPE.ADMIN, action=PolicyAction.USERLIST + "=true")

        self.assertEqual(odpowiedz.status_code, 403, odpowiedz.json)
        self.assertEqual(get_policies(name="amfa-test-admin"), [], "polityka administracyjna jednak powstala")

    def test_03_prawo_zawezone_nie_przenosi_polityki_w_inny_zakres(self):
        set_policy("amfa-test-przenosiny", scope=SCOPE.AUTH, action="otppin=userstore")
        self.addCleanup(self._sprzataj("amfa-test-przenosiny"))
        self._ogranicz(policy_write_action(SCOPE.AUTH))

        odpowiedz = self._post("amfa-test-przenosiny", SCOPE.ADMIN, action=PolicyAction.USERLIST + "=true")

        self.assertEqual(odpowiedz.status_code, 403, odpowiedz.json)
        polityki = get_policies(name="amfa-test-przenosiny")
        self.assertEqual(polityki[0].get("scope"), SCOPE.AUTH, "zakres polityki sie zmienil")

    def test_04_prawo_zawezone_do_zapisu_nie_usuwa_polityki(self):
        set_policy("amfa-test-usuwanie", scope=SCOPE.AUTH, action="otppin=userstore")
        self.addCleanup(self._sprzataj("amfa-test-usuwanie"))
        self._ogranicz(policy_write_action(SCOPE.AUTH))

        odmowa = self._delete("amfa-test-usuwanie")
        self.assertEqual(odmowa.status_code, 403, odmowa.json)
        self.assertTrue(get_policies(name="amfa-test-usuwanie"), "polityka zniknela bez prawa usuniecia")

        # Po dodaniu prawa usuwania dla tego zakresu operacja przechodzi.
        set_policy("amfa-ograniczony", scope=SCOPE.ADMIN,
                   action=f"{policy_write_action(SCOPE.AUTH)},"
                          f"{policy_write_action(SCOPE.AUTH, delete=True)}",
                   adminuser="testadmin")
        zgoda = self._delete("amfa-test-usuwanie")
        self.assertEqual(zgoda.status_code, 200, zgoda.json)
        self.assertEqual(get_policies(name="amfa-test-usuwanie"), [])

    def test_05_pelne_prawo_dziala_jak_dotad(self):
        """Zgodnosc wstecz: `policywrite` obejmuje tez zakres `admin` (inaczej starsi klienci padna)."""
        self._ogranicz(PolicyAction.POLICYWRITE)
        self.addCleanup(self._sprzataj("amfa-test-pelne"))

        odpowiedz = self._post("amfa-test-pelne", SCOPE.ADMIN, action=PolicyAction.USERLIST + "=true")

        self.assertEqual(odpowiedz.status_code, 200, odpowiedz.json)
        self.assertTrue(get_policies(name="amfa-test-pelne"))

    def test_06_zawezone_nazwy_sa_w_definicjach_i_nie_ma_wsrod_nich_admina(self):
        """Kontrakt dla klienta: nazwy widoczne w `GET /policy/defs/admin`, bez zakresu `admin`."""
        with self.app.test_request_context("/policy/defs/admin", method="GET",
                                            headers={"Authorization": self.at}):
            odpowiedz = self.app.full_dispatch_request()

        self.assertEqual(odpowiedz.status_code, 200, odpowiedz.json)
        definicje = odpowiedz.json["result"]["value"]

        oczekiwane = {"policywrite_" + scope for scope in PolicyAction.POLICY_WRITE_SCOPES} | \
                     {"policydelete_" + scope for scope in PolicyAction.POLICY_WRITE_SCOPES}
        self.assertTrue(oczekiwane.issubset(set(definicje)), sorted(oczekiwane - set(definicje)))
        self.assertNotIn("policywrite_admin", definicje)
        self.assertNotIn("policydelete_admin", definicje)
        # Pelne prawa zostaja na miejscu (zgodnosc wstecz).
        self.assertIn(PolicyAction.POLICYWRITE, definicje)
        self.assertIn(PolicyAction.POLICYDELETE, definicje)
        # Kazde zawezone prawo jest typu bool, tak jak pozostale akcje administracyjne.
        for nazwa in oczekiwane:
            self.assertEqual(definicje[nazwa].get("type"), "bool", nazwa)
