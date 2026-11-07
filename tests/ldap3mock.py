# SPDX-FileCopyrightText: 2024 NetKnights GmbH <https://netknights.it>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
2020-09-07 Cornelius Kölbel <cornelius.koelbel@netknights.it>
           Add exception
2017-04-26 Friedrich Weber <friedrich.weber@netknights.it>
           Make it possible to check for correct LDAPS/STARTTLS settings
2017-01-08 Cornelius Kölbel <cornelius.koelbel@netknights.it>
           Remove objectGUID. Since we stick with ldap3 version 2.1,
           the objectGUID is returned in a human readable format.
2016-12-05 Martin Wheldon <martin.wheldon@greenhills-it.co.uk>
           Fixed issue creating ldap entries with objectClasses defined
           Fix problem when searching for attribute values containing the
           space character.
2016-05-26 Martin Wheldon <martin.wheldon@greenhills-it.co.uk>
           Rewrite of search functionality to add recursive parsing
           of ldap search filters
           Fixed issue searching for attributes with multiple values
           Added ability to use ~= in searches
           Created unittests for mock
2016-02-19 Cornelius Kölbel <cornelius.koelbel@netknights.it>
           Add the possibility to check objectGUID
2015-01-31 Change responses.py to be able to run with SMTP
        Cornelius Kölbel <cornelius@privacyidea.org>

Original responses.py is:
Copyright 2013 Dropbox, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import datetime
import os

from passlib.hash import ldap_salted_sha1
from ast import literal_eval
import uuid
from ldap3.utils.conv import escape_bytes
import ldap3
from ldap3.core.exceptions import LDAPSocketOpenError
from mock import Mock
import re
import pyparsing

from .smtpmock import get_wrapped

from collections import namedtuple
from collections.abc import Sequence, Sized

from privacyidea.lib.utils import to_bytes, to_unicode

# Each pytest-xdist worker gets its own scratch file, otherwise concurrent
# writes to tmp_directory from parallel workers silently clobber each other's
# mock LDAP state — producing spurious LDAP auth failures in tests that rely
# on the mock being stable across ``_on_Connection`` reloads. See the
# ``setLDAPDirectory`` / ``_on_Connection._load_data`` round trip below.
DIRECTORY = "tests/testdata/tmp_directory" + (
    "_" + os.environ["PYTEST_XDIST_WORKER"]
    if os.environ.get("PYTEST_XDIST_WORKER") else ""
)

Call = namedtuple('Call', ['request', 'response'])

_wrapper_template = """\
def wrapper%(signature)s:
    with ldap3mock:
        return func%(funcargs)s
"""


def _convert_objectGUID(item):
    item = uuid.UUID("{{{0!s}}}".format(item)).bytes_le
    item = escape_bytes(item)
    return item


class CallList(Sequence, Sized):
    def __init__(self):
        self._calls = []

    def __iter__(self):
        return iter(self._calls)

    def __len__(self):
        return len(self._calls)

    def __getitem__(self, idx):
        return self._calls[idx]

    def setdata(self, request, response):
        self._calls.append(Call(request, response))

    def reset(self):
        self._calls = []


class Connection(object):

    class Extend(object):

        class Standard(object):

            def __init__(self, connection):
                self.connection = connection

            def paged_search(self, **kwargs):
                connection = self.connection
                # ldap3 (and the resolver) pass the page size as ``paged_size``; accept the
                # older ``page_size`` spelling too so both callers work.
                page_size = kwargs.get("paged_size") or kwargs.get("page_size") or 0
                cookie = kwargs.get("paged_cookie")
                # Fetch the full result set for this filter once, then hand out the pages. The
                # real ldap3 walks the pages itself (and hands the cookie back to the server);
                # here the cookie is the offset of the next page, so a test can page manually.
                connection.search(search_base=kwargs.get("search_base"),
                                  search_scope=kwargs.get("search_scope"),
                                  search_filter=kwargs.get("search_filter"),
                                  attributes=kwargs.get("attributes"),
                                  paged_size=page_size,
                                  size_limit=kwargs.get("size_limit"),
                                  paged_cookie=None)
                full = list(connection.response)
                if not page_size or page_size <= 0:
                    page_size = len(full) or 1
                start = 0
                if cookie not in (None, "", b""):
                    try:
                        start = int(cookie)
                    except (TypeError, ValueError):
                        start = 0
                if kwargs.get("generator", False):
                    # If ``generator=True`` is passed, ``paged_search`` should return an
                    # iterator that walks every page, exactly like ldap3 does.
                    return connection._paged_generator(full, page_size)
                page = full[start:start + page_size]
                connection.response = page
                connection.result = Connection._paged_result(start + page_size, len(full))
                return page

        def __init__(self, connection):
            self.standard = self.Standard(connection)

    def __init__(self, directory=None, tls_rejected=False, bind_result=None,
                 search_result=None, search_response=None):
        if directory is None:
            directory = []
        import copy
        self.directory = copy.deepcopy(directory)
        self.bound = False
        self.start_tls_called = False
        # Steering hooks for tests: a connection can be told to reject TLS, to fail the bind
        # with a directory result (e.g. LDAP 49 plus an Active Directory sub-code), or to answer
        # a search with a specific LDAP result instead of "success".
        self.tls_rejected = tls_rejected
        self.bind_result = bind_result
        self.search_result = search_result
        self.search_response = search_response
        self.extend = self.Extend(self)
        self.usage = Mock(**{"elapsed_time": datetime.timedelta(microseconds=500)})

        self.operation = {
                    "!": self._search_not,
                    "&": self._search_and,
                    "|": self._search_or}
        self.result = {'dn': '',
                       'referrals': None,
                       'description': 'success',
                       'result': 0,
                       'message': '',
                       'type': 'addResponse'}

    def set_directory(self, directory):
        self.directory = directory

    def _find_user(self, dn):
        return next(i for (i, d) in enumerate(self.directory) if d["dn"] == dn)

    def open(self, read_server_info=True):
        # A directory that rejects TLS never yields a usable connection. Raising here mirrors
        # ldap3, where the socket/TLS layer fails before any bind can be attempted.
        if self.tls_rejected:
            raise LDAPSocketOpenError("TLS handshake failed")
        return

    def bind(self, read_server_info=True):
        if self.tls_rejected:
            raise LDAPSocketOpenError("TLS handshake failed")
        if self.bind_result is not None:
            # The directory answered the bind with a failure result. The caller reads
            # ``connection.result`` (e.g. ``description`` and the AD ``data <code>`` message).
            self.result = dict(self.bind_result)
            self.bound = False
        return self.bound

    def start_tls(self, read_server_info=True):
        self.start_tls_called = True
        if self.tls_rejected:
            self.result = {'dn': '', 'referrals': None,
                           'description': 'unwillingToPerform', 'result': 53,
                           'message': 'TLS handshake failed', 'type': 'extendedResponse'}
            return False
        return True

    def add(self, dn, object_class=None, attributes=None):
        # Check to see if the user exists in the directory
        try:
            index = self._find_user(dn)
        except StopIteration:
            # If we get here the user doesn't exist so continue
            # to create an entry object for the new user
            entry = {'dn': dn, 'attributes': attributes}
            if object_class is not None:
                entry['attributes'].update( {'objectClass': object_class})
        else:
            # User already exists
            self.result["description"] = "failure"
            self.result["result"] = 68
            self.result["message"] = f"Error entryAlreadyExists for {dn}"
            return False

        # Add the user entry to the directory
        self.directory.append(entry)

        # Attempt to write changes to disk
        with open(DIRECTORY, 'w+') as f:
            f.write(str(self.directory))

        return True

    def delete(self, dn, controls=None):

        self.result = {'dn': '',
                       'referrals': None,
                       'description': 'success',
                       'result': 0,
                       'message': '',
                       'type': 'addResponse'}

        # Check to see if the user exists in the directory
        try:
            index = self._find_user(dn)
        except StopIteration:
            # If we get here the user doesn't exist so continue
            self.result["description"] = "failure"
            self.result["result"] = 32
            self.result["message"] = "Error no such object: {0}".format(dn)
            return False

        # Delete the entry object for the user
        self.directory.pop(index)

        # Attempt to write changes to disk
        with open(DIRECTORY, 'w+') as f:
            f.write(str(self.directory))

        return True

    def modify(self, dn, changes, controls=None):

        self.result = { 'dn' : '',
                        'referrals' : None,
                        'description' : 'success',
                        'result' : 0,
                        'message' : '',
                        'type' : 'modifyResponse'}

        # Check to see if the user exists in the directory
        try:
            index = self._find_user(dn)
        except StopIteration:
            # If we get here the user doesn't exist so continue
            self.result["description"] = "failure"
            self.result["result"] = 32
            self.result["message"] = "Error no such object: {0!s}".format(dn)
            return False

        # extract the hash we are interested in
        entry = self.directory[index].get("attributes")

        # Loop over the changes hash and apply them
        for k, v in changes.items():
            if v[0] == "MODIFY_DELETE":
                entry.pop(k)
            elif v[0] == "MODIFY_REPLACE" or v[0] == "MODIFY_ADD":
                entry[k] = v[1][0]
            else:
                self.result["result"] = 2
                self.result["message"] = "Error bad/missing/not implemented" \
                    "modify operation: %s" % k[1]

        # Place the attributes back into the directory hash
        self.directory[index]["attributes"] = entry

        # Attempt to write changes to disk
        with open(DIRECTORY, 'w+') as f:
            f.write(str(self.directory))

        return True

    @staticmethod
    def _match_greater_than_or_equal(search_base, attribute, value, candidates):
        matches = list()
        for entry in candidates:
            dn = entry.get("dn")
            if not dn.endswith(search_base):
                continue

            value_from_directory = entry.get("attributes").get(attribute)
            if str(value_from_directory) >= str(value):
                entry["type"] = "searchResEntry"
                matches.append(entry)

        return matches

    @staticmethod
    def _match_greater_than(search_base, attribute, value, candidates):
        matches = list()
        for entry in candidates:
            dn = entry.get("dn")
            if not dn.endswith(search_base):
                continue

            value_from_directory = entry.get("attributes").get(attribute)
            if str(value_from_directory) > str(value):
                entry["type"] = "searchResEntry"
                matches.append(entry)

        return matches

    @staticmethod
    def _match_less_than_or_equal(search_base, attribute, value, candidates):
        matches = list()
        for entry in candidates:
            dn = entry.get("dn")
            if not dn.endswith(search_base):
                continue

            value_from_directory = entry.get("attributes").get(attribute)
            if str(value_from_directory) <= str(value):
                entry["type"] = "searchResEntry"
                matches.append(entry)

        return matches

    @staticmethod
    def _match_less_than(search_base, attribute, value, candidates):
        matches = list()
        for entry in candidates:
            dn = entry.get("dn")
            if not dn.endswith(search_base):
                continue

            value_from_directory = entry.get("attributes").get(attribute)
            if str(value_from_directory) < str(value):
                entry["type"] = "searchResEntry"
                matches.append(entry)

        return matches

    @staticmethod
    def _match_equal_to(search_base, attribute, value, candidates):
        matches = list()
        match_using_regex = False

        if "*" in value:
            match_using_regex = True
            #regex = check_escape(value)
            regex = value.replace('*', '.*')
            regex = "^{0}$".format(regex)

        for entry in candidates:
            dn = to_unicode(entry.get("dn"))

            if attribute not in entry.get("attributes") or not dn.endswith(search_base):
                continue

            values_from_directory = entry.get("attributes").get(attribute)
            if isinstance(values_from_directory, list):
                for item in values_from_directory:
                    if attribute == "objectGUID":
                        item = _convert_objectGUID(item)

                    if match_using_regex:
                        m = re.match(regex, str(item), re.I)
                        if m:
                            entry["type"] = "searchResEntry"
                            matches.append(entry)
                    else:
                        if item == value:
                            entry["type"] = "searchResEntry"
                            matches.append(entry)

            else:
                if attribute == "objectGUID":
                    values_from_directory = _convert_objectGUID(values_from_directory)

                if match_using_regex:
                    m = re.match(regex, str(values_from_directory), re.I)
                    if m:
                        entry["type"] = "searchResEntry"
                        matches.append(entry)
                else:
                    # The value, which we compare is unicode, so we convert
                    # the values_from_directory to unicode rather than str.
                    if isinstance(values_from_directory, bytes):
                        values_from_directory = values_from_directory.decode(
                            "utf-8")
                    elif type(values_from_directory) == int:
                        values_from_directory = "{0!s}".format(values_from_directory)
                    if value == values_from_directory:
                        entry["type"] = "searchResEntry"
                        matches.append(entry)

        return matches

    @staticmethod
    def _match_notequal_to(search_base, attribute, value, candidates):
        matches = list()
        match_using_regex = False

        if "*" in value:
            match_using_regex = True
            #regex = check_escape(value)
            regex = value.replace('*', '.*')
            regex = "^{0}$".format(regex)

        for entry in candidates:
            found = False
            dn = entry.get("dn")

            if not dn.endswith(search_base):
                continue

            values_from_directory = entry.get("attributes").get(attribute)
            if isinstance(values_from_directory, list):
                for item in values_from_directory:
                    if attribute == "objectGUID":
                        item = _convert_objectGUID(item)

                    if match_using_regex:
                        m = re.match(regex, str(item), re.I)
                        if m:
                            found = True
                    else:
                        if item == value:
                            found = True
                if found is False:
                    entry["type"] = "searchResEntry"
                    matches.append(entry)
            else:
                if attribute == "objectGUID":
                    values_from_directory = _convert_objectGUID(values_from_directory)

                if match_using_regex:
                    m = re.match(regex, str(values_from_directory), re.I)
                    if not m:
                        entry["type"] = "searchResEntry"
                        matches.append(entry)
                else:
                    if str(value) != str(values_from_directory):
                        entry["type"] = "searchResEntry"
                        matches.append(entry)

        return matches

    @staticmethod
    def _parse_filter():
        op = pyparsing.one_of('! & |')
        lpar  = pyparsing.Literal('(').suppress()
        rpar  = pyparsing.Literal(')').suppress()

        k = pyparsing.Word(pyparsing.alphanums)
        # NOTE: We may need to expand on this list, but as this is not a real
        # LDAP server we should be OK.
        # Value to contain:
        #   numbers, upper/lower case letters, astrisk, at symbol, minus, full
        #   stop, backslash or a space
        v = pyparsing.Word(pyparsing.alphanums + "-*@.\\ äöü")
        rel = pyparsing.one_of("= ~= >= <=")

        expr = pyparsing.Forward()
        atom = pyparsing.Group(lpar + op + expr + rpar) \
                            | pyparsing.Combine(lpar + k + rel + v + rpar)
        expr << atom + pyparsing.ZeroOrMore( expr )

        return expr

    @staticmethod
    def _deDuplicate(results):
        found = dict()
        deDuped = list()
        for entry in results:
            dn = entry.get("dn")
            if not dn in found:
                found[dn] = 1
                deDuped.append(entry)

        return deDuped

    def _invert_results(self, candidates):
        inverted_candidates = list(self.directory)

        for candidate in candidates:
            try:
                inverted_candidates.remove(candidate)
            except ValueError:
                pass

        return inverted_candidates

    def _search_not(self, base, search_filter, candidates=None):
        # Create empty candidates list as we need to use self.directory for
        # each search
        candidates = list()
        this_filter = list()

        index = 0
        search_filter.remove("!")
        for condition in search_filter:
            if not isinstance(condition, list):
                this_filter.append(condition)
            index +=1

        # Remove this_filter items from search_filter list
        for condition in this_filter:
            search_filter.remove(condition)

        try:
            search_filter = list(search_filter[0])
            for sub_filter in search_filter:
                if not isinstance(sub_filter, list):
                    candidates = self.operation.get(sub_filter)(base,
                                                                search_filter,
                                                                candidates)
                else:
                    candidates = self.operation.get(sub_filter[0])(base,
                                                                   sub_filter,
                                                                   candidates)
        except IndexError:
            pass

        candidates = self._invert_results(candidates)

        for item in this_filter:
            if ">=" in item:
                k, v = item.split(">=")
                candidates = Connection._match_less_than(base, k, v,
                                                            self.directory)
            elif "<=" in item:
                k, v = item.split("<=")
                candidates = Connection._match_greater_than(base, k, v,
                                                         self.directory)
            # Emulate AD functionality, same as "="
            elif "~=" in item:
                k, v = item.split("~=")
                candidates = Connection._match_notequal_to(base, k, v,
                                                         self.directory)
            elif "=" in item:
                k, v = item.split("=")
                candidates = Connection._match_notequal_to(base, k, v,
                                                         self.directory)
        return candidates

    def _search_and(self, base, search_filter, candidates=None):
        # Load the data from the directory, if we aren't passed any
        if candidates == [] or candidates is None:
            candidates = self.directory
        this_filter = list()

        index = 0
        search_filter.remove("&")
        for condition in search_filter:
            if not isinstance(condition, list):
                this_filter.append(condition)
            index +=1

        # Remove this_filter items from search_filter list
        for condition in this_filter:
            search_filter.remove(condition)

        try:
            search_filter = list(search_filter[0])
            for sub_filter in search_filter:
                if not isinstance(sub_filter, list):
                    candidates = self.operation.get(sub_filter)(base,
                                                                search_filter,
                                                                candidates)
                else:
                    candidates = self.operation.get(sub_filter[0])(base,
                                                                   sub_filter,
                                                                   candidates)
        except IndexError:
            pass

        for item in this_filter:
            if ">=" in item:
                k, v = item.split(">=")
                candidates = Connection._match_greater_than_or_equal(base, k, v,
                                                                     candidates)
            elif "<=" in item:
                k, v = item.split("<=")
                candidates = Connection._match_less_than_or_equal(base, k, v,
                                                                  candidates)
            # Emulate AD functionality, same as "="
            elif "~=" in item:
                k, v = item.split("~=")
                candidates = Connection._match_equal_to(base, k, v,
                                                         candidates)
            elif "=" in item:
                k, v = item.split("=")
                candidates = Connection._match_equal_to(base, k, v,
                                                         candidates)
        return candidates

    def _search_or(self, base, search_filter, candidates=None):
        # Create empty candidates list as we need to use self.directory for
        # each search
        candidates = list()
        this_filter = list()

        index = 0
        search_filter.remove("|")
        for condition in search_filter:
            if not isinstance(condition, list):
                this_filter.append(condition)
            index +=1

        # Remove this_filter items from search_filter list
        for condition in this_filter:
            search_filter.remove(condition)

        try:
            search_filter = list(search_filter[0])
            for sub_filter in search_filter:
                if not isinstance(sub_filter, list):
                    candidates += self.operation.get(sub_filter)(base,
                                                                 search_filter,
                                                                 candidates)
                else:
                    candidates += self.operation.get(sub_filter[0])(base,
                                                                    sub_filter,
                                                                    candidates)
        except IndexError:
            pass

        for item in this_filter:
            if ">=" in item:
                k, v = item.split(">=")
                candidates += Connection._match_greater_than_or_equal(base, k, v,
                                                             self.directory)
            elif "<=" in item:
                k, v = item.split("<=")
                candidates += Connection._match_less_than_or_equal(base, k, v,
                                                          self.directory)
            # Emulate AD functionality, same as "="
            elif "~=" in item:
                k, v = item.split("~=")
                candidates += Connection._match_equal_to(base, k, v,
                                                         self.directory)
            elif "=" in item:
                k, v = item.split("=")
                candidates += Connection._match_equal_to(base, k, v,
                                                         self.directory)
        return candidates

    def search(self, search_base=None, search_scope=None,
               search_filter=None, attributes=None, paged_size=5,
               size_limit=0, paged_cookie=None):
        s_filter = list()
        candidates = list()
        self.response = list()

        try:
            if isinstance(search_filter, bytes):
                # We need to convert to unicode otherwise pyparsing will not
                # find the "ö"
                search_filter = to_unicode(search_filter)
            expr = Connection._parse_filter()
            s_filter = expr.parse_string(search_filter).as_list()[0]
        except pyparsing.ParseBaseException as exx:
            # Just for debugging purposes
            s = "{!s}".format(exx)

        for item in s_filter:
            if item[0] in self.operation:
                candidates = self.operation.get(item[0])(search_base,
                                                         s_filter)
        self.response = Connection._deDuplicate(candidates)

        if self.search_result is not None:
            # A test told this connection to answer the search with a directory result
            # (sizeLimitExceeded, noSuchObject, insufficientAccess, ...). An empty response then
            # means "error", not "no matches" - the two are told apart by ``result``.
            self.result = dict(self.search_result)
            if self.search_response is not None:
                self.response = list(self.search_response)
            elif int(self.result.get("result", 0)) != 0:
                self.response = []
        else:
            self.result = {'dn': '', 'referrals': None, 'description': 'success',
                           'result': 0, 'message': '', 'type': 'searchResEntry'}

        return True

    @staticmethod
    def _paged_result(next_start, total):
        """LDAP result carrying the paged-results control with the next page's cookie."""
        cookie = str(next_start) if next_start < total else ""
        return {'dn': '', 'referrals': None, 'description': 'success', 'result': 0,
                'message': '', 'type': 'searchResEntry',
                'controls': {'1.2.840.113556.1.4.319': {
                    'criticality': True,
                    'value': {'size': total, 'cookie': cookie}}}}

    def _paged_generator(self, full, page_size):
        """Yield every entry across pages, exposing each page in ``response`` like ldap3 does."""
        for start in range(0, len(full), page_size):
            page = full[start:start + page_size]
            self.response = page
            self.result = Connection._paged_result(start + page_size, len(full))
            yield from page
        if not full:
            self.response = []
            self.result = Connection._paged_result(0, 0)

    def unbind(self):
        return True


class Ldap3Mock(object):

    def __init__(self):
        self._calls = CallList()
        self._server_mock = None
        self.directory = []
        self.exception = None
        self.reset()

    def reset(self):
        self._calls.reset()
        # Steering state for tests. Cleared between runs so one test's forced bind/search
        # result or TLS rejection cannot leak into the next (``__exit__`` calls this).
        self.tls_rejected = False
        self.server_options = []
        self.bind_result = None
        self.bind_result_user = None
        self.search_result = None
        self.search_response = None

    def setLDAPDirectory(self, directory=None):
        if directory is None:
                self.directory = []
        else:
            try:
                with open(DIRECTORY, 'w+') as f:
                    f.write(str(directory))
                    self.directory = directory
            except OSError as e:
                raise

    def set_exception(self, exc=True):
        """Set the exception raised when a connection is created.

        ``True`` raises ``LDAPSocketOpenError`` (a real ldap3 error, message kept as
        ``"LDAP request failed"``), a class or an instance is raised as given (e.g.
        ``LDAPOperationResult(result=4)``), ``False``/``None`` disables it.
        """
        self.exception = exc

    def _exception_to_raise(self):
        if self.exception is True:
            return LDAPSocketOpenError("LDAP request failed")
        if isinstance(self.exception, BaseException):
            return self.exception
        if isinstance(self.exception, type) and issubclass(self.exception, BaseException):
            return self.exception("LDAP request failed")
        return LDAPSocketOpenError("LDAP request failed")

    def set_bind_result(self, result=49, description="invalidCredentials",
                        message=None, code=None, user=None):
        """Force the next bind(s) to fail with a directory result.

        ``code`` is the Active Directory sub-code as it appears in the directory message
        (``52e``, ``773``, ...). When given, a realistic ``AcceptSecurityContext`` message with
        ``data <code>`` is built, so the resolver's state mapping sees what AD would send.
        ``user`` restricts the override to a bind for that DN (``None`` applies it to every bind).
        """
        if code is not None:
            message = message or ("80090308: LdapErr: DSID-0C0904DC, comment: "
                                  f"AcceptSecurityContext error, data {code}, v3839")
        self.bind_result = {"dn": "", "referrals": None, "description": description,
                            "result": int(result), "message": message or "",
                            "type": "bindResponse"}
        self.bind_result_user = user

    def set_search_result(self, result=32, description="noSuchObject", message="",
                          response=None):
        """Force searches to answer with a directory result.

        Covers e.g. ``4`` sizeLimitExceeded, ``32`` noSuchObject, ``50`` insufficientAccess.
        ``response`` overrides the returned entries; when it is ``None`` the matches are kept
        for a size-limit result and dropped for any other error, so an empty result can be told
        apart from an error by ``connection.result["result"]``.
        """
        self.search_result = {"dn": "", "referrals": None, "description": description,
                              "result": int(result), "message": message,
                              "type": "searchResEntry"}
        self.search_response = response

    def set_tls_rejected(self, rejected=True):
        """Make a connection that asked for TLS (ldaps or StartTLS) fail to open."""
        self.tls_rejected = rejected

    def _load_data(self, directory):
        try:
            with open(directory, 'r') as f:
                data = f.read()
                return literal_eval(data)
        except OSError as e:
            raise

    @property
    def calls(self):
        return self._calls

    def __enter__(self):
        self.start()

    def __exit__(self, *args):
        self.stop()
        self.reset()

    def activate(self, func):
        evaldict = {'ldap3mock': self, 'func': func}
        return get_wrapped(func, _wrapper_template, evaldict)

    def _on_Server(self, host, port, use_ssl, connect_timeout, get_info=None,
                   tls=None):
        # Record what the resolver asked for (ldaps, StartTLS, timeout) so a test can assert it
        # and so a TLS-rejecting directory fails only the connections that asked for TLS.
        self.server_options.append({"host": host, "port": port, "use_ssl": use_ssl,
                                    "connect_timeout": connect_timeout, "tls": tls})
        return "FakeServerObject"

    def _tls_requested(self):
        return any(opts.get("use_ssl") or opts.get("tls") is not None
                   for opts in self.server_options)

    def _bind_result_for(self, user):
        if self.bind_result is None:
            return None
        if self.bind_result_user is not None and to_unicode(self.bind_result_user) != user:
            return None
        return self.bind_result

    def _on_Connection(self, server, user, password,
                       auto_bind=None, client_strategy=None,
                       authentication=None, check_names=None,
                       auto_referrals=None, receive_timeout=None,
                       collect_usage=None):
        """
        We need to create a Connection object with
        methods:
            add()
            modify()
            search()
            unbind()
        and object
            response
        """
        # Raise an exception, if we are told to do so
        if self.exception:
            raise self._exception_to_raise()
        # check the password
        correct_password = False
        # Anonymous bind
        # Reload the directory just in case a change has been made to
        # user credentials
        self.directory = self._load_data(DIRECTORY)
        if authentication == ldap3.ANONYMOUS and user is None:
            correct_password = True
        for entry in self.directory:
            if to_unicode(entry.get("dn")) == user:
                pw = entry.get("attributes").get("userPassword")
                # password can be unicode. Active Directory never returns ``userPassword``, so
                # such an entry can only be authenticated through a forced bind result below.
                if pw is not None and to_bytes(pw) == to_bytes(password):
                    correct_password = True
                elif pw is not None and str(pw).startswith('{SSHA}'):
                    correct_password = ldap_salted_sha1.verify(password, pw)
                else:
                    correct_password = False
        self.con_obj = Connection(
            self.directory,
            tls_rejected=self.tls_rejected and self._tls_requested(),
            bind_result=self._bind_result_for(user),
            search_result=self.search_result,
            search_response=self.search_response)
        self.con_obj.bound = correct_password
        return self.con_obj

    def start(self):
        import mock

        def unbound_on_Server(host, port,
                              use_ssl,
                              connect_timeout, *a, **kwargs):
            return self._on_Server(host, port,
                              use_ssl,
                              connect_timeout, *a, **kwargs)
        self._server_mock = mock.MagicMock()
        self._server_mock.side_effect = unbound_on_Server
        self._patcher = mock.patch('ldap3.Server',
                                   self._server_mock)
        self._patcher.start()

        def unbound_on_Connection(server=None, user=None,
                                  password=None,
                                  auto_bind=None,
                                  client_strategy=None,
                                  authentication=None,
                                  check_names=None,
                                  auto_referrals=None, *a, **kwargs):
            return self._on_Connection(server, user,
                                       password,
                                       auto_bind,
                                       client_strategy,
                                       authentication,
                                       check_names,
                                       auto_referrals, *a,
                                       **kwargs)

        self._patcher2 = mock.patch('ldap3.Connection',
                                    unbound_on_Connection)
        self._patcher2.start()

    def stop(self):
        self._patcher.stop()
        self._patcher2.stop()
        self._server_mock = None

    def get_server_mock(self):
        return self._server_mock

# expose default mock namespace
mock = _default_mock = Ldap3Mock()
__all__ = []
for __attr in (a for a in dir(_default_mock) if not a.startswith('_')):
    __all__.append(__attr)
    globals()[__attr] = getattr(_default_mock, __attr)
