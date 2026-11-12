import network
import company
import scanner
import main
import contextlib
import io
import json
import time
import unittest
from unittest.mock import patch
from bs4 import BeautifulSoup
import main as app

NIP = '5170441148'
OTHER = '8522666251'
URL = 'https://example.com/'


def soup(html):
    return BeautifulSoup(html, 'html.parser')


def html_response(html, url=URL):
    return network.outcome('ok', {'body': html.encode(), 'charset': 'utf-8',
                             'redirects': [url]}, url)


class ParserTests(unittest.TestCase):
    def test_known_formats(self):
        for raw in ['NIP: 5170441148', 'nip / VAT ID: PL517-044-11-48',
                    'NIP PL: 5170441148', 'VAT ID: PL5170441148',
                    'NIP: 517\u00a0044\u00a011\u00a048']:
            with self.subTest(raw=raw):
                items, _ = company.extract_nips(soup('<p>'+raw+'</p>'), URL)
                self.assertEqual([x['nip'] for x in items], [NIP])

    def test_extra_digits_not_silently_truncated(self):
        for raw in ['NIP: 51704411489', 'NIP: 5170441148 9', 'NIP: 5170441148 9foo']:
            with self.subTest(raw=raw):
                items, _ = company.extract_nips(soup('<p>'+raw+'</p>'), URL)
                self.assertEqual(items, [])

    def test_separate_paragraphs(self):
        items, warnings = company.extract_nips(soup('<p>NIP: 51704</p><p>41148</p>'), URL)
        self.assertEqual(items, [])
        self.assertTrue(warnings)

    def test_inline_spans(self):
        items, _ = company.extract_nips(soup('<p><b>NIP:</b><span>5170441148</span></p>'), URL)
        self.assertEqual(items[0]['nip'], NIP)

    def test_definition_list_label(self):
        items, _ = company.extract_nips(soup('<dl><dt>NIP</dt><dd>5170441148</dd></dl>'), URL)
        self.assertEqual(items[0]['nip'], NIP)

    def test_definition_list_seller(self):
        items, _ = company.extract_nips(soup('<dl><dt>Sprzedawca</dt><dd>Firma NIP: 5170441148</dd></dl>'), URL)
        self.assertEqual(items[0]['role'], 'seller_declared')

    def test_roles_and_all_nips(self):
        html = '<p>Sprzedawca MTuning NIP: 5170441148</p><p>Operator płatności IdoPayments NIP: 8522666251</p>'
        items, _ = company.extract_nips(soup(html), URL)
        self.assertEqual([x['nip'] for x in items], [NIP, OTHER])
        self.assertEqual([x['role'] for x in items], ['seller_declared', 'payment_declared'])

    def test_mixed_roles_unknown(self):
        self.assertEqual(company.declared_role('Sprzedawca i operator płatności NIP: 5170441148'), 'ambiguous')

    def test_plain_scripts_and_hidden_ignored(self):
        html = '<script>NIP: 5170441148</script><div hidden>NIP: 8522666251</div>'
        self.assertEqual(company.extract_nips(soup(html), URL)[0], [])

    def test_structured_declaration_separate(self):
        html = '<script type="application/ld+json">{"@type":"Organization","name":"Firma","taxID":"PL5170441148"}</script>'
        item = company.extract_nips(soup(html), URL)[0][0]
        self.assertEqual(item['kind'], 'json_ld')
        self.assertEqual(item['role'], 'unknown')

    def test_checksum(self):
        for raw in [NIP, OTHER, '517-044-11-48']:
            self.assertTrue(company.is_valid_nip(raw))
        for raw in ['0000000000', '5170441149', '517044114', '51704411489', 'abcdef1234']:
            self.assertFalse(company.is_valid_nip(raw))

    def test_false_terms_and_fragment(self):
        links = scanner.collect_links(soup('<a href="/photos">Photos</a><a href="#">Regulamin</a>'), URL)
        self.assertEqual(links, [])

    def test_base_and_priorities(self):
        html = '<base href="/pl/"><a href="contact">Kontakt</a>'
        links = scanner.collect_links(soup(html), URL)
        self.assertEqual(links[0]['url'], 'https://example.com/pl/contact')
        many = [{'url': URL+f'about{i}', 'labels': ['O firmie']} for i in range(10)]
        many += [{'url': URL+'contact', 'labels': ['Kontakt']}, {'url': URL+'terms','labels':['Regulamin']}]
        selected = scanner.choose_company_pages(many, URL)
        self.assertEqual(selected[:2], [URL+'contact', URL+'terms'])
        self.assertLessEqual(len(selected), scanner.MAX_EXTRA_PAGES)


class RegistryTests(unittest.TestCase):
    def validate(self, subject, nip=NIP):
        return company.validate_vat_payload({'result': {'subject': subject, 'requestId':'test'}}, nip, '2026-11-11', URL)

    def test_valid(self):
        result = self.validate({'nip':NIP,'name':'Firma','statusVat':'Czynny'})
        self.assertEqual(result['status'],'found')

    def test_empty_not_success(self):
        self.assertEqual(self.validate({})['status'],'invalid_response')

    def test_wrong_nip(self):
        self.assertEqual(self.validate({'nip':OTHER,'name':'Firma'})['status'],'invalid_response')

    def test_missing_name(self):
        self.assertEqual(self.validate({'nip':NIP})['status'],'invalid_response')

    def test_partial_vat_status(self):
        self.assertEqual(self.validate({'nip':NIP,'name':'Firma'})['status'],'partial')

    def test_null_vs_missing(self):
        self.assertEqual(self.validate(None)['status'],'not_found')
        result = company.validate_vat_payload({'result':{}},NIP,'2026-11-11',URL)
        self.assertEqual(result['status'],'invalid_response')

    def test_registry_cache(self):
        payload = network.outcome('ok',{'payload':{'result':{'subject':{'nip':NIP,'name':'Firma','statusVat':'Czynny'}}}}, URL)
        cache = {}
        with patch.object(company,'fetch_json',return_value=payload) as fetch:
            for _ in range(2):
                company.get_vat_company(NIP,'2026-11-11',time.monotonic()+10,cache)
            self.assertEqual(fetch.call_count,1)

    def test_name_absence_is_not_mismatch(self):
        self.assertEqual(company.compare_name('Firma sp. z o.o.',[{'context':'Marka NIP: 5170441148'}]),'not_established')

    def test_seller_conflict(self):
        findings = [{'nip': n, 'evidence':[{'role':'seller_declared'}]} for n in (NIP,OTHER)]
        self.assertEqual(company.summarize_seller(findings)['status'],'ambiguous')


class NetworkTests(unittest.TestCase):
    def test_url_validation(self):
        for url in ['', 'https://user:pass@example.com', 'https://example.com:8080', 'file:///etc/passwd', 'https://exam ple.com']:
            with self.subTest(url=url), self.assertRaises((ValueError,UnicodeError)):
                network.normalize_url(url)
        self.assertEqual(network.normalize_url('EXAMPLE.com/path#x'), 'https://example.com/path')

    def test_nonpublic_addresses(self):
        for ip in ['127.0.0.1','10.1.2.3','169.254.169.254','192.168.1.1','::1','fc00::1','::ffff:127.0.0.1','224.0.0.1','64:ff9b::7f00:1']:
            with self.subTest(ip=ip):
                self.assertFalse(network.public_address(ip))
        self.assertTrue(network.public_address('8.8.8.8'))

    def test_direct_local_no_socket(self):
        with patch.object(network.socket,'socket') as socket:
            with self.assertRaises(network.FetchError):
                network.connect_public('127.0.0.1',80,False,time.monotonic()+10)
            socket.assert_not_called()

    def test_psl(self):
        self.assertEqual(network.registrable_domain('www.shop.example.co.uk'),'example.co.uk')
        self.assertIsNone(network.registrable_domain('127.0.0.1'))

    def test_rdap_null(self):
        with patch.object(network,'fetch_json',return_value=network.outcome('ok',{'payload':{'events':None}})):
            self.assertEqual(network.check_domain_age('example.com',time.monotonic()+10)['status'],'unknown')

    def test_rdap_future(self):
        payload={'events':[{'eventAction':'registration','eventDate':'2999-01-01T00:00:00Z'}]}
        with patch.object(network,'fetch_json',return_value=network.outcome('ok',{'payload':payload})):
            self.assertEqual(network.check_domain_age('example.com',time.monotonic()+10)['status'],'invalid_response')

    def test_terminal_escape(self):
        self.assertNotIn('\x1b',main.terminal_text('\x1b[31mNIP'))


class ScanTests(unittest.TestCase):
    def test_one_fetch_per_page_and_no_false_missing(self):
        html='<a href="/contact">Kontakt</a><p>Sprzedawca Firma NIP: 5170441148</p>'
        def fetch(url,*args,**kwargs):
            return html_response(html if url==URL else '<p>NIP: 5170441148</p>',url)
        with patch.object(scanner, 'fetch_resource',side_effect=fetch) as fetch_mock, \
             patch.object(scanner, 'check_domain_age',return_value=network.outcome('ok')), \
             patch.object(scanner, 'check_tls',return_value=network.outcome('ok')), \
             patch.object(scanner, 'check_dns',return_value=network.outcome('not_found')):
            report=scanner.analyze_shop(URL,skip_vat=True)
        self.assertEqual(fetch_mock.call_count,2)
        self.assertEqual(len(report['findings']),1)
        self.assertEqual(len(report['findings'][0]['evidence']),2)
        self.assertEqual(report['seller']['status'],'declared')
        output=io.StringIO()
        with contextlib.redirect_stdout(output):main.print_report(report)
        self.assertNotIn('Nie znaleziono numerów',output.getvalue())
        json.dumps(report)

    def test_vat_disabled(self):
        with patch.object(scanner, 'fetch_resource',return_value=html_response('<p>NIP: 5170441148</p>')), \
             patch.object(scanner, 'check_domain_age',return_value=network.outcome('ok')), \
             patch.object(scanner, 'check_tls',return_value=network.outcome('ok')), \
             patch.object(scanner, 'check_dns',return_value=network.outcome('not_found')), \
             patch.object(scanner, 'get_vat_company') as vat:
            scanner.analyze_shop(URL,skip_vat=True)
            vat.assert_not_called()




class FakeSocket:
    def settimeout(self, value): pass


class FakeHeaders:
    def get_content_charset(self): return 'utf-8'


class FakeResponse:
    def __init__(self,status=200,headers=None,body=b'<p>ok</p>'):
        self.status=status
        self.values=headers or {'Content-Type':'text/html'}
        self.body=body
        self.headers=FakeHeaders()
        self.closed=False
    def getheader(self,key,default=None): return self.values.get(key,default)
    def read1(self,size):
        chunk,self.body=self.body[:size],self.body[size:]
        return chunk
    def close(self):self.closed=True


class FakeConnection:
    def __init__(self,response):self.response=response;self.sock=FakeSocket();self.closed=False
    def request(self,*args,**kwargs):pass
    def getresponse(self):return self.response
    def close(self):self.closed=True


class TransportTests(unittest.TestCase):
    def test_success_and_cleanup(self):
        response=FakeResponse();connection=FakeConnection(response)
        with patch.object(network, 'PinnedConnection',return_value=connection):
            result=network.fetch_resource(URL,time.monotonic()+10)
        self.assertEqual(result['status'],'ok')
        self.assertTrue(response.closed and connection.closed)

    def test_same_host_redirect_escape(self):
        response=FakeResponse(302,{'Location':'https://attacker.example/'})
        with patch.object(network, 'PinnedConnection',return_value=FakeConnection(response)) as connect:
            result=network.fetch_resource(URL,time.monotonic()+10,allowed_host='example.com')
        self.assertEqual(result['status'],'blocked')
        self.assertEqual(connect.call_count,1)

    def test_redirect_downgrade(self):
        response=FakeResponse(302,{'Location':'http://example.com/'})
        with patch.object(network, 'PinnedConnection',return_value=FakeConnection(response)):
            result=network.fetch_resource(URL,time.monotonic()+10)
        self.assertEqual(result['status'],'blocked')

    def test_response_too_large_without_length(self):
        response=FakeResponse(body=b'123456789')
        with patch.object(network, 'PinnedConnection',return_value=FakeConnection(response)),patch.object(network, 'MAX_PAGE_BYTES',5):
            result=network.fetch_resource(URL,time.monotonic()+10)
        self.assertEqual(result['status'],'too_large')

    def test_wrong_mime(self):
        response=FakeResponse(headers={'Content-Type':'application/pdf'})
        with patch.object(network, 'PinnedConnection',return_value=FakeConnection(response)):
            result=network.fetch_resource(URL,time.monotonic()+10)
        self.assertEqual(result['status'],'unsupported_type')

    def test_429_stays_distinct(self):
        with patch.object(network, 'PinnedConnection',return_value=FakeConnection(FakeResponse(429))):
            result=network.fetch_resource(URL,time.monotonic()+10)
        self.assertEqual(result['status'],'rate_limited')

    def test_private_ip_redirect_uses_validation(self):
        first=FakeConnection(FakeResponse(302,{'Location':'https://127.0.0.1/'}))
        original=network.PinnedConnection
        def factory(host,use_tls,deadline):
            return first if host=='example.com' else original(host,use_tls,deadline)
        with patch.object(network, 'PinnedConnection',side_effect=factory),patch.object(network.socket,'socket') as sock:
            result=network.fetch_resource(URL,time.monotonic()+10)
        self.assertEqual(result['status'],'blocked')
        sock.assert_not_called()

    def test_no_dns_reresolution_when_connecting(self):
        from types import SimpleNamespace
        address=SimpleNamespace(address='8.8.8.8')
        resolver=unittest.mock.Mock()
        resolver.resolve.side_effect=[[address],network.dns.resolver.NoAnswer()]
        with patch.object(network.dns.resolver,'Resolver',return_value=resolver),patch.object(network.socket,'socket') as sock:
            network.connect_public('example.com',80,False,time.monotonic()+10)
        sock.return_value.connect.assert_called_once_with(('8.8.8.8',80))

    def test_mixed_public_private_dns_blocked(self):
        from types import SimpleNamespace
        resolver=unittest.mock.Mock()
        resolver.resolve.side_effect=[[SimpleNamespace(address='8.8.8.8'),SimpleNamespace(address='127.0.0.1')],network.dns.resolver.NoAnswer()]
        with patch.object(network.dns.resolver,'Resolver',return_value=resolver),patch.object(network.socket,'socket') as sock:
            with self.assertRaises(network.FetchError):
                network.connect_public('example.com',80,False,time.monotonic()+10)
        sock.assert_not_called()

class LiveReportRegressionTests(unittest.TestCase):
    def test_mtuning_name_abbreviation(self):
        self.assertEqual(company.compare_name(
            'MTUNING SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ',
            [{'context':'Sprzedawca MTuning Sp. z o.o. NIP 5170441148 REGON 526876239'}]),
            'name_equivalent')

    def test_idopayments_name_abbreviation(self):
        self.assertEqual(company.compare_name(
            'IDOPAYMENTS SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ',
            [{'context':'Operator IdoPayments sp. z o.o. NIP 8522666251'}]),
            'name_equivalent')

    def test_different_name_not_equivalent(self):
        self.assertEqual(company.compare_name('MTUNING SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ',
                                         [{'context':'IdoPayments sp. z o.o.'}]),'not_established')
        self.assertEqual(company.compare_name('MTUNING SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ',
                                         [{'context':'MTuning spółka akcyjna'}]),'not_established')

    def test_long_payment_block(self):
        block=('Operator IdoPayments sp. z o.o. z siedzibą al. Piastów 30, 71-064 Szczecin, '
               'wpisana do rejestru przedsiębiorców prowadzonego przez Sąd Rejonowy Szczecin-Centrum '
               'w Szczecinie, XIII Wydział Gospodarczy KRS pod nr 0000859711, NIP 8522666251, '
               'REGON 387039893, o kapitale zakładowym 800 000,00 złotych. '
               'Adres do doręczeń: al. Piastów 30, 71-064 Szczecin; określana także jako IdoPayments, '
               'będąca krajową instytucją płatniczą.')
        item=company.extract_nips(soup('<p>'+block+'</p>'),URL)[0][0]
        self.assertEqual(item['role'],'payment_declared')
        self.assertEqual(item['analysis_context'],block)
        self.assertEqual(company.compare_name('IDOPAYMENTS SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ',[item]),'name_equivalent')
        self.assertNotEqual(item['context'][:5],'rator')

    def test_multiple_firms_one_block_not_assigned(self):
        html='<p>Sprzedawca Firma NIP: 5170441148. Partner NIP: 8522666251.</p>'
        items=company.extract_nips(soup(html),URL)[0]
        self.assertEqual(len(items),2)
        self.assertTrue(all(item['role']=='ambiguous' for item in items))

    def test_rdap_tls_is_provider_failure(self):
        error=network.outcome('tls_invalid',{'redirects':['https://rdap.org/','https://rdap.dns.pl/']},
                          'https://rdap.dns.pl/domain/mtuning.pl','TLS: unable to get local issuer certificate')
        with patch.object(network,'fetch_json',return_value=error):
            result=network.check_domain_age('mtuning.pl',time.monotonic()+10)
        self.assertEqual(result['status'],'unavailable')
        self.assertEqual(result['data']['dependency_status'],'tls_invalid')
        self.assertIn('nie wynik kontroli TLS sklepu',result['message'])
        self.assertIn('unable to get local issuer certificate',result['message'])

    def test_certificate_diagnostics_retained(self):
        error=network.ssl.SSLCertVerificationError(1,'certificate failed')
        error.verify_code=20
        error.verify_message='unable to get local issuer certificate'
        with patch.object(network, 'resolve_public',return_value=['8.8.8.8']), \
             patch.object(network.socket,'socket'), \
             patch.object(network.ssl,'create_default_context') as context:
            context.return_value.wrap_socket.side_effect=error
            with self.assertRaises(network.FetchError) as caught:
                network.connect_public('rdap.dns.pl',443,True,time.monotonic()+10)
        self.assertEqual(caught.exception.status,'tls_invalid')
        self.assertIn('kod 20',str(caught.exception))
        self.assertIn('rdap.dns.pl',str(caught.exception))
        self.assertIn('unable to get local issuer certificate',str(caught.exception))

class CompactAndTrustTests(unittest.TestCase):
    def test_ca_bundle_added_without_disabling_verification(self):
        context=network.create_tls_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode,network.ssl.CERT_REQUIRED)
        with patch.object(network.ssl,'create_default_context') as factory:
            network.create_tls_context()
            factory.return_value.load_verify_locations.assert_called_once_with(cafile=network.certifi.where())

    def make_report(self):
        age=network.outcome('unavailable',{'dependency_status':'tls_invalid'},'https://rdap.dns.pl/',
                        'DIAGNOSTIC: unable to get local issuer certificate')
        with patch.object(scanner, 'fetch_resource',return_value=html_response('<p>NIP: 5170441148</p>')), \
             patch.object(scanner, 'check_domain_age',return_value=age), \
             patch.object(scanner, 'check_tls',return_value=network.outcome('ok')), \
             patch.object(scanner, 'check_dns',return_value=network.outcome('present')):
            return scanner.analyze_shop(URL,skip_vat=True)

    def test_compact_hides_diagnostics_but_verbose_keeps_them(self):
        report=self.make_report()
        short=io.StringIO();full=io.StringIO()
        with contextlib.redirect_stdout(short): main.print_report(report)
        with contextlib.redirect_stdout(full): main.print_report(report,verbose=True)
        self.assertNotIn('DIAGNOSTIC',short.getvalue())
        self.assertNotIn('Kontekst:',short.getvalue())
        self.assertIn('DIAGNOSTIC',full.getvalue())
        self.assertIn('Kontekst:',full.getvalue())
        self.assertIn('5170441148',short.getvalue())
        self.assertLess(len(short.getvalue().splitlines()),25)
        self.assertIn('błąd zaufania TLS usługi RDAP',short.getvalue())

class SeparatedSellerTests(unittest.TestCase):
    def test_pan_sadzonka_declaration_in_three_blocks(self):
        html='<section><p>Sprzedawca:</p><p>PAN SADZONKA SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ</p><p>NIP : 8181739203</p></section>'
        items,_=company.extract_nips(soup(html),URL)
        self.assertEqual(items[0]['role'],'seller_declared')
        self.assertEqual(company.compare_name('PAN SADZONKA SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ',items),'name_present')

    def test_feria_separate_nip(self):
        html='<li><p>Sprzedawca – Podwysocki sp.j z siedzibą w Łodzi przy ul. Lodowej 92</p><p>NIP 8291658173, REGON 100130834</p></li>'
        items,_=company.extract_nips(soup(html),URL)
        self.assertEqual(items[0]['role'],'seller_declared')
        self.assertEqual(company.compare_name('PODWYSOCKI SPÓŁKA JAWNA',items),'name_equivalent')

    def test_no_arbitrary_role_inheritance(self):
        html='<p>Sprzedawca: Firma</p><p>Operator płatności: Inna firma</p><p>NIP 8522666251</p>'
        items,_=company.extract_nips(soup(html),URL)
        self.assertEqual(items[0]['role'],'payment_declared')

    def test_previous_nip_blocks_joining(self):
        html='<p>Sprzedawca Firma NIP 5170441148</p><p>NIP 8522666251</p>'
        items,_=company.extract_nips(soup(html),URL)
        self.assertEqual(items[1]['role'],'unknown')

    def test_no_html_not_reported_as_search(self):
        with patch.object(scanner, 'fetch_resource',return_value=network.outcome('http_error',source=URL,message='HTTP 403')), \
             patch.object(scanner, 'check_domain_age',return_value=network.outcome('unknown')), \
             patch.object(scanner, 'check_tls',return_value=network.outcome('ok')), \
             patch.object(scanner, 'check_dns',return_value=network.outcome('present')):
            report=scanner.analyze_shop(URL,True)
        output=io.StringIO()
        with contextlib.redirect_stdout(output): main.print_report(report)
        self.assertIn('Analiza NIP niewykonana',output.getvalue())
        self.assertNotIn('Nie znaleziono numerów',output.getvalue())

class GermanVatTests(unittest.TestCase):
    def test_german_labels(self):
        for raw in ['Numer VAT: DE 260543043','VAT ID: DE260543043','VAT registration number: DE 260543043', 'USt-IdNr.: DE260543043','NIP: DE260543043']:
            with self.subTest(raw=raw):
                items=company.extract_german_vat_ids(soup('<p>'+raw+'</p>'),URL)
                self.assertEqual(items[0]['identifier'],'DE260543043')
                self.assertEqual(items[0]['verification_status'],'not_checked')

    def test_foreign_never_becomes_polish_nip(self):
        parsed=soup('<p>NIP: DE260543043</p>')
        self.assertEqual(company.extract_nips(parsed,URL)[0],[])

    def test_bad_length_or_unlabelled_not_accepted(self):
        for raw in ['VAT: DE2605430439','VAT: DE26054304','WEEE-Reg. DE72754189','DE260543043','VAT: DE260543043 9']:
            self.assertEqual(company.extract_german_vat_ids(soup('<p>'+raw+'</p>'),URL),[])

    def test_separate_tax_label(self):
        parsed=soup('<dl><dt>Numer VAT:</dt><dd>DE260543043</dd></dl>')
        self.assertEqual(company.extract_german_vat_ids(parsed,URL)[0]['identifier'],'DE260543043')

    def test_jsonld(self):
        parsed=soup('<script type="application/ld+json">{"vatID":"DE260543043","name":"Firma"}</script>')
        self.assertEqual(company.extract_german_vat_ids(parsed,URL)[0]['identifier'],'DE260543043')

    def test_foreign_not_queried_in_polish_registry(self):
        with patch.object(scanner, 'fetch_resource',return_value=html_response('<p>Numer VAT: DE260543043</p>')), \
             patch.object(scanner, 'check_domain_age',return_value=network.outcome('unknown')), \
             patch.object(scanner, 'check_tls',return_value=network.outcome('ok')), \
             patch.object(scanner, 'check_dns',return_value=network.outcome('present')), \
             patch.object(scanner, 'get_vat_company') as mf:
            report=scanner.analyze_shop(URL)
        mf.assert_not_called()
        self.assertEqual(report['foreign_identifiers'][0]['identifier'],'DE260543043')
        output=io.StringIO()
        with contextlib.redirect_stdout(output): main.print_report(report)
        self.assertIn('DE260543043',output.getvalue())
        self.assertIn('nie zostały zweryfikowane',output.getvalue())


class CrawlReviewTests(unittest.TestCase):
    def test_newsletter_after_company(self):
        links = [
            {"url": URL + "faq/newsletter", "text": "Kontakt", "labels": ["Kontakt"]},
            {"url": URL + "terms", "text": "Regulamin", "labels": ["Regulamin"]},
        ]
        result = scanner.rank_company_pages(links, URL)
        self.assertEqual(result[0]["url"], URL + "terms")
        self.assertTrue(result[1]["secondary"])
        self.assertIn("Regulamin", result[0]["reason"])

    def test_exact_content_duplicates(self):
        first = {"data": {"body": b"<p>Company</p>"}}
        second = {"data": {"body": b"<p>Other company</p>"}}
        self.assertEqual(scanner.content_fingerprint(first), scanner.content_fingerprint(first))
        self.assertNotEqual(scanner.content_fingerprint(first), scanner.content_fingerprint(second))

    def test_slash_variants_are_not_blindly_merged(self):
        links = [{"url": URL + path, "text": "Kontakt", "labels": ["Kontakt"]}
                 for path in ["contact", "contact/"]]
        self.assertEqual(len(scanner.rank_company_pages(links, URL)), 2)

if __name__ == "__main__":
    unittest.main()
