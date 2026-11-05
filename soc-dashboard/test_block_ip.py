"""Tests du blocage d'IP — validation, commande, et obligation d'approbation.

Hermetiques : aucun pare-feu touche, aucune base ecrite, aucun reseau.
"""

import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import block_ip  # noqa: E402
import broker  # noqa: E402


class TestValidation(unittest.TestCase):
    def test_refuse_adresse_invalide(self):
        for mauvais in ("1.2.3.999", "abc", "", "10.0.0.1.5", "-", "*"):
            ip, motif = block_ip.valider_ip(mauvais)
            self.assertIsNone(ip, mauvais)
            self.assertTrue(motif, mauvais)

    def test_refuse_reseaux_plus_larges_qu_un_hote(self):
        ip, motif = block_ip.valider_ip("198.51.100.0/24")
        self.assertIsNone(ip)
        self.assertIn("/32", motif)

    def test_accepte_hote_unique_et_32(self):
        for bon in ("198.51.100.23", "198.51.100.23/32", "  198.51.100.23  "):
            ip, motif = block_ip.valider_ip(bon)
            self.assertEqual(ip, "198.51.100.23", bon)
            self.assertIsNone(motif)

    def test_refuse_plages_locales(self):
        for locale in ("127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.10",
                       "169.254.5.5", "0.0.0.0", "224.0.0.1"):
            ip, motif = block_ip.valider_ip(locale)
            self.assertIsNone(ip, locale)
            self.assertIn("locale ou protegee", motif)

    def test_allow_private_les_autorise(self):
        ip, motif = block_ip.valider_ip("192.168.1.10", allow_private=True)
        self.assertEqual(ip, "192.168.1.10")
        self.assertIsNone(motif)

    def test_ipv6_mappee_redevient_ipv4(self):
        ip, _ = block_ip.valider_ip("::ffff:198.51.100.23")
        self.assertEqual(ip, "198.51.100.23")

    def test_ipv6_publique_acceptee(self):
        ip, motif = block_ip.valider_ip("2001:db8::1")
        self.assertEqual(ip, "2001:db8::1")
        self.assertIsNone(motif)


class TestCommande(unittest.TestCase):
    def test_nom_de_regle_deterministe(self):
        self.assertEqual(block_ip.nom_regle("198.51.100.23"), "SOC-Block-198-51-100-23-in")
        self.assertEqual(block_ip.nom_regle("2001:db8::1", "out"),
                         "SOC-Block-2001-db8--1-out")

    def test_commande_sans_metacaractere(self):
        cmd = block_ip.commande("198.51.100.23", raison="brute force; rm -rf /")
        texte = " ".join(cmd)
        for dangereux in (";", "|", "&&", "`"):
            self.assertNotIn(dangereux, texte)

    def test_simulation_ajoute_whatif(self):
        cmd = block_ip.commande("198.51.100.23", simulation=True)
        self.assertIn("-WhatIf", cmd)

    def test_masquer_entoure_les_espaces(self):
        cmd = block_ip.commande("198.51.100.23", raison="brute force SSH")
        texte = block_ip.masquer(cmd)
        self.assertIn('"brute force SSH"', texte)


class TestApprobationObligatoire(unittest.TestCase):
    def test_commande_classee_critique(self):
        """La commande generee doit tomber dans la categorie la plus sensible."""
        cmd = block_ip.masquer(block_ip.commande("198.51.100.23"))
        risque, motif = broker.classify(cmd)
        self.assertEqual(risque, "critique")
        self.assertTrue(motif)

    def test_ps1_direct_classe_critique(self):
        risque, _ = broker.classify("powershell -File block_ip.ps1 -IpAddress 198.51.100.23")
        self.assertEqual(risque, "critique")

    def test_demande_force_le_risque_critique(self):
        with mock.patch.object(broker, "new_request", return_value=("abcd1234", "critique", "regle de pare-feu")) as demande, \
             mock.patch.object(broker, "notify_request", return_value=None):
            block_ip.demander(block_ip.commande("198.51.100.23"))
            kwargs = demande.call_args.kwargs
            self.assertEqual(kwargs["risk"], "critique")
            self.assertIn("block_ip.ps1", kwargs and demande.call_args.args[0])

    def test_pas_d_execution_sans_approbation(self):
        """wait_for_decision refuse : aucune commande ne doit etre lancee."""
        with mock.patch.object(broker, "new_request", return_value=("abcd1234", "critique", "regle de pare-feu")), \
             mock.patch.object(broker, "notify_request", return_value=None), \
             mock.patch.object(broker, "wait_for_decision", return_value="denied"), \
             mock.patch.object(broker, "execute") as execution:
            code = block_ip.principal(["block", "198.51.100.23", "--whatif"])
            self.assertEqual(code, 1)
            execution.assert_not_called()

    def test_adresse_privee_refusee_avant_toute_demande(self):
        with mock.patch.object(broker, "new_request") as demande:
            code = block_ip.principal(["block", "192.168.1.10"])
            self.assertEqual(code, 2)
            demande.assert_not_called()


if __name__ == "__main__":
    unittest.main()
