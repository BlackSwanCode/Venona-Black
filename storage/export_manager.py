import json
import hashlib
import os
from datetime import datetime
from typing import List, Dict, Any
import zipfile
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from stix2 import Indicator, Bundle, Identity, MarkingDefinition, StatementMarking

class ExportManager:
    def __init__(self, db_path: str = "osint_searches.db"):
        self.db_path = db_path

    def export_stix21(self, iocs: List[Dict[str, Any]], case_name: str) -> str:
        """Génère un bundle STIX 2.1."""
        stix_objects = []
        
        # Identity de l'organisation
        identity = Identity(
            name="Dorker Pro OSINT",
            identity_class="organization"
        )
        stix_objects.append(identity)
        
        # Marking definition (TLP:WHITE)
        marking_def = MarkingDefinition(
            definition_type="statement",
            definition=StatementMarking(statement="TLP:WHITE")
        )
        stix_objects.append(marking_def)
        
        for ioc in iocs:
            pattern = ""
            if ioc["type"] == "DOMAIN":
                pattern = f"[domain-name:value = '{ioc['value']}']"
            elif ioc["type"] == "IPV4":
                pattern = f"[ipv4-addr:value = '{ioc['value']}']"
            elif ioc["type"] == "EMAIL":
                pattern = f"[email-addr:value = '{ioc['value']}']"
            elif ioc["type"] == "URL":
                pattern = f"[url:value = '{ioc['value']}']"
            else:
                continue
            
            indicator = Indicator(
                pattern=pattern,
                pattern_type="stix",
                labels=["malicious-activity"],
                name=f"IOC: {ioc['value']}",
                description=f"Extrait du cas: {case_name}",
                created_by_ref=identity.id,
                object_marking_refs=[marking_def.id]
            )
            stix_objects.append(indicator)
        
        bundle = Bundle(objects=stix_objects)
        filename = f"stix_export_{case_name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(bundle.serialize(pretty=True))
        
        return filename

    def export_misp(self, iocs: List[Dict[str, Any]], case_name: str) -> str:
        """Génère un événement MISP au format JSON."""
        misp_event = {
            "Event": {
                "info": f"OSINT Investigation: {case_name}",
                "date": datetime.now().strftime("%Y-%m-%d"),
                "threat_level_id": 2,  # Medium
                "analysis": 1,  # Ongoing
                "distribution": 1,  # Community
                "Attribute": []
            }
        }
        
        type_mapping = {
            "DOMAIN": "domain",
            "IPV4": "ip-dst",
            "EMAIL": "email-src",
            "URL": "url",
            "HASH_MD5": "md5",
            "HASH_SHA256": "sha256"
        }
        
        for ioc in iocs:
            misp_type = type_mapping.get(ioc["type"])
            if misp_type:
                misp_event["Event"]["Attribute"].append({
                    "type": misp_type,
                    "value": ioc["value"],
                    "category": "Network activity",
                    "to_ids": True,
                    "comment": f"Source: Dorker Pro - {case_name}"
                })
        
        filename = f"misp_export_{case_name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(misp_event, f, indent=2)
        
        return filename

    def export_pdf_report(self, case_data: Dict[str, Any], iocs: List[Dict[str, Any]], output_path: str) -> str:
        """Génère un rapport PDF synthétique."""
        c = canvas.Canvas(output_path, pagesize=letter)
        width, height = letter
        
        # En-tête
        c.setFillColor(colors.darkred)
        c.setFont("Helvetica-Bold", 20)
        c.drawString(50, height - 50, "RAPPORT D'INVESTIGATION OSINT")
        
        c.setFont("Helvetica", 12)
        c.setFillColor(colors.black)
        c.drawString(50, height - 80, f"Cas: {case_data.get('name', 'N/A')}")
        c.drawString(50, height - 100, f"Date: {datetime.now().strftime('%d/%m/%Y %H:%M')}")
        c.drawString(50, height - 120, f"Investigateur: {case_data.get('investigator', 'N/A')}")
        
        # Hash d'intégrité
        integrity_hash = hashlib.sha256(json.dumps(case_data, default=str).encode()).hexdigest()
        c.drawString(50, height - 140, f"Hash intégrité (SHA-256): {integrity_hash[:32]}...")
        
        # Résumé
        y_pos = height - 180
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y_pos, "1. Résumé Exécutif")
        c.setFont("Helvetica", 11)
        c.drawString(50, y_pos - 25, case_data.get('description', 'Aucune description fournie.'))
        
        # IOC
        y_pos -= 60
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y_pos, f"2. Indicateurs Compromis ({len(iocs)} trouvés)")
        
        c.setFont("Helvetica", 10)
        y_pos -= 25
        for ioc in iocs[:20]:  # Limite à 20 pour le PDF
            c.drawString(50, y_pos, f"• [{ioc['type']}] {ioc['value']}")
            y_pos -= 15
            if y_pos < 100:
                c.showPage()
                y_pos = height - 50
        
        c.save()
        return output_path

    def export_bundle_zip(self, case_data: Dict[str, Any], iocs: List[Dict[str, Any]], case_name: str) -> str:
        """Génère un bundle ZIP contenant tous les exports."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        zip_filename = f"case_bundle_{case_name.replace(' ', '_')}_{timestamp}.zip"
        
        with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # STIX 2.1
            stix_file = self.export_stix21(iocs, case_name)
            zipf.write(stix_file, f"stix/{os.path.basename(stix_file)}")
            os.remove(stix_file)
            
            # MISP
            misp_file = self.export_misp(iocs, case_name)
            zipf.write(misp_file, f"misp/{os.path.basename(misp_file)}")
            os.remove(misp_file)
            
            # PDF
            pdf_file = f"report_{case_name}_{timestamp}.pdf"
            self.export_pdf_report(case_data, iocs, pdf_file)
            zipf.write(pdf_file, f"report/{os.path.basename(pdf_file)}")
            os.remove(pdf_file)
            
            # JSON brut
            json_file = f"raw_data_{case_name}_{timestamp}.json"
            with open(json_file, "w", encoding="utf-8") as f:
                json.dump({"case": case_data, "iocs": iocs}, f, indent=2, default=str)
            zipf.write(json_file, f"raw/{os.path.basename(json_file)}")
            os.remove(json_file)
            
            # Manifest
            manifest = {
                "case_name": case_name,
                "export_date": datetime.now().isoformat(),
                "files": [
                    f"stix/{os.path.basename(stix_file)}",
                    f"misp/{os.path.basename(misp_file)}",
                    f"report/{os.path.basename(pdf_file)}",
                    f"raw/{os.path.basename(json_file)}"
                ]
            }
            manifest_file = "manifest.json"
            with open(manifest_file, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
            zipf.write(manifest_file, "manifest.json")
            os.remove(manifest_file)
        
        return zip_filename
