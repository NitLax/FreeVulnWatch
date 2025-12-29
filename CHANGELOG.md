# Changelog - Améliorations du module openSourceVulnIntelligence

## 2025-12-29 - Corrections et améliorations

### 1. Sélection des scrapers
- ✅ Ajout du support pour `--scrapers` avec liste séparée par espaces OU virgules
- ✅ Validation automatique des noms de scrapers
- ✅ Exemples: `--scrapers nvd cveorg` ou `--scrapers nvd,cveorg,wiz`

### 2. Extraction CWE (NVD Scraper)
**Problème**: Le scraper prenait le dernier CWE ID de la liste au lieu du plus spécifique
**Solution**: Utilisation de `max(cwe_ids, key=int)` pour sélectionner le CWE ID le plus élevé (plus spécifique)

**Exemple**:
```python
# Avant: cwe_ids = ['917', '400', '502', '20'] → retournait '20'
# Après: cwe_ids = ['917', '400', '502', '20'] → retourne '917' (plus spécifique)
```

### 3. Fonction get_mitre_cwe_name
**Problèmes**:
- Regex avec backslashes incorrects (`\\-` au lieu de `-`)
- Format HTML de MITRE peut varier
- Erreurs SSL

**Solutions**:
- ✅ Correction du regex
- ✅ Ajout de 4 patterns différents pour robustesse
- ✅ Workaround SSL avec `verify=False`
- ✅ Meilleure gestion d'erreurs

### 4. Extraction des produits affectés (NVD Scraper)
**Problème**: Seule la première configuration était traitée
```python
# Avant
cpes = data['configurations'][0]['nodes'][0]['cpeMatch']  # ❌ Seulement le premier
```

**Solution**: Itération sur TOUTES les configurations et nodes
```python
# Après
for config in configurations:
    for node in config['nodes']:
        for cpe in node['cpeMatch']:
            # Traiter tous les CPE
```

**Résultat**: Extraction complète de tous les produits affectés, pas seulement ceux de la première configuration.

### 5. Déduplication des produits affectés (Affichage)
**Problème**: Les produits dupliqués s'affichaient plusieurs fois
```
Mozilla:
  - Firefox
  - Firefox
  - Firefox
  - Thunderbird
  - Thunderbird
```

**Solution**: Déduplication par nom de produit lors de l'affichage
```python
# Dans display_vulnerability() et to_markdown()
seen_products = set()
for product_info in products:
    product = product_info.get('product')
    if product not in seen_products:
        # Afficher le produit
        seen_products.add(product)
```

**Résultat**: Affichage propre sans doublons
```
Mozilla:
  - Firefox
  - Thunderbird
```

### 6. Workaround SSL global
**Problème**: Erreurs SSL récurrentes avec tous les scrapers
```
InsecureRequestWarning: Unverified HTTPS request is being made to host...
```

**Solution**: Ajout de `verify=False` et suppression des warnings dans tous les scrapers
```python
# Dans chaque scraper
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

# Dans les requêtes
response = requests.get(url, timeout=15, verify=False)
```

**Fichiers modifiés**:
- `scrapers/nvd.py`
- `scrapers/cveorg.py`
- `scrapers/wiz.py`
- `utils.py` (IsInCISAKEV et get_mitre_cwe_name)

**Résultat**: Plus d'avertissements SSL lors de l'exécution ✅

## Tests effectués

✅ CVE-2021-44228 (Log4Shell):
- CWE ID: 917 (correct, le plus spécifique)
- Nom CWE: Récupéré depuis MITRE
- Produits affectés: Liste complète incluant tous les vendors

✅ Sélection de scrapers:
- `--scrapers nvd cveorg` (espaces) ✓
- `--scrapers nvd,cveorg` (virgules) ✓
- Validation des noms ✓

## Fichiers modifiés

1. `openSourceVulnIntelligence/scrapers/nvd.py`
   - `_extract_cwe_id()`: Sélection du CWE le plus spécifique
   - `_extract_affected()`: Itération sur toutes les configurations

2. `openSourceVulnIntelligence/utils.py`
   - `get_mitre_cwe_name()`: Regex corrigé + patterns multiples + SSL workaround

3. `openSourceVulnIntelligence.py` (CLI)
   - Argument `--scrapers` avec support espace/virgule
   - Validation des scrapers
