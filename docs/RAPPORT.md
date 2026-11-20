# SFUMATO : un SOC autonome sur une architecture Big Data (rapport de projet)

*Cloud Data Structure — projet Big Data. Projet GCP `gen-lang-client-0426716352`. Tous les chiffres viennent de scripts du dépôt ; ce qui n'a pas été mesuré est dit comme tel.*

## 1. Problème et justification

Un centre d'opérations de sécurité (SOC) reçoit des millions de flux réseau par jour. Personne ne peut les lire, et une machine seule ne tient pas quelques jours de trafic en mémoire (un seul fichier du jeu de données fait 4 Go). Notre question comporte deux volets :

1. Un pipeline distribué, en lots puis en flux, sait-il séparer attaques et trafic normal ?
2. Que devient-il face à une famille d'attaque qu'il n'a jamais vue ?

Objectifs mesurables : traiter 6,9 Go de façon reproductible ; chiffrer ce qui est écarté ; publier précision et rappel sur un découpage aléatoire **et** chronologique ; garder le flux en vie quand une VM tombe ; mesurer comment le système monte en charge.

## 2. Données (Volume, Variété, Véracité)

Jeu **CSE-CIC-IDS2018** (Canadian Institute for Cybersecurity et CSE), public sur AWS Open Data : 10 CSV, **6,89 Go**, 16 233 002 flux bruts, environ 80 variables CICFlowMeter, 14 familles d'attaque, 83 % de trafic normal.

| V | Dans ce projet |
|---|---|
| Volume | 6,89 Go ; 16,2 M de flux ; table BigQuery d'environ 12,5 Go |
| Vélocité | rejeu Kafka mesuré jusqu'à plus de 23 800 flux/s (voir §6) ; flux CVE horaire |
| Variété | deux formats de CSV (80 et 84 colonnes) ; CVE, KEV, EPSS ; journaux applicatifs |
| Véracité | en-têtes répétés, `Infinity`, `NaN`, durées négatives : 95 833 lignes écartées (0,59 %) |
| Valeur | alertes, procédures de réponse, agent Da Vinci, tableau de bord |

## 3. Architecture

Cinq étages : sources, ingestion, stockage, traitement, valeur.

- **Stockage :** Cloud Storage (données brutes, Parquet partitionné par jour), BigQuery (SQL), Elasticsearch (journaux).
- **Lots :** Spark sur Dataproc Serverless.
- **Flux :** Kafka 4.1.2 en KRaft sur 3 VM, scoreurs en groupe de consommateurs, Flink 1.20.5 pour les fenêtres.
- **Valeur :** tableau de bord (Next.js, FastAPI, Caddy), agent Da Vinci (règles puis réécriture par un LLM : Qwen 2.5 7B interne via Ollama, ou une clé externe), API Console, Logs.

| VM | Type | Rôle |
|---|---|---|
| sfumato | e2-medium (e2-micro avant l'essai de charge) | tableau de bord, API |
| sfumato-kafka-1/2/3 | e2-small Spot | brokers Kafka, scoreurs, producteur de rejeu |
| sfumato-flink | e2-medium Spot | Flink, 2 travaux SQL |
| sfumato-elk | e2-standard-2 Spot | Elasticsearch, Logstash |
| sfumato-qwen | e2-standard-4 Spot | Ollama, Qwen 2.5 7B (et générateur de charge pour les tests) |

Services managés : Cloud Storage, Dataproc Serverless, BigQuery, Cloud Run Job + Cloud Scheduler (ingestion des CVE, toutes les 12 h).

## 4. Traitement par lots (Spark)

Lecture des 10 CSV, union des deux formats, retrait des en-têtes répétés et des valeurs invalides, écriture en Parquet partitionné par jour, agrégats, puis Random Forest (60 arbres).

- Total mesuré : **851 s** (préparation 414 s, apprentissage 425 s) ; 16 137 169 lignes conservées ; BigQuery contient exactement ce nombre de lignes.
- Les attaques sont planifiées par jour (requête SQL) : c'est la clé pour comprendre les résultats chronologiques.

## 5. Apprentissage et familles inconnues

| Évaluation | Précision | Rappel | AUC-PR |
|---|---|---|---|
| Découpage aléatoire (3,2 M de flux) | 0,983 | 0,941 | 0,980 |
| Chronologique, coupure au 28 février (2,0 M) | 0,065 | **0,0005** | 0,479 |

Le découpage aléatoire est trompeur : toutes les familles sont dans l'entraînement. Nous publions les deux chiffres.

Famille retirée de l'entraînement (rappel inconnue / connue, environ 1,2 % de faux positifs, échantillons plafonnés) : SlowHTTPTest 1,00 / 1,00 ; FTP 1,00 / 1,00 ; HOIC 0,985 / 1,00 ; Hulk 0,92 / 1,00 ; Slowloris 0,66 / 0,99 ; GoldenEye 0,39 / 1,00 ; SSH 0,06 / 1,00 ; LOIC-HTTP 0,002 / 1,00 ; Infiltration 0,006 / 0,23 ; Botnet 0,000 / 1,00.

**Résultat négatif assumé :** le détecteur d'anomalies KMeans (appris sur le trafic normal) a échoué : seuls LOIC-UDP (537 flux seulement) et Slowloris (0,23) ressortent, rappel proche de 0 pour 12 familles sur 14. Les causes n'ont pas été testées (variables à queue lourde, trafic normal trop varié). Conclusion pour un SOC : le modèle supervisé est fiable sur les familles connues et leurs variantes, aveugle aux comportements nouveaux.

## 6. Flux continu, résilience et montée en charge

### 6.1 Kafka et scoreurs

3 brokers, 6 partitions, réplication 3, `min.insync.replicas` 2, `acks=all`, producteur idempotent. En direct, sur 71 485 flux connus : précision 0,9895, rappel 0,9319 (identique à l'évaluation hors ligne). Familles inconnues : rappel 0,0015, botnet jamais détecté (0 sur 17 113). C'est un rejeu de données étiquetées, pas du trafic réel.

**Panne :** kafka-3 arrêté en plein flux (300 flux/s) : 0 erreur du producteur, les 2 scoreurs restants reprennent les 6 partitions. Traitement au moins une fois (quelques flux peuvent être scorés deux fois).

### 6.2 Flink

Fenêtres de 10 s sur le temps de l'événement, règles de débit (200 flux courts par port, DNS exclu) sans modèle : 257 alertes de brute force et 253 rafales HTTP ; 90 % des flux des fenêtres alertées sont des attaques selon les étiquettes du rejeu. Limite : rejeu à 62 % d'attaques et sans adresse source ; sur du vrai trafic, un pic sur le port 80 est souvent légitime.

### 6.3 Montée en charge et tests de stress

Le premier stress test (4 078 à 6 472 flux/s) était limité par son propre producteur, placé sur kafka-1 à côté d'un broker : ce n'était qu'une borne basse. Nous l'avons refait avec les producteurs sur une VM séparée de 4 vCPU, et comparé trois façons d'ajouter des ressources. Détails et limites : `docs/SCALABILITY.md` ; résultats bruts : `ml/scale/`.

| Étage | Ce qui change | Avant → après | Lecture |
|---|---|---|---|
| API | e2-micro (0,25 vCPU) → e2-medium (2 vCPU) | 15 → 181 req/s ; p95 9,5 s → 0,54 s (64 connexions) | le CPU était le goulot (montée verticale) |
| Scoreurs Kafka | 1 → 2 → 3 VM e2-small | 9 546 → 17 865 → au moins 23 834 flux/s | presque linéaire (montée horizontale) |
| Spark | 2 → 3 → 4 exécuteurs (8 → 12 → 16 vCPU) | préparation 738 s → 536 s → 416 s | ×1,38 et ×1,77 (idéal ×1,5 et ×2) ; efficacité 92 % puis 89 % |
| Cache de réponses (API) | aucune ressource | aucun gain mesuré | conservé, non présenté comme une amélioration |

Constats :

- **Kafka :** un scoreur décroche à 12 000 flux/s, deux à 21 000 ; trois tiennent 24 000 (palier le plus haut testé, producteurs sur une seule VM : borne basse). Les 6 partitions plafonnent à 6 scoreurs utiles.
- **Spark :** le gain est un peu sous le linéaire (lecture, écriture et démarrage ne se parallélisent pas parfaitement). Dataproc Serverless refuse moins de 2 exécuteurs ; le quota global de 32 vCPU du projet a refusé 4 exécuteurs tant que les VM tournaient et interdit 8 exécuteurs sans demande de quota. Un seul run par point : pas d'intervalle de confiance.
- **API :** nous avions d'abord supposé que les routes lourdes (relecture de fichiers, recherche BM25) étaient le problème et ajouté un cache ; la mesure a montré que non : c'est le CPU de la petite VM. Les mesures partent d'un PC à environ 138 ms du serveur.
- Aucun coût n'est donné : il n'a pas été mesuré.


## 7. Journaux, API et agent

Les applications envoient leurs journaux à Logstash par HTTP ; Elasticsearch les indexe ; l'onglet Logs les analyse (Kibana n'est pas déployé). L'API est exposée derrière HTTPS et un login d'équipe : consultation des CVE, des procédures, des jeux de données, création d'incidents. L'agent Da Vinci répond d'abord par des règles (instantané), puis une réécriture par un LLM (Qwen interne : 5,5 jetons/s, 32 à 78 s par réponse sur CPU).

Flux CVE : 17 899 CVE sur 30 jours, 1 786 entrées KEV (dont 361 liées à des rançongiciels), score EPSS pour environ 8 500 CVE. 102 procédures de réponse (NIST 800-61, MITRE ATT&CK), dont 14 reliées aux familles du jeu de données.

## 8. Limites et ce qui n'est pas fait

- Le rejeu n'est pas du trafic réel ; les règles Flink produiraient des faux positifs sur du vrai trafic.
- Le modèle n'est pas relié au playbook SOAR (travail futur).
- Les procédures de réponse sont des brouillons générés par IA, non validés par un analyste.
- L'analyse par heure n'est pas fiable (les horodatages ne couvrent que les heures 1 à 12 dans les fichiers sources).
- Les coûts ne sont pas mesurés ici : à lire dans Facturation. Le quota global de vCPU du projet (environ 32) limite aussi les tests de montée en charge.
- Aucun test de sécurité formel : réseau interne, login d'équipe, clés jamais commitées.

## 9. Reproduire

Scripts : `scripts/gcp_bigdata.ps1` (lots), `gcp_stream.ps1` (Kafka), `gcp_flink.ps1`, `gcp_elk.ps1`, `gcp_qwen.ps1`, `gcp_cve_job.ps1`, `gcp_vm.ps1` (tableau de bord), `gcp_scale.ps1`, `gcp_spark_scale.ps1`, `api_loadtest.py` (tests de charge). Documentation détaillée dans `docs/` ; résultats de montée en charge dans `ml/scale/` et `docs/SCALABILITY.md`.
