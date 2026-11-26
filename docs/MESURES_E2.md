# Mesures faites sur les VM E2 (référence avant le changement d'architecture)

Document de référence : tout ce qui a été **mesuré** sur des VM de la famille E2 de Google Compute Engine, avec le type de machine, la date
et le fichier source. Il sert de point de départ pour comparer la future architecture (moins de VM, plus puissantes : C4 et N1).
Rien n'est extrapolé : quand une valeur n'a pas été relevée, c'est écrit. Les coûts n'ont jamais été lus dans Billing.

Lecture : E2 est la famille « optimisée coût » (processeurs partagés, performances variables, pas de garantie de fréquence).
Le premier jeu de mesures (19 et 20 novembre) a été fait sur des E2 très petites ; le deuxième (25 novembre, « pro Max ») sur des E2 plus grosses.

## 1. Configurations E2 utilisées

| VM | 19-20 nov. (économique) | 25-26 nov. (« pro Max ») |
|---|---|---|
| `sfumato` (tableau de bord, API) | e2-micro puis e2-medium | e2-standard-4 |
| `sfumato-kafka-1` | e2-small Spot | e2-standard-4 Spot |
| `sfumato-kafka-2`, `-3` | e2-small Spot | e2-standard-2 Spot |
| `sfumato-flink` | e2-medium Spot | e2-standard-4 Spot |
| `sfumato-elk` | e2-standard-2 Spot | e2-standard-2 Spot |
| Qwen (CPU, avant la GPU) | e2-standard-4 Spot (7B) | remplacé par une GPU (voir la section 7) |
| Générateur de charge | `sfumato-qwen` e2-standard-4 | `sfumato-lg` e2-standard-8 Spot |
| Renforts autoscalés | n/a | `sfumato-scorer-1`, `-2` e2-standard-4 Spot (26 nov.) |

## 2. Kafka : débit des scorers (producteurs sur une VM séparée)

Méthode : paliers de 30 s, un palier est « tenu » si les scorers consomment au moins 95 % du produit et si le retard final reste sous 3 s de trafic.
Sources : `ml/scale/kafka_scorers{1,2,3}.json` et `ml/scale/kafka_scorers{1,2,3}_promax.json`.

| Scorers | Brokers e2-small (20 nov.) | Brokers e2-standard-4/2/2 (25 nov.) |
|---|---|---|
| 1 | 9 546 flux/s (échec à 12 000 : retard 26 840) | 9 569 flux/s (échec à 14 400 : retard 146 680) |
| 2 | 17 865 flux/s (échec à 21 000 : retard 32 400) | 18 427 flux/s (échec à 24 000 : retard 140 503) |
| 3 | ≥ 23 834 flux/s (borne basse : producteurs limités) | 28 399 flux/s (palier 30 000 : retard 43 374, producteurs limités) |

Lecture honnête : passer des E2 les plus petites aux E2 plus grosses change peu le débit par scorer (environ 9 500 flux/s par scorer dans les deux cas).
Le goulot est donc le scorer (Python et XGBoost), pas le broker. Une seule exécution par configuration, sans intervalle de confiance.

## 3. Kafka : mise à l'échelle automatique des scorers (26 nov.)

Source : `ml/scale/autoscale_e2.json`. Charge constante de 32 000 flux/s pendant 300 s (8 processus producteurs), 9 569 200 messages envoyés, 0 erreur.
Politique : monter si le retard dépasse 3 000 pendant 20 s, descendre s'il reste sous 300 pendant 240 s, 90 s entre deux actions.

| Heure locale | Événement | Retard au moment de la décision |
|---|---|---|
| 16:29:11 | démarrage de `sfumato-scorer-1` | 13 305 |
| 16:31:29 | démarrage de `sfumato-scorer-2` | 23 858 |
| 16:38:00 | arrêt de `sfumato-scorer-2` | 140 |
| 16:42:14 | arrêt de `sfumato-scorer-1` | 194 |

Débit moyen produit 32 198 flux/s, consommé 32 188 flux/s ; pic de retard 62 197 messages (à 234 s) ; retard final 181.
Limite : les producteurs n'ont pas dépassé environ 32 000 flux/s, donc ce test prouve le mécanisme (monter, redescendre, retard résorbé), pas la capacité de 4 ou 5 scorers.
Les deux VM ont mis plusieurs minutes à rejoindre le groupe (démarrage, puis installation déjà faite, puis rééquilibrage).

## 4. Kafka : test historique à 300 flux/s (19 nov., brokers e2-small)

Source : `ml/stream/results.json`. Détection sur 71 485 flux (scénario « familles connues ») : précision 0,9895, rappel 0,9319.
Scénario « familles inconnues » (46 097 flux) : précision 0,619, rappel 0,0015, c'est-à-dire que le modèle supervisé ne voit presque rien.
Latence p50 des scorers environ 550 ms (comprend le regroupement et l'attente, sur e2-small).
Test de panne : un broker et un scorer arrêtés pendant le flux, 0 erreur côté producteur, les deux scorers restants ont repris les 6 partitions,
le retard est retombé à environ 15 à 20 messages par scorer après le redémarrage. Une seule panne testée.

## 5. Flink (règle par source, fenêtres de 60 s)

| Jeu | Enregistrements | Parallélisme 1 | Parallélisme 2 | Parallélisme 4 | Source |
|---|---|---|---|---|---|
| 14 février | 23 669 308 | 214 590/s moyen (110 s) | 590 257/s (40 s) | 471 500/s (50 s) | `flink_source_p*.json` |
| 7 jours (14 à 23 fév.) | 42 449 865 | 211 720/s (200 s) | 302 565/s (140 s) | 282 246/s (150 s) | `flink_source7_p*.json` |

Machine : `sfumato-flink` ou `sfumato-flink-src`, e2-standard-4 Spot d'après mes notes ; les fichiers ne la notent pas. Le gain s'arrête à 2 : le parallélisme 4 est plus lent,
probablement parce que 4 emplacements se partagent 4 vCPU E2 avec la lecture Kafka, hypothèse non vérifiée.
Qualité des alertes de la règle par source sur les 7 jours : voir `ml/scale/flink_source7_alerts.json` (99,6 % de précision contre 4,9 % pour une règle sur le volume seul).
Test du 19 nov. (fenêtres de 10 s) : 218 fenêtres en environ 30 minutes, 257 alertes de force brute et 253 de rafales HTTP, 90,2 % de flux d'attaque dans les fenêtres alertées.

## 6. API du tableau de bord (charge depuis Internet, 64 connexions)

| Route | e2-micro (0,25 vCPU) | e2-medium (2 vCPU) | e2-standard-4 |
|---|---|---|---|
| `/health` | 125 req/s (meilleur essai propre ; 17 req/s au deuxième essai) | 182 req/s, p95 0,53 s | 243 req/s |
| `/procedures?q=ransomware` | 16 req/s, p95 9,6 s | 181 req/s, p95 0,54 s | non mesuré |
| `/bigdata/overview` | 10 req/s, p95 13 s | 133 req/s, p95 0,66 s | 206 req/s |
| `/cves/summary` | 11 req/s à 32 connexions, p95 5,4 s | 84 req/s, p95 1,0 s | non mesuré |

Sources : `ml/scale/{before,medium,promax}_*.json`. Le client (un PC, via Internet, environ 138 ms) limite aussi ce qui est mesuré. Le passage e2-micro → e2-medium donne un gain
de ×7,6 à ×13 sur les routes lourdes (de 11 à 84 req/s pour `/cves/summary`, de 10 à 133 pour `/bigdata/overview`) : le CPU était le goulot. De e2-medium à e2-standard-4, le gain est plus faible : ×1,3 (`/health`) et ×1,5 (`/bigdata/overview`).

## 7. Autres mesures qui ne sont pas sur E2

* Spark (Dataproc Serverless, hors E2) : préparation de 6,89 Go en 738 s, 536 s, 416 s avec 2, 3 et 4 exécuteurs (`spark_scale.json`).
* LLM sur CPU E2 (19 nov.) : Qwen 2.5 7B sur e2-standard-4 Spot, 5,53 tokens/s, chargement 4,7 s, réponse de l'agent en 32 à 78 s sur quatre questions.
* LLM sur GPU T4 (25-26 nov.) : 7B 23,3 tokens/s, 14B 16,6, 27B 2,9 (`llm_bench.json`). La T4 est ensuite remplacée par un L4 (aucun nouveau benchmark).
* Traitement des PCAP (Zeek) : VM e2-standard-8 Spot, un jour par VM. Les durées exactes par jour n'ont pas été relevées.

## 8. Ce qui n'est PAS mesuré (à ne pas affirmer)

* Aucun coût réel lu dans Billing.
* Aucun test de l'API avec la nouvelle GPU L4 ni du temps de réponse de bout en bout d'une investigation sous charge.
* Aucune mesure de débit avec 4 ou 5 scorers : il faut un deuxième générateur de charge pour dépasser 32 000 flux/s.
* Pas de répétition des mesures : chaque point est une seule exécution.
