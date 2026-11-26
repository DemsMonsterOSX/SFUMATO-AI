# Mesures sur la nouvelle architecture Kafka (C4 + N1)

Architecture mesurée le 26 novembre 2026 : `sfumato-kafka-1` en c4-standard-8 (broker et contrôleur KRaft, Hyperdisk), `sfumato-kafka-2` en n1-standard-4 (broker seul),
réplication 2, au moins 1 réplica synchronisé, 6 partitions sur `network-flows`. VM à tarif normal (pas Spot). Producteurs sur `sfumato-lg` (e2-standard-8).
Même méthode que les mesures E2 (`docs/MESURES_E2.md`) : paliers de 30 s, un palier est tenu si les scorers consomment au moins 95 % du produit.

## Résultat (un seul run, fichier `ml/scale/kafka_scorers1_c4n1.json`)

| Scorers | E2 (brokers e2-standard-4/2/2, 25 nov.) | C4 + N1 (26 nov.) |
|---|---|---|
| 1 | 9 569 flux/s (échec à 14 400) | **23 896 flux/s** (échec à 30 000 : consommé 25 151, retard 140 104) |
| 2 | 18 427 flux/s | **non mesuré** : l'arrêt demandé a interrompu le run |
| 3 | 28 399 flux/s | non applicable : il y a deux VM de broker |

Un scorer sur la C4 tient donc environ 2,5 fois ce qu'il tenait sur E2. C'est cohérent avec le micro-benchmark du modèle seul (×2,9 par cœur, `ml/scale/bench_scorer_cpu.json`),
mais les deux mesures ne sont pas identiques : le micro-benchmark ne mesure que le modèle, ici c'est le scorer complet et le broker.

## Limites

* Une seule exécution, pas d'intervalle de confiance. Le run à 2 scorers n'existe pas.
* Le scorer et le broker sont sur la même VM (la C4) : le résultat mélange les deux, et je n'ai pas mesuré lequel limite à 30 000 flux/s.
* Les producteurs (une e2-standard-8) plafonnent vers 32 000 flux/s, donc au-delà de 30 000 flux/s on ne mesure plus rien de fiable.
* Aucun coût lu dans Billing. La C4 et la N1 coûtent plus cher que les E2 qu'elles remplacent : le gain de débit n'est pas un gain de coût.
* Contrôleur unique sur la C4 : si elle tombe, la N1 garde les données mais le cluster ne se réélit pas seul.
* Kafka 3 et Kafka 4 à la demande (`gcp_stream.ps1 add-brokers` / `drop-brokers`) : écrits, jamais exécutés, donc non prouvés.
