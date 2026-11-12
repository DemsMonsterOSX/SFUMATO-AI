# Machine learning

Two models support incident classification. Neither is allowed to decide alone: their influence is capped and both can
**abstain**. Classes: `true_positive`, `false_positive`, `benign_positive` (≈ our `LEGITIMATE_ACTIVITY`).

## Dataset research (what fits the objective)

| Dataset | Labels | Verdict |
|---|---|---|
| CIC-IDS2017 / CSE-CIC-IDS2018 / UNSW-NB15 | network *flows* (attack vs benign) | **Not suitable**: they do not label SOC alert triage outcomes (false positive vs legitimate), so they cannot teach this task |
| **Microsoft GUIDE** (Kaggle, CDLA-Permissive-2.0) | real analyst triage grades: TP / BP / FP on ~1M incidents | **Right label taxonomy.** Used for the reference model. Most columns are anonymised IDs, so only portable signals are used |
| `Vyber07/cyber-security` (Hugging Face) | none (instruction/Q&A text) | Not for classification; used as a **knowledge base** (RAG) |
| Synthetic SOC alerts (generated) | defined by analyst-archetype generators | Used for the primary triage model, **explicitly labelled synthetic** |

Licences/availability were taken from the dataset pages and the GUIDE paper (arXiv 2407.09017); verify them before redistribution.

## 1. Primary triage model (synthetic data)

* **Why synthetic**: no public dataset maps onto Sfumato's alert format (features come from its own behaviour, CTI and context
  rules). `backend/app/ml/synthetic.py` samples alerts from documented archetypes (macro dropper, C2 beacon, brute force,
  approved software, sanctioned update, admin scripting, patch deployment…) with overlapping distributions, missing
  telemetry, feature noise (2 %) and label noise (3 %).
* **Features** (37, `ml/features.py`): alert-level, telemetry presence, behaviour flags, organisation context, CTI.
* **Method** (`python -m app.ml.train`): stratified 70/15/15 split; rows of validation/test identical to training rows are
  removed (leakage control); candidates Logistic Regression (baseline), Random Forest, XGBoost; selection by validation
  macro-F1, the simpler model wins ties within 0.005; final metrics measured once on the held-out test split.
* **Reported** (`ml/evaluation/metrics.json`, shown in the Observatory): per-class precision/recall/F1, macro-F1, accuracy,
  ROC-AUC (one-vs-rest), confusion matrix, feature importance. At the time of writing XGBoost was selected with a test
  macro-F1 of ≈ 0.90. **These numbers measure how well the model recovers the generator's archetypes. They are not a
  claim about real-world SOC performance**, and the features overlap with the deterministic rules, so the model is not an
  independent witness (hence the 15-point cap).
* **Abstention**: evidence completeness < 40 %, input outside the training range (IsolationForest score below the 0.5th
  percentile or out-of-range features) or top probability < 0.55. Per-incident explanation by occlusion.
* The artifact is rebuilt automatically on first start or when the scikit-learn version differs.

## 2. Reference model on Microsoft GUIDE (bucket)

Trained on Kaggle (`ml/guide/train_guide.py`, notebook `sfumato_guide_kaggle.ipynb`), published signed to a bucket, served by
`app/ml/guide_inference.py`. See `ml/guide/README.md` for the full procedure.

* **Features**: alert category, MITRE techniques (a sub-technique also counts as its parent), entity types, hour of day (cyclic),
  weekend; matched through a vocabulary learnt from the data with normalised names. Anonymised IDs are ignored.
* **Leakage control**: an incident is one atomic example; **15 % of organisations are held out as the test set**, so metrics
  estimate generalisation to an unseen SOC. Validation is a stratified split of the remaining incidents.
* **Metrics** also include the binary view *threat (TP) vs non-threat (FP+BP)*: ROC-AUC, precision and recall.
* **Abstention**: no recognised category/technique, out-of-distribution, or confidence < 0.5. Cap in the decision: 10 points;
  a disagreement with the final verdict forces human review.
* **Status**: the pipeline is tested end to end with a *test fixture* in the GUIDE column layout. **No real GUIDE training run
  has been executed in this repository**: real metrics will exist only after running the notebook.
* Limits: GUIDE reflects Microsoft customers' detections and analysts' decisions (not ground truth); other tools' alerts may
  be out of distribution.

## Improving it

The best next step is to train on your own analysts' verdicts (a feedback loop exporting reviewed incidents to the bucket).
That is not implemented yet.
