# CerebRAN: A Dynamic Behavioural Dataset for Ransomware Detection

Abstract: Ransomware remains a significant cyber threat, yet research is often hampered by a lack of modern, balanced datasets. This study proposed CerebRAN, a new dataset made from dynamic analysis of ransomware (400 samples) and goodware (399 samples). We provide a detailed methodology from the sample collection to extraction of features using Cuckoo Sandbox on a Windows 7 operating system. To validate the usability of CerebRAN, we performed machine learning experiments using Random Forests and Logistic Regression using the Recursive Feature Elimination with Cross-Validation (RFECV) technique. The results we obtained from the experiments show that the Random forests were the superior classifier on CerebRAN scoring accuracy of 0.9625, precision of 0.9628, recall of 0.9625 and f1-score of 0.9625. Logistic regression scored an accuracy of 0.9562, precision of 0.9563, recall of 0.9563 and an F1-score of 0.9562. Random forests outperformed Logistic regression using an optimum 48 features while logistic regression used 174 features. This experiment highlighted how effective and valuable CerebRAN is for the development of robust detection tools.

# Dataset Description

The CerebRAN dataset is a balanced collection of behavioural indicators designed for training and evaluating machine learning-based ransomware detectors. The dataset was created by performing dynamic analysis on 799 unique software samples in a Cuckoo Sandbox environment running a Windows 10 guest.

The dataset comprises:

400 ransomware samples, representing a diverse range of modern families (labeled as 1).

399 goodware samples, consisting of legitimate and benign software (labeled as 0).

Dynamic analysis generated an initial set of 28,004 unique behavioural features, including API calls, file system operations, registry modifications, and network activity. After a rigorous preprocessing phase to remove non-informative and zero-variance features, the final dataset used for modeling contains 426 distinct, predictive behavioural indicators. The features are one-hot encoded, with a value of '1' indicating the presence of a specific behaviour during execution and '0' indicating its absence.




# Disclaimer!

All ransomware analyses were conducted in controlled sandbox environments. This repository does not distribute raw binaries. However, we provide the hashes of the samples and complete metadata to help in downloading the samples. Researchers are advised to follow appropriate safety protocols when working with malware and to comply with their institution’s ethical and legal standards.
