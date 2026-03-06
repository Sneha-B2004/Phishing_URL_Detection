# PHISHING URL DETECTION – MACHINE LEARNING PROJECT

# LIVE DEMO
https://phishingurldetection-i46jpr2np6abcr6reqskxn.streamlit.app/

# PROJECT OVERVIEW
This project detects whether a given URL is **Phishing** or **Legitimate** based on structural and security-related features extracted from the URL.

It is a Supervised Machine Learning Classification Problem because:
  *The dataset contains labeled output (Result)
  *The output is categorical (Phishing or Legitimate)
  *The model learns patterns from historical phishing data
The objective is to build a reliable phishing detection system that can classify suspicious URLs accurately.

# OBJECTIVES
* Understand phishing URL dataset
* Perform data cleaning and preprocessing
* Extract meaningful URL-based features
* Train classification models
* Evaluate performance using proper metrics
* Deploy the model using Streamlit
* Provide confidence score for predictions

# PROBLEM STATEMENT
Phishing websites are designed to mimic legitimate websites in order to steal sensitive information such as login credentials, banking details, and personal data.

Manual detection of phishing URLs is difficult because:
* Malicious URLs often look similar to real websites
* Users cannot easily identify suspicious patterns
* Traditional blacklisting methods fail for newly created phishing domains

Without an automated detection system:
* Users are vulnerable to cyber attacks
* Organizations face data breaches
* Financial losses increase

# Project Goal
To detect phishing URLs using supervised machine learning techniques based on URL characteristics.

By building this phishing detection system, stakeholders can:
* Identify malicious websites before accessing them
* Reduce cybersecurity risks
* Support automated threat detection
* Improve online safety

# DATASET USED
The project uses a labeled phishing dataset containing URL features.

### Target Column:

Result
* 1 → Legitimate
* 0 (or -1 depending on dataset) → Phishing

### Important Features Include:

* Having IP Address
* URL Length
* Presence of @ Symbol
* Double Slash Redirecting
* Prefix-Suffix (-) in domain
* Having Subdomain
* HTTPS Token
* SSL Final State
* Domain Registration Length
* Request URL
* URL of Anchor
* Links in Tags
* IFrame detection

# PROJECT APPROACH

### Exploratory Data Analysis (EDA)
* Studied distribution of phishing vs legitimate URLs
* Identified most influential features
* Checked correlation between features

### Data Preprocessing
* Handled missing values
* Converted categorical values into numerical format
* Balanced dataset (if required)
* Split dataset into training and testing sets

### Model Building
Trained classification models such as:
* Logistic Regression
* Random Forest Classifier

### Model Evaluation
Models were evaluated using:
* Accuracy
* Precision
* Recall
* F1 Score
* Confusion Matrix
The best-performing model was selected based on evaluation metrics.

### Deployment
The final model is deployed using **Streamlit** to provide a user-friendly web interface where users can:
* Enter a URL manually
* Upload a CSV file for bulk scanning
* View prediction result
* See confidence score (%)

# BLOCK DIAGRAM

<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/1250f9b4-bb06-4a07-8262-2f31e9ac70b0" />
